use std::{path::PathBuf, time::Duration};

use libafl::{
    corpus::{CachedOnDiskCorpus, Corpus, OnDiskCorpus, Testcase},
    events::SimpleEventManager,
    feedbacks::{CrashFeedback, ListFeedback, NautilusFeedback},
    inputs::{BytesInput, NautilusBytesConverter, NautilusInput},
    monitors::SimpleMonitor,
    mutators::{HavocScheduledMutator, NautilusRandomMutator,
        NautilusRecursionMutator, NautilusSpliceMutator,},
    observers::ListObserver,
    schedulers::QueueScheduler,
    stages::StdMutationalStage,
    state::StdState,
    Fuzzer, StdFuzzer,
    feedback_or,
    generators::{NautilusContext, NautilusGenerator},
};
#[cfg(unix)]
use libafl_bolts::shmem::UnixShMemProvider;
#[cfg(windows)]
use libafl_bolts::shmem::Win32ShMemProvider;
use libafl_bolts::{
    ownedref::OwnedMutPtr, rands::StdRand, shmem::ShMemProvider, tuples::tuple_list,
};
use libafl_tinyinst::executor::TinyInstExecutor;
static mut COVERAGE: Vec<u64> = vec![];

#[cfg(not(any(target_vendor = "apple", windows, target_os = "linux")))]
fn main() {}

#[cfg(any(target_vendor = "apple", windows, target_os = "linux"))]
fn main() {
    // Load grammar from json file
    let ctx = NautilusContext::from_file(15, "grammar.json").unwrap();
    // Tinyinst things
    let tinyinst_args = vec!["-instrument_module".to_string(), "test.exe".to_string()];

    // use shmem to pass testcases
    let args = vec!["test.exe".to_string(), "-m".to_string(), "@@".to_string()];

    // use file to pass testcases
    // let args = vec!["test.exe".to_string(), "-f".to_string(), "@@".to_string()];

    let coverage = OwnedMutPtr::Ptr(&raw mut COVERAGE);
    let observer = ListObserver::new("cov", coverage);
    let mut feedback = feedback_or!(ListFeedback::new(&observer), NautilusFeedback::new(&ctx));
    #[cfg(windows)]
    let mut shmem_provider = Win32ShMemProvider::new().unwrap();

    #[cfg(unix)]
    let mut shmem_provider = UnixShMemProvider::new().unwrap();

    let rand = StdRand::new();
    let mut corpus = CachedOnDiskCorpus::new(PathBuf::from("./corpus_discovered"), 64).unwrap();
    let solutions = OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap();

    let mut objective = CrashFeedback::new();
    let mut state = StdState::new(rand, corpus, solutions, &mut feedback, &mut objective).unwrap();
    let scheduler = QueueScheduler::new();
    // let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let monitor = SimpleMonitor::new(|x| println!("{x}"));

    let mut mgr = SimpleEventManager::new(monitor);

    let mut generator = NautilusGenerator::new(&ctx);

    let mut fuzzer: StdFuzzer<QueueScheduler, _, _, NautilusInput, BytesInput> = StdFuzzer::builder()
        .scheduler(scheduler)
        .feedback(feedback)
        .objective(objective)
        .target_bytes_converter(NautilusBytesConverter::new(&ctx))
        .build();

    let mut executor = TinyInstExecutor::builder()
        .tinyinst_args(tinyinst_args)
        .program_args(args)
        .use_shmem()
        .persistent("test.exe".to_string(), "fuzz".to_string(), 1, 10000)
        .timeout(Duration::new(5, 0))
        .shmem_provider(&mut shmem_provider)
        .coverage_ptr(&raw mut COVERAGE)
        .build(tuple_list!(observer))
        .unwrap();

    if state.must_load_initial_inputs() {
        state
            .generate_initial_inputs_forced(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 4)
            .expect("Failed to generate the initial corpus");
    }

    let mutator = HavocScheduledMutator::with_max_stack_pow(
        tuple_list!(
            NautilusRandomMutator::new(&ctx),
            NautilusRandomMutator::new(&ctx),
            NautilusRecursionMutator::new(&ctx),
            NautilusSpliceMutator::new(&ctx),
        ),
        2,
    );
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));
    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("error in fuzzing loop");
}

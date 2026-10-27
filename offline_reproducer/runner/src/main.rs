#![feature(path_absolute_method)]

// SPDX-FileCopyrightText: 2026 Quarkslab
//
// SPDX-License-Identifier: Apache-2.0

use libafl::corpus::InMemoryCorpus;
use libafl::events::SimpleEventManager;
use libafl::executors::ExitKind;
use libafl::feedbacks::{ConstFeedback, CrashFeedback};
use libafl::monitors::NopMonitor;
use libafl::observers::{CanTrack, HitcountsMapObserver, TimeObserver, VariableMapObserver};
use libafl::schedulers::QueueScheduler;
use libafl::state::StdState;
use libafl::{Evaluator, StdFuzzer};
use libafl_bolts::{current_nanos, ownedref::OwnedMutSlice, rands::StdRand, tuples::tuple_list};
use libafl_qemu::modules::{AsanHostModule, DrCovModule};
use libafl_qemu::{
    modules::{utils::filters::StdAddressFilter, StdEdgeCoverageModule},
    Emulator, QemuExecutor, QemuParams,
};
use libafl_targets::{edges_map_mut_ptr, EDGES_MAP_DEFAULT_SIZE, MAX_EDGES_FOUND};

use std::{fs, ops::Range, path::PathBuf, time::Duration};

use crate::misc::{MyInput, ThisEmulator};

mod libslirp;
mod misc;

static INPUT_ADDR: u64 = 0x0000000000010000;

fn main() {
    env_logger::init();

    let mut edges_observer = unsafe {
        HitcountsMapObserver::new(VariableMapObserver::from_mut_slice(
            "edges",
            OwnedMutSlice::from_raw_parts_mut(edges_map_mut_ptr(), EDGES_MAP_DEFAULT_SIZE),
            &raw mut MAX_EDGES_FOUND,
        ))
        .track_indices()
    };

    let cov_module = StdEdgeCoverageModule::builder()
        .map_observer(edges_observer.as_mut())
        .build()
        .expect("failed to build edge coverage module");

    let asan_filter = StdAddressFilter::deny_list(vec![
        Range {
            start: INPUT_ADDR,
            end: INPUT_ADDR + 0x1000,
        },
        Range {
            start: 0xffffffffff600000_u64,
            end: 0xffffffffff601000_u64,
        },
    ]);

    let repro_file = std::env::args().nth(1).unwrap();

    log::warn!("repro file: {}", repro_file);

    let filename = repro_file
        .split('/')
        .last()
        .unwrap()
        .split('.')
        .next()
        .unwrap();

    let mut cov_file = String::from("./coverage/");
    cov_file.push_str(filename);
    cov_file.push_str(".cov");
    let cov_file_path = PathBuf::from(cov_file);
    log::debug!("cov file: {:?}", cov_file_path.absolute());
    let emulator_modules = tuple_list!(
        cov_module,
        DrCovModule::builder().path(cov_file_path).build(),
        unsafe {
            AsanHostModule::builder()
                .filter(asan_filter)
                .asan_report()
                .build()
        }
    );

    let params = ["qemu-x86_64".to_string(), "./qemu-target".to_string()].to_vec();
    let params = QemuParams::Cli(params);

    let mut emulator: ThisEmulator = Emulator::empty()
        .qemu_parameters(params)
        .modules(emulator_modules)
        .build()
        .expect("failed to build emulator");

    libslirp::hooks::add_hooks(&mut emulator);

    let (target_addr, stop_addr) = libslirp::utils::retrieve_target_and_stop_addr(&emulator);

    let mut qemu = emulator.qemu();
    let _ = qemu.map_private(INPUT_ADDR, 0x1000, libafl_qemu::MmapPerms::ReadWrite);

    libslirp::utils::setup_target(&mut qemu, target_addr, stop_addr);

    let bytes = fs::read(repro_file).unwrap();
    let inputs = postcard::from_bytes(&bytes).unwrap();

    let mut harness = |emu: &mut ThisEmulator,
                       _state: &mut StdState<
        InMemoryCorpus<MyInput>,
        MyInput,
        libafl_bolts::rands::RomuDuoJrRand,
        InMemoryCorpus<MyInput>,
    >,
                       inputs: &MyInput| {
        let mut qemu = emu.qemu();
        let inputs = &inputs.inner;
        log::debug!("{:?}", inputs);
        for input in inputs {
            // Copy the input into Qemu's memory
            let _ = qemu.write_mem(INPUT_ADDR, input);
            // Write the arguments for the fuzz_me function and restore RIP to the start of fuzz_me
            libslirp::utils::setup_target_arguments(&mut qemu, target_addr, input.len() as u64);

            let _ = unsafe { qemu.run() };
        }
        ExitKind::Ok
    };

    let monitor = NopMonitor::new();
    let mut feedback = ConstFeedback::False;
    let time_observer = TimeObserver::new("time");
    let mut objective = CrashFeedback::new();
    let mut state: StdState<
        InMemoryCorpus<MyInput>,
        MyInput,
        libafl_bolts::rands::RomuDuoJrRand,
        InMemoryCorpus<MyInput>,
    > = StdState::new(
        StdRand::with_seed(current_nanos()),
        InMemoryCorpus::new(),
        InMemoryCorpus::new(),
        &mut feedback,
        &mut objective,
    )
    .unwrap();
    let mut mgr = SimpleEventManager::new(monitor);
    let scheduler = QueueScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let mut executor = QemuExecutor::new(
        emulator,
        &mut harness,
        tuple_list!(time_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        Duration::from_secs(10),
    )
    .unwrap();

    let wrapped_inputs = MyInput { inner: inputs };
    let _ = fuzzer.evaluate_input(&mut state, &mut executor, &mut mgr, &wrapped_inputs);
}

// SPDX-FileCopyrightText: 2026 Quarkslab
//
// SPDX-License-Identifier: Apache-2.0

mod feedback;
mod libslirp;
mod network_targets_utils;
mod observer_module;
mod snapshot_manager;
mod utils;

use std::ops::Range;
use std::time::Duration;

use libafl::corpus::Corpus;
use libafl::stages::StdMutationalStage;
use libafl::state::{HasCorpus, HasCurrentTestcase};
use libafl::{
    Error, Fuzzer, StdFuzzer,
    corpus::OnDiskCorpus,
    events::SimpleRestartingEventManager,
    executors::ExitKind,
    feedback_or,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback},
    monitors::MultiMonitor,
    observers::{CanTrack, HitcountsMapObserver, TimeObserver, VariableMapObserver},
    schedulers::{PowerQueueScheduler, powersched::PowerSchedule},
    state::StdState,
};
use libafl::{Evaluator, HasMetadata, monitors};
use libafl_bolts::{
    ownedref::OwnedMutSlice,
    rands::StdRand,
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::tuple_list,
};
use libafl_qemu::modules::IntervalSnapshotFilter;
use libafl_qemu::modules::snapshot::IntervalSnapshotFilters;
use libafl_qemu::{
    Emulator, QemuExecutor, QemuParams,
    modules::{SnapshotModule, StdEdgeCoverageModule},
};
use libafl_qemu::{IsSnapshotManager, QemuMappingsViewer};
use libafl_targets::{EDGES_MAP_DEFAULT_SIZE, MAX_EDGES_FOUND, edges_map_mut_ptr};

use crate::feedback::{SnapshotMetadata, StateChangedFeedback};
use crate::observer_module::ObserverModule;
use crate::snapshot_manager::IncrementalSnapshotManager;

type Emu = Emulator<
    libafl_qemu::command::NopCommand,
    libafl_qemu::command::NopCommandManager,
    libafl_qemu::NopEmulatorDriver,
    (
        SnapshotModule,
        (
            libafl_qemu::modules::EdgeCoverageModule<
                libafl_qemu::modules::utils::filters::StdAddressFilter,
                libafl_qemu::modules::utils::filters::NopPageFilter,
                libafl_qemu::modules::edges::EdgeCoverageFullVariant,
                false,
                0,
            >,
            (
                ObserverModule,
                (network_targets_utils::tcp::TCPObserverModule, ()),
            ),
        ),
    ),
    network_targets_utils::inputs::Packet,
    StdState<
        OnDiskCorpus<network_targets_utils::inputs::Packet>,
        network_targets_utils::inputs::Packet,
        libafl_bolts::rands::RomuDuoJrRand,
        OnDiskCorpus<network_targets_utils::inputs::Packet>,
    >,
    IncrementalSnapshotManager,
>;

static INPUT_ADDR: u64 = 0x0000000000010000;

fn main() {
    env_logger::init();

    let toml_monitor = monitors::OnDiskTomlMonitor::new("stats.toml");
    let monitor = tuple_list!(MultiMonitor::new(|s| println!("{s}")), toml_monitor);
    let mut shmem_provider = StdShMemProvider::new().unwrap();

    let mut edges_observer = unsafe {
        HitcountsMapObserver::new(VariableMapObserver::from_mut_slice(
            "edges",
            OwnedMutSlice::from_raw_parts_mut(edges_map_mut_ptr(), EDGES_MAP_DEFAULT_SIZE),
            &raw mut MAX_EDGES_FOUND,
        ))
        .track_indices()
    };

    let (state, mut mgr) =
        match SimpleRestartingEventManager::launch(monitor, &mut shmem_provider, true) {
            Ok(res) => res,
            Err(err) => match err {
                Error::ShuttingDown => {
                    return;
                }
                _ => {
                    panic!("Failed to setup the restarter: {err}");
                }
            },
        };
    let time_observer = TimeObserver::new("time");
    let map_feedback = MaxMapFeedback::new(&edges_observer);

    let state_feedback = StateChangedFeedback::new();
    let mut feedback = feedback_or!(
        state_feedback,
        map_feedback,
        TimeFeedback::new(&time_observer),
    );
    let mut objective = CrashFeedback::new();
    let mut state = state.unwrap_or_else(|| {
        StdState::new(
            StdRand::new(),
            OnDiskCorpus::new("./corpus").unwrap(),
            OnDiskCorpus::new("./crash").unwrap(),
            &mut feedback,
            &mut objective,
        )
        .unwrap()
    });

    let cov_module = StdEdgeCoverageModule::builder()
        .map_observer(edges_observer.as_mut())
        .build()
        .expect("failed to build edge coverage module");
    let obsmod = ObserverModule::new();
    let tcp_obsmod = network_targets_utils::tcp::TCPObserverModule::new();

    let skip_input_filter =
        IntervalSnapshotFilters::from(vec![IntervalSnapshotFilter::DenyList(vec![
            Range {
                start: INPUT_ADDR,
                end: INPUT_ADDR + 0x1000,
            },
            Range {
                start: 0xffffffffff600000_u64,
                end: 0xffffffffff601000_u64,
            },
        ])]);
    let mut snap: SnapshotModule = SnapshotModule::with_filters(skip_input_filter);
    snap.use_manual_reset();

    let emulator_modules = tuple_list!(snap, cov_module, obsmod, tcp_obsmod);

    let snap_mgr = IncrementalSnapshotManager::new();

    let params = ["qemu-x86_64".to_string(), "./qemu-target".to_string()].to_vec();
    let params = QemuParams::Cli(params);

    // Need to give the full type because Rust can infer it for some purpose
    let mut emulator: Emu = Emulator::empty()
        .qemu_parameters(params)
        .modules(emulator_modules)
        .snapshot_manager(snap_mgr)
        .build()
        .expect("failed to build emulator");

    let (target_addr, stop_addr) = libslirp::utils::retrieve_target_and_stop_addr(&emulator);

    // Add libslirp-related hooks
    libslirp::hooks::add_hooks(&mut emulator);

    let mut qemu = emulator.qemu();

    // Allocate some memory region to place our inputs instead of re-using the target's one
    let _ = qemu.map_private(INPUT_ADDR, 0x1000, libafl_qemu::MmapPerms::ReadWrite);

    log::debug!("{:?}", QemuMappingsViewer::new(&qemu));
    // Set breakpoints to the start and end of the fuzz_me function. The one on start will be
    // removed once the function is reached to start fuzzing. The one on end is used to signal the
    // end of processing the testcase.
    libslirp::utils::setup_target(&mut qemu, target_addr, stop_addr);

    // We are using our own lain based packet mutator to generate seemingly valid TCP packets
    // so we only hit code relevant to our target
    let packet_mutator = network_targets_utils::mutator::PacketMutator::new();
    let mutation_stage = StdMutationalStage::new(packet_mutator);
    let scheduler = PowerQueueScheduler::new(&mut state, &edges_observer, PowerSchedule::fast());
    let mut stages = tuple_list!(mutation_stage);
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let mut harness = |emulator: &mut Emulator<_, _, _, _, _, _, _>,
                       state: &mut StdState<
        OnDiskCorpus<network_targets_utils::inputs::Packet>,
        network_targets_utils::inputs::Packet,
        libafl_bolts::rands::RomuDuoJrRand,
        OnDiskCorpus<network_targets_utils::inputs::Packet>,
    >,
                       input: &network_targets_utils::inputs::Packet| {
        let mut qemu = emulator.qemu();

        // Restore the testcase's associated snapshotId.
        // Special case to handle the loading of initial inputs phase as there is no current_testcase
        let current_testcase = state.current_testcase();
        if let Ok(ref current_testcase) = current_testcase {
            let snapshot_meta = current_testcase.metadata::<SnapshotMetadata>().unwrap();
            let id = snapshot_meta.snapshot_id();
            log::trace!("{:?}", id);
            let sm: &mut IncrementalSnapshotManager = emulator.snapshot_manager_mut();
            sm.restore(qemu, &id)
                .expect("Failed to restore the snapshot of the current testcase");
            let parent_id = sm.parent_id;
            let snapshot_obs = utils::get_observer_module_mut();
            *snapshot_obs.snapshot_id_mut() = Some(id);
            *snapshot_obs.snapshot_parent_id_mut() = parent_id;
            let b = snapshot_obs.snapshot_gen_bytes_mut();
            b.clear();
            b.extend_from_slice(snapshot_meta.snapshot_gen_bytes());

            network_targets_utils::utils::retrieve_tcp_infos(current_testcase, input);
        } else {
            let sm: &mut IncrementalSnapshotManager = emulator.snapshot_manager_mut();
            let id = sm.save(qemu);
            let parent_id = sm.parent_id;

            let snapshot_obs = utils::get_observer_module_mut();
            *snapshot_obs.snapshot_id_mut() = Some(id);
            *snapshot_obs.snapshot_parent_id_mut() = parent_id;

            let (input_bytes, _next_seq) = match &input.packet {
                network_targets_utils::inputs::PacketType::Ip4(ipv4) => {
                    network_targets_utils::inputs::get_ipv4_bytes(ipv4, 0, 0)
                }
                network_targets_utils::inputs::PacketType::Ip6(ipv6) => {
                    network_targets_utils::inputs::get_ipv6_bytes(ipv6, 0, 0)
                }
            };
            let b = snapshot_obs.snapshot_gen_bytes_mut();
            b.clear();
            b.extend_from_slice(&input_bytes);
        }

        let (input_bytes, new_seq) =
            network_targets_utils::utils::get_input_bytes(&current_testcase, input);
        libslirp::misc::log_target_state(&qemu);

        log::warn!("{:?}", input_bytes);

        // Copy the input into Qemu's memory
        let _ = qemu.write_mem(INPUT_ADDR, &input_bytes);
        // Write the arguments for the fuzz_me function and restore RIP to the start of fuzz_me
        libslirp::utils::setup_target_arguments(&mut qemu, target_addr, input_bytes.len() as u64);

        // Run the target
        let _run_result = unsafe { qemu.run() };

        // Trigger a snapshot if the (TCP) state was changed during execution
        let snapshot_obs = utils::get_observer_module_mut();
        let state_changed = *snapshot_obs.state_changed();
        if state_changed {
            let sm: &mut IncrementalSnapshotManager = emulator.snapshot_manager_mut();
            let current_id = sm.current_id.unwrap();
            let new_id = sm.save(qemu);
            // If we didn' t hit a snapshot collision register it,
            // else mark the testcase as not interesting for the state changed feedback
            if new_id != current_id {
                log::debug!("from {:?} to {:?} with {:x}", current_id, new_id, new_seq);
                let snapshot_obs = crate::utils::get_observer_module_mut();
                let b = snapshot_obs.snapshot_gen_bytes_mut();
                b.clear();
                b.extend_from_slice(&input_bytes);
                *snapshot_obs.snapshot_id_mut() = Some(new_id);
                network_targets_utils::utils::update_tcp_seq(new_seq);
            } else {
                let snapshot_obs = utils::get_observer_module_mut();
                *snapshot_obs.state_changed_mut() = false;
                if let Ok(ref current_testcase) = current_testcase {
                    network_targets_utils::utils::update_tcp_response_bytes(current_testcase);
                }
            }
        }

        ExitKind::Ok
    };

    let mut executor = QemuExecutor::new(
        emulator,
        &mut harness,
        tuple_list!(edges_observer, time_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        Duration::from_secs(10),
    )
    .unwrap();

    let mut ipv4 = network_targets_utils::inputs::Ipv4::default();
    ipv4.params.ttl = 10;
    ipv4.payload.data_offset = 5;
    ipv4.src_port = network_targets_utils::inputs::Port::FortyTwo;
    ipv4.dst_port = network_targets_utils::inputs::Port::FourTwenty;
    ipv4.payload.params.win_size = 100;
    let first_input_v4 = network_targets_utils::inputs::Packet {
        packet: network_targets_utils::inputs::PacketType::Ip4(ipv4),
    };

    if state.must_load_initial_inputs() {
        log::warn!("Importing inputs");
        fuzzer
            .evaluate_input(&mut state, &mut executor, &mut mgr, &first_input_v4)
            .expect("Failed to load initial testcase");
        log::warn!("We imported {} input(s).", state.corpus().count());
    }

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}

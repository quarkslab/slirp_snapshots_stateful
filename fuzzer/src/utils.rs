// SPDX-FileCopyrightText: 2026 Quarkslab
//
// SPDX-License-Identifier: Apache-2.0

use libafl::{corpus::InMemoryOnDiskCorpus, inputs::ValueInput};
use libafl_qemu::{
    EmulatorModules,
    modules::{self, SnapshotModule},
};

use crate::{network_targets_utils::tcp::TCPObserverModule, observer_module::ObserverModule};

pub type EmulatorModuleType = EmulatorModules<
    (
        SnapshotModule,
        (
            modules::EdgeCoverageModule<
                modules::utils::filters::StdAddressFilter,
                modules::utils::filters::NopPageFilter,
                modules::edges::EdgeCoverageFullVariant,
                false,
                0,
            >,
            (ObserverModule, (TCPObserverModule, ())),
        ),
    ),
    ValueInput<Vec<u8>>,
    InMemoryOnDiskCorpus<ValueInput<Vec<u8>>>,
>;

pub fn get_snapshot_module_mut() -> &'static mut SnapshotModule {
    let emulator_modules = unsafe {
        EmulatorModuleType::emulator_modules_mut()
            .unwrap()
            .modules_mut()
    };
    &mut emulator_modules.0
}

pub fn get_observer_module_mut() -> &'static mut ObserverModule {
    let emulator_modules = unsafe {
        EmulatorModuleType::emulator_modules_mut()
            .unwrap()
            .modules_mut()
    };

    &mut emulator_modules.1.1.0
}

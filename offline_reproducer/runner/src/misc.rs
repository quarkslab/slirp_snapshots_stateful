// SPDX-FileCopyrightText: 2026 Quarkslab
//
// SPDX-License-Identifier: Apache-2.0

use libafl::{corpus::InMemoryCorpus, inputs::Input, state::StdState};
use libafl_qemu::{
    Emulator, NopSnapshotManager,
    modules::{AsanHostModule, DrCovModule, utils::filters::NopAddressFilter},
};
use serde::{Deserialize, Serialize};

pub type ThisEmulator = Emulator<
    libafl_qemu::command::NopCommand,
    libafl_qemu::command::NopCommandManager,
    libafl_qemu::NopEmulatorDriver,
    (
        libafl_qemu::modules::EdgeCoverageModule<
            libafl_qemu::modules::utils::filters::StdAddressFilter,
            libafl_qemu::modules::utils::filters::NopPageFilter,
            libafl_qemu::modules::edges::EdgeCoverageFullVariant,
            false,
            0,
        >,
        (DrCovModule<NopAddressFilter>, (AsanHostModule, ())),
    ),
    MyInput,
    StdState<
        InMemoryCorpus<MyInput>,
        MyInput,
        libafl_bolts::rands::RomuDuoJrRand,
        InMemoryCorpus<MyInput>,
    >,
    NopSnapshotManager,
>;

#[derive(Debug, Hash, Clone, Serialize, Deserialize)]
pub struct MyInput {
    pub(crate) inner: Vec<Vec<u8>>,
}

impl Input for MyInput {}

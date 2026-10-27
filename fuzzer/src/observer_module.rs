// SPDX-FileCopyrightText: 2026 Quarkslab
//
// SPDX-License-Identifier: Apache-2.0

use libafl_qemu::{SnapshotId, modules::EmulatorModule};

#[derive(Debug)]
pub struct ObserverModule {
    state_changed: bool,
    snapshot_id: Option<SnapshotId>,
    snapshot_parent_id: Option<SnapshotId>,
    snapshot_gen_bytes: Vec<u8>,
}

impl ObserverModule {
    pub fn new() -> Self {
        Self {
            state_changed: false,
            snapshot_id: None,
            snapshot_parent_id: None,
            snapshot_gen_bytes: Vec::new(),
        }
    }

    pub fn state_changed(&self) -> &bool {
        &self.state_changed
    }

    pub fn state_changed_mut(&mut self) -> &mut bool {
        &mut self.state_changed
    }

    #[allow(unused)]
    pub fn snapshot_id(&self) -> &Option<SnapshotId> {
        &self.snapshot_id
    }

    #[allow(unused)]
    pub fn snapshot_id_mut(&mut self) -> &mut Option<SnapshotId> {
        &mut self.snapshot_id
    }

    #[allow(unused)]
    pub fn snapshot_parent_id(&self) -> &Option<SnapshotId> {
        &self.snapshot_parent_id
    }

    #[allow(unused)]
    pub fn snapshot_parent_id_mut(&mut self) -> &mut Option<SnapshotId> {
        &mut self.snapshot_parent_id
    }

    #[allow(unused)]
    pub fn snapshot_gen_bytes(&self) -> &[u8] {
        &self.snapshot_gen_bytes
    }

    #[allow(unused)]
    pub fn snapshot_gen_bytes_mut(&mut self) -> &mut Vec<u8> {
        &mut self.snapshot_gen_bytes
    }
}

impl<I, S> EmulatorModule<I, S> for ObserverModule
where
    I: Unpin,
    S: Unpin,
{
    const HOOKS_DO_SIDE_EFFECTS: bool = true;

    fn pre_qemu_init<ET>(
        &mut self,
        _emulator_modules: &mut libafl_qemu::EmulatorModules<ET, I, S>,
        _qemu_params: &mut libafl_qemu::QemuParams,
    ) where
        ET: libafl_qemu::modules::EmulatorModuleTuple<I, S>,
    {
    }

    fn post_qemu_init<ET>(
        &mut self,
        _qemu: libafl_qemu::Qemu,
        _emulator_modules: &mut libafl_qemu::EmulatorModules<ET, I, S>,
    ) where
        ET: libafl_qemu::modules::EmulatorModuleTuple<I, S>,
    {
    }

    fn first_exec<ET>(
        &mut self,
        _qemu: libafl_qemu::Qemu,
        _emulator_modules: &mut libafl_qemu::EmulatorModules<ET, I, S>,
        _state: &mut S,
    ) where
        ET: libafl_qemu::modules::EmulatorModuleTuple<I, S>,
    {
    }

    fn pre_exec<ET>(
        &mut self,
        _qemu: libafl_qemu::Qemu,
        _emulator_modules: &mut libafl_qemu::EmulatorModules<ET, I, S>,
        _state: &mut S,
        _input: &I,
    ) where
        ET: libafl_qemu::modules::EmulatorModuleTuple<I, S>,
    {
        self.state_changed = false;
    }

    fn post_exec<OT, ET>(
        &mut self,
        _qemu: libafl_qemu::Qemu,
        _emulator_modules: &mut libafl_qemu::EmulatorModules<ET, I, S>,
        _state: &mut S,
        _input: &I,
        _observers: &mut OT,
        _exit_kind: &mut libafl::executors::ExitKind,
    ) where
        OT: libafl::observers::ObserversTuple<I, S>,
        ET: libafl_qemu::modules::EmulatorModuleTuple<I, S>,
    {
    }

    unsafe fn on_crash(&mut self) {}

    unsafe fn on_timeout(&mut self) {}
}

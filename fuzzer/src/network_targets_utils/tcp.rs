// SPDX-FileCopyrightText: 2026 Quarkslab
//
// SPDX-License-Identifier: Apache-2.0

use serde::Deserialize;
use serde::Serialize;

use libafl_bolts::impl_serdeany;

impl_serdeany!(TCPMetadata);

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TCPMetadata {
    state_addr: u64,
    seq: u32,
    ack: u32,
    response_bytes: Vec<u8>,
}

impl TCPMetadata {
    #[allow(unused)]
    pub fn new(state_addr: u64, seq: u32, ack: u32, response_bytes: &[u8]) -> Self {
        Self {
            state_addr,
            seq,
            ack,
            response_bytes: Vec::from(response_bytes),
        }
    }

    #[allow(unused)]
    pub fn state_addr(&self) -> u64 {
        self.state_addr
    }

    #[allow(unused)]
    pub fn seq(&self) -> u32 {
        self.seq
    }

    #[allow(unused)]
    pub fn ack(&self) -> u32 {
        self.ack
    }

    #[allow(unused)]
    pub fn response_bytes(&self) -> &[u8] {
        &self.response_bytes
    }
}

use libafl_qemu::modules::EmulatorModule;

#[derive(Debug)]
pub struct TCPObserverModule {
    state_addr: u64,
    resp_seq: u32,
    resp_ack: u32,
    resp_flags: [bool; 9],
    sent_flags: [bool; 9],
    previous_state: u16,
    response_bytes: Vec<u8>,
}

impl TCPObserverModule {
    pub fn new() -> Self {
        Self {
            state_addr: 0,
            resp_seq: 0,
            resp_ack: 0,
            resp_flags: [false; 9],
            sent_flags: [false; 9],
            previous_state: 0,
            response_bytes: Vec::new(),
        }
    }

    #[allow(unused)]
    pub fn state_addr(&self) -> &u64 {
        &self.state_addr
    }

    #[allow(unused)]
    pub fn state_addr_mut(&mut self) -> &mut u64 {
        &mut self.state_addr
    }

    #[allow(unused)]
    pub fn seq(&self) -> &u32 {
        &self.resp_seq
    }

    #[allow(unused)]
    pub fn seq_mut(&mut self) -> &mut u32 {
        &mut self.resp_seq
    }

    #[allow(unused)]
    pub fn ack(&self) -> &u32 {
        &self.resp_ack
    }

    #[allow(unused)]
    pub fn ack_mut(&mut self) -> &mut u32 {
        &mut self.resp_ack
    }

    #[allow(unused)]
    pub fn resp_flags(&self) -> &[bool; 9] {
        &self.resp_flags
    }

    #[allow(unused)]
    pub fn resp_flags_mut(&mut self) -> &mut [bool; 9] {
        &mut self.resp_flags
    }

    #[allow(unused)]
    pub fn sent_flags(&self) -> &[bool; 9] {
        &self.sent_flags
    }

    #[allow(unused)]
    pub fn sent_flags_mut(&mut self) -> &mut [bool; 9] {
        &mut self.sent_flags
    }

    #[allow(unused)]
    pub fn previous_state(&self) -> &u16 {
        &self.previous_state
    }

    #[allow(unused)]
    pub fn previous_state_mut(&mut self) -> &mut u16 {
        &mut self.previous_state
    }

    #[allow(unused)]
    pub fn response_bytes(&self) -> &Vec<u8> {
        &self.response_bytes
    }

    #[allow(unused)]
    pub fn response_bytes_mut(&mut self) -> &mut Vec<u8> {
        &mut self.response_bytes
    }
}

impl<I, S> EmulatorModule<I, S> for TCPObserverModule
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
        self.state_addr = 0;
        self.resp_seq = 0;
        self.resp_ack = 0;
        self.resp_flags = [false; 9];
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

// SPDX-FileCopyrightText: 2026 Quarkslab
//
// SPDX-License-Identifier: Apache-2.0

use libafl_qemu::{
    EmulatorModules, GuestAddr, Hook, Qemu, Regs, SyscallHookResult, elf::EasyElf,
    modules::EmulatorModuleTuple,
};

use crate::misc::ThisEmulator;

pub fn add_hooks(emulator: &mut ThisEmulator) {
    // Retrieve some functions of interest addresses
    let load_addr = emulator.load_addr();
    let mut elf_buffer = Vec::new();
    let elf =
        EasyElf::from_file("./qemu-target", &mut elf_buffer).expect("failed to read elf file");
    let checksum = elf
        .resolve_symbol("cksum", load_addr)
        .expect("failed to retrieve checksum validation function");
    let checksum_ret = checksum + 0x11f6;

    let hooks = emulator.modules_mut().hooks_mut();
    // Add a hook on the ret of checksum function as it's not possible to early return from a hook
    hooks.instructions(checksum_ret, Hook::Function(checksum_hook), false);
    // Hook the socket and fcntl syscalls to avoid error on too many file descriptors open
    hooks.pre_syscalls(Hook::Function(socket_hook));
}
fn checksum_hook<ET, I, S>(
    qemu: Qemu,
    _emulator_modules: &mut EmulatorModules<ET, I, S>,
    _state: Option<&mut S>,
    _something: GuestAddr,
) where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
{
    // not changing PC to return address as hooks are buggy
    let _ = qemu.write_reg(Regs::Rax, 0_u64);
}

fn socket_hook<ET, I, S>(
    _qemu: Qemu,
    _emulator_modules: &mut EmulatorModules<ET, I, S>,
    _state: Option<&mut S>,
    sys_num: i32,
    _a0: GuestAddr,
    _a1: GuestAddr,
    _a2: GuestAddr,
    _a3: GuestAddr,
    _a4: GuestAddr,
    _a5: GuestAddr,
    _a6: GuestAddr,
    _a7: GuestAddr,
) -> SyscallHookResult
where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
{
    match sys_num {
        0x29 => {
            log::trace!("------- socket !! -------");
            SyscallHookResult::Skip(42)
        }
        0x48 => {
            log::trace!("------- fcntl !! -------");
            SyscallHookResult::Skip(0)
        }
        _ => SyscallHookResult::Run,
    }
}

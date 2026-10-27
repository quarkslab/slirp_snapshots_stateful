// SPDX-FileCopyrightText: 2026 Quarkslab
//
// SPDX-License-Identifier: Apache-2.0

use libafl_qemu::{Qemu, Regs, elf::EasyElf};

use crate::{INPUT_ADDR, misc::ThisEmulator};

static mut SLIRP_ADDR: u64 = 0x0;

pub fn setup_target_arguments(qemu: &mut Qemu, target_addr: u64, input_len: u64) {
    let args = [unsafe { SLIRP_ADDR }, INPUT_ADDR, input_len];
    let _ = qemu.write_function_arguments(&args);
    let _ = qemu.write_reg(Regs::Rip, target_addr);
}

pub fn retrieve_target_and_stop_addr(emulator: &ThisEmulator) -> (u64, u64) {
    let load_addr = emulator.load_addr();
    let mut elf_buffer = Vec::new();
    let elf =
        EasyElf::from_file("./qemu-target", &mut elf_buffer).expect("failed to read elf file");
    let fuzzme = elf
        .resolve_symbol("fuzz_me", load_addr)
        .expect("failed to retrieve fuzz_me");
    let end_fuzzme = fuzzme + 0x63;
    log::debug!("fuzz_me {:x}", fuzzme);

    (fuzzme, end_fuzzme)
}

pub fn setup_target(qemu: &mut Qemu, target_addr: u64, stop_addr: u64) {
    qemu.set_breakpoint(target_addr);
    qemu.set_breakpoint(stop_addr);

    // Allocate some memory region to place our inputs instead of re-using the target's one
    let _ = qemu.map_private(INPUT_ADDR, 0x1000, libafl_qemu::MmapPerms::ReadWrite);

    let _ = unsafe { qemu.run() };
    unsafe {
        SLIRP_ADDR = qemu.read_reg(Regs::Rdi).unwrap();
    }
    qemu.remove_breakpoint(target_addr);

    let arp = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x52, 0x55, 0x0a, 0x00, 0x02, 0x0a, 0x08, 0x06, 0x00,
        0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x00,
        0x02, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x02, 0x02,
    ];
    // Copy the input into Qemu's memory
    let _ = qemu.write_mem(INPUT_ADDR, &arp);
    // Write the arguments for the fuzz_me function and restore RIP to the start of fuzz_me
    let args = [unsafe { SLIRP_ADDR }, INPUT_ADDR, arp.len() as u64];
    let _ = qemu.write_function_arguments(&args);
    let _ = qemu.write_reg(Regs::Rip, target_addr);

    let _ = unsafe { qemu.run() };
}

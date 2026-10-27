// SPDX-FileCopyrightText: 2026 Quarkslab
//
// SPDX-License-Identifier: Apache-2.0

use libafl_qemu::{Qemu, Regs, elf::EasyElf};

use crate::network_targets_utils::utils::get_tcp_observer_module;
use crate::{Emu, INPUT_ADDR};
use xxhash_rust::const_xxh64::xxh64;

static mut SLIRP_ADDR: u64 = 0x0;

pub fn retrieve_target_and_stop_addr(emulator: &Emu) -> (u64, u64) {
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

    // Run the emulator until we hit the fuzz_me function and save the first argument to re-use it
    // on subsequent calls during fuzzing.
    let _ = unsafe { qemu.run() };
    unsafe {
        SLIRP_ADDR = qemu.read_reg(Regs::Rdi).unwrap();
    }
    qemu.remove_breakpoint(target_addr);

    // Send a first ARP packet to setup the ARP table so we don't have to respond later during transactions
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

pub fn setup_target_arguments(qemu: &mut Qemu, target_addr: u64, input_len: u64) {
    let args = [unsafe { SLIRP_ADDR }, INPUT_ADDR, input_len];
    let _ = qemu.write_function_arguments(&args);
    let _ = qemu.write_reg(Regs::Rip, target_addr);
}

pub fn hash_state(qemu: &Qemu) -> u64 {
    let tcp_obs = get_tcp_observer_module();
    let state_addr = *tcp_obs.state_addr();
    let resp_flags = *tcp_obs.resp_flags();

    let state: u16 = unsafe { qemu.read_mem_val(state_addr).unwrap() };

    let mut data = Vec::with_capacity(10);
    data.extend_from_slice(&state.to_be_bytes());
    for flag in &resp_flags {
        data.push(*flag as u8);
    }
    xxh64(&data, 0)
}

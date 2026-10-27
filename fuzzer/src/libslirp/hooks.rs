// SPDX-FileCopyrightText: 2026 Quarkslab
//
// SPDX-License-Identifier: Apache-2.0

use libafl_qemu::{
    EmulatorModules, GuestAddr, Hook, Qemu, Regs, SyscallHookResult, elf::EasyElf,
    modules::EmulatorModuleTuple,
};

use crate::{Emu, network_targets_utils, observer_module::ObserverModule};

pub(crate) fn write_to_state_hook<ET, I, S>(
    qemu: Qemu,
    emulator_modules: &mut EmulatorModules<ET, I, S>,
    _state: Option<&mut S>,
    _id: u64,
    _pc: GuestAddr,
    addr: GuestAddr,
) where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
{
    let tcp_obs_mod = emulator_modules
        .get_mut::<network_targets_utils::tcp::TCPObserverModule>()
        .unwrap();
    let state_addr_obs = *tcp_obs_mod.state_addr();
    if addr == state_addr_obs {
        let obs_mod = emulator_modules.get_mut::<ObserverModule>().unwrap();
        let state_changed = obs_mod.state_changed_mut();
        *state_changed = true;
        let state: u16 = unsafe { qemu.read_mem_val(state_addr_obs).unwrap() };
        let tcp_obs_mod = emulator_modules
            .get_mut::<network_targets_utils::tcp::TCPObserverModule>()
            .unwrap();
        let prev_state = tcp_obs_mod.previous_state_mut();
        *prev_state = state;
    }
}

fn write_to_state_hook_n<ET, I, S>(
    _qemu: Qemu,
    _emulator_modules: &mut EmulatorModules<ET, I, S>,
    _state: Option<&mut S>,
    _id: u64,
    _pc: GuestAddr,
    _addr: GuestAddr,
    _size: usize,
) where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
{
}

fn get_malloc_return<ET, I, S>(
    qemu: Qemu,
    emulator_modules: &mut EmulatorModules<ET, I, S>,
    _state: Option<&mut S>,
    _something: GuestAddr,
) where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
{
    // 0x10 is tp->t_state offset inside the tcpcb structure
    let state_addr = qemu.read_reg(Regs::Rax).unwrap() + 0x10;
    let tcp_obs_mod = emulator_modules
        .get_mut::<network_targets_utils::tcp::TCPObserverModule>()
        .unwrap();
    let state_addr_obs = tcp_obs_mod.state_addr_mut();
    if *state_addr_obs == 0 {
        *state_addr_obs = state_addr;
    }
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

fn send_packet_hook<ET, I, S>(
    qemu: Qemu,
    emulator_modules: &mut EmulatorModules<ET, I, S>,
    _state: Option<&mut S>,
    _something: GuestAddr,
) where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
{
    let pkt_size = qemu.read_function_argument(1).unwrap();
    let pkt_addr = qemu.read_function_argument(0).unwrap();
    let pkt = qemu.read_mem_vec(pkt_addr, pkt_size as usize).unwrap();
    let snapshot_obs = emulator_modules.get_mut::<ObserverModule>().unwrap();
    let f = *snapshot_obs.state_changed();
    let tcp_obs_mod = emulator_modules
        .get_mut::<network_targets_utils::tcp::TCPObserverModule>()
        .unwrap();
    let state_addr_obs = *tcp_obs_mod.state_addr();
    if f || state_addr_obs == 0 {
        let b = tcp_obs_mod.response_bytes_mut();
        b.clear();
        b.extend_from_slice(&pkt);
    }
    if pkt_size < 54 {
        return;
    }
    let eth_type: [u8; 2] = [pkt[12], pkt[13]];
    if eth_type == network_targets_utils::inputs::ETH_P_IP && pkt[0x17] == 6 && f {
        let seq = u32::from_be_bytes(pkt[38..42].try_into().unwrap());
        let ack = tcp_obs_mod.ack_mut();
        *ack = seq;
        let resp_flags = tcp_obs_mod.resp_flags_mut();
        for (i, flag) in resp_flags.iter_mut().enumerate().take(8) {
            *flag = (pkt[47] & (1 << i)) != 0;
        }
    } else if pkt_size > 74
        && eth_type == network_targets_utils::inputs::ETH_P_IPV6
        && pkt[0x14] == 6
        && f
    {
        let seq = u32::from_be_bytes(pkt[58..62].try_into().unwrap());
        let ack = tcp_obs_mod.ack_mut();
        *ack = seq;
        let resp_flags = tcp_obs_mod.resp_flags_mut();
        for (i, flag) in resp_flags.iter_mut().enumerate().take(8) {
            *flag = (pkt[67] & (1 << i)) != 0;
        }
    }
}

fn glog_hook<ET, I, S>(
    qemu: Qemu,
    _emulator_modules: &mut EmulatorModules<ET, I, S>,
    _state: Option<&mut S>,
    _something: GuestAddr,
) where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
{
    log::debug!("g_error called");
    unsafe {
        qemu.target_signal(libafl_bolts::os::unix_signals::Signal::SigAbort);
    }
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
    log::debug!("------- syscall ? {:x?} -------", sys_num);
    match sys_num {
        0x29 => {
            log::debug!("------- socket !! -------");
            SyscallHookResult::Skip(42)
        }
        0x48 => {
            log::debug!("------- fcntl !! -------");
            SyscallHookResult::Skip(0)
        }
        _ => SyscallHookResult::Run,
    }
}

pub fn add_hooks(emulator: &mut Emu) {
    let load_addr = emulator.load_addr();
    let mut elf_buffer = Vec::new();
    let elf =
        EasyElf::from_file("./qemu-target", &mut elf_buffer).expect("failed to read elf file");
    let tcp_newtcpcb = elf
        .resolve_symbol("tcp_newtcpcb", load_addr)
        .expect("failed to retrieve TCP object allocation function");
    let tcp_allocation = tcp_newtcpcb + 0x1b;

    let checksum = elf
        .resolve_symbol("cksum", load_addr)
        .expect("failed to retrieve checksum validation function");
    let checksum_ret = checksum + 0xa82;
    let send_packet = elf
        .resolve_symbol("send_packet", load_addr)
        .expect("failed to retrieve send_packet");
    let glog = elf
        .resolve_symbol("g_log", load_addr)
        .expect("failed to retrieve g_log");

    log::debug!("tcp_newtcpcb {:x}", tcp_newtcpcb);
    log::debug!("tcp_allocation {:x}", tcp_allocation);
    log::debug!("checksum {:x}", checksum);
    log::debug!("send_packet {:x}", send_packet);
    log::debug!("glog {:x}", glog);

    let hooks = emulator.modules_mut().hooks_mut();
    // Add a hook to the instruction right after allocating the TCP Control Block to retrieve its address
    hooks.instructions(tcp_allocation, Hook::Function(get_malloc_return), false);
    // Add a hook on the ret of checksum function as it's not possible to early return from a hook
    hooks.instructions(checksum_ret, Hook::Function(checksum_hook), false);
    // Add a hook to parse the SEQ/ACK values to setup next packet
    hooks.instructions(send_packet, Hook::Function(send_packet_hook), false);
    // Add a hook to detect calls to g_error and inform the fuzzer we have a bug
    hooks.instructions(glog, Hook::Function(glog_hook), false);

    // Hook the socket and fcntl syscalls to avoid error on too many file descriptors open
    hooks.pre_syscalls(Hook::Function(socket_hook));

    // Add hooks to memory writes. The hook is responsible for checking if the address of the TCPCB's state was written to
    hooks.writes(
        Hook::Empty,
        Hook::Function(write_to_state_hook),
        Hook::Function(write_to_state_hook),
        Hook::Function(write_to_state_hook),
        Hook::Function(write_to_state_hook),
        Hook::Function(write_to_state_hook_n),
    );
}

// SPDX-FileCopyrightText: 2026 Quarkslab
//
// SPDX-License-Identifier: Apache-2.0

use libafl_qemu::Qemu;
use num_enum::TryFromPrimitive;

use crate::libslirp;
use crate::network_targets_utils::utils::get_tcp_observer_module;

#[allow(unused)]
#[derive(Debug, TryFromPrimitive)]
#[repr(u16)]
pub enum TCPState {
    TcpsClosed = 0,      /* closed */
    TcpsListen = 1,      /* listening for connection */
    TcpsSynSent = 2,     /* active, have sent syn */
    TcpsSynReceived = 3, /* have send and received syn */
    /* states < TCPS_ESTABLISHED are those where connections not established */
    TcpsEstablished = 4, /* established */
    TcpsCloseWait = 5,   /* rcvd fin, waiting for close */
    /* states > TCPS_CLOSE_WAIT are those where user has closed */
    TcpsFinWait1 = 6, /* have closed, sent fin */
    TcpsClosing = 7,  /* closed xchd FIN; await FIN ACK */
    TcpsLastAck = 8,  /* had fin and close; await FIN ACK */
    /* states > TCPS_CLOSE_WAIT && < TCPS_FIN_WAIT_2 await ACK of FIN */
    TcpsFinWait2 = 9, /* have closed, fin is acked */
    TcpsTimeWait = 10,
}

pub fn log_target_state(qemu: &Qemu) {
    let tcp_obs = get_tcp_observer_module();
    let state_addr = *tcp_obs.state_addr();

    let state = if state_addr != 0 {
        let state_val: u16 = unsafe { qemu.read_mem_val(state_addr).unwrap() };
        libslirp::misc::TCPState::try_from(state_val).unwrap()
    } else {
        libslirp::misc::TCPState::TcpsClosed
    };
    log::warn!("{:?}", state);
}

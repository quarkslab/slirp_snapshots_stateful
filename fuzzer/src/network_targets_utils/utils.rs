// SPDX-FileCopyrightText: 2026 Quarkslab
//
// SPDX-License-Identifier: Apache-2.0

use libafl::{Error, HasMetadata, inputs::Input};

use crate::{
    network_targets_utils::{
        inputs,
        tcp::{self, TCPMetadata, TCPObserverModule},
    },
    utils::EmulatorModuleType,
};

pub fn add_tcp_metadata<I>(testcase: &mut libafl::corpus::Testcase<I>)
where
    I: Input,
{
    let tcp_obs = get_tcp_observer_module();
    let tcp_meta = TCPMetadata::new(
        *tcp_obs.state_addr(),
        *tcp_obs.seq(),
        *tcp_obs.ack(),
        tcp_obs.response_bytes(),
    );
    log::debug!("{:?}", tcp_meta);

    testcase.add_metadata(tcp_meta);
}

pub fn get_tcp_observer_module() -> &'static TCPObserverModule {
    let emulator_modules = unsafe {
        EmulatorModuleType::emulator_modules_mut()
            .unwrap()
            .modules_mut()
    };

    &emulator_modules.1.1.1.0
}

pub fn get_tcp_observer_module_mut() -> &'static mut TCPObserverModule {
    let emulator_modules = unsafe {
        EmulatorModuleType::emulator_modules_mut()
            .unwrap()
            .modules_mut()
    };

    &mut emulator_modules.1.1.1.0
}

pub fn retrieve_tcp_infos(
    current_testcase: &std::cell::Ref<'_, libafl::corpus::Testcase<inputs::Packet>>,
    input: &inputs::Packet,
) {
    let tcp_meta = current_testcase.metadata::<tcp::TCPMetadata>().unwrap();
    let state_addr = tcp_meta.state_addr();
    let tcp_obs = get_tcp_observer_module_mut();
    *tcp_obs.state_addr_mut() = state_addr;
    let r = tcp_obs.response_bytes_mut();
    r.clear();
    r.extend_from_slice(tcp_meta.response_bytes());
    let sent_flags = tcp_obs.sent_flags_mut();
    match &input.packet {
        inputs::PacketType::Ip4(ipv4) => {
            *sent_flags = ipv4.payload.params.flags;
        }
        inputs::PacketType::Ip6(ipv6) => {
            *sent_flags = ipv6.payload.params.flags;
        }
    }
}

pub fn update_tcp_response_bytes(
    current_testcase: &std::cell::Ref<'_, libafl::corpus::Testcase<inputs::Packet>>,
) {
    let tcp_meta = current_testcase.metadata::<tcp::TCPMetadata>().unwrap();
    let tcp_obs = get_tcp_observer_module_mut();
    let r = tcp_obs.response_bytes_mut();
    r.clear();
    r.extend_from_slice(tcp_meta.response_bytes());
}

pub fn update_tcp_seq(new_seq: u32) {
    let tcp_obs = get_tcp_observer_module_mut();
    *tcp_obs.seq_mut() = new_seq;
}

pub fn get_input_bytes(
    current_testcase: &Result<std::cell::Ref<'_, libafl::corpus::Testcase<inputs::Packet>>, Error>,
    input: &inputs::Packet,
) -> (Vec<u8>, u32) {
    let (seq, ack) = if let Ok(current_testcase) = current_testcase {
        let tcp_meta = current_testcase.metadata::<tcp::TCPMetadata>().unwrap();
        (tcp_meta.seq(), tcp_meta.ack())
    } else {
        (0, 0)
    };

    match &input.packet {
        inputs::PacketType::Ip4(ipv4) => inputs::get_ipv4_bytes(ipv4, seq, ack),
        inputs::PacketType::Ip6(ipv6) => inputs::get_ipv6_bytes(ipv6, seq, ack),
    }
}

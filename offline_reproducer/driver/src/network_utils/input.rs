// SPDX-FileCopyrightText: 2026 Quarkslab
//
// SPDX-License-Identifier: Apache-2.0

use std::{
    fs::File,
    io::{Error, Read},
    path::Path,
};

use serde::{Deserialize, Serialize};

static DST_MAC: [u8; 6] = [0xDE, 0xAD, 0x00, 0x00, 0xBE, 0xEF];
static SRC_MAC: [u8; 6] = [0xDE, 0xAD, 0x00, 0x00, 0xD0, 0x0D];
pub static ETH_P_IP: [u8; 2] = (0x0800_u16).to_be_bytes();
pub static ETH_P_IPV6: [u8; 2] = (0x86dd_u16).to_be_bytes();

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(u16)]
pub enum Port {
    FortyTwo = 42,
    FourTwenty = 420,
}

impl Default for Port {
    fn default() -> Self {
        Port::FourtyTwo
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[repr(C)]
pub struct Packet {
    pub packet: PacketType,
}

impl Packet {
    /// Load the content of this input from a file
    pub fn from_file<P>(path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let mut file = File::open(path)?;
        let mut bytes = vec![];
        file.read_to_end(&mut bytes)?;
        Ok(postcard::from_bytes(&bytes).unwrap())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[repr(C)]
pub(crate) enum PacketType {
    Ip4(Ipv4),
    Ip6(Ipv6),
}

impl Default for PacketType {
    fn default() -> Self {
        PacketType::Ip4(Ipv4::default())
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[repr(C)]
pub(crate) struct Tcp {
    pub params: TcpParams,
    seq: u32,
    ack: u32,
    checksum: u16,
    pub(crate) data_offset: u8,
    options: [u32; 10],
    pub payload: TcpPayload,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub(crate) struct TcpPayload {
    pub bytes: Vec<u8>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[repr(C)]
pub(crate) struct TcpParams {
    pub(crate) win_size: u16,
    pub(crate) flags: [bool; 9],
    urg_ptr: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[repr(C)]
pub(crate) struct Ipv4 {
    header_size: u8, // for now, fixed to 5 as no option is used
    pub params: Ipv4Params,
    checksum: u16,     // fuzzed target ignores checksum issues in fuzzing configuration
    src_addr: [u8; 4], // default address should be kept, not important
    dst_addr: [u8; 4], // default address should be kept, not important
    options: [u8; 4],  // will be unused for now
    pub(crate) src_port: Port,
    pub(crate) dst_port: Port,
    pub payload: Tcp,
}

impl Default for Ipv4 {
    fn default() -> Self {
        Self {
            header_size: 5,
            params: Ipv4Params::default(),
            checksum: Default::default(),
            src_addr: [0x0A, 0x00, 0x02, 0x0A], // 10.0.2.10
            dst_addr: [0x0A, 0x00, 0x02, 0x02], // 10.0.2.2
            options: [0, 0, 0, 0],
            src_port: Port::FourtyTwo,
            dst_port: Port::FourTwenty,
            payload: Tcp::default(),
        }
    }
}

pub fn get_ipv4_bytes(ipv4: &Ipv4, seq: u32, ack: u32) -> (Vec<u8>, u32) {
    let mut data = Vec::new();

    data.extend_from_slice(&DST_MAC);
    data.extend_from_slice(&SRC_MAC);
    data.extend_from_slice(&ETH_P_IP);

    let version = 0x4u8;
    let ver_and_hd_size = version << 4 | (ipv4.header_size & 0x0f);
    data.push(ver_and_hd_size);

    data.push(ipv4.params.type_of_service);

    let offset_total_len = data.len();
    data.push(0x0);
    data.push(0x0);

    data.extend_from_slice(&ipv4.params.frag_id.to_be_bytes());
    data.extend_from_slice(&ipv4.params.flags_and_frag_offset.to_be_bytes());
    data.push(ipv4.params.ttl);

    let offset_protocol = data.len();
    data.push(0x0);

    data.extend_from_slice(&ipv4.checksum.to_be_bytes());
    data.extend_from_slice(&ipv4.src_addr);
    data.extend_from_slice(&ipv4.dst_addr);

    let tcp_start = data.len();
    if let Some(proto) = data.get_mut(offset_protocol) {
        *proto = 6;
    }
    data.extend_from_slice(&(ipv4.src_port as u16).to_be_bytes());
    data.extend_from_slice(&(ipv4.dst_port as u16).to_be_bytes());
    data.extend_from_slice(&seq.to_be_bytes());
    let ack = ack + 1;
    data.extend_from_slice(&ack.to_be_bytes());
    let mut offset_reserved_ns = ipv4.payload.data_offset << 4;
    if ipv4.payload.params.flags[0] {
        offset_reserved_ns |= 0x1;
    }
    data.push(offset_reserved_ns);
    let mut flags: u8 = 0;
    if ipv4.payload.params.flags[1] {
        flags |= 0x1 << 7;
    }
    if ipv4.payload.params.flags[2] {
        flags |= 0x1 << 6;
    }
    if ipv4.payload.params.flags[3] {
        flags |= 0x1 << 5;
    }
    if ipv4.payload.params.flags[4] {
        flags |= 0x1 << 4;
    }
    if ipv4.payload.params.flags[5] {
        flags |= 0x1 << 3;
    }
    if ipv4.payload.params.flags[6] {
        flags |= 0x1 << 2;
    }
    if ipv4.payload.params.flags[7] {
        flags |= 0x1 << 1;
    }
    if ipv4.payload.params.flags[8] {
        flags |= 0x1;
    }
    data.push(flags);
    data.extend_from_slice(&ipv4.payload.params.win_size.to_be_bytes());
    data.extend_from_slice(&ipv4.payload.checksum.to_be_bytes());
    data.extend_from_slice(&ipv4.payload.params.urg_ptr.to_be_bytes());
    data.extend_from_slice(&ipv4.payload.payload.bytes);

    let length_payload: u16 = (data.len() - tcp_start) as u16;
    // Fixing the total length in Ipv4 header
    let length = (length_payload + (ipv4.header_size as u16 * 4u16)).to_be_bytes();
    if let Some(first) = data.get_mut(offset_total_len + 1) {
        *first = *length.get(1).unwrap();
    }
    if let Some(second) = data.get_mut(offset_total_len) {
        *second = *length.first().unwrap();
    }
    let next_seq = seq + ipv4.payload.payload.bytes.len() as u32;
    (data, next_seq)
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[repr(C)]
pub(crate) struct Ipv4Params {
    type_of_service: u8,
    frag_id: u16,
    flags_and_frag_offset: u16,
    pub(crate) ttl: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[repr(C)]
pub(crate) struct Ipv6 {
    pub params: Ipv6Params,
    payload_len: u16,
    next_header: u8,
    src_addr: [u8; 16],
    dst_addr: [u8; 16],
    pub(crate) src_port: Port,
    pub(crate) dst_port: Port,
    pub payload: Tcp,
}

impl Default for Ipv6 {
    fn default() -> Self {
        Self {
            params: Ipv6Params::default(),
            payload_len: 0, // keeping the values as default for now
            next_header: 0, // keeping the values as default for now
            src_addr: [
                0xFE, 0xC0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0A,
            ], // fixed address don't change
            dst_addr: [
                0xFE, 0xC0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x02,
            ], // fixed address don't change
            src_port: Port::FourtyTwo,
            dst_port: Port::FourTwenty,
            payload: Tcp::default(),
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[repr(C)]
pub(crate) struct Ipv6Params {
    traffic_class: u8,
    flow_label: u32,
    pub(crate) hop_limit: u8,
}

pub fn get_ipv6_bytes(ipv6: &Ipv6, seq: u32, ack: u32) -> (Vec<u8>, u32) {
    let mut data = Vec::new();

    data.extend_from_slice(&DST_MAC);
    data.extend_from_slice(&SRC_MAC);
    data.extend_from_slice(&ETH_P_IPV6);

    let version = 0x6u8;
    let ver_and_hd_size = version << 4 | ((ipv6.params.traffic_class >> 4) & 0x0f);
    data.push(ver_and_hd_size);

    let trafic_and_flow =
        ((ipv6.params.traffic_class & 0x0f) << 4) | (((ipv6.params.flow_label >> 16) & 0xf) as u8);
    data.push(trafic_and_flow);

    let remaining_flow: u16 = (ipv6.params.flow_label & 0xffff) as u16;
    data.extend_from_slice(&remaining_flow.to_be_bytes());

    let offset_payload_len = data.len();
    data.push(0x0);
    data.push(0x0);

    let offset_protocol = data.len();
    data.push(ipv6.next_header);
    data.push(ipv6.params.hop_limit);
    data.extend_from_slice(&ipv6.src_addr);
    data.extend_from_slice(&ipv6.dst_addr);

    if let Some(proto) = data.get_mut(offset_protocol) {
        *proto = 6;
    }
    let tcp_start = data.len();
    data.extend_from_slice(&(ipv6.src_port as u16).to_be_bytes());
    data.extend_from_slice(&(ipv6.dst_port as u16).to_be_bytes());
    data.extend_from_slice(&seq.to_be_bytes());
    data.extend_from_slice(&ack.to_be_bytes());
    let mut offset_reserved_ns = ipv6.payload.data_offset << 4;
    if ipv6.payload.params.flags[0] {
        offset_reserved_ns |= 0x1;
    }
    data.push(offset_reserved_ns);
    let mut flags: u8 = 0;
    if ipv6.payload.params.flags[1] {
        flags |= 0x1 << 7;
    }
    if ipv6.payload.params.flags[2] {
        flags |= 0x1 << 6;
    }
    if ipv6.payload.params.flags[3] {
        flags |= 0x1 << 5;
    }
    if ipv6.payload.params.flags[4] {
        flags |= 0x1 << 4;
    }
    if ipv6.payload.params.flags[5] {
        flags |= 0x1 << 3;
    }
    if ipv6.payload.params.flags[6] {
        flags |= 0x1 << 2;
    }
    if ipv6.payload.params.flags[7] {
        flags |= 0x1 << 1;
    }
    if ipv6.payload.params.flags[8] {
        flags |= 0x1;
    }
    data.push(flags);
    data.extend_from_slice(&ipv6.payload.params.win_size.to_be_bytes());
    data.extend_from_slice(&ipv6.payload.checksum.to_be_bytes());
    data.extend_from_slice(&ipv6.payload.params.urg_ptr.to_be_bytes());
    data.extend_from_slice(&ipv6.payload.payload.bytes);

    // Fixing the total length in Ipv6 header
    let length_payload = (data.len() - tcp_start) as u16;
    let length = length_payload.to_be_bytes();
    if let Some(first) = data.get_mut(offset_payload_len + 1) {
        *first = *length.get(1).unwrap();
    }
    if let Some(second) = data.get_mut(offset_payload_len) {
        *second = *length.first().unwrap();
    }
    let next_seq = seq + ipv6.payload.payload.bytes.len() as u32;
    (data, next_seq)
}

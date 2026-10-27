// SPDX-FileCopyrightText: 2026 Quarkslab
//
// SPDX-License-Identifier: Apache-2.0

pub fn retrieve_tcp_metadata(content: &String) -> (u32, u32) {
    let pattern_seq = "\"seq\": ";
    let pattern_ack = "\"ack\": ";

    let start_seq = content.find(pattern_seq).unwrap() + pattern_seq.len();
    let start_ack = content.find(pattern_ack).unwrap() + pattern_ack.len();

    let end_seq = content[start_seq..].find(",").unwrap() + start_seq;
    let end_ack = content[start_ack..].find(",").unwrap() + start_ack;

    let seq = content[start_seq..end_seq].parse::<u32>().unwrap();
    let ack = content[start_ack..end_ack].parse::<u32>().unwrap();

    (seq, ack)
}

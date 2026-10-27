// SPDX-FileCopyrightText: 2026 Quarkslab
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

pub fn retrieve_snapshot_metadata(
    content: &String,
    snapshot_gen: &mut HashMap<u64, (Option<u64>, Vec<u8>)>,
) -> u64 {
    let pattern_snap = "\"associated_snapshot\": {\n            \"id\": ";
    let pattern_parent = "\"parent_snapshot\": {\n            \"id\": ";
    let pattern_gen = "\"gen_bytes\": [\n";

    let start_snap = content.find(pattern_snap).unwrap() + pattern_snap.len();
    let start_gen = content.find(pattern_gen).unwrap() + pattern_gen.len();

    let end_snap = content[start_snap..].find("\n").unwrap() + start_snap;
    let end_gen = content[start_gen..].find("]").unwrap() + start_gen;

    let id_snap = content[start_snap..end_snap].parse::<u64>().unwrap();

    let id_parent = if let Some(start_id) = content.find(pattern_parent) {
        let start_parent = start_id + pattern_parent.len();
        let end_parent = content[start_parent..].find("\n").unwrap() + start_parent;
        content[start_parent..end_parent].parse::<u64>().ok()
    } else {
        None
    };
    let gen_bytes = content[start_gen..end_gen]
        .split('\n')
        .map(|x| x.trim())
        .filter(|x| !x.is_empty())
        .map(|x| x.trim_suffix(',').parse::<u8>().unwrap())
        .collect::<Vec<u8>>();

    snapshot_gen.insert(id_snap, (id_parent, gen_bytes));
    id_snap
}

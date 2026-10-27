#![feature(path_absolute_method)]
#![feature(trim_prefix_suffix)]
#![feature(exit_status_error)]

// SPDX-FileCopyrightText: 2026 Quarkslab
//
// SPDX-License-Identifier: Apache-2.0

use std::process;
use std::thread::sleep;
use std::{collections::HashMap, fs, path::Path, time::Duration};

use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};

mod network_utils;
mod utils;

fn main() {
    env_logger::init();

    let mut snapshot_gen = HashMap::new();

    let corpus_path = "corpus/";
    let _offline_crashes_path = "offline_crashes";

    let (tx, rx) = std::sync::mpsc::channel();

    let p: &Path = corpus_path.as_ref();
    log::warn!("watching {:?}", p.absolute());

    let config = Config::default();

    let mut watcher = RecommendedWatcher::new(tx, config).unwrap();
    watcher.watch(p, RecursiveMode::Recursive).unwrap();

    for res in rx {
        match res {
            Ok(event) => {
                if let notify::EventKind::Create(_create_kind) = event.kind {
                    let path = event.paths.first().unwrap().as_os_str().to_str().unwrap();
                    if path.contains("metadata") {
                        if path.ends_with(".tmp") {
                            sleep(Duration::from_millis(100));
                        }
                        let path = path.strip_suffix(".tmp").unwrap();
                        let path = path.replace("..", ".");
                        let content = fs::read_to_string(path.clone()).unwrap();

                        let id_snap =
                            utils::retrieve_snapshot_metadata(&content, &mut snapshot_gen);
                        let (seq, ack) = network_utils::utils::retrieve_tcp_metadata(&content);

                        let mut input_path = corpus_path.to_string();
                        let input_file = path
                            .split('/')
                            .last()
                            .unwrap()
                            .trim_prefix(".")
                            .trim_suffix("_1.metadata");
                        input_path.push_str(input_file);

                        let packet = network_utils::input::Packet::from_file(&input_path).unwrap();
                        let (input_bytes, _) = match &packet.packet {
                            network_utils::input::PacketType::Ip4(ipv4) => {
                                network_utils::input::get_ipv4_bytes(ipv4, seq, ack)
                            }
                            network_utils::input::PacketType::Ip6(ipv6) => {
                                network_utils::input::get_ipv6_bytes(&ipv6, seq, ack)
                            }
                        };
                        log::warn!("reproducing {:?}", input_path);

                        reproduce(&snapshot_gen, id_snap, input_bytes, input_file);
                    }
                }
            }
            Err(e) => log::error!("watch error: {:?}", e),
        }
    }
}

fn reproduce(
    map: &HashMap<u64, (Option<u64>, Vec<u8>)>,
    id: u64,
    input: Vec<u8>,
    input_file: &str,
) {
    log::trace!("starting from {:?}", id);
    let mut seq: Vec<Vec<u8>> = Vec::new();
    let data = map.get(&id).unwrap();
    let mut parent = data.0;
    seq.push(data.1.clone());
    while parent.is_some() {
        log::trace!("parent {:?}", parent);
        let id = parent.unwrap();
        let a = map.get(&id).unwrap();
        seq.push(a.1.clone());
        parent = a.0;
    }
    seq.reverse();
    seq.push(input);

    let mut repro_file = "./repro_files/".to_string();
    repro_file.push_str(&input_file);
    repro_file.push_str(".repro");

    let mut buf = [0_u8; 0x10000];
    let serialized_inputs = postcard::to_slice(&seq, &mut buf).unwrap();

    fs::write(&repro_file, serialized_inputs).unwrap();

    let process = match process::Command::new("./offline_runner")
        .args(&[repro_file])
        .spawn()
    {
        Ok(process) => process,
        Err(err) => panic!("Running process error: {}", err),
    };

    let output = match process.wait_with_output() {
        Ok(output) => output,
        Err(err) => panic!("Retrieving output error: {}", err),
    };

    if !output.clone().exit_ok().is_ok() {
        let stdout = match std::string::String::from_utf8(output.stdout) {
            Ok(stdout) => stdout,
            Err(err) => panic!("Translating output error: {}", err),
        };
        log::debug!("{}", stdout);
    }
}

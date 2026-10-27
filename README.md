<!--
SPDX-FileCopyrightText: 2026 Quarkslab

SPDX-License-Identifier: Apache-2.0
-->

# slirp_snapshots_stateful

## Install and run

### step 0: install dependencies

```
sudo apt install meson ninja-build valgrind clang-20 binutils libglib-2.0-dev cmake python3-venv
```

Install a Rust toolchain.

### step 1: clone libafl

clone libafl next to the fuzzer directory and checkout the right commit

```
git clone https://github.com/AFLplusplus/LibAFL.git libafl/
cd libafl
git checkout 6e7ea0da898b63c5098f84c0908a8c427a5c73ff
```

### step 2: apply patches to libafl

```
git apply ../patches/libafl/module_snapshot.patch
git apply ../patches/libafl/snapshot.patch
git apply ../patches/libafl/libafl_bolts_wide.patch
git apply ../patches/libafl/libafl_targets_simd.patch
```

### step 3: clone libslirp

```
cd ..
git clone https://gitlab.freedesktop.org/slirp/libslirp.git
cd libslirp
git checkout 4ddbcd5cc4f7a14473ebfc1dcdd1afb4edf96908
```

### step 4: apply patches to libslirp

```
git apply ../patches/libslirp/meson_fuzzing.patch
git apply ../patches/libslirp/meson_options.patch
git apply ../patches/libslirp/meson.patch
git apply ../patches/libslirp/qemu_target.patch
git apply ../patches/libslirp/tcp_input.patch
git apply ../patches/libslirp/tcp_outpt.patch
```

### step 5: compile the target

```
CC=clang-20 CXX=clang++-20 meson build
ninja -C build
```

### step 6: find the offset of the checksum's ret instruction

Either open the binary in IDA/Binja/ghidra to find the offset of the `ret` instruction of the `cksum` function or

```
nm -n build/fuzzing/qemu-target | grep cksum
objdump -d --disassemble=cksum build/fuzzing/qemu-target | grep -E '\bret[qwl]?\b'
```

substrack the first offset you found to the second one and remplace the value in `fuzzer/src/libslirp/hooks.rs:200`


### step 7: compile the fuzzer

```
cd ../fuzzer
cargo +nightly build --release
```

Note: Depending on your llvm install you might need to specify the `LLVM_CONFIG_PATH` environment variable. 

### step 8: run the fuzzer

```
cp ../libslirp/build/fuzzing/qemu-target ./target/release/
cd target/release
mkdir corpus
RUST_LOG=warn ./slirp-snapshots-stateful-fuzzer
```

## Run with ASAN and coverage

warning: this does not work in folders shared with a VM or network mounts.

Do step 6 to change the offset in `offline_reproducer/runner/src/libslirp/hooks.rs:17`. Then compile the runner and driver

```
cd runner
cargo +nightly-2026-06-11 build --release
cp target/release/offline_runner ../../fuzzer/target/release
cp target/release/x86_64-unknown-linux-gnu/release/libafl_qemu_asan_host.so ../../fuzzer/target/release
cd ../driver
cargo +nightly build --release
cp target/release/offline_driver ../../fuzzer/target/release
cd ../../fuzzer/target/release
mkdir corpus coverage repro_files
```

In a terminal run the driver, then in another one run the fuzzer.

```
RUST_LOG=warn ./offline_driver
```

```
RUST_LOG=warn ./slirp-snapshots-stateful-fuzzer
```

### Coverage

Coverage files will be stored in the `coverage` folder, they can be opened with bncov (binja)/lighthouse (ida/binja)/lightkeeper (ghidra). If necessary merging can be done with [drcov-merge](https://github.com/vanhauser-thc/drcov-merge).

## Known bugs

- Qemu dies when a bug is found and it kills the fuzzer (libafl limitation).
- The offline reproducer does not send crashes into the crashes folder.


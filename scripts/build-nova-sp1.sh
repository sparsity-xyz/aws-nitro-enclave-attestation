#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

# Use the reviewed, committed guest ELFs; the host compiler is pinned in
# rust-toolchain.toml and all host dependencies are pinned in Cargo.lock.
export REPRODUCIBLE_BUILD=prebuilt
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_PROFILE_RELEASE_DEBUG=0
export CARGO_PROFILE_RELEASE_LTO=false
cargo build --release --locked -p nitro-attest-cli --no-default-features --features sp1
sha256sum target/release/nitro-attest-cli

#!/usr/bin/env bash
# S2 mollusk gate (SOLR §3.1.3 / §5.1): SBF build + the harness gate tests.
# The iteration loop for the Solana rail — e2e (solana-test-validator) stays a
# separate final gate per the heavy-gates rule.
#
# Toolchain: Agave (version pinned as AGAVE_VERSION in .github/ci-pins.env;
# ships cargo-build-sbf + platform-tools v1.52) + the host toolchain pinned
# in ../rust-toolchain.toml.
set -euo pipefail
cd "$(dirname "$0")/.."

export PATH="$HOME/.local/share/solana/install/active_release/bin:$HOME/.cargo/bin:$PATH"

cargo-build-sbf --manifest-path program/Cargo.toml

export SBF_OUT_DIR="$PWD/target/deploy"
# Workspace-wide: the program crate's host unit tests (recipient binding,
# byte-layout helpers) + the mollusk gate harness.
cargo test --workspace -- --nocapture

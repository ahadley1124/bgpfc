#!/usr/bin/env bash
# AGENTS.md §5: Miri on the crates with unsafe code or byte-level parsing.
# Needs `rustup toolchain install nightly -c miri -c rust-src` once.
set -euo pipefail
cd "$(dirname "$0")/.."

export MIRIFLAGS="${MIRIFLAGS:--Zmiri-strict-provenance}"
exec cargo +nightly miri test -p bgpfc-wire -p bgpfc-sys -p bgpfc-fib "$@"

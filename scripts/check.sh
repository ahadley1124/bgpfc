#!/usr/bin/env bash
# AGENTS.md §5: every gate that must pass before a commit, in the default
# and the profiling configuration (docs/PROFILING.md).
# Usage: scripts/check.sh [--no-miri]
set -euo pipefail
cd "$(dirname "$0")/.."

miri=1
for arg in "$@"; do
  case "$arg" in
    --no-miri) miri=0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

run() { echo "==> $*"; "$@"; }

run cargo fmt --all --check
run cargo clippy --workspace --all-targets -- -D warnings
run cargo clippy --workspace --all-targets --features profiling -- -D warnings
run cargo test --workspace
run cargo test --workspace --features profiling
run scripts/check-deps.sh
if [ "$miri" = 1 ]; then
  run scripts/miri.sh
fi
echo "==> all gates passed"

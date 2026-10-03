#!/usr/bin/env bash
# AGENTS.md §5: every gate that must pass before a commit.
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
run cargo test --workspace
run scripts/check-deps.sh
if [ "$miri" = 1 ]; then
  run scripts/miri.sh
fi
echo "==> all gates passed"

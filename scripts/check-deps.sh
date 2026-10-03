#!/usr/bin/env bash
# AGENTS.md §1.1: shipped crates depend on std and other bgpfc-* crates only.
#
# Lists every package reachable through normal and build dependency edges of
# the shipped workspace members (everything except `interop`; `fuzz/` is not
# a workspace member) and fails if any of them is not a bgpfc-* crate.
set -euo pipefail
cd "$(dirname "$0")/.."

offenders=$(
  cargo tree --workspace --exclude interop -e normal,build --prefix none --format '{p}' \
    | awk '{print $1}' \
    | sort -u \
    | grep -v -E '^(bgpfc-[a-z]+|bgpfcd|bgpfcctl)$' || true
)

if [ -n "$offenders" ]; then
  echo "check-deps: non-bgpfc crates in a shipped dependency graph:" >&2
  echo "$offenders" | sed 's/^/  /' >&2
  echo "AGENTS.md §1.1: shipped crates are std-only. Move it to [dev-dependencies], fuzz/ or interop/, or write it yourself." >&2
  exit 1
fi
echo "check-deps: ok (std only)"

//! Interoperability test harness. Drives BIRD, FRR and `GoBGP` in network
//! namespaces and peers them with `bgpfcd`. Nothing in this crate is shipped.
//!
//! Scenarios are added from milestone 3 onwards (AGENTS.md §9).
#![forbid(unsafe_code)]

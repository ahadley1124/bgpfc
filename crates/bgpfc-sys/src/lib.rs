//! The unsafe FFI boundary of bgpfc: sockets, netlink, `setsockopt`,
//! privilege drop and capability inspection.
//!
//! This is the only crate in the workspace that may contain `unsafe`
//! (AGENTS.md §1.3). It exports safe wrappers only; raw pointers and file
//! descriptors never cross its boundary.
//!
//! Implements: nothing yet.
#![cfg(target_os = "linux")]

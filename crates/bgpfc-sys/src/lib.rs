//! The unsafe FFI boundary of bgpfc: the netlink socket, signals,
//! privilege drop and capability inspection.
//!
//! This is the only crate in the workspace that may contain `unsafe`
//! (AGENTS.md §1.3). It exports safe wrappers only; raw pointers and file
//! descriptors never cross its boundary. Every entry point is declared by
//! hand in `ffi.rs` with the header it comes from (AGENTS.md §1.4).
//!
//! Implements: `netlink(7)` socket plumbing for `bgpfc-fib`; the
//! self-pipe signal handler of AGENTS.md §3; the two privilege modes of
//! the README.
#![cfg(target_os = "linux")]

mod caps;
mod ffi;
mod netlink;
mod privilege;
mod signal;

pub use caps::{Capability, Effective};
pub use netlink::NetlinkSocket;
pub use privilege::{Identity, drop_to, is_root, lookup_group, lookup_user};
pub use signal::{Signal, Signals};

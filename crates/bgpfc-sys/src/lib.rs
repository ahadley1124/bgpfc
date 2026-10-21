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
//!
//! Also implements, for the supervised RPKI sidecar, the child-process
//! controls std lacks: a parent-death signal (`prctl(2)`) and sending a
//! chosen signal (`kill(2)`).
#![cfg(target_os = "linux")]

mod caps;
mod ffi;
mod netlink;
mod privilege;
mod process;
mod signal;

pub use caps::{Capability, Effective};
pub use netlink::NetlinkSocket;
pub use privilege::{Identity, drop_to, is_root, lookup_group, lookup_user};
pub use process::send_signal_to_group;
pub use process::wait_for_exit;
pub use process::{ChildSignal, send_signal, set_parent_death_signal};
pub use signal::{Signal, Signals};

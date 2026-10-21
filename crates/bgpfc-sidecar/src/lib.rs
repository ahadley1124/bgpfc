//! The supervised RPKI sidecar (GitHub issues #26, #70, #71, #72).
//!
//! bgpfcd does not validate RPKI itself: it runs Routinator, an RPKI
//! relying-party implementation, as a child process and reads the
//! validated data over RTR (RFC 8210). This crate holds
//! the pure parts of looking after that child; the I/O shell that spawns,
//! signals and reaps it lives in bgpfcd.
//!
//! - [`Backoff`]: restart delays that double up to a cap, with jitter,
//!   reset once the child has stayed up for a stable period.
//!
//! Nothing here reads the clock, touches the file system or starts a
//! process: time is passed in, so every behaviour is testable with
//! injected time (AGENTS.md §3, "Time").
//!
//! Implements: no RFC.
#![forbid(unsafe_code)]

mod backoff;

pub use backoff::{Backoff, BackoffConfig};

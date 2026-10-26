//! The supervised RPKI sidecar (GitHub issues #26, #70, #71, #72).
//!
//! bgpfcd does not validate RPKI itself: it runs Routinator, an RPKI
//! relying-party implementation, as a child process and reads the
//! validated data over RTR (RFC 8210). This crate looks after that child.
//!
//! - [`Sidecar`]: the I/O shell. It checks the binary, picks the RTR
//!   port, and spawns, restarts, signals and reaps Routinator on one
//!   long-lived supervisor thread, logging what it prints and publishing
//!   a [`SidecarStatus`]. [`Sidecar::check`] runs the checks alone,
//!   starting nothing, so that a reload can refuse settings or a binary
//!   before it stops the running Routinator.
//! - [`SidecarConfig`]: what to run and how to supervise it, checked by
//!   [`SidecarConfig::validate`]: an absolute binary path that is never
//!   looked up on `PATH` (issue #70), RTR on loopback only (issue #71).
//! - [`routinator_args`]: Routinator's command line, with an escape hatch
//!   for options bgpfcd does not model (issue #72).
//! - [`parse_version`] and [`check_compatible`]: the startup check that
//!   the binary is the release series the command line was written for,
//!   [`TESTED_VERSION`] (issue #72).
//! - [`Backoff`]: restart delays that double up to a cap, with jitter,
//!   reset once the child has stayed up for a stable period.
//! - [`Supervisor`]: the state machine that starts the child, restarts it
//!   with backoff, raises the [`SidecarState::Failed`] alarm after
//!   repeated failures (issue #70) and stops it with `SIGTERM`, then
//!   `SIGKILL`, never restarting it during a requested shutdown.
//! - [`SidecarStatus`]: the snapshot the control plane shows.
//!
//! Everything but [`Sidecar`] is pure: it does not read the clock, touch
//! the file system or start a process. Time is passed in, so every
//! decision is testable with injected time (AGENTS.md §3, "Time"), and
//! [`Sidecar`] is the thin shell that carries the decisions out (§7).
//!
//! Linux only, like the `bgpfc-sys` calls it needs: the parent-death
//! signal, signals to a child and its process group, and waiting for a
//! child without reaping it.
//!
//! Implements: RFC 8210 §6 (the bounds on the refresh interval Routinator
//! announces).
#![forbid(unsafe_code)]

mod args;
mod backoff;
mod child;
mod config;
mod error;
mod output;
mod shell;
mod status;
mod supervisor;
mod version;

pub use args::routinator_args;
pub use backoff::{Backoff, BackoffConfig};
pub use config::{SidecarConfig, TalConfig};
pub use error::SidecarError;
pub use shell::Sidecar;
pub use status::{ExitReason, SidecarState, SidecarStatus};
pub use supervisor::{Action, Event, LogField, Supervisor};
pub use version::{TESTED_VERSION, Version, check_compatible, check_version_output, parse_version};

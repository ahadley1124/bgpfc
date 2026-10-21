//! What the control plane shows about the sidecar: where supervision
//! stands, which child runs, how often it was restarted and how it last
//! ended. A validator that is not running while the speaker enforces RPKI
//! must be visible to the operator (issue #70).
//!
//! Implements: no RFC.

use std::fmt;
use std::net::SocketAddr;
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;
use std::time::Instant;

/// Where supervision stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SidecarState {
    /// Not running, and not started again until asked.
    Stopped,
    /// A start is under way: the I/O shell was asked to spawn the child
    /// and has not reported the result yet.
    Starting,
    /// The child is running.
    Running {
        /// Its process id.
        pid: u32,
        /// When it was spawned.
        since: Instant,
    },
    /// The child failed, fewer times in a row than the failure threshold,
    /// and is started again at `until`.
    BackingOff {
        /// When the next attempt starts.
        until: Instant,
        /// Consecutive failures so far.
        failures: u32,
    },
    /// The child failed at least the failure threshold of times in a row:
    /// an operational alarm, because the speaker may be enforcing RPKI
    /// with a validator that is not running (issue #70). Supervision keeps
    /// retrying, at the backoff cap, starting at `until`.
    Failed {
        /// When the next attempt starts.
        until: Instant,
        /// Consecutive failures so far.
        failures: u32,
    },
    /// A stop was requested and the child has not exited yet. Nothing is
    /// restarted from here (issue #70).
    ShuttingDown {
        /// The child being stopped, or `None` while its spawn has not been
        /// reported yet.
        pid: Option<u32>,
    },
}

impl SidecarState {
    /// A short lower-case name for logs and the control plane.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            SidecarState::Stopped => "stopped",
            SidecarState::Starting => "starting",
            SidecarState::Running { .. } => "running",
            SidecarState::BackingOff { .. } => "backing-off",
            SidecarState::Failed { .. } => "failed",
            SidecarState::ShuttingDown { .. } => "shutting-down",
        }
    }
}

impl fmt::Display for SidecarState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// How the child last ended.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ExitReason {
    /// It exited with this status code.
    Code(i32),
    /// A signal ended it.
    Signal {
        /// The signal number.
        number: i32,
        /// Whether it left a core dump.
        core_dumped: bool,
    },
    /// A wait status that is neither an exit nor a signal, such as a
    /// stopped child; std's `wait` does not report those, so this only
    /// keeps the conversion total.
    Other(i32),
    /// It could not be started at all; the error message.
    SpawnFailed(String),
}

impl From<ExitStatus> for ExitReason {
    fn from(status: ExitStatus) -> ExitReason {
        if let Some(code) = status.code() {
            ExitReason::Code(code)
        } else if let Some(number) = status.signal() {
            ExitReason::Signal {
                number,
                core_dumped: status.core_dumped(),
            }
        } else {
            ExitReason::Other(status.into_raw())
        }
    }
}

impl fmt::Display for ExitReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExitReason::Code(code) => write!(f, "exited with status {code}"),
            ExitReason::Signal {
                number,
                core_dumped,
            } => {
                write!(f, "killed by signal {number}")?;
                if let Some(name) = signal_name(*number) {
                    write!(f, " ({name})")?;
                }
                if *core_dumped {
                    f.write_str(", core dumped")?;
                }
                Ok(())
            }
            ExitReason::Other(raw) => write!(f, "ended with wait status {raw:#x}"),
            ExitReason::SpawnFailed(error) => write!(f, "could not be started: {error}"),
        }
    }
}

/// The name of a standard signal, numbered as in
/// `<asm-generic/signal.h>` (`signal(7)`, the numbering of x86 and Arm).
fn signal_name(number: i32) -> Option<&'static str> {
    const NAMES: [&str; 31] = [
        "SIGHUP",
        "SIGINT",
        "SIGQUIT",
        "SIGILL",
        "SIGTRAP",
        "SIGABRT",
        "SIGBUS",
        "SIGFPE",
        "SIGKILL",
        "SIGUSR1",
        "SIGSEGV",
        "SIGUSR2",
        "SIGPIPE",
        "SIGALRM",
        "SIGTERM",
        "SIGSTKFLT",
        "SIGCHLD",
        "SIGCONT",
        "SIGSTOP",
        "SIGTSTP",
        "SIGTTIN",
        "SIGTTOU",
        "SIGURG",
        "SIGXCPU",
        "SIGXFSZ",
        "SIGVTALRM",
        "SIGPROF",
        "SIGWINCH",
        "SIGIO",
        "SIGPWR",
        "SIGSYS",
    ];
    let index = usize::try_from(number).ok()?.checked_sub(1)?;
    NAMES.get(index).copied()
}

/// A snapshot of the sidecar for the control plane.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SidecarStatus {
    /// Where supervision stands.
    pub state: SidecarState,
    /// The child's process id while one exists.
    pub pid: Option<u32>,
    /// How often the child was started again after it failed, over the
    /// supervisor's life.
    pub restarts: u64,
    /// Failures since the child last stayed up for the stable period. It
    /// stays at or above the failure threshold, the alarm level, while
    /// retries keep failing, even during the short runs between them.
    pub consecutive_failures: u32,
    /// How the child last ended, if it has.
    pub last_exit: Option<ExitReason>,
    /// The address Routinator serves RTR on.
    pub rtr: SocketAddr,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_reasons_from_wait_statuses() {
        // Raw wait statuses as `wait(2)` encodes them: the exit code in
        // bits 8-15, a terminating signal in bits 0-6, 0x80 for a core
        // dump, and 0x7f in the low byte for a stopped child (here by
        // SIGSTOP, 19).
        let cases: &[(i32, ExitReason, &str)] = &[
            (0, ExitReason::Code(0), "exited with status 0"),
            (0x100, ExitReason::Code(1), "exited with status 1"),
            (0xff00, ExitReason::Code(255), "exited with status 255"),
            (
                9,
                ExitReason::Signal {
                    number: 9,
                    core_dumped: false,
                },
                "killed by signal 9 (SIGKILL)",
            ),
            (
                15,
                ExitReason::Signal {
                    number: 15,
                    core_dumped: false,
                },
                "killed by signal 15 (SIGTERM)",
            ),
            (
                0x8b,
                ExitReason::Signal {
                    number: 11,
                    core_dumped: true,
                },
                "killed by signal 11 (SIGSEGV), core dumped",
            ),
            (
                0x86,
                ExitReason::Signal {
                    number: 6,
                    core_dumped: true,
                },
                "killed by signal 6 (SIGABRT), core dumped",
            ),
            (
                40,
                ExitReason::Signal {
                    number: 40,
                    core_dumped: false,
                },
                "killed by signal 40",
            ),
            (
                0x137f,
                ExitReason::Other(0x137f),
                "ended with wait status 0x137f",
            ),
        ];
        for (raw, reason, text) in cases {
            let got = ExitReason::from(ExitStatus::from_raw(*raw));
            assert_eq!(&got, reason, "{raw:#x}");
            assert_eq!(got.to_string(), *text, "{raw:#x}");
        }
        assert_eq!(
            ExitReason::SpawnFailed("No such file or directory (os error 2)".into()).to_string(),
            "could not be started: No such file or directory (os error 2)"
        );
    }

    #[test]
    fn signal_names_cover_the_standard_signals_only() {
        let cases: &[(i32, Option<&str>)] = &[
            (i32::MIN, None),
            (-1, None),
            (0, None),
            (1, Some("SIGHUP")),
            (2, Some("SIGINT")),
            (9, Some("SIGKILL")),
            (15, Some("SIGTERM")),
            (31, Some("SIGSYS")),
            (32, None),
            (64, None),
            (i32::MAX, None),
        ];
        for (number, name) in cases {
            assert_eq!(signal_name(*number), *name, "{number}");
        }
    }

    #[test]
    fn state_names() {
        let now = Instant::now();
        let cases = [
            (SidecarState::Stopped, "stopped"),
            (SidecarState::Starting, "starting"),
            (SidecarState::Running { pid: 1, since: now }, "running"),
            (
                SidecarState::BackingOff {
                    until: now,
                    failures: 1,
                },
                "backing-off",
            ),
            (
                SidecarState::Failed {
                    until: now,
                    failures: 5,
                },
                "failed",
            ),
            (SidecarState::ShuttingDown { pid: None }, "shutting-down"),
        ];
        for (state, name) in cases {
            assert_eq!(state.name(), name);
            assert_eq!(state.to_string(), name);
        }
    }
}

//! The crate's error type (AGENTS.md §7: one enum per crate, `Display` and
//! `Error` by hand).

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use crate::args::BUNDLED_TALS;
use crate::status::ExitReason;
use crate::version::{TESTED_VERSION, Version};

/// Why a sidecar setting or a Routinator binary is unusable, or why the
/// sidecar could not be started.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SidecarError {
    /// The binary path is relative. bgpfcd never searches `PATH` for the
    /// validator: a BGP daemon must not run whatever happens to be called
    /// `routinator` (issue #70).
    BinaryNotAbsolute(PathBuf),
    /// Another path setting is relative. Routinator would resolve it
    /// against its own working directory.
    NotAbsolute {
        /// The setting.
        setting: &'static str,
        /// The path as given.
        path: PathBuf,
    },
    /// A setting contains a NUL byte, which no program argument can carry
    /// (`execve(2)`), so every spawn would fail.
    NulByte {
        /// The setting.
        setting: &'static str,
    },
    /// The RTR listen address is not a loopback address. The sidecar
    /// serves RTR to this host only (issue #71).
    RtrNotLoopback(SocketAddr),
    /// A TAL name that the supported Routinator release does not bundle.
    UnknownTal(String),
    /// The ARIN TAL is named, but ARIN's Relying Party Agreement has not
    /// been accepted.
    ArinRpaNotAccepted,
    /// The TAL settings leave Routinator without a trust anchor.
    NoTrustAnchors,
    /// A numeric or duration setting is outside its range.
    OutOfRange {
        /// The setting.
        setting: &'static str,
        /// The accepted range, in words.
        expected: &'static str,
    },
    /// An extra argument that bgpfcd sets itself, or that would defeat
    /// supervision or the loopback-only RTR listener.
    ReservedArg {
        /// The argument as given, converted to UTF-8 lossily.
        arg: String,
        /// Why it is refused.
        reason: &'static str,
    },
    /// `routinator --version` printed something that is not a Routinator
    /// version.
    UnrecognizedVersion {
        /// The start of what it printed.
        output: String,
    },
    /// The Routinator binary is from a release series the command line was
    /// not written for (issue #72).
    IncompatibleVersion {
        /// The version the binary reported.
        found: Version,
        /// [`TESTED_VERSION`](crate::TESTED_VERSION).
        tested: Version,
    },
    /// `routinator --version` could not be started or did not exit
    /// successfully.
    VersionCheck {
        /// The binary.
        binary: PathBuf,
        /// How it ended, or why it could not be started.
        outcome: ExitReason,
        /// The start of what it printed, stdout and stderr together.
        output: String,
    },
    /// `routinator --version` did not finish in time and was killed. A
    /// binary that hangs there would hang bgpfcd's startup.
    VersionTimeout {
        /// The binary.
        binary: PathBuf,
        /// How long it had.
        timeout: Duration,
    },
    /// The operating system refused something the sidecar needs: a free
    /// RTR port, a socket pair for the child's output, or a thread.
    Io {
        /// What failed, such as `"picking a free RTR port"`.
        action: &'static str,
        /// The kind of the error.
        kind: io::ErrorKind,
        /// The error's message.
        message: String,
    },
}

impl SidecarError {
    /// [`SidecarError::Io`] for `error` while doing `action`.
    pub(crate) fn io(action: &'static str, error: &io::Error) -> SidecarError {
        SidecarError::Io {
            action,
            kind: error.kind(),
            message: error.to_string(),
        }
    }
}

impl fmt::Display for SidecarError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SidecarError::BinaryNotAbsolute(path) => write!(
                f,
                "the Routinator binary must be an absolute path, not {:?}: bgpfcd never searches PATH for it",
                path.display().to_string()
            ),
            SidecarError::NotAbsolute { setting, path } => write!(
                f,
                "{setting} must be an absolute path, not {:?}",
                path.display().to_string()
            ),
            SidecarError::NulByte { setting } => write!(f, "{setting} contains a NUL byte"),
            SidecarError::RtrNotLoopback(addr) => write!(
                f,
                "RTR listen address {addr} is not a loopback address; the sidecar serves this host only"
            ),
            SidecarError::UnknownTal(name) => write!(
                f,
                "Routinator {}.{} bundles no TAL named {name:?}; it knows {}",
                TESTED_VERSION.major,
                TESTED_VERSION.minor,
                BUNDLED_TALS.join(", ")
            ),
            SidecarError::ArinRpaNotAccepted => f.write_str(
                "the ARIN TAL is listed, but ARIN's Relying Party Agreement has not been accepted",
            ),
            SidecarError::NoTrustAnchors => f.write_str(
                "no trust anchors: enable the RIR TALs, name a bundled TAL or give an extra TAL directory",
            ),
            SidecarError::OutOfRange { setting, expected } => {
                write!(f, "{setting} must be {expected}")
            }
            SidecarError::ReservedArg { arg, reason } => {
                write!(f, "extra Routinator argument {arg:?} is not allowed: {reason}")
            }
            SidecarError::UnrecognizedVersion { output } => write!(
                f,
                "`routinator --version` printed {output:?}, which is not a Routinator version"
            ),
            SidecarError::IncompatibleVersion { found, tested } => write!(
                f,
                "Routinator {found} is not supported: bgpfcd drives Routinator {}.{}.x and was tested with {tested}",
                tested.major, tested.minor
            ),
            SidecarError::VersionCheck {
                binary,
                outcome,
                output,
            } => {
                write!(f, "`{} --version` {outcome}", binary.display())?;
                if !output.is_empty() {
                    write!(f, ": {output:?}")?;
                }
                Ok(())
            }
            SidecarError::VersionTimeout { binary, timeout } => write!(
                f,
                "`{} --version` did not finish within {timeout:?} and was killed",
                binary.display()
            ),
            SidecarError::Io {
                action, message, ..
            } => write!(f, "{action}: {message}"),
        }
    }
}

impl std::error::Error for SidecarError {}

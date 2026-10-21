//! The crate's error type (AGENTS.md §7: one enum per crate, `Display` and
//! `Error` by hand).

use std::fmt;

use crate::version::Version;

/// Why a sidecar setting or a Routinator binary is unusable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SidecarError {
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
}

impl fmt::Display for SidecarError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SidecarError::UnrecognizedVersion { output } => write!(
                f,
                "`routinator --version` printed {output:?}, which is not a Routinator version"
            ),
            SidecarError::IncompatibleVersion { found, tested } => write!(
                f,
                "Routinator {found} is not supported: bgpfcd drives Routinator {}.{}.x and was tested with {tested}",
                tested.major, tested.minor
            ),
        }
    }
}

impl std::error::Error for SidecarError {}

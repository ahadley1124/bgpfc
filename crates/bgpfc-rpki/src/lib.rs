//! RPKI route origin validation: the Validated ROA Payloads a relying-party
//! cache hands to a router, and the validation state each route gets from
//! them.
//!
//! The crate knows nothing about how VRPs arrive; the RTR client fills it
//! from a cache (RFC 8210).
//!
//! Implements: RFC 6811 §2 (VRPs, the Route Origin ASN, Covered, Matched,
//! the three validation states); RFC 6483 §2 (validation outcome),
//! §4 (an AS 0 ROA disavows origination); RFC 7607 §2 (AS 0 is never a
//! valid origin); RFC 9319 §3 (a VRP authorises nothing longer than its
//! maxLength); RFC 8210 §5.1, §5.6, §5.7 (bounds of Max Length).
#![forbid(unsafe_code)]

pub mod origin;
pub mod state;
pub mod vrp;

use std::fmt;

use bgpfc_wire::prefix::Prefix;

pub use origin::RouteOrigin;
pub use state::{AspaState, RovState};
pub use vrp::Vrp;

/// Everything that can go wrong in this crate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RpkiError {
    /// A VRP whose maximum length is shorter than its prefix
    /// (RFC 8210 §5.1: Max Length "MUST NOT be less than the Prefix
    /// Length element").
    MaxLenBelowPrefixLen {
        /// The VRP prefix.
        prefix: Prefix,
        /// The maximum length given.
        max_len: u8,
    },
    /// A VRP whose maximum length exceeds the address size of its family
    /// (RFC 8210 §5.6: 0..32; §5.7: 0..128).
    MaxLenTooLong {
        /// The VRP prefix.
        prefix: Prefix,
        /// The maximum length given.
        max_len: u8,
    },
    /// Text that names no validation state.
    UnknownState(String),
}

impl fmt::Display for RpkiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RpkiError::MaxLenBelowPrefixLen { prefix, max_len } => {
                write!(
                    f,
                    "VRP {prefix}: max length {max_len} is shorter than the prefix"
                )
            }
            RpkiError::MaxLenTooLong { prefix, max_len } => {
                write!(
                    f,
                    "VRP {prefix}: max length {max_len} exceeds the address size"
                )
            }
            RpkiError::UnknownState(s) => write!(f, "unknown validation state {s:?}"),
        }
    }
}

impl std::error::Error for RpkiError {}

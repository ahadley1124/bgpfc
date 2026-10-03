//! BGP-4 message codec. Pure functions from bytes to typed messages and
//! back; no I/O, no clock.
//!
//! Implements: RFC 4271 §4.5 (error codes), RFC 6793 §3 (ASN types),
//! RFC 4760 §3 (AFI/SAFI), RFC 6286 §2.1.
#![forbid(unsafe_code)]

pub mod error;
pub mod reader;
pub mod types;

pub use error::{DecodeError, EncodeError, ErrorCode, HeaderSubcode, OpenSubcode};
pub use types::{AddressFamily, Afi, Asn, HoldTime, RouterId, Safi};

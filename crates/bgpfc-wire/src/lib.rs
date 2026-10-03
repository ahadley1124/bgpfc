//! BGP-4 message codec. Pure functions from bytes to typed messages and
//! back; no I/O, no clock.
//!
//! Implements: RFC 4271 §4.1, §4.5, §6.1; RFC 2918 §3 (type code);
//! RFC 8654 §4, §6; RFC 6793 §3 (ASN types); RFC 4760 §3; RFC 6286 §2.1.
#![forbid(unsafe_code)]

pub mod error;
pub mod header;
pub mod reader;
pub mod types;

pub use error::{DecodeError, EncodeError, ErrorCode, HeaderSubcode, OpenSubcode};
pub use header::{HEADER_LEN, Header, MessageType, frame};
pub use types::{AddressFamily, Afi, Asn, HoldTime, RouterId, Safi};

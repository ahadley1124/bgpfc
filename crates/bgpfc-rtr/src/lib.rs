//! The RPKI-to-Router protocol: how a router learns Validated ROA Payloads
//! from an RPKI cache.
//!
//! [`pdu`] is the codec: [`Pdu::decode`] turns the octets of one PDU into
//! a typed [`Pdu`], and [`Pdu::encode`] turns it back. A PDU that cannot
//! be accepted becomes an [`RtrError`] that names the [`ErrorCode`] of
//! the Error Report to send in reply.
//!
//! Both protocol versions are supported: version 0 (RFC 6810) and
//! version 1 (RFC 8210), which adds the Router Key PDU and the timing
//! intervals of End of Data. Router Keys are decoded and re-encoded but
//! not interpreted: path validation with router keys (RFC 8205) is out of
//! scope.
//!
//! Implements: RFC 8210 §5 (reserved fields), §5.1 (header fields,
//! Flags, Max Length), §5.2–§5.11 (every PDU), §6 (timing parameters),
//! §7 (unsupported and unexpected versions), §12 (error codes), §14 (PDU
//! types per version); RFC 6810 §5 (version 0 PDUs), §10 (error codes).
#![forbid(unsafe_code)]

pub mod error;
pub mod pdu;

pub use error::{ErrorCode, RtrError};
pub use pdu::{ErrorReport, Intervals, MAX_PDU_LEN, Pdu, PduType, RouterKey, Version};

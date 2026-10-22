//! The RPKI-to-Router protocol: how a router learns Validated ROA Payloads
//! from an RPKI cache.
//!
//! [`pdu`] is the codec: [`Pdu::decode`] turns the octets of one PDU into
//! a typed [`Pdu`], and [`Pdu::encode`] turns it back. A PDU that cannot
//! be accepted becomes an [`RtrError`] that names the [`ErrorCode`] of
//! the Error Report to send in reply. [`framer`] cuts the byte stream
//! from a cache into PDUs, with a cap on how much it buffers. [`session`]
//! is the router's side of the protocol with one cache: a pure state
//! machine, with time injected, that sends the queries, stages each reply
//! until it is complete, commits whole VRP sets and runs the timers.
//! [`client`] is the thread around it: TCP to the configured caches in
//! order of preference, reconnects with a back-off, and every commit
//! published to the RIB through a
//! [`ValidationSink`](bgpfc_rpki::ValidationSink).
//!
//! Both protocol versions are supported: version 0 (RFC 6810) and
//! version 1 (RFC 8210), which adds the Router Key PDU and the timing
//! intervals of End of Data. Router Keys are decoded and re-encoded but
//! not interpreted: path validation with router keys (RFC 8205) is out of
//! scope.
//!
//! Implements: RFC 8210 §4 (operational overview), §5 (reserved fields),
//! §5.1 (header fields, Flags, Max Length, Length, Session ID),
//! §5.2–§5.11 (every PDU), §6 (timing parameters), §7 (version
//! negotiation, unsupported and unexpected versions, Serial Notify during
//! negotiation), §8 (protocol sequences), §9 (TCP to the rpki-rtr port),
//! §10 (keeping the data while the cache is away; the cache list in order
//! of preference), §12 (error codes), §14 (PDU types per version);
//! RFC 6810 §5 (version 0 PDUs), §6.1 (version 0 polling), §7 (the
//! port), §8 (deleting data that cannot be refreshed; the cache list),
//! §10 (error codes).
#![forbid(unsafe_code)]

pub mod client;
pub mod error;
pub mod framer;
pub mod pdu;
pub mod session;

pub use client::Client;
pub use error::{ErrorCode, RtrError};
pub use framer::{Framer, Received};
pub use pdu::{ErrorReport, Intervals, MAX_PDU_LEN, Pdu, PduType, RouterKey, Version};
pub use session::Session;

//! Control plane building blocks (AGENTS.md §3, "Control plane"): the
//! `bgpfcctl` line protocol, a minimal HTTP/1.1 request parser and
//! response writer, and a JSON writer. No sockets: `bgpfcd` wires these
//! to its listeners and its threads. The protocols are documented in
//! `docs/control.md`.
//!
//! Implements: RFC 8259 (JSON output); RFC 9112 §2, §3, §5, §6.2 (the
//! HTTP subset served); RFC 6750 §2.1 (bearer tokens).
#![forbid(unsafe_code)]

pub mod http;
pub mod json;
pub mod proto;

pub use json::Json;

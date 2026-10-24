//! Load generation and benchmarking for `bgpfcd` (`docs/PROFILING.md`).
//!
//! - [`speaker`]: a minimal BGP speaker over `TcpStream`, as client or
//!   server, with keepalives on the negotiated Hold Time.
//! - [`synth`]: a reproducible synthetic IPv4 table.
//! - [`pack`]: UPDATE packing to the negotiated message size, with the
//!   daemon's own encoder.
//!
//! Development tooling only; the daemon never links it.
//!
//! Implements: RFC 4271 §4 (the messages a speaker sends), §4.2 and §10
//! (Hold Time negotiation and keepalive interval); RFC 4724 §2 (End-of-RIB
//! markers); RFC 4760 §3, §4 (`MP_REACH_NLRI` / `MP_UNREACH_NLRI`);
//! RFC 6793 §3; RFC 8654 §4 (message size).
#![forbid(unsafe_code)]

pub mod cli;
pub mod pack;
pub mod rng;
pub mod speaker;
pub mod synth;
pub mod table;

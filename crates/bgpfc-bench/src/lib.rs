//! Load generation and benchmarking for `bgpfcd` (`docs/PROFILING.md`).
//!
//! - [`speaker`]: a minimal BGP speaker over `TcpStream`, as client or
//!   server, with keepalives on the negotiated Hold Time.
//! - [`synth`]: a reproducible synthetic IPv4 table; [`mrt`]: routes from a
//!   `TABLE_DUMP_V2` file.
//! - [`pack`]: UPDATE packing to the negotiated message size, with the
//!   daemon's own encoder.
//! - [`scenario`]: the `load`, `churn`, `withdraw-all` and `flap` drivers.
//! - [`results`] and [`stats`]: what the benchmark harness records.
//!
//! Development tooling only; the daemon never links it.
//!
//! Implements: RFC 4271 §4 (the messages a speaker sends), §4.2 and §10
//! (Hold Time negotiation and keepalive interval); RFC 4724 §2 (End-of-RIB
//! markers); RFC 4760 §3, §4 (`MP_REACH_NLRI` / `MP_UNREACH_NLRI`); RFC 6396
//! §4.3 (`TABLE_DUMP_V2`); RFC 6793 §3; RFC 8654 §4 (message size).
#![forbid(unsafe_code)]

pub mod cli;
pub mod mrt;
pub mod pack;
pub mod results;
pub mod rng;
pub mod scenario;
pub mod speaker;
pub mod stats;
pub mod synth;
pub mod table;

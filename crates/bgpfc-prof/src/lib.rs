//! Profiling instruments for bgpfc (`docs/PROFILING.md`): counters,
//! gauges, log2 latency histograms, a span timer, `/proc` memory readers
//! and the `key=value` report line.
//!
//! Zero cost when off: the crates it instruments (`bgpfc-wire`,
//! `bgpfc-rib`, `bgpfcd`) depend on it only through their `profiling`
//! feature, and every call site is behind `#[cfg(feature = "profiling")]`.
//! A default build does not link this crate at all.
//!
//! Everything is lock-free and allocation-free on the recording side:
//! counters and histogram buckets are `AtomicU64`s updated with `Relaxed`
//! ordering. Only the reporter allocates.
//!
//! Implements: no RFC; instrumentation only.
#![forbid(unsafe_code)]

pub mod counter;
pub mod hist;
pub mod metrics;
pub mod procfs;
pub mod report;
pub mod timer;

pub use counter::{Counter, Gauge};
pub use hist::{Histogram, Snapshot};
pub use report::Line;
pub use timer::{Timer, now, set_spans, spans};

//! Monotonic counters and last-value gauges.

use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

/// A count that only goes up.
#[derive(Debug, Default)]
pub struct Counter(AtomicU64);

impl Counter {
    /// A counter at zero.
    #[must_use]
    pub const fn new() -> Counter {
        Counter(AtomicU64::new(0))
    }

    /// Add one.
    pub fn inc(&self) {
        self.0.fetch_add(1, Relaxed);
    }

    /// Add `n`.
    pub fn add(&self, n: usize) {
        self.0.fetch_add(n as u64, Relaxed);
    }

    /// The current count.
    #[must_use]
    pub fn get(&self) -> u64 {
        self.0.load(Relaxed)
    }
}

/// A value that is overwritten, such as a table size.
#[derive(Debug, Default)]
pub struct Gauge(AtomicU64);

impl Gauge {
    /// A gauge at zero.
    #[must_use]
    pub const fn new() -> Gauge {
        Gauge(AtomicU64::new(0))
    }

    /// Replace the value.
    pub fn set(&self, v: usize) {
        self.0.store(v as u64, Relaxed);
    }

    /// The current value.
    #[must_use]
    pub fn get(&self) -> u64 {
        self.0.load(Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_add_and_gauges_overwrite() {
        let c = Counter::new();
        c.inc();
        c.add(41);
        assert_eq!(c.get(), 42);
        let g = Gauge::new();
        g.set(7);
        g.set(3);
        assert_eq!(g.get(), 3);
    }
}

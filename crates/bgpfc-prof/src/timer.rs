//! Span timing: a guard that records the time until it is dropped.
//!
//! Spans can be switched off at run time (`BGP_PROFILE_SPANS=0`, read by
//! the daemon at startup), which turns [`now`] into `None` and every
//! [`Timer`] into a no-op. That measures the cost of the instrumentation
//! itself: about two `clock_gettime` calls per span.

use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::time::Instant;

use crate::hist::Histogram;

static SPANS: AtomicBool = AtomicBool::new(true);

/// Turn span timing on or off for the whole process.
pub fn set_spans(on: bool) {
    SPANS.store(on, Relaxed);
}

/// Whether span timing is on.
#[must_use]
pub fn spans() -> bool {
    SPANS.load(Relaxed)
}

/// The current time when spans are on: the start of a span that is
/// finished with [`Histogram::record_since`].
#[must_use]
pub fn now() -> Option<Instant> {
    spans().then(Instant::now)
}

impl Histogram {
    /// Record the time since `start`, if spans were on when it was taken.
    pub fn record_since(&self, start: Option<Instant>) {
        if let Some(t) = start {
            self.record_duration(t.elapsed());
        }
    }
}

/// Records the time from [`Timer::start`] to its drop into a histogram.
#[derive(Debug)]
#[must_use = "the span ends when the timer is dropped"]
pub struct Timer {
    hist: &'static Histogram,
    start: Option<Instant>,
}

impl Timer {
    /// Start a span that `hist` records.
    pub fn start(hist: &'static Histogram) -> Timer {
        Timer { hist, start: now() }
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        self.hist.record_since(self.start);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static H: Histogram = Histogram::new();

    #[test]
    fn a_timer_records_on_drop_unless_spans_are_off() {
        {
            let _t = Timer::start(&H);
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        let s = H.snapshot();
        assert_eq!(s.count, 1);
        assert!(s.max >= 2_000_000, "{}", s.max);

        set_spans(false);
        assert!(now().is_none());
        drop(Timer::start(&H));
        H.record_since(now());
        set_spans(true);
        assert_eq!(H.snapshot().count, 1);
        H.record_since(now());
        assert_eq!(H.snapshot().count, 2);
    }
}

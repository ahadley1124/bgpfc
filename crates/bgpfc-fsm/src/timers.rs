//! Timer bookkeeping: each RFC 4271 §8 timer is a deadline on an injected
//! clock, plus the §10 jitter.
//!
//! Implements: RFC 4271 §10 (timer semantics, jitter in [0.75, 1.0]).

use std::time::{Duration, Instant};

/// One timer: either stopped ("set to zero" in RFC 4271's words) or
/// running until a deadline.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timer {
    deadline: Option<Instant>,
}

impl Timer {
    /// Stop the timer.
    pub fn stop(&mut self) {
        self.deadline = None;
    }

    /// Start or restart the timer to fire `after` from `now`.
    pub fn start(&mut self, now: Instant, after: Duration) {
        self.deadline = Some(now + after);
    }

    /// Whether the timer is running.
    #[must_use]
    pub const fn is_running(&self) -> bool {
        self.deadline.is_some()
    }

    /// The deadline, if running.
    #[must_use]
    pub const fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// Whether the timer is running and its deadline has passed.
    #[must_use]
    pub fn has_expired(&self, now: Instant) -> bool {
        self.deadline.is_some_and(|d| d <= now)
    }
}

/// RFC 4271 §10 jitter: a uniformly distributed factor in [0.75, 1.0],
/// freshly drawn each time a timer is set. A tiny xorshift generator keeps
/// the FSM pure and deterministic for a given seed; seed zero disables
/// jitter so that tests see exact durations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Jitter {
    state: u64,
}

impl Jitter {
    /// Seed zero means "no jitter".
    #[must_use]
    pub(crate) const fn new(seed: u64) -> Jitter {
        Jitter { state: seed }
    }

    /// Scale `base` by a fresh factor in [0.75, 1.0].
    pub(crate) fn apply(&mut self, base: Duration) -> Duration {
        if self.state == 0 {
            return base;
        }
        // xorshift64*; quality is irrelevant here, only spread.
        self.state ^= self.state >> 12;
        self.state ^= self.state << 25;
        self.state ^= self.state >> 27;
        let r = self.state.wrapping_mul(0x2545_f491_4f6c_dd1d);
        // Factor = 0.75 + 0.25 * (r / 2^64), computed in nanoseconds
        // without floating point: base * (3/4) + base/4 * fraction.
        let nanos = base.as_nanos();
        let quarter = nanos / 4;
        let fraction = u128::from(r >> 32); // 32-bit fraction
        let extra = quarter * fraction / (1u128 << 32);
        let total = nanos - quarter + extra;
        Duration::from_nanos(u64::try_from(total).unwrap_or(u64::MAX))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timer_lifecycle() {
        let t0 = Instant::now();
        let mut t = Timer::default();
        assert!(!t.is_running());
        assert!(!t.has_expired(t0));
        t.start(t0, Duration::from_secs(5));
        assert!(t.is_running());
        assert_eq!(t.deadline(), Some(t0 + Duration::from_secs(5)));
        assert!(!t.has_expired(t0 + Duration::from_secs(4)));
        assert!(t.has_expired(t0 + Duration::from_secs(5)));
        t.stop();
        assert!(!t.is_running());
        assert!(!t.has_expired(t0 + Duration::from_secs(60)));
    }

    #[test]
    fn jitter_stays_within_rfc_bounds() {
        // RFC 4271 §10: factor uniformly in [0.75, 1.0].
        let base = Duration::from_secs(120);
        let mut j = Jitter::new(0x1234_5678_9abc_def0);
        let mut seen_low = false;
        let mut seen_high = false;
        for _ in 0..1000 {
            let d = j.apply(base);
            assert!(d >= Duration::from_secs(90), "{d:?}");
            assert!(d <= base, "{d:?}");
            seen_low |= d < Duration::from_secs(97);
            seen_high |= d > Duration::from_secs(113);
        }
        assert!(seen_low && seen_high, "factor should spread over the range");
        // Seed zero: exact.
        assert_eq!(Jitter::new(0).apply(base), base);
    }
}

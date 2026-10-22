//! Restart delays: exponential backoff up to a cap, with deterministic
//! jitter, reset once the child has stayed up long enough to count as
//! healthy.
//!
//! Implements: no RFC. Jitter spreads restarts so that validators that
//! failed together (say, on the same malformed RPKI object) do not all
//! fetch from the RPKI repositories at the same moment when they return.

use std::time::Duration;

/// Backoff settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BackoffConfig {
    /// Nominal delay before the first restart after a failure.
    pub initial: Duration,
    /// Longest nominal delay. Each failure doubles the delay until it
    /// reaches this.
    pub cap: Duration,
    /// How long the child must stay up for its next failure to count as a
    /// first failure again.
    pub stable: Duration,
}

impl Default for BackoffConfig {
    /// One second, doubling to five minutes; five minutes of uptime
    /// count as stable.
    fn default() -> BackoffConfig {
        BackoffConfig {
            initial: Duration::from_secs(1),
            cap: Duration::from_secs(300),
            stable: Duration::from_secs(300),
        }
    }
}

/// Exponential backoff with jitter.
///
/// Each [`Backoff::next_delay`] returns the current nominal delay, scaled
/// by a jitter factor in [0.5, 1.0], and then doubles the nominal delay up
/// to the cap. Jitter only shortens a delay, so the cap is never exceeded.
/// The jitter comes from a small xorshift generator seeded per instance:
/// a given seed always produces the same sequence, and seed zero disables
/// jitter so that tests see exact delays.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Backoff {
    config: BackoffConfig,
    next: Duration,
    rng: u64,
}

impl Backoff {
    /// A backoff at its initial delay. `seed` zero means no jitter.
    #[must_use]
    pub const fn new(config: BackoffConfig, seed: u64) -> Backoff {
        Backoff {
            config,
            next: config.initial,
            rng: seed,
        }
    }

    /// The settings.
    #[must_use]
    pub const fn config(&self) -> BackoffConfig {
        self.config
    }

    /// The nominal delay the next [`Backoff::next_delay`] scales, before
    /// jitter.
    #[must_use]
    pub fn nominal(&self) -> Duration {
        self.next.min(self.config.cap)
    }

    /// Whether the backoff is at its initial delay, so a reset would change
    /// nothing.
    #[must_use]
    pub fn is_reset(&self) -> bool {
        self.next == self.config.initial
    }

    /// The delay before the next restart; doubles the nominal delay for the
    /// one after, up to the cap.
    pub fn next_delay(&mut self) -> Duration {
        let nominal = self.nominal();
        self.next = nominal.saturating_mul(2).min(self.config.cap);
        self.jittered(nominal)
    }

    /// A delay at the cap, jittered, whatever the current nominal delay.
    /// The supervisor waits this long between retries once it has given
    /// up on a quick recovery.
    pub fn cap_delay(&mut self) -> Duration {
        self.jittered(self.config.cap)
    }

    /// Back to the initial delay.
    pub fn reset(&mut self) {
        self.next = self.config.initial;
    }

    /// Report how long the child stayed up. At least the stable period
    /// resets the backoff, and the return value says whether it did.
    pub fn record_uptime(&mut self, uptime: Duration) -> bool {
        if uptime >= self.config.stable {
            self.reset();
            true
        } else {
            false
        }
    }

    /// Scale `nominal` by a fresh factor in [0.5, 1.0].
    fn jittered(&mut self, nominal: Duration) -> Duration {
        if self.rng == 0 {
            return nominal;
        }
        // xorshift64*: only spread matters here, not statistical quality.
        self.rng ^= self.rng >> 12;
        self.rng ^= self.rng << 25;
        self.rng ^= self.rng >> 27;
        let r = self.rng.wrapping_mul(0x2545_f491_4f6c_dd1d);
        // nominal * (1/2 + 1/2 * fraction), in integer nanoseconds.
        let nanos = nominal.as_nanos();
        let half = nanos / 2;
        let fraction = u128::from(r >> 32); // a 32-bit fraction of 2^32
        let total = half + (nanos - half) * fraction / (1u128 << 32);
        // `total` is at most `nanos`, which came from a `Duration`; the
        // fallback is unreachable but keeps this total.
        let secs = u64::try_from(total / 1_000_000_000).unwrap_or(u64::MAX);
        let sub = u32::try_from(total % 1_000_000_000).unwrap_or(0);
        Duration::new(secs, sub)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    fn config(initial: u64, cap: u64, stable: u64) -> BackoffConfig {
        BackoffConfig {
            initial: secs(initial),
            cap: secs(cap),
            stable: secs(stable),
        }
    }

    #[test]
    fn grows_by_doubling_up_to_the_cap() {
        // (initial, cap, the delays of successive failures)
        let cases: &[(u64, u64, &[u64])] = &[
            (1, 300, &[1, 2, 4, 8, 16, 32, 64, 128, 256, 300, 300, 300]),
            (1, 10, &[1, 2, 4, 8, 10, 10]),
            (5, 5, &[5, 5, 5]),
            (3, 20, &[3, 6, 12, 20, 20]),
            // A misconfigured initial delay above the cap is held at the cap.
            (60, 30, &[30, 30]),
        ];
        for &(initial, cap, expected) in cases {
            let mut b = Backoff::new(config(initial, cap, 60), 0);
            let got: Vec<u64> = expected.iter().map(|_| b.next_delay().as_secs()).collect();
            assert_eq!(got, expected, "initial {initial}s cap {cap}s");
        }
    }

    #[test]
    fn doubling_saturates_instead_of_overflowing() {
        let mut b = Backoff::new(
            BackoffConfig {
                initial: Duration::MAX / 2 + Duration::from_secs(1),
                cap: Duration::MAX,
                stable: secs(1),
            },
            0,
        );
        let _ = b.next_delay();
        assert_eq!(b.next_delay(), Duration::MAX);
        assert_eq!(b.next_delay(), Duration::MAX);
    }

    #[test]
    fn cap_delay_ignores_the_current_step() {
        let mut b = Backoff::new(config(1, 300, 60), 0);
        assert_eq!(b.cap_delay(), secs(300));
        // ...and does not advance the doubling.
        assert_eq!(b.next_delay(), secs(1));
    }

    #[test]
    fn resets_only_after_the_stable_period() {
        let mut b = Backoff::new(config(1, 300, 60), 0);
        for _ in 0..4 {
            let _ = b.next_delay();
        }
        assert!(!b.is_reset());
        assert_eq!(b.nominal(), secs(16));
        // Uptimes below the stable period keep the backoff where it is.
        for up in [
            Duration::ZERO,
            secs(1),
            secs(59),
            Duration::from_nanos(59_999_999_999),
        ] {
            assert!(!b.record_uptime(up), "{up:?}");
            assert_eq!(b.nominal(), secs(16), "{up:?}");
        }
        assert!(b.record_uptime(secs(60)));
        assert!(b.is_reset());
        assert_eq!(b.next_delay(), secs(1));
        let _ = b.next_delay();
        assert!(b.record_uptime(secs(3600)));
        assert_eq!(b.next_delay(), secs(1));
        // An explicit reset does the same.
        let _ = b.next_delay();
        b.reset();
        assert_eq!(b.next_delay(), secs(1));
    }

    #[test]
    fn jitter_stays_in_range_and_never_exceeds_the_cap() {
        let mut b = Backoff::new(config(1, 300, 60), 0x1234_5678_9abc_def0);
        let mut low = false;
        let mut high = false;
        for _ in 0..1000 {
            let nominal = b.nominal();
            let d = b.next_delay();
            assert!(d >= nominal / 2 && d <= nominal, "{d:?} of {nominal:?}");
            let c = b.cap_delay();
            assert!(c >= secs(150) && c <= secs(300), "{c:?}");
            low |= c < secs(175);
            high |= c > secs(275);
        }
        assert!(low && high, "the factor should spread over [0.5, 1.0]");
    }

    #[test]
    fn jitter_is_deterministic_per_seed() {
        let run = |seed| {
            let mut b = Backoff::new(config(1, 300, 60), seed);
            (0..20).map(|_| b.next_delay()).collect::<Vec<_>>()
        };
        assert_eq!(run(7), run(7));
        assert_ne!(run(7), run(8));
        // Seed zero: exact nominal delays.
        let exact: Vec<u64> = run(0).iter().map(Duration::as_secs).collect();
        assert_eq!(&exact[..5], &[1, 2, 4, 8, 16]);
        assert!(run(0).iter().all(|d| d.subsec_nanos() == 0));
    }
}

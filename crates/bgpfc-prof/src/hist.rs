//! Latency histograms with 64 power-of-two buckets of nanoseconds.
//!
//! Bucket 0 holds 0 ns; bucket `b` (1..=62) holds `[2^(b-1), 2^b)`; bucket
//! 63 holds everything from `2^62` up. Recording is four relaxed atomic
//! updates and never allocates. Percentiles are estimated from the buckets
//! by interpolating linearly inside the bucket that holds the requested
//! rank, so an estimate is never off by more than the width of that bucket
//! (a factor of two); the top of that bucket is capped at the largest
//! value seen.

use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::Duration;

/// Number of buckets.
pub const BUCKETS: usize = 64;

/// The bucket `ns` falls in.
#[must_use]
pub const fn bucket_of(ns: u64) -> usize {
    let b = ns.bit_width() as usize;
    if b < BUCKETS { b } else { BUCKETS - 1 }
}

/// The smallest and largest value bucket `b` holds, both inclusive.
#[must_use]
pub const fn bucket_bounds(b: usize) -> (u64, u64) {
    match b {
        0 => (0, 0),
        b if b >= BUCKETS - 1 => (1 << (BUCKETS - 2), u64::MAX),
        b => (1 << (b - 1), (1 << b) - 1),
    }
}

/// A concurrent latency histogram.
#[derive(Debug)]
pub struct Histogram {
    buckets: [AtomicU64; BUCKETS],
    count: AtomicU64,
    sum: AtomicU64,
    max: AtomicU64,
}

impl Default for Histogram {
    fn default() -> Self {
        Histogram::new()
    }
}

impl Histogram {
    /// An empty histogram.
    #[must_use]
    pub const fn new() -> Histogram {
        Histogram {
            buckets: [const { AtomicU64::new(0) }; BUCKETS],
            count: AtomicU64::new(0),
            sum: AtomicU64::new(0),
            max: AtomicU64::new(0),
        }
    }

    /// Record one sample of `ns` nanoseconds.
    pub fn record(&self, ns: u64) {
        self.buckets[bucket_of(ns)].fetch_add(1, Relaxed);
        self.count.fetch_add(1, Relaxed);
        // Wraps after 584 years of recorded time.
        self.sum.fetch_add(ns, Relaxed);
        if ns > self.max.load(Relaxed) {
            self.max.fetch_max(ns, Relaxed);
        }
    }

    /// Record a duration.
    pub fn record_duration(&self, d: Duration) {
        self.record(u64::try_from(d.as_nanos()).unwrap_or(u64::MAX));
    }

    /// A copy of the current figures. Not atomic as a whole: samples
    /// recorded meanwhile may be in some fields and not others.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            buckets: std::array::from_fn(|i| self.buckets[i].load(Relaxed)),
            count: self.count.load(Relaxed),
            sum: self.sum.load(Relaxed),
            max: self.max.load(Relaxed),
        }
    }
}

/// A histogram's figures at one moment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    /// Samples per bucket.
    pub buckets: [u64; BUCKETS],
    /// Number of samples.
    pub count: u64,
    /// Sum of all samples, ns.
    pub sum: u64,
    /// Largest sample, ns.
    pub max: u64,
}

impl Snapshot {
    /// Estimated value at `per_mille`/1000 of the samples (500 for the
    /// median, 990 for p99); 0 when empty.
    #[must_use]
    pub fn quantile(&self, per_mille: u32) -> u64 {
        let total: u64 = self.buckets.iter().sum();
        if total == 0 {
            return 0;
        }
        // The rank of the sample asked for, 1-based: ceil(total * q).
        let q = u128::from(per_mille.min(1000));
        let rank = (u128::from(total) * q).div_ceil(1000).max(1);
        let mut below = 0u128;
        for (b, &n) in self.buckets.iter().enumerate() {
            let n = u128::from(n);
            if n == 0 {
                continue;
            }
            if below + n >= rank {
                // Nothing above the maximum was seen, which matters for the
                // top bucket: 1..=1000 fills [512, 1000], not [512, 1023].
                let (lo, hi) = bucket_bounds(b);
                let hi = hi.min(self.max).max(lo);
                let (lo, hi) = (u128::from(lo), u128::from(hi));
                let est = lo + (hi - lo) * (rank - below) / n;
                return u64::try_from(est).unwrap_or(u64::MAX);
            }
            below += n;
        }
        self.max
    }

    /// Mean in ns; 0 when empty.
    #[must_use]
    pub fn mean(&self) -> u64 {
        self.sum.checked_div(self.count).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_are_powers_of_two() {
        assert_eq!(bucket_of(0), 0);
        assert_eq!(bucket_of(1), 1);
        assert_eq!(bucket_of(2), 2);
        assert_eq!(bucket_of(3), 2);
        assert_eq!(bucket_of(4), 3);
        assert_eq!(bucket_of(1023), 10);
        assert_eq!(bucket_of(1024), 11);
        assert_eq!(bucket_of(1 << 62), 63);
        assert_eq!(bucket_of(u64::MAX), 63);
        for b in 0..BUCKETS {
            let (lo, hi) = bucket_bounds(b);
            assert_eq!(bucket_of(lo), b, "low end of {b}");
            assert_eq!(bucket_of(hi), b, "high end of {b}");
            if b + 1 < BUCKETS {
                assert_eq!(bucket_bounds(b + 1).0, hi + 1, "{b} and {} touch", b + 1);
            }
        }
    }

    #[test]
    fn count_sum_max_and_mean() {
        let h = Histogram::new();
        for v in [10, 20, 30, 1_000_000] {
            h.record(v);
        }
        h.record_duration(Duration::from_micros(2));
        let s = h.snapshot();
        assert_eq!(s.count, 5);
        assert_eq!(s.sum, 1_002_060);
        assert_eq!(s.max, 1_000_000);
        assert_eq!(s.mean(), 200_412);
        assert_eq!(s.buckets.iter().sum::<u64>(), 5);
        assert_eq!(s.buckets[bucket_of(2_000)], 1);
    }

    #[test]
    fn empty_histogram_reports_zero() {
        let s = Histogram::new().snapshot();
        assert_eq!(s.quantile(500), 0);
        assert_eq!(s.quantile(990), 0);
        assert_eq!(s.mean(), 0);
    }

    #[test]
    fn one_value_is_every_quantile() {
        let h = Histogram::new();
        h.record(1000);
        let s = h.snapshot();
        // The bucket is [512, 1023], but nothing above the maximum was
        // seen, so interpolation ends at the value itself.
        for q in [0, 500, 900, 990, 1000] {
            assert_eq!(s.quantile(q), 1000, "q={q}");
        }
    }

    #[test]
    fn uniform_values_interpolate_close_to_the_truth() {
        let h = Histogram::new();
        for v in 1..=1000 {
            h.record(v);
        }
        let s = h.snapshot();
        assert_eq!(s.quantile(500), 500);
        assert_eq!(s.quantile(900), 900);
        assert_eq!(s.quantile(990), 990);
        assert_eq!(s.quantile(1000), 1000);
    }

    #[test]
    fn estimates_stay_in_the_true_values_bucket() {
        // A skewed distribution: many fast samples and a slow tail.
        let h = Histogram::new();
        let mut values = Vec::new();
        for i in 0..10_000u64 {
            let v = if i % 100 == 0 {
                50_000 + i
            } else {
                300 + i % 97
            };
            h.record(v);
            values.push(v);
        }
        values.sort_unstable();
        let s = h.snapshot();
        for q in [500u32, 900, 990, 999] {
            let rank = (values.len() * q as usize).div_ceil(1000);
            let truth = values[rank - 1];
            let est = s.quantile(q);
            assert_eq!(bucket_of(est), bucket_of(truth), "q={q} {est} vs {truth}");
            assert!(est <= s.max);
        }
    }

    #[test]
    fn concurrent_records_are_all_counted() {
        let h = std::sync::Arc::new(Histogram::new());
        let threads: Vec<_> = (0..4)
            .map(|t| {
                let h = std::sync::Arc::clone(&h);
                std::thread::spawn(move || {
                    for i in 0..1000 {
                        h.record(t * 1000 + i);
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        let s = h.snapshot();
        assert_eq!(s.count, 4000);
        assert_eq!(s.max, 3999);
        assert_eq!(s.sum, (0..4000).sum::<u64>());
    }
}

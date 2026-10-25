//! Medians and percentage changes, in integer arithmetic.

use std::time::Duration;

/// The median, smallest and largest of a set of runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Summary {
    /// The middle value; for an even count, the midpoint of the middle two.
    pub median: u64,
    /// The smallest value.
    pub min: u64,
    /// The largest value.
    pub max: u64,
}

/// Summarise `values`; `None` when empty.
#[must_use]
pub fn summarize(values: &[u64]) -> Option<Summary> {
    let mut v = values.to_vec();
    v.sort_unstable();
    let (&min, &max) = (v.first()?, v.last()?);
    let mid = v.len() / 2;
    let median = if v.len() % 2 == 1 {
        v[mid]
    } else {
        v[mid - 1].midpoint(v[mid])
    };
    Some(Summary { median, min, max })
}

/// [`summarize`] for values that may be negative.
#[must_use]
pub fn summarize_signed(values: &[i64]) -> Option<(i64, i64, i64)> {
    let mut v = values.to_vec();
    v.sort_unstable();
    let (&min, &max) = (v.first()?, v.last()?);
    let mid = v.len() / 2;
    let median = if v.len() % 2 == 1 {
        v[mid]
    } else {
        v[mid - 1].midpoint(v[mid])
    };
    Some((median, min, max))
}

/// The median of durations, for the micro-benchmarks.
#[must_use]
pub fn median_duration(samples: &[Duration]) -> Duration {
    let nanos: Vec<u64> = samples
        .iter()
        .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
        .collect();
    summarize(&nanos).map_or(Duration::ZERO, |s| Duration::from_nanos(s.median))
}

/// The change from `old` to `new` in basis points (1/100 of a percent);
/// `None` when `old` is zero.
#[must_use]
pub fn change_bp(old: u64, new: u64) -> Option<i64> {
    if old == 0 {
        return None;
    }
    let d = (i128::from(new) - i128::from(old)) * 10_000 / i128::from(old);
    Some(i64::try_from(d).unwrap_or(if d < 0 { i64::MIN } else { i64::MAX }))
}

/// Basis points as a signed percentage: `+12.34%`.
#[must_use]
pub fn percent(bp: i64) -> String {
    let sign = if bp < 0 { '-' } else { '+' };
    let a = bp.unsigned_abs();
    format!("{sign}{}.{:02}%", a / 100, a % 100)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn medians() {
        assert_eq!(summarize(&[]), None);
        assert_eq!(
            summarize(&[5, 1, 9]),
            Some(Summary {
                median: 5,
                min: 1,
                max: 9
            })
        );
        assert_eq!(summarize(&[4, 1, 3, 2]).unwrap().median, 2);
        assert_eq!(summarize(&[u64::MAX, u64::MAX]).unwrap().median, u64::MAX);
        assert_eq!(summarize_signed(&[-5, 3, -1]), Some((-1, -5, 3)));
        assert_eq!(summarize_signed(&[-3, 0]), Some((-1, -3, 0)));
        let d = [3, 1, 2].map(Duration::from_micros);
        assert_eq!(median_duration(&d), Duration::from_micros(2));
    }

    #[test]
    fn changes() {
        assert_eq!(change_bp(100, 110), Some(1000));
        assert_eq!(change_bp(200, 150), Some(-2500));
        assert_eq!(change_bp(3, 4), Some(3333));
        assert_eq!(change_bp(0, 4), None);
        assert_eq!(percent(1234), "+12.34%");
        assert_eq!(percent(-5), "-0.05%");
        assert_eq!(percent(0), "+0.00%");
    }
}

//! xorshift64* (Vigna, "An experimental exploration of Marsaglia's xorshift
//! generators, scrambled", 2016): small, fast, and the same sequence for
//! the same seed on every platform. Not for anything secret.

/// A seeded pseudo-random number generator.
#[derive(Clone, Debug)]
pub struct Rng(u64);

impl Rng {
    /// A generator for `seed`. The seed goes through one splitmix64 round
    /// so that nearby seeds give unrelated sequences and 0 is a valid seed.
    #[must_use]
    pub fn new(seed: u64) -> Rng {
        let mut z = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        // The xorshift state must not be zero.
        Rng(if z == 0 { 0x9E37_79B9_7F4A_7C15 } else { z })
    }

    /// The next 64 bits.
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// A number in `0..n`, by multiply-and-shift: the bias is at most
    /// `n / 2^64`, nothing a benchmark can see. `n` must not be zero.
    pub fn below(&mut self, n: u64) -> u64 {
        debug_assert!(n > 0);
        let wide = u128::from(self.next_u64()) * u128::from(n);
        // invariant: the high half of a 64x64-bit product fits 64 bits.
        u64::try_from(wide >> 64).unwrap_or(u64::MAX)
    }

    /// [`Rng::below`] for indexes.
    pub fn index(&mut self, n: usize) -> usize {
        usize::try_from(self.below(n as u64)).unwrap_or(0)
    }

    /// A number in `lo..=hi`.
    pub fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.below(hi - lo + 1)
    }

    /// `true` with probability `per_mille / 1000`.
    pub fn chance(&mut self, per_mille: u32) -> bool {
        self.below(1000) < u64::from(per_mille)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_same_sequence() {
        let a: Vec<u64> = {
            let mut r = Rng::new(42);
            (0..5).map(|_| r.next_u64()).collect()
        };
        let b: Vec<u64> = {
            let mut r = Rng::new(42);
            (0..5).map(|_| r.next_u64()).collect()
        };
        assert_eq!(a, b);
        let mut c = Rng::new(43);
        assert_ne!(a[0], c.next_u64());
        // Zero is a usable seed.
        assert_ne!(Rng::new(0).next_u64(), 0);
    }

    #[test]
    fn known_first_value() {
        // Pins the algorithm: a change here changes every benchmark table,
        // and bench/results.csv rows stop being comparable.
        assert_eq!(Rng::new(1).next_u64(), 0x4b46_a55d_f361_1b9b);
    }

    #[test]
    fn ranges_hold_and_cover() {
        let mut r = Rng::new(7);
        let mut seen = [0u32; 10];
        for _ in 0..10_000 {
            let v = r.below(10);
            seen[usize::try_from(v).unwrap()] += 1;
            let w = r.range(5, 8);
            assert!((5..=8).contains(&w));
        }
        // Each of ten buckets gets roughly a tenth.
        for n in seen {
            assert!((800..1200).contains(&n), "{seen:?}");
        }
        let hits = (0..10_000).filter(|_| r.chance(250)).count();
        assert!((2200..2800).contains(&hits), "{hits}");
    }
}

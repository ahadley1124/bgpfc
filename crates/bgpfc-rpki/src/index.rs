//! A prefix-keyed index answering "which stored prefixes cover this one":
//! one hash map per prefix length, keyed by the masked network, and a
//! bitmask of the lengths in use so that a lookup probes only those.
//!
//! Lookups do not allocate. A covering lookup for a route of length `L`
//! costs one hash probe per stored length `<= L`.
//!
//! Implements: RFC 6811 §2 ("Covered": the VRP prefix length is at most
//! the route prefix length, and the addresses agree on every bit the VRP
//! prefix length specifies).

use std::collections::HashMap;
use std::hash::Hash;
use std::net::{Ipv4Addr, Ipv6Addr};

use bgpfc_wire::prefix::Prefix;

/// The address of one family as an unsigned integer, most significant
/// bit first, as `u32::from(Ipv4Addr)` and `u128::from(Ipv6Addr)` give
/// it.
pub(crate) trait Bits: Copy + Eq + Hash {
    /// Address size in bits.
    const WIDTH: u8;

    /// `self` with every bit after the first `len` cleared.
    fn masked(self, len: u8) -> Self;

    /// The prefix `self/len`. `self` has no bits set after `len`.
    fn prefix(self, len: u8) -> Prefix;
}

impl Bits for u32 {
    const WIDTH: u8 = 32;

    fn masked(self, len: u8) -> Self {
        // A shift by the whole width is the empty mask (length 0).
        self & u32::MAX
            .checked_shl(u32::from(Self::WIDTH.saturating_sub(len)))
            .unwrap_or(0)
    }

    fn prefix(self, len: u8) -> Prefix {
        Prefix::V4 {
            addr: Ipv4Addr::from(self),
            len,
        }
    }
}

impl Bits for u128 {
    const WIDTH: u8 = 128;

    fn masked(self, len: u8) -> Self {
        self & u128::MAX
            .checked_shl(u32::from(Self::WIDTH.saturating_sub(len)))
            .unwrap_or(0)
    }

    fn prefix(self, len: u8) -> Prefix {
        Prefix::V6 {
            addr: Ipv6Addr::from(self),
            len,
        }
    }
}

/// The prefix lengths, 0..=128, that have at least one entry.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct LenMask([u64; 3]);

impl LenMask {
    fn set(&mut self, len: u8) {
        if let Some(word) = self.0.get_mut(usize::from(len / 64)) {
            *word |= 1 << (len % 64);
        }
    }

    fn clear(&mut self, len: u8) {
        if let Some(word) = self.0.get_mut(usize::from(len / 64)) {
            *word &= !(1 << (len % 64));
        }
    }

    /// The lengths present that are at most `max`, shortest first.
    fn up_to(self, max: u8) -> Lengths {
        let mut words = self.0;
        for (base, word) in (0u8..).step_by(64).zip(words.iter_mut()) {
            if max < base {
                *word = 0;
            } else if max - base < 63 {
                // Keep bits 0..=max-base.
                *word &= (2u64 << (max - base)) - 1;
            }
        }
        Lengths { words, next: 0 }
    }
}

/// Iterator over the lengths of a [`LenMask`].
struct Lengths {
    words: [u64; 3],
    /// Index of the word being drained.
    next: u8,
}

impl Iterator for Lengths {
    type Item = u8;

    fn next(&mut self) -> Option<u8> {
        while let Some(word) = self.words.get_mut(usize::from(self.next)) {
            if *word != 0 {
                let bit = u8::try_from(word.trailing_zeros()).ok()?;
                *word &= *word - 1;
                // At most 2 * 64 + 63: fits.
                return Some(self.next * 64 + bit);
            }
            self.next += 1;
        }
        None
    }
}

/// Values keyed by prefix, one map per prefix length.
#[derive(Clone, Debug)]
pub(crate) struct LenIndex<K, V> {
    /// Indexed by prefix length, `0..=K::WIDTH`; keys are masked networks.
    by_len: Vec<HashMap<K, V>>,
    /// The lengths whose map is not empty.
    present: LenMask,
}

impl<K: Bits, V> Default for LenIndex<K, V> {
    fn default() -> Self {
        LenIndex {
            by_len: (0..=K::WIDTH).map(|_| HashMap::new()).collect(),
            present: LenMask::default(),
        }
    }
}

impl<K: Bits, V> LenIndex<K, V> {
    /// The value stored for exactly `key/len`.
    pub(crate) fn get(&self, key: K, len: u8) -> Option<&V> {
        self.by_len.get(usize::from(len))?.get(&key)
    }

    /// The value stored for exactly `key/len`, mutably.
    pub(crate) fn get_mut(&mut self, key: K, len: u8) -> Option<&mut V> {
        self.by_len.get_mut(usize::from(len))?.get_mut(&key)
    }

    /// The value for `key/len`, inserting the default if there is none.
    /// `None` only for a length past the address size.
    pub(crate) fn get_or_default(&mut self, key: K, len: u8) -> Option<&mut V>
    where
        V: Default,
    {
        let map = self.by_len.get_mut(usize::from(len))?;
        self.present.set(len);
        Some(map.entry(key).or_default())
    }

    /// Remove the value for `key/len`.
    pub(crate) fn remove(&mut self, key: K, len: u8) -> Option<V> {
        let map = self.by_len.get_mut(usize::from(len))?;
        let value = map.remove(&key)?;
        if map.is_empty() {
            self.present.clear(len);
        }
        Some(value)
    }

    /// The values of every stored prefix that covers `key/len`, shortest
    /// prefix first (RFC 6811 §2, "Covered"). `key` has no bits set after
    /// `len`.
    pub(crate) fn covering(&self, key: K, len: u8) -> impl Iterator<Item = &V> + '_ {
        self.present
            .up_to(len)
            .filter_map(move |l| self.by_len.get(usize::from(l))?.get(&key.masked(l)))
    }

    /// Every entry as `(key, len, value)`, in no particular order.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (K, u8, &V)> + '_ {
        (0u8..)
            .zip(&self.by_len)
            .flat_map(|(len, map)| map.iter().map(move |(key, value)| (*key, len, value)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masking() {
        assert_eq!(0xffff_ffff_u32.masked(0), 0);
        assert_eq!(0xffff_ffff_u32.masked(1), 0x8000_0000);
        assert_eq!(0xffff_ffff_u32.masked(24), 0xffff_ff00);
        assert_eq!(0xffff_ffff_u32.masked(32), 0xffff_ffff);
        assert_eq!(u128::MAX.masked(0), 0);
        assert_eq!(u128::MAX.masked(64), u128::MAX << 64);
        assert_eq!(u128::MAX.masked(127), u128::MAX << 1);
        assert_eq!(u128::MAX.masked(128), u128::MAX);
        assert_eq!(
            0x0a01_0203_u32.prefix(32),
            "10.1.2.3/32".parse::<Prefix>().unwrap()
        );
    }

    #[test]
    fn length_mask_iterates_in_order_up_to_a_bound() {
        let mut mask = LenMask::default();
        for len in [0, 1, 8, 63, 64, 65, 127, 128] {
            mask.set(len);
        }
        let all: Vec<u8> = mask.up_to(128).collect();
        assert_eq!(all, [0, 1, 8, 63, 64, 65, 127, 128]);
        assert_eq!(mask.up_to(0).collect::<Vec<_>>(), [0]);
        assert_eq!(mask.up_to(7).collect::<Vec<_>>(), [0, 1]);
        assert_eq!(mask.up_to(63).collect::<Vec<_>>(), [0, 1, 8, 63]);
        assert_eq!(mask.up_to(64).collect::<Vec<_>>(), [0, 1, 8, 63, 64]);
        assert_eq!(
            mask.up_to(127).collect::<Vec<_>>(),
            [0, 1, 8, 63, 64, 65, 127]
        );
        assert_eq!(mask.up_to(255).count(), 8);
        mask.clear(64);
        mask.clear(0);
        assert_eq!(
            mask.up_to(128).collect::<Vec<_>>(),
            [1, 8, 63, 65, 127, 128]
        );
        assert_eq!(LenMask::default().up_to(128).next(), None);
    }

    #[test]
    fn covering_probes_every_shorter_length() {
        let mut index: LenIndex<u32, &str> = LenIndex::default();
        *index.get_or_default(0, 0).unwrap() = "default";
        *index.get_or_default(0x0a00_0000, 8).unwrap() = "10/8";
        *index.get_or_default(0x0a01_0000, 16).unwrap() = "10.1/16";
        *index.get_or_default(0x0a02_0000, 16).unwrap() = "10.2/16";
        *index.get_or_default(0x0a01_0200, 24).unwrap() = "10.1.2/24";
        let found: Vec<&str> = index.covering(0x0a01_0200, 24).copied().collect();
        assert_eq!(found, ["default", "10/8", "10.1/16", "10.1.2/24"]);
        let found: Vec<&str> = index.covering(0x0a01_0000, 16).copied().collect();
        assert_eq!(found, ["default", "10/8", "10.1/16"]);
        let found: Vec<&str> = index.covering(0x0b00_0000, 8).copied().collect();
        assert_eq!(found, ["default"]);
        // Removing the last entry of a length stops it being probed.
        assert_eq!(index.remove(0, 0), Some("default"));
        assert_eq!(index.remove(0, 0), None);
        assert_eq!(index.covering(0x0b00_0000, 8).count(), 0);
        assert_eq!(index.remove(0x0a01_0000, 16), Some("10.1/16"));
        assert_eq!(index.covering(0x0a02_0000, 16).count(), 2);
        // Lengths past the address size are refused, not a panic.
        assert!(index.get_or_default(0, 33).is_none());
        assert!(index.get(0, 200).is_none());
        assert!(index.remove(0, 33).is_none());
        let mut entries: Vec<(u32, u8, &str)> = index.iter().map(|(k, l, v)| (k, l, *v)).collect();
        entries.sort_unstable();
        assert_eq!(
            entries,
            [
                (0x0a00_0000, 8, "10/8"),
                (0x0a01_0200, 24, "10.1.2/24"),
                (0x0a02_0000, 16, "10.2/16"),
            ]
        );
    }

    #[test]
    fn covering_handles_host_routes_of_both_families() {
        let mut index: LenIndex<u128, ()> = LenIndex::default();
        let host = 0x2001_0db8_0000_0000_0000_0000_0000_0001_u128;
        index.get_or_default(host, 128).unwrap();
        index.get_or_default(host.masked(127), 127).unwrap();
        assert_eq!(index.covering(host, 128).count(), 2);
        assert_eq!(index.covering(host.masked(127), 127).count(), 1);
        assert_eq!(index.covering(host ^ 1, 128).count(), 1);
    }
}

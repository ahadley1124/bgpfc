//! A synthetic IPv4 table, the same for the same options and seed.
//!
//! Prefix lengths follow the shape of the public IPv4 table: about 62 %
//! /24, a third between /23 and /16, and a few shorter ones. Each route
//! takes one of `attr_sets` attribute sets, every set with its own
//! `AS_PATH` of 2 to 8 ASes; the choice is skewed (`i = u²/M` for uniform
//! `u`), so a few paths carry thousands of prefixes and most carry a few,
//! as in a real table. ORIGIN, MED, `LOCAL_PREF` (internal sessions only:
//! RFC 4271 §5.1.5) and communities vary between sets.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};

use bgpfc_wire::as_path::AsPath;
use bgpfc_wire::attribute::{Origin, PathAttribute};
use bgpfc_wire::community::{Community, LargeCommunity};
use bgpfc_wire::mp::NextHop;
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::Asn;

use crate::rng::Rng;
use crate::table::{AttrSet, Route, Table};

/// What to generate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SynthOpts {
    /// Number of distinct prefixes.
    pub prefixes: usize,
    /// Number of distinct attribute sets (and `AS_PATH`s).
    pub attr_sets: usize,
    /// PRNG seed.
    pub seed: u64,
    /// The sending speaker's AS: first on every path of an external
    /// session (RFC 4271 §5.1.2).
    pub local_as: Asn,
    /// The receiver's AS, never put on a path (it would be an AS loop,
    /// RFC 4271 §9.1.2).
    pub peer_as: Asn,
    /// An internal session: no AS prepended, `LOCAL_PREF` sent.
    pub internal: bool,
    /// Next hops to draw from.
    pub next_hops: Vec<Ipv4Addr>,
}

impl SynthOpts {
    /// A million prefixes over 50 000 attribute sets, as an external peer.
    #[must_use]
    pub fn new(local_as: Asn, peer_as: Asn) -> SynthOpts {
        SynthOpts {
            prefixes: 1_000_000,
            attr_sets: 50_000,
            seed: 1,
            local_as,
            peer_as,
            internal: local_as == peer_as,
            next_hops: (1..=4).map(|i| Ipv4Addr::new(192, 0, 2, i)).collect(),
        }
    }
}

/// Prefix lengths and their weight per 10 000 prefixes.
const LENGTHS: [(u8, u32); 17] = [
    (24, 6210),
    (23, 1000),
    (22, 1150),
    (21, 450),
    (20, 420),
    (19, 270),
    (18, 130),
    (17, 90),
    (16, 150),
    (15, 40),
    (14, 30),
    (13, 20),
    (12, 15),
    (11, 10),
    (10, 8),
    (9, 5),
    (8, 2),
];

/// Tries before a length that has run out of free prefixes is replaced by
/// /24 (there are only 221 usable /8s).
const TRIES: u32 = 64;

/// Build the table.
///
/// # Panics
/// If `next_hops` is empty, or more prefixes are asked for than the unicast
/// IPv4 space holds as /24s and shorter (about 14 million).
#[must_use]
pub fn generate(o: &SynthOpts) -> Table {
    assert!(!o.next_hops.is_empty(), "no next hops to draw from");
    assert!(o.prefixes <= 14_000_000, "too many prefixes for IPv4");
    let mut rng = Rng::new(o.seed);
    let sets = attribute_sets(o, &mut rng);
    let mut seen: HashSet<Prefix> = HashSet::with_capacity(o.prefixes);
    let mut routes = Vec::with_capacity(o.prefixes);
    let m = sets.len() as u64;
    while routes.len() < o.prefixes {
        let prefix = random_prefix(&mut rng, &seen);
        seen.insert(prefix);
        routes.push(Route {
            set: skewed(&mut rng, m),
            prefix,
        });
    }
    Table { sets, routes }
}

/// `u² / m` for `u` uniform in `0..m`, computed at 2^16 times the
/// resolution: with whole `u`, consecutive values land two apart near the
/// top and half the high indexes could never be drawn.
fn skewed(rng: &mut Rng, m: u64) -> u32 {
    const FINE: u32 = 16;
    let u = u128::from(rng.below(m << FINE));
    let i = u * u / (u128::from(m) << (2 * FINE));
    u32::try_from(i).unwrap_or(0)
}

fn random_prefix(rng: &mut Rng, seen: &HashSet<Prefix>) -> Prefix {
    let pick = u32::try_from(rng.below(10_000)).unwrap_or(0);
    let mut acc = 0;
    let mut len = 24;
    for (l, w) in LENGTHS {
        acc += w;
        if pick < acc {
            len = l;
            break;
        }
    }
    loop {
        for _ in 0..TRIES {
            if let Some(p) = unicast(rng, len)
                && !seen.contains(&p)
            {
                return p;
            }
        }
        // This length is (nearly) used up.
        len = 24;
    }
}

/// A random prefix of `len` in 1.0.0.0/8–223.0.0.0/8 outside 10/8 and
/// 127/8, or `None` if the draw fell outside.
fn unicast(rng: &mut Rng, len: u8) -> Option<Prefix> {
    let a = u32::try_from(rng.below(1 << 32)).unwrap_or(0);
    let first = a >> 24;
    if first == 0 || first == 10 || first == 127 || first >= 224 {
        return None;
    }
    Prefix::new(IpAddr::V4(Ipv4Addr::from(a)), len)
}

fn attribute_sets(o: &SynthOpts, rng: &mut Rng) -> Vec<AttrSet> {
    let mut paths: HashSet<Vec<u32>> = HashSet::with_capacity(o.attr_sets);
    let mut sets = Vec::with_capacity(o.attr_sets);
    while sets.len() < o.attr_sets.max(1) {
        let len = rng.range(2, 8);
        let mut path = Vec::new();
        if !o.internal {
            path.push(o.local_as.0);
        }
        while (path.len() as u64) < len {
            path.push(random_asn(rng, o.peer_as));
        }
        if !paths.insert(path.clone()) {
            continue;
        }
        sets.push(attribute_set(o, rng, &path));
    }
    sets
}

/// A public ASN: mostly two-octet, a fifth four-octet; never the
/// receiver's, AS 0 (RFC 7607), `AS_TRANS` (RFC 6793) or private.
fn random_asn(rng: &mut Rng, peer_as: Asn) -> u32 {
    loop {
        let asn = if rng.chance(200) {
            u32::try_from(rng.range(131_072, 399_999)).unwrap_or(131_072)
        } else {
            u32::try_from(rng.range(1, 64_495)).unwrap_or(1)
        };
        if asn != peer_as.0 && asn != u32::from(Asn::TRANS_TWO_OCTET) {
            return asn;
        }
    }
}

fn attribute_set(o: &SynthOpts, rng: &mut Rng, path: &[u32]) -> AttrSet {
    let origin = match rng.below(100) {
        0..80 => Origin::Igp,
        80..95 => Origin::Incomplete,
        _ => Origin::Egp,
    };
    let asns: Vec<Asn> = path.iter().map(|a| Asn(*a)).collect();
    let mut attributes = vec![
        PathAttribute::Origin(origin),
        PathAttribute::AsPath(AsPath::sequence(&asns)),
    ];
    if rng.chance(300) {
        attributes.push(PathAttribute::MultiExitDisc(
            u32::try_from(rng.below(1000)).unwrap_or(0),
        ));
    }
    if o.internal {
        let lp = [100, 100, 200, 50][rng.index(4)];
        attributes.push(PathAttribute::LocalPref(lp));
    }
    if rng.chance(400) {
        // Communities tagged with a two-octet AS from the path.
        let tag = path
            .iter()
            .copied()
            .find_map(|a| u16::try_from(a).ok())
            .unwrap_or(65_000);
        let n = rng.range(1, 6);
        let mut cs: Vec<Community> = (0..n)
            .map(|_| Community::new(tag, u16::try_from(rng.below(1000)).unwrap_or(0)))
            .collect();
        cs.sort_unstable();
        cs.dedup();
        attributes.push(PathAttribute::Communities(cs));
    }
    if rng.chance(50) {
        attributes.push(PathAttribute::LargeCommunities(vec![LargeCommunity {
            global: path[path.len() - 1],
            local1: u32::try_from(rng.below(100)).unwrap_or(0),
            local2: u32::try_from(rng.below(100)).unwrap_or(0),
        }]));
    }
    let next_hop = NextHop::Ipv4(o.next_hops[rng.index(o.next_hops.len())]);
    AttrSet {
        attributes,
        next_hop,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(prefixes: usize, attr_sets: usize) -> SynthOpts {
        SynthOpts {
            prefixes,
            attr_sets,
            ..SynthOpts::new(Asn(65_001), Asn(65_000))
        }
    }

    #[test]
    fn same_seed_same_table() {
        let a = generate(&opts(2000, 100));
        let b = generate(&opts(2000, 100));
        assert_eq!(a, b);
        let c = generate(&SynthOpts {
            seed: 2,
            ..opts(2000, 100)
        });
        assert_ne!(a.routes, c.routes);
    }

    #[test]
    fn prefixes_are_unique_and_shaped_like_the_internet() {
        let t = generate(&opts(20_000, 500));
        assert_eq!(t.routes.len(), 20_000);
        let unique: HashSet<_> = t.routes.iter().map(|r| r.prefix).collect();
        assert_eq!(unique.len(), 20_000);
        let slash24 = t
            .routes
            .iter()
            .filter(|r| r.prefix.prefix_len() == 24)
            .count();
        let mid = t
            .routes
            .iter()
            .filter(|r| (16..=23).contains(&r.prefix.prefix_len()))
            .count();
        let short = t
            .routes
            .iter()
            .filter(|r| r.prefix.prefix_len() < 16)
            .count();
        assert!((11_500..13_300).contains(&slash24), "{slash24}");
        assert!((6_500..8_000).contains(&mid), "{mid}");
        assert!((100..800).contains(&short), "{short}");
        for r in &t.routes {
            let IpAddr::V4(a) = r.prefix.addr() else {
                panic!("not IPv4");
            };
            let first = a.octets()[0];
            assert!(
                first != 0 && first != 10 && first != 127 && first < 224,
                "{a}"
            );
        }
    }

    #[test]
    fn attribute_sets_have_distinct_paths_from_our_as() {
        let o = opts(5000, 300);
        let t = generate(&o);
        assert_eq!(t.sets.len(), 300);
        let mut paths = HashSet::new();
        for s in &t.sets {
            let PathAttribute::AsPath(p) = &s.attributes[1] else {
                panic!("AS_PATH second");
            };
            assert_eq!(p.first_asn(), Some(o.local_as));
            assert!(!p.contains(o.peer_as));
            assert!((2..=8).contains(&p.hop_count()), "{}", p.hop_count());
            assert!(paths.insert(p.clone()));
            assert!(
                !s.attributes
                    .iter()
                    .any(|a| matches!(a, PathAttribute::LocalPref(_)))
            );
        }
        // Skewed but complete: the first sets carry the most routes and
        // nearly all sets are used.
        let mut per_set = vec![0usize; t.sets.len()];
        for r in &t.routes {
            per_set[r.set as usize] += 1;
        }
        assert!(
            per_set[0] > per_set[299] * 5,
            "{} {}",
            per_set[0],
            per_set[299]
        );
        assert!(t.used_sets() > 295, "{}", t.used_sets());
    }

    #[test]
    fn internal_sessions_get_local_pref_and_no_prepend() {
        let t = generate(&SynthOpts::new(Asn(65_000), Asn(65_000)).with(100, 20));
        for s in &t.sets {
            assert!(
                s.attributes
                    .iter()
                    .any(|a| matches!(a, PathAttribute::LocalPref(_)))
            );
            let PathAttribute::AsPath(p) = &s.attributes[1] else {
                panic!("AS_PATH second");
            };
            assert!(!p.contains(Asn(65_000)));
        }
    }

    impl SynthOpts {
        fn with(self, prefixes: usize, attr_sets: usize) -> SynthOpts {
            SynthOpts {
                prefixes,
                attr_sets,
                ..self
            }
        }
    }
}

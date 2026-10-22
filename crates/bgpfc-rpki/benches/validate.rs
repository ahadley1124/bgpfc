//! Route origin validation at full-table scale (AGENTS.md §5, benches
//! row): a VRP set the size of the global RPKI (about 500k VRPs, four
//! IPv4 to one IPv6), validating routes against it, building and cloning
//! it as an RTR client publishing snapshots would, and the diff that
//! decides which routes to validate again. Set `BGPFC_BENCH_VRPS` to
//! change the set size.

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bgpfc_rpki::{AffectedPrefixes, RouteOrigin, Vrp, VrpSet};
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::Asn;
use criterion::{BatchSize, Criterion, Throughput};

/// Deterministic xorshift64, so that runs compare.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    /// A value in `0..n`.
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn len(&mut self, from: u8, to: u8) -> u8 {
        from + u8::try_from(self.below(u64::from(to - from) + 1)).unwrap()
    }
}

/// A VRP shaped like those of the global RPKI: IPv4 /12 to /24 or IPv6
/// /19 to /48, most with max length equal to the prefix length, origins
/// from a pool of 60k ASes.
fn random_vrp(rng: &mut Rng, v6: bool) -> Vrp {
    let (addr, len, bits) = if v6 {
        let addr = 0x2_u128 << 124 | u128::from(rng.next()) << 60;
        (IpAddr::V6(Ipv6Addr::from(addr)), rng.len(19, 48), 48)
    } else {
        let addr = u32::try_from(rng.below(1 << 32)).unwrap();
        (IpAddr::V4(Ipv4Addr::from(addr)), rng.len(12, 24), 24)
    };
    let max_len = if rng.below(10) < 7 {
        len
    } else {
        rng.len(len, bits)
    };
    Vrp::new(Prefix::new(addr, len).unwrap(), max_len, random_asn(rng)).unwrap()
}

fn random_asn(rng: &mut Rng) -> Asn {
    Asn(1 + u32::try_from(rng.below(60_000)).unwrap())
}

/// `n` VRPs, four IPv4 to one IPv6.
fn vrps(n: u64, rng: &mut Rng) -> Vec<Vrp> {
    (0..n).map(|i| random_vrp(rng, i % 5 == 4)).collect()
}

/// `n` routes: half are authorised by one of `vrps` (Valid), half are
/// random prefixes and origins (mostly `NotFound` or Invalid).
fn routes(n: u64, vrps: &[Vrp], rng: &mut Rng) -> Vec<(Prefix, RouteOrigin)> {
    let pool = u64::try_from(vrps.len()).unwrap();
    (0..n)
        .map(|i| {
            if i % 2 == 0 {
                let vrp = vrps[usize::try_from(rng.below(pool)).unwrap()];
                let len = rng.len(vrp.prefix().prefix_len(), vrp.max_len());
                let prefix = Prefix::new(vrp.prefix().addr(), len).unwrap();
                (prefix, RouteOrigin::As(vrp.asn()))
            } else {
                let prefix = random_vrp(rng, i % 10 == 9).prefix();
                (prefix, RouteOrigin::As(random_asn(rng)))
            }
        })
        .collect()
}

fn bench(c: &mut Criterion) {
    let n: u64 = std::env::var("BGPFC_BENCH_VRPS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(500_000);
    let mut rng = Rng(0x5eed_1234_abcd_ef01);
    let list = vrps(n, &mut rng);
    let set: VrpSet = list.iter().copied().collect();
    let batch = routes(10_000, &list, &mut rng);
    // One percent of the VRPs replaced, as between two RTR serials.
    let churn = n / 100;
    let mut changed = set.clone();
    for vrp in list.iter().take(usize::try_from(churn).unwrap()) {
        changed.remove(*vrp);
    }
    let added = vrps(churn, &mut rng);
    changed.extend(added.iter().copied());

    let mut group = c.benchmark_group("rpki");
    group.sample_size(10);
    group.throughput(Throughput::Elements(10_000));
    group.bench_function(format!("validate_10000_routes_against_{n}_vrps"), |b| {
        b.iter(|| {
            for (prefix, origin) in &batch {
                black_box(set.validate(*prefix, *origin));
            }
        });
    });
    group.throughput(Throughput::Elements(n));
    group.bench_function(format!("build_{n}_vrps"), |b| {
        b.iter(|| list.iter().copied().collect::<VrpSet>());
    });
    group.bench_function(format!("clone_{n}_vrps"), |b| {
        b.iter(|| black_box(set.clone()));
    });
    group.bench_function(
        format!("affected_between_{n}_vrps_one_percent_changed"),
        |b| {
            b.iter(|| black_box(AffectedPrefixes::between(&set, &changed)));
        },
    );
    group.throughput(Throughput::Elements(churn * 2));
    group.bench_function(
        format!("apply_and_track_{churn}_withdrawals_and_announcements"),
        |b| {
            b.iter_batched(
                || set.clone(),
                |mut working| {
                    let mut delta = Vec::new();
                    for vrp in list.iter().take(usize::try_from(churn).unwrap()) {
                        if working.remove(*vrp) {
                            delta.push(*vrp);
                        }
                    }
                    for vrp in &added {
                        if working.insert(*vrp) {
                            delta.push(*vrp);
                        }
                    }
                    // Returned so that the set is dropped outside the timing.
                    (AffectedPrefixes::from_vrps(delta), working)
                },
                BatchSize::LargeInput,
            );
        },
    );
    group.finish();
}

/// Entry point; `criterion_main!` is not used because its generated items
/// lack docs and the workspace warns on that.
fn main() {
    let mut c = Criterion::default().configure_from_args();
    bench(&mut c);
    c.final_summary();
}

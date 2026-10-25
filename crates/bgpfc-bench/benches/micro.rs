//! In-process micro-benchmarks with nothing but std (`docs/PROFILING.md`):
//! UPDATE and attribute decoding, RIB insert, withdraw and peer down, the
//! decision process, attribute interning, and the clock read every
//! profiling span costs.
//!
//! `cargo bench -p bgpfc-bench --bench micro [NAME-FILTER]`
//!
//! Each benchmark runs for a warm-up, then takes 15 samples; a sample times
//! a batch of operations (setup excluded) and divides. The median per
//! operation is the figure to compare; min and max show the spread.

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bgpfc_bench::pack::Packer;
use bgpfc_bench::stats::summarize;
use bgpfc_bench::synth::{SynthOpts, generate};
use bgpfc_bench::table::Table;
use bgpfc_rib::decision::{Candidate, Neighbor, best};
use bgpfc_rib::{Interner, PathAttrs, PeerInfo, Rib};
use bgpfc_wire::header::HEADER_LEN;
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::{AddressFamily, Asn, RouterId};
use bgpfc_wire::update::{DecodeContext, DecodedUpdate, PeerKind, UpdateMessage};

const SAMPLES: usize = 15;
const WARMUP: Duration = Duration::from_millis(300);

/// Run `sample` until the warm-up has passed, then [`SAMPLES`] times; each
/// call returns the time its measured part took and how many operations
/// that was. Prints ns per operation.
fn bench(filter: Option<&str>, name: &str, mut sample: impl FnMut() -> (Duration, u64)) {
    if filter.is_some_and(|f| !name.contains(f)) {
        return;
    }
    let start = Instant::now();
    while start.elapsed() < WARMUP {
        black_box(sample());
    }
    let mut ps_per_op = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let (took, ops) = sample();
        let ps = took.as_nanos() * 1000 / u128::from(ops.max(1));
        ps_per_op.push(u64::try_from(ps).unwrap_or(u64::MAX));
    }
    let Some(s) = summarize(&ps_per_op) else {
        return;
    };
    println!(
        "{name:36} {:>11} {:>11} {:>11}",
        ns(s.median),
        ns(s.min),
        ns(s.max)
    );
}

/// Time all of `op`, which returns how many operations it did.
fn timed(mut op: impl FnMut() -> u64) -> impl FnMut() -> (Duration, u64) {
    move || {
        let t = Instant::now();
        let n = op();
        (t.elapsed(), n)
    }
}

/// Picoseconds as nanoseconds with one decimal.
fn ns(ps: u64) -> String {
    format!("{}.{}", ps / 1000, ps % 1000 / 100)
}

const CTX: DecodeContext = DecodeContext {
    four_octet_as: true,
    peer: PeerKind::External,
    allow_as_set: false,
};

fn peer() -> PeerInfo {
    PeerInfo {
        addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        local_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 254)),
        remote_as: Asn(65_001),
        router_id: RouterId::from(Ipv4Addr::new(10, 0, 0, 1)),
        kind: PeerKind::External,
        families: vec![AddressFamily::IPV4_UNICAST],
        four_octet_as: true,
        extended_messages: false,
    }
}

fn table(prefixes: usize, attr_sets: usize) -> Table {
    generate(&SynthOpts {
        prefixes,
        attr_sets,
        ..SynthOpts::new(Asn(65_001), Asn(65_000))
    })
}

fn decode_all(messages: &[Vec<u8>]) -> Vec<DecodedUpdate> {
    messages
        .iter()
        .map(|m| UpdateMessage::decode(&m[HEADER_LEN..], &CTX).expect("own encoding decodes"))
        .collect()
}

/// A RIB holding `adds` from [`peer`].
fn loaded(adds: &[DecodedUpdate]) -> Rib {
    let mut rib = Rib::new(Asn(65_000));
    let mut out = Vec::new();
    rib.peer_up(peer(), &mut out);
    for u in adds {
        rib.update(peer().addr, u, &mut out);
        out.clear();
    }
    rib
}

fn main() {
    // `cargo bench` passes `--bench`; anything else is a name filter.
    let filter = std::env::args().skip(1).find(|a| !a.starts_with("--"));
    let filter = filter.as_deref();
    println!(
        "{:36} {:>11} {:>11} {:>11}   ns per operation, median of {SAMPLES}",
        "benchmark", "median", "min", "max"
    );
    bench(
        filter,
        "instant_now",
        timed(|| {
            for _ in 0..10_000 {
                black_box(Instant::now());
            }
            10_000
        }),
    );
    decoding(filter);
    let adds = rib_work(filter);
    decision(filter, &adds[0]);
}

fn decoding(filter: Option<&str>) {
    let packer = Packer::new(true, false);
    // One prefix: the decode is mostly the attribute section.
    let one = packer.table(&table(1, 1)).expect("packs");
    let one = one[0][HEADER_LEN..].to_vec();
    bench(
        filter,
        "update_decode_1_prefix",
        timed(|| {
            for _ in 0..10_000 {
                black_box(UpdateMessage::decode(black_box(&one), &CTX).is_ok());
            }
            10_000
        }),
    );
    // A full 4096-octet message, per prefix.
    let full = packer.table(&table(5000, 1)).expect("packs");
    let full = full[0][HEADER_LEN..].to_vec();
    let per_message = UpdateMessage::decode(&full, &CTX)
        .expect("own encoding decodes")
        .message
        .nlri
        .len() as u64;
    bench(
        filter,
        "update_decode_full_message_per_prefix",
        timed(|| {
            for _ in 0..100 {
                black_box(UpdateMessage::decode(black_box(&full), &CTX).is_ok());
            }
            100 * per_message
        }),
    );
}

/// RIB work per route: 100 000 routes over 5 000 attribute sets from one
/// external peer, as packed UPDATEs. Returns the UPDATEs.
fn rib_work(filter: Option<&str>) -> Vec<DecodedUpdate> {
    let packer = Packer::new(true, false);
    let t = table(100_000, 5_000);
    let adds = decode_all(&packer.table(&t).expect("packs"));
    let prefixes: Vec<Prefix> = t.routes.iter().map(|r| r.prefix).collect();
    let mut withdrawn = Vec::new();
    packer
        .withdraw(AddressFamily::IPV4_UNICAST, &prefixes, &mut withdrawn)
        .expect("packs");
    let dels = decode_all(&withdrawn);
    let routes = t.routes.len() as u64;
    let from = peer().addr;
    bench(filter, "rib_insert_per_route_100k", || {
        let mut rib = Rib::new(Asn(65_000));
        let mut out = Vec::new();
        rib.peer_up(peer(), &mut out);
        let t = Instant::now();
        for u in &adds {
            rib.update(from, u, &mut out);
            black_box(&out);
            out.clear();
        }
        (t.elapsed(), routes)
    });
    bench(filter, "rib_withdraw_per_route_100k", || {
        let mut rib = loaded(&adds);
        let mut out = Vec::new();
        let t = Instant::now();
        for u in &dels {
            rib.update(from, u, &mut out);
            black_box(&out);
            out.clear();
        }
        (t.elapsed(), routes)
    });
    // A second peer coming up is sent the whole Loc-RIB (RFC 4271 §9.2):
    // export and UPDATE packing for every route.
    bench(filter, "rib_peer_up_send_per_route_100k", || {
        let mut rib = loaded(&adds);
        let mut out = Vec::new();
        let second = PeerInfo {
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            remote_as: Asn(65_002),
            router_id: RouterId::from(Ipv4Addr::new(10, 0, 0, 2)),
            ..peer()
        };
        let t = Instant::now();
        rib.peer_up(second, &mut out);
        black_box(&out);
        (t.elapsed(), routes)
    });
    bench(filter, "rib_peer_down_per_route_100k", || {
        let mut rib = loaded(&adds);
        let mut out = Vec::new();
        let t = Instant::now();
        rib.peer_down(from, &mut out);
        black_box(&out);
        (t.elapsed(), routes)
    });
    adds
}

/// The decision process over n candidates that only the BGP Identifier
/// tells apart (RFC 4271 §9.1.2.2 f), so every step runs; and interning
/// an attribute set already held, as each UPDATE does once per family.
fn decision(filter: Option<&str>, update: &DecodedUpdate) {
    let attrs = Arc::new(
        PathAttrs::from_update(&update.message, AddressFamily::IPV4_UNICAST)
            .expect("the synthetic UPDATE has a next hop"),
    );
    for n in [1u8, 2, 4, 8, 16] {
        let neighbors: Vec<Neighbor> = (1..=n)
            .map(|i| Neighbor {
                addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, i)),
                kind: PeerKind::External,
                router_id: u32::from(i),
                remote_as: Asn(65_001),
            })
            .collect();
        bench(
            filter,
            &format!("best_path_{n}_candidates"),
            timed(|| {
                for _ in 0..10_000 {
                    let neighbors = black_box(&neighbors);
                    black_box(best(neighbors.len(), |i| Candidate {
                        from: neighbors[i],
                        attrs: &attrs,
                    }));
                }
                10_000
            }),
        );
    }
    let mut interner = Interner::default();
    let held = (*attrs).clone();
    let _ = interner.intern(held.clone());
    bench(
        filter,
        "intern_existing_attribute_set",
        timed(|| {
            for _ in 0..10_000 {
                black_box(interner.intern(black_box(held.clone())));
            }
            10_000
        }),
    );
}

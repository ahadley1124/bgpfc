//! RIB insert and withdraw at scale (AGENTS.md §5, benches row), from one
//! peer and from two that send the same table, as a multi-homed network
//! has it, churn
//! under the RFC 4271 §9.2.1.1 advertisement interval, and validating
//! routes again when the validation source changes (RFC 6811 §4). The
//! default sizes are a fraction of a full table so the bench finishes
//! quickly; set `BGPFC_BENCH_ROUTES` to 1250000 for the full-table figure.
//! The `add_path` group is the cost of RFC 7911: three paths to every
//! prefix from one peer, and the same sent to a peer that takes them.

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bgpfc_rib::{Output, PathLimit, PeerInfo, Rib};
use bgpfc_rpki::{AffectedPrefixes, ValidationChange, ValidationSource, Vrp, VrpSet};
use bgpfc_wire::as_path::AsPath;
use bgpfc_wire::attribute::{Origin, PathAttribute};
use bgpfc_wire::mp::{MpReach, NextHop};
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::{AddressFamily, Asn, PathId, RouterId};
use bgpfc_wire::update::{DecodedUpdate, PathIds, PeerKind, UpdateMessage};
use criterion::Criterion;

/// Run one RIB input and collect what it produced.
fn outputs(input: impl FnOnce(&mut Vec<Output>)) -> Vec<Output> {
    let mut out = Vec::new();
    input(&mut out);
    out
}

/// Give the RIB `updates` from `from` at `now`, with one output buffer
/// for them all, as the daemon does.
fn feed<'a>(
    rib: &mut Rib,
    from: IpAddr,
    updates: impl IntoIterator<Item = &'a DecodedUpdate>,
    now: Instant,
    out: &mut Vec<Output>,
) {
    for u in updates {
        rib.update(from, u, now, out);
        black_box(&*out);
        out.clear();
    }
}

/// An external peer with no advertisement interval.
fn peer(i: u8) -> PeerInfo {
    PeerInfo {
        addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, i)),
        local_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 254)),
        remote_as: Asn(65_000 + u32::from(i)),
        router_id: RouterId::new(u32::from(i)).unwrap(),
        kind: PeerKind::External,
        families: vec![AddressFamily::IPV4_UNICAST, AddressFamily::IPV6_UNICAST],
        receive_families: vec![AddressFamily::IPV4_UNICAST, AddressFamily::IPV6_UNICAST],
        four_octet_as: true,
        extended_messages: false,
        extended_next_hop: Vec::new(),
        advertisement_interval: Duration::ZERO,
        prefix_limits: Vec::new(),
        add_path_receive: Vec::new(),
        add_path_send: Vec::new(),
    }
}

/// An external peer with the RFC 4271 §10 default interval of 30 s.
fn paced_peer(i: u8) -> PeerInfo {
    PeerInfo {
        advertisement_interval: Duration::from_secs(30),
        prefix_limits: Vec::new(),
        ..peer(i)
    }
}

/// `n` routes in UPDATEs of 200 prefixes, with a different `AS_PATH` every
/// 50 messages so attribute sets are shared but not identical. `origin`
/// is the last AS of every path, so a second set with another one changes
/// every route.
fn updates(n: u32, v6: bool, peer_as: u32, origin: u32) -> Vec<DecodedUpdate> {
    let mut out = Vec::new();
    let mut i = 0u32;
    while i < n {
        let mut message = UpdateMessage::default();
        let path = AsPath::sequence(&[Asn(peer_as), Asn(1 + (i / 10_000) % 500), Asn(origin)]);
        message.attributes = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(path),
        ];
        let nlri: Vec<Prefix> = (i..(i + 200).min(n))
            .map(|k| {
                if v6 {
                    // One /48 each, from 2001:db8::/32 on: the third group
                    // takes the low 16 bits of `k`, the second the rest.
                    let [_, hi, mid, lo] = k.to_be_bytes();
                    Prefix::new(
                        IpAddr::V6(Ipv6Addr::new(
                            0x2001,
                            0xdb8 + u16::from(hi),
                            u16::from_be_bytes([mid, lo]),
                            0,
                            0,
                            0,
                            0,
                            0,
                        )),
                        48,
                    )
                    .unwrap()
                } else {
                    Prefix::new(IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + (k << 8))), 24).unwrap()
                }
            })
            .collect();
        if v6 {
            message.mp_reach = Some(MpReach {
                family: AddressFamily::IPV6_UNICAST,
                next_hop: NextHop::Ipv6 {
                    global: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                    link_local: None,
                },
                nlri,
            });
        } else {
            message
                .attributes
                .push(PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 1)));
            message.nlri = nlri;
        }
        out.push(DecodedUpdate {
            message,
            treated_as_withdraw: None,
            discarded: Vec::new(),
            disabled: Vec::new(),
        });
        i += 200;
    }
    out
}

fn bench(c: &mut Criterion) {
    let routes: u32 = std::env::var("BGPFC_BENCH_ROUTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100_000);
    let v4 = updates(routes * 4 / 5, false, 65_001, 7);
    let v6 = updates(routes / 5, true, 65_001, 7);
    let mut group = c.benchmark_group("rib");
    group.sample_size(10);
    group.bench_function(format!("insert_{routes}_from_one_peer_to_one_peer"), |b| {
        b.iter(|| {
            let now = Instant::now();
            let mut rib = Rib::new(Asn(65_000));
            let mut out = Vec::new();
            outputs(|o| rib.peer_up(peer(1), now, o));
            outputs(|o| rib.peer_up(peer(2), now, o));
            feed(&mut rib, peer(1).addr, v4.iter().chain(&v6), now, &mut out);
            rib
        });
    });
    // Every destination heard from two peers: what the RIB keeps per
    // destination beyond the first route shows here and not above.
    let v4_other = updates(routes * 4 / 5, false, 65_003, 7);
    let v6_other = updates(routes / 5, true, 65_003, 7);
    group.bench_function(format!("insert_{routes}_from_two_peers_to_one_peer"), |b| {
        b.iter(|| {
            let now = Instant::now();
            let mut rib = Rib::new(Asn(65_000));
            let mut out = Vec::new();
            outputs(|o| rib.peer_up(peer(1), now, o));
            outputs(|o| rib.peer_up(peer(2), now, o));
            outputs(|o| rib.peer_up(peer(3), now, o));
            feed(&mut rib, peer(1).addr, v4.iter().chain(&v6), now, &mut out);
            feed(
                &mut rib,
                peer(3).addr,
                v4_other.iter().chain(&v6_other),
                now,
                &mut out,
            );
            rib
        });
    });
    group.bench_function(format!("withdraw_{routes}_on_peer_down"), |b| {
        b.iter_batched(
            || {
                let now = Instant::now();
                let mut rib = Rib::new(Asn(65_000));
                let mut out = Vec::new();
                outputs(|o| rib.peer_up(peer(1), now, o));
                outputs(|o| rib.peer_up(peer(2), now, o));
                feed(&mut rib, peer(1).addr, v4.iter().chain(&v6), now, &mut out);
                rib
            },
            |mut rib| black_box(outputs(|o| rib.peer_down(peer(1).addr, Instant::now(), o))),
            criterion::BatchSize::LargeInput,
        );
    });
    // RFC 4271 §9.2.1.1 at scale: every route was just advertised to a
    // peer with a 30 s interval, then changes three times inside it. The
    // changes are held (one wake-up per destination), and one flush at
    // the end of the interval sends the latest route of each.
    let churn: Vec<Vec<DecodedUpdate>> = (8..11)
        .map(|origin| {
            let mut u = updates(routes * 4 / 5, false, 65_001, origin);
            u.extend(updates(routes / 5, true, 65_001, origin));
            u
        })
        .collect();
    group.bench_function(format!("mrai_churn_{routes}_three_times_then_flush"), |b| {
        b.iter_batched(
            || {
                let t0 = Instant::now();
                let mut rib = Rib::new(Asn(65_000));
                let mut out = Vec::new();
                outputs(|o| rib.peer_up(peer(1), t0, o));
                outputs(|o| rib.peer_up(paced_peer(2), t0, o));
                feed(&mut rib, peer(1).addr, v4.iter().chain(&v6), t0, &mut out);
                (rib, t0)
            },
            |(mut rib, t0)| {
                let mut out = Vec::new();
                for (s, round) in (1u64..).zip(&churn) {
                    feed(
                        &mut rib,
                        peer(1).addr,
                        round,
                        t0 + Duration::from_secs(s),
                        &mut out,
                    );
                }
                black_box(outputs(|o| rib.flush(t0 + Duration::from_secs(30), o)))
            },
            criterion::BatchSize::LargeInput,
        );
    });
    group.finish();
    revalidation(c, routes, &v4, &v6);
    add_path_receive(c, routes);
    add_path_send(c, routes);
}

/// RFC 6811 §4 at scale. Every route of a table from one peer, exported to
/// another, has a VRP of its own and is Valid. A delta gives a share of
/// them, spread over the table, to another AS, so that they turn Invalid,
/// and the next iteration gives them back: every iteration changes the
/// same number of routes, found from the changed prefixes alone. `all`
/// turns validation on and off, so that every route changes state.
fn revalidation(c: &mut Criterion, routes: u32, v4: &[DecodedUpdate], v6: &[DecodedUpdate]) {
    let prefixes: Vec<Prefix> = v4
        .iter()
        .chain(v6)
        .flat_map(|u| {
            let m = &u.message;
            m.nlri
                .iter()
                .chain(m.mp_reach.iter().flat_map(|r| &r.nlri))
                .copied()
        })
        .collect();
    let vrp = |p: Prefix, asn: u32| Vrp::new(p, p.prefix_len(), Asn(asn)).unwrap();
    let valid: VrpSet = prefixes.iter().map(|p| vrp(*p, 7)).collect();
    let valid: Arc<dyn ValidationSource> = Arc::new(valid);
    let now = Instant::now();
    let mut rib = Rib::new(Asn(65_000));
    let mut out = Vec::new();
    outputs(|o| rib.peer_up(peer(1), now, o));
    outputs(|o| rib.peer_up(peer(2), now, o));
    feed(&mut rib, peer(1).addr, v4.iter().chain(v6), now, &mut out);
    let on = || ValidationChange {
        source: Arc::clone(&valid),
        affected: AffectedPrefixes::All,
    };
    outputs(|o| rib.validation_changed(on(), now, o));

    let mut group = c.benchmark_group("rib");
    group.sample_size(10);
    let n = prefixes.len();
    for changed in [1000, n / 10] {
        let moved: Vec<Prefix> = prefixes.iter().step_by(n / changed).copied().collect();
        let mut invalid: VrpSet = prefixes.iter().map(|p| vrp(*p, 7)).collect();
        for p in &moved {
            invalid.remove(vrp(*p, 7));
            invalid.insert(vrp(*p, 8));
        }
        let invalid: Arc<dyn ValidationSource> = Arc::new(invalid);
        let affected = AffectedPrefixes::from_vrps(moved.iter().map(|p| vrp(*p, 8)));
        let mut flip = false;
        group.bench_function(format!("revalidate_{}_of_{routes}", moved.len()), |b| {
            b.iter(|| {
                flip = !flip;
                let source = if flip { &invalid } else { &valid };
                let change = ValidationChange {
                    source: Arc::clone(source),
                    affected: affected.clone(),
                };
                black_box(outputs(|o| rib.validation_changed(change, now, o)))
            });
        });
        // Leave every route Valid for the next case.
        if flip {
            outputs(|o| rib.validation_changed(on(), now, o));
        }
    }
    let mut flip = false;
    group.bench_function(format!("revalidate_all_{routes}"), |b| {
        b.iter(|| {
            flip = !flip;
            let change = if flip {
                ValidationChange::disabled()
            } else {
                on()
            };
            black_box(outputs(|o| rib.validation_changed(change, now, o)))
        });
    });
    group.finish();
}

/// `updates` as a peer sends them with ADD-PATH: every prefix with Path
/// Identifier `id`.
fn with_path_id(updates: &[DecodedUpdate], id: u32) -> Vec<DecodedUpdate> {
    updates
        .iter()
        .map(|u| {
            let m = &u.message;
            let ids = PathIds {
                nlri: vec![PathId(id); m.nlri.len()],
                mp_reach: vec![PathId(id); m.mp_reach.as_ref().map_or(0, |r| r.nlri.len())],
                ..PathIds::default()
            };
            let mut u = u.clone();
            u.message.path_ids = Some(Box::new(ids));
            u
        })
        .collect()
}

/// A peer that sends three paths of each prefix (`receive`), or is sent up
/// to `limit` of them.
fn path_peer(i: u8, receive: bool, limit: Option<PathLimit>) -> PeerInfo {
    let families = [AddressFamily::IPV4_UNICAST, AddressFamily::IPV6_UNICAST];
    PeerInfo {
        add_path_receive: if receive {
            families.to_vec()
        } else {
            Vec::new()
        },
        add_path_send: limit.map_or(Vec::new(), |l| families.map(|f| (f, l)).to_vec()),
        ..peer(i)
    }
}

/// Three plain peers' tables, each with its own origin: three paths to
/// every prefix, as three upstreams would send them.
fn plain_tables(routes: u32) -> Vec<Vec<DecodedUpdate>> {
    [(65_001u32, 7), (65_003, 8), (65_004, 9)]
        .iter()
        .map(|(asn, origin)| {
            let mut u = updates(routes * 4 / 5, false, *asn, *origin);
            u.extend(updates(routes / 5, true, *asn, *origin));
            u
        })
        .collect()
}

/// A RIB that has the three tables of `plain` from peers 1, 3 and 4.
fn with_three_tables(plain: &[Vec<DecodedUpdate>]) -> (Rib, Instant) {
    let now = Instant::now();
    let mut rib = Rib::new(Asn(65_000));
    let mut out = Vec::new();
    for (i, t) in [1u8, 3, 4].iter().zip(plain) {
        outputs(|o| rib.peer_up(peer(*i), now, o));
        feed(&mut rib, peer(*i).addr, t, now, &mut out);
    }
    (rib, now)
}

/// RFC 7911 at scale: what holding three paths to every prefix costs next
/// to holding one (`insert_*_from_one_peer_to_one_peer` above).
fn add_path_receive(c: &mut Criterion, routes: u32) {
    let mut group = c.benchmark_group("add_path");
    group.sample_size(10);
    let tables: Vec<Vec<DecodedUpdate>> = plain_tables(routes)
        .iter()
        .zip(1u32..)
        .map(|(t, id)| with_path_id(t, id))
        .collect();
    let load = || {
        let now = Instant::now();
        let mut rib = Rib::new(Asn(65_000));
        let mut out = Vec::new();
        outputs(|o| rib.peer_up(path_peer(1, true, None), now, o));
        outputs(|o| rib.peer_up(peer(2), now, o));
        for t in &tables {
            feed(&mut rib, peer(1).addr, t, now, &mut out);
        }
        rib
    };
    group.bench_function(format!("receive_{routes}_prefixes_3_paths_each"), |b| {
        b.iter(load);
    });
    group.bench_function(
        format!("withdraw_{routes}_prefixes_3_paths_each_on_peer_down"),
        |b| {
            b.iter_batched(
                load,
                |mut rib| black_box(outputs(|o| rib.peer_down(peer(1).addr, Instant::now(), o))),
                criterion::BatchSize::LargeInput,
            );
        },
    );
    group.finish();
}

/// What sending paths costs: the whole table to a peer that comes up, and
/// a round of changes to one of the paths of every prefix, to a peer sent
/// all the paths and to one sent the two best.
fn add_path_send(c: &mut Criterion, routes: u32) {
    let mut group = c.benchmark_group("add_path");
    group.sample_size(10);
    let plain = plain_tables(routes);
    let changed: Vec<DecodedUpdate> = {
        let mut u = updates(routes * 4 / 5, false, 65_003, 10);
        u.extend(updates(routes / 5, true, 65_003, 10));
        u
    };
    for (name, limit) in [("all", PathLimit::All), ("best_2", PathLimit::Best(2))] {
        group.bench_function(
            format!("send_{name}_of_3_paths_of_{routes}_prefixes_to_a_new_peer"),
            |b| {
                b.iter_batched(
                    || with_three_tables(&plain),
                    |(mut rib, now)| {
                        let sender = path_peer(5, false, Some(limit));
                        black_box(outputs(|o| rib.peer_up(sender, now, o)))
                    },
                    criterion::BatchSize::LargeInput,
                );
            },
        );
        group.bench_function(
            format!("change_one_of_3_paths_of_{routes}_prefixes_sent_{name}"),
            |b| {
                b.iter_batched(
                    || {
                        let (mut rib, now) = with_three_tables(&plain);
                        outputs(|o| rib.peer_up(path_peer(5, false, Some(limit)), now, o));
                        (rib, now)
                    },
                    |(mut rib, now)| {
                        let mut out = Vec::new();
                        feed(&mut rib, peer(3).addr, &changed, now, &mut out);
                        rib
                    },
                    criterion::BatchSize::LargeInput,
                );
            },
        );
    }
    group.finish();
}

/// Entry point; `criterion_main!` is not used because its generated items
/// lack docs and the workspace warns on that.
fn main() {
    let mut c = Criterion::default().configure_from_args();
    bench(&mut c);
    c.final_summary();
}

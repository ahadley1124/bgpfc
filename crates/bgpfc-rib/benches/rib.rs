//! RIB insert and withdraw at scale (AGENTS.md §5, benches row), from one
//! peer and from two that send the same table, as a multi-homed network
//! has it, churn
//! under the RFC 4271 §9.2.1.1 advertisement interval, and validating
//! routes again when the validation source changes (RFC 6811 §4), and the
//! Only to Customer procedures of sessions with BGP Roles (RFC 9234 §5). The
//! default sizes are a fraction of a full table so the bench finishes
//! quickly; set `BGPFC_BENCH_ROUTES` to 1250000 for the full-table figure.

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bgpfc_rib::{Output, PeerInfo, Rib};
use bgpfc_rpki::{AffectedPrefixes, ValidationChange, ValidationSource, Vrp, VrpSet};
use bgpfc_wire::as_path::AsPath;
use bgpfc_wire::attribute::{Origin, PathAttribute};
use bgpfc_wire::mp::{MpReach, NextHop};
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::role::Role;
use bgpfc_wire::types::{AddressFamily, Asn, RouterId};
use bgpfc_wire::update::{DecodedUpdate, PeerKind, UpdateMessage};
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
        role: None,
    }
}

/// An external peer with the RFC 4271 §10 default interval of 30 s.
fn paced_peer(i: u8) -> PeerInfo {
    PeerInfo {
        advertisement_interval: Duration::from_secs(30),
        prefix_limits: Vec::new(),
        role: None,
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
    roles(c, routes, &v4, &v6);
    revalidation(c, routes, &v4, &v6);
}

/// RFC 9234 §5 at scale, against the first case above, which is the same
/// load with no Roles: a table from a provider (ours Customer: every
/// attribute set gains the attribute on the way in) sent to a customer
/// (ours Provider: it goes out as it is), and one from a customer sent to a
/// peer (ours Peer: every set gains ours on the way out).
fn roles(c: &mut Criterion, routes: u32, v4: &[DecodedUpdate], v6: &[DecodedUpdate]) {
    let with = |i: u8, role: Role| PeerInfo {
        role: Some(role),
        ..peer(i)
    };
    let mut group = c.benchmark_group("rib");
    group.sample_size(10);
    for (name, from, to) in [
        (
            "from_a_provider_to_a_customer",
            Role::Customer,
            Role::Provider,
        ),
        ("from_a_customer_to_a_peer", Role::Provider, Role::Peer),
    ] {
        group.bench_function(format!("insert_{routes}_{name}"), |b| {
            b.iter(|| {
                let now = Instant::now();
                let mut rib = Rib::new(Asn(65_000));
                let mut out = Vec::new();
                outputs(|o| rib.peer_up(with(1, from), now, o));
                outputs(|o| rib.peer_up(with(2, to), now, o));
                feed(&mut rib, peer(1).addr, v4.iter().chain(v6), now, &mut out);
                rib
            });
        });
    }
    group.finish();
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

/// Entry point; `criterion_main!` is not used because its generated items
/// lack docs and the workspace warns on that.
fn main() {
    let mut c = Criterion::default().configure_from_args();
    bench(&mut c);
    c.final_summary();
}

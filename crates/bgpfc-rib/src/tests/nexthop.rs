//! Next hops resolved against the kernel's routing table (RFC 4271
//! §9.1.2, §9.1.2.1): a route whose next hop does not resolve is held and
//! never wins, comes back when it resolves, and is installed through the
//! immediate hop of the kernel route that resolves it; a change of the
//! kernel's table decides again only the destinations of the next hops
//! whose resolution it moved.

use std::collections::BTreeMap;
use std::sync::Mutex;

use bgpfc_rpki::{AffectedPrefixes, Enforcement, ValidationChange, Vrp, VrpSet};
use proptest::prelude::*;

use super::*;
use crate::nexthop::{
    Hop, Kernel, KernelChange, KernelRoute, KernelUpdate, NextHopReport, NextHopsChanged,
    Resolution, Via,
};
use crate::{Held, Imported, Policies, Verdict};

fn connected(prefix: &str, oif: u32) -> KernelRoute {
    KernelRoute {
        prefix: p(prefix),
        metric: 0,
        via: Via::Unicast {
            gateway: None,
            oif,
            onlink: false,
        },
    }
}

fn via(prefix: &str, gateway: &str, oif: u32, metric: u32) -> KernelRoute {
    KernelRoute {
        prefix: p(prefix),
        metric,
        via: Via::Unicast {
            gateway: Some(ip(gateway)),
            oif,
            onlink: false,
        },
    }
}

fn blackhole(prefix: &str) -> KernelRoute {
    KernelRoute {
        prefix: p(prefix),
        metric: 0,
        via: Via::Unreachable,
    }
}

/// A whole table, with interfaces 2 (`eth0`) and 3 (`eth1`).
fn table(routes: &[KernelRoute]) -> KernelUpdate {
    KernelUpdate::Table {
        routes: routes.to_vec(),
        links: vec![(2, "eth0".to_owned()), (3, "eth1".to_owned())],
    }
}

fn hop(gateway: &str, oif: Option<u32>) -> Hop {
    Hop {
        gateway: ip(gateway),
        oif,
        onlink: false,
    }
}

fn kernel(rib: &mut Rib, update: KernelUpdate) -> Vec<Output> {
    let out = outputs(|o| rib.kernel(update, now(), o));
    rib.check_next_hops();
    out
}

fn change(rib: &mut Rib, changes: &[KernelChange]) -> Vec<Output> {
    kernel(rib, KernelUpdate::Changes(changes.to_vec()))
}

/// The one report of a kernel change, which comes first.
fn report(out: &[Output]) -> &NextHopsChanged {
    let reports: Vec<&NextHopsChanged> = out
        .iter()
        .filter_map(|o| match o {
            Output::NextHops(r) => Some(r),
            _ => None,
        })
        .collect();
    assert_eq!(reports.len(), 1, "{out:?}");
    assert!(matches!(out[0], Output::NextHops(_)), "{out:?}");
    reports[0]
}

/// Two external peers: e1 sends, e2 receives.
fn two_peers(rib: &mut Rib) -> (PeerInfo, PeerInfo) {
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_002, 2);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    outputs(|o| rib.peer_up(e2.clone(), now(), o));
    (e1, e2)
}

/// `from`'s routes to `prefixes` with `next_hop`, `AS_PATH` `path`.
fn send(
    rib: &mut Rib,
    from: &PeerInfo,
    prefixes: &[&str],
    path: &[u32],
    next_hop: &str,
) -> Vec<Output> {
    let out = outputs(|o| {
        rib.update(
            from.addr,
            &announce(prefixes, &attrs(path, next_hop)),
            now(),
            o,
        );
    });
    rib.check_next_hops();
    out
}

/// What was sent to `to`: (NLRI, withdrawn).
fn sent(out: &[Output], to: &PeerInfo) -> (Vec<Prefix>, Vec<Prefix>) {
    let mut nlri = Vec::new();
    let mut withdrawn = Vec::new();
    for messages in sends(out, to.addr) {
        for m in decode_sent(messages, to) {
            nlri.extend(m.nlri);
            withdrawn.extend(m.withdrawn);
            if let Some(r) = m.mp_reach {
                nlri.extend(r.nlri);
            }
            if let Some(u) = m.mp_unreach {
                withdrawn.extend(u.withdrawn);
            }
        }
    }
    (nlri, withdrawn)
}

/// Each route to `prefix`: its peer and why it is held.
fn kept(rib: &Rib, prefix: &str) -> Vec<(IpAddr, Option<Held>)> {
    let family = if prefix.contains(':') { V6 } else { V4 };
    rib.routes(family, p(prefix))
        .iter()
        .map(|r| (r.peer, r.held))
        .collect()
}

fn resolution(rib: &Rib, next_hop: &str) -> Resolution {
    rib.next_hops()
        .into_iter()
        .find(|r| r.addr == ip(next_hop))
        .map(|r| r.resolution)
        .unwrap()
}

#[test]
fn without_a_kernel_table_every_next_hop_resolves_to_itself() {
    // Until it is given a kernel table, the library resolves every next
    // hop to itself with no interface, as before resolution existed: a
    // next hop on no network the router is attached to is chosen,
    // installed and advertised like any other. bgpfcd gives the table
    // before any session starts.
    let mut rib = Rib::new(LOCAL_AS);
    let (e1, e2) = two_peers(&mut rib);
    let out = send(&mut rib, &e1, &["192.0.2.0/24"], &[65_001], "203.0.113.99");
    assert_eq!(
        fib(&out),
        vec![FibChange {
            family: V4,
            prefix: p("192.0.2.0/24"),
            next_hop: Some(hop("203.0.113.99", None)),
            previous: None,
        }]
    );
    assert_eq!(sends(&out, e2.addr).len(), 1);
    assert_eq!(
        rib.next_hops(),
        vec![NextHopReport {
            addr: ip("203.0.113.99"),
            resolution: Resolution::Resolved {
                hop: hop("203.0.113.99", None),
                through: None
            },
            interface: None,
            routes: 1,
        }]
    );
    assert_eq!(rib.kernel_routes(), None);
    assert_eq!(
        rib.fib_routes().collect::<Vec<_>>(),
        vec![(p("192.0.2.0/24"), hop("203.0.113.99", None))]
    );
}

#[test]
fn unresolvable_next_hops_are_held_and_never_win() {
    // RFC 4271 §9.1.2: "If the NEXT_HOP attribute of a BGP route depicts
    // an address that is not resolvable ... the BGP route MUST be
    // excluded from the Phase 2 decision function." Kept in the
    // Adj-RIB-In all the same.
    let mut rib = Rib::new(LOCAL_AS);
    kernel(&mut rib, table(&[connected("10.0.0.0/24", 2)]));
    let (e1, e2) = two_peers(&mut rib);
    let out = send(&mut rib, &e1, &["192.0.2.0/24"], &[65_001], "203.0.113.99");
    assert_eq!(out, vec![]);
    assert_eq!(
        kept(&rib, "192.0.2.0/24"),
        vec![(e1.addr, Some(Held::NextHop))]
    );
    assert_eq!(rib.loc_rib(V4).count(), 0);
    assert_eq!(rib.candidates(V4, p("192.0.2.0/24")).len(), 0);
    assert_eq!(rib.held(V4).count(), 1);
    assert_eq!(Held::NextHop.to_string(), "next-hop");
    // A worse route through a next hop that resolves wins: the held one
    // is no candidate at all, however much better its path.
    let e3 = peer("10.0.0.3", 65_003, 3);
    outputs(|o| rib.peer_up(e3.clone(), now(), o));
    let out = send(
        &mut rib,
        &e3,
        &["192.0.2.0/24"],
        &[65_003, 64_500, 64_501],
        "10.0.0.3",
    );
    assert_eq!(
        fib(&out),
        vec![FibChange {
            family: V4,
            prefix: p("192.0.2.0/24"),
            next_hop: Some(hop("10.0.0.3", Some(2))),
            previous: None,
        }]
    );
    assert_eq!(sent(&out, &e2).0, vec![p("192.0.2.0/24")]);
    assert_eq!(
        kept(&rib, "192.0.2.0/24"),
        vec![(e3.addr, None), (e1.addr, Some(Held::NextHop))]
    );
    assert_eq!(resolution(&rib, "203.0.113.99"), Resolution::Unresolved);
}

#[test]
fn a_route_comes_back_when_its_next_hop_resolves() {
    let mut rib = Rib::new(LOCAL_AS);
    kernel(&mut rib, table(&[connected("10.0.0.0/24", 2)]));
    let (e1, e2) = two_peers(&mut rib);
    send(&mut rib, &e1, &["192.0.2.0/24"], &[65_001], "203.0.113.99");
    // A route to the next hop appears: the route is used, with no UPDATE.
    let route = via("203.0.113.0/24", "10.0.0.9", 2, 0);
    let out = change(&mut rib, &[KernelChange::Route(route)]);
    let r = report(&out);
    assert_eq!(
        (
            r.resolved,
            r.unresolved,
            r.moved,
            r.held,
            r.released,
            r.best_changed
        ),
        (1, 0, 0, 0, 1, 1)
    );
    assert_eq!(
        r.next_hops,
        vec![NextHopReport {
            addr: ip("203.0.113.99"),
            resolution: Resolution::Resolved {
                hop: hop("10.0.0.9", Some(2)),
                through: Some(p("203.0.113.0/24")),
            },
            interface: Some("eth0".to_owned()),
            routes: 1,
        }]
    );
    assert_eq!(
        r.next_hops[0].to_string(),
        "203.0.113.99 via 10.0.0.9 dev eth0"
    );
    assert_eq!(
        fib(&out),
        vec![FibChange {
            family: V4,
            prefix: p("192.0.2.0/24"),
            next_hop: Some(hop("10.0.0.9", Some(2))),
            previous: None,
        }]
    );
    assert_eq!(sent(&out, &e2), (vec![p("192.0.2.0/24")], vec![]));
    assert_eq!(kept(&rib, "192.0.2.0/24"), vec![(e1.addr, None)]);
    // And it goes again with the kernel's route.
    let out = change(
        &mut rib,
        &[KernelChange::Gone {
            prefix: p("203.0.113.0/24"),
            metric: 0,
        }],
    );
    let r = report(&out);
    assert_eq!((r.unresolved, r.held, r.best_changed), (1, 1, 1));
    assert_eq!(r.next_hops[0].to_string(), "203.0.113.99 unresolved");
    assert_eq!(
        fib(&out),
        vec![FibChange {
            family: V4,
            prefix: p("192.0.2.0/24"),
            next_hop: None,
            previous: Some(hop("10.0.0.9", Some(2))),
        }]
    );
    assert_eq!(sent(&out, &e2), (vec![], vec![p("192.0.2.0/24")]));
    assert_eq!(
        kept(&rib, "192.0.2.0/24"),
        vec![(e1.addr, Some(Held::NextHop))]
    );
    // A change of an interface's name alone moves nothing.
    let out = change(
        &mut rib,
        &[KernelChange::Link {
            index: 2,
            name: "wan".to_owned(),
        }],
    );
    assert_eq!(out, vec![]);
}

#[test]
fn resolution_takes_the_longest_match_and_the_lowest_metric() {
    // RFC 4271 §9.1.2.1 1): "only the longest matching route SHOULD be
    // considered"; among routes to that prefix the kernel uses the lowest
    // metric, and so does the resolution.
    let mut rib = Rib::new(LOCAL_AS);
    kernel(
        &mut rib,
        table(&[
            via("192.0.2.0/24", "10.0.0.9", 2, 10),
            via("192.0.2.0/24", "10.0.0.8", 3, 5),
            via("192.0.2.0/28", "10.0.0.7", 2, 100),
            connected("10.0.0.0/24", 2),
        ]),
    );
    let (e1, _) = two_peers(&mut rib);
    send(&mut rib, &e1, &["198.51.100.0/24"], &[65_001], "192.0.2.1");
    send(
        &mut rib,
        &e1,
        &["198.51.101.0/24"],
        &[65_001],
        "192.0.2.100",
    );
    let resolved = |gateway, oif, through| Resolution::Resolved {
        hop: hop(gateway, Some(oif)),
        through: Some(p(through)),
    };
    assert_eq!(
        resolution(&rib, "192.0.2.1"),
        resolved("10.0.0.7", 2, "192.0.2.0/28")
    );
    assert_eq!(
        resolution(&rib, "192.0.2.100"),
        resolved("10.0.0.8", 3, "192.0.2.0/24")
    );
    // The lowest metric goes: the next one is used, a move.
    let out = change(
        &mut rib,
        &[KernelChange::Gone {
            prefix: p("192.0.2.0/24"),
            metric: 5,
        }],
    );
    let r = report(&out);
    assert_eq!((r.moved, r.best_changed), (1, 0));
    assert_eq!(
        resolution(&rib, "192.0.2.100"),
        resolved("10.0.0.9", 2, "192.0.2.0/24")
    );
    assert_eq!(
        fib(&out),
        vec![FibChange {
            family: V4,
            prefix: p("198.51.101.0/24"),
            next_hop: Some(hop("10.0.0.9", Some(2))),
            previous: Some(hop("10.0.0.8", Some(3))),
        }]
    );
    assert_eq!(rib.kernel_routes(), Some(3));
}

#[test]
fn default_routes_our_routes_and_blackholes_resolve_nothing() {
    // What reaches the RIB is what the FIB's filter keeps: never a default
    // route, never bgpfcd's own routes (`bgpfc_fib::kernel::relevant`);
    // blackholes are kept. A default route given anyway is not used, and
    // a more specific blackhole shadows a covering route, as in the kernel.
    let mut rib = Rib::new(LOCAL_AS);
    kernel(
        &mut rib,
        table(&[
            connected("192.0.2.0/24", 2),
            blackhole("192.0.2.66/32"),
            via("0.0.0.0/0", "192.0.2.254", 2, 0),
            via("::/0", "fe80::1", 2, 0),
        ]),
    );
    assert_eq!(rib.kernel_routes(), Some(2));
    let (e1, _) = two_peers(&mut rib);
    send(&mut rib, &e1, &["198.51.100.0/24"], &[65_001], "192.0.2.66");
    send(&mut rib, &e1, &["198.51.101.0/24"], &[65_001], "192.0.2.67");
    send(
        &mut rib,
        &e1,
        &["198.51.102.0/24"],
        &[65_001],
        "203.0.113.1",
    );
    send(
        &mut rib,
        &e1,
        &["2001:db8:1::/48"],
        &[65_001],
        "2001:db8::1",
    );
    assert_eq!(resolution(&rib, "192.0.2.66"), Resolution::Unresolved);
    assert!(resolution(&rib, "192.0.2.67").is_resolved());
    assert_eq!(resolution(&rib, "203.0.113.1"), Resolution::Unresolved);
    assert_eq!(resolution(&rib, "2001:db8::1"), Resolution::Unresolved);
    let best: Vec<Prefix> = rib.loc_rib(V4).map(|(p, _)| p).collect();
    assert_eq!(best, vec![p("198.51.101.0/24")]);
}

#[test]
fn install_goes_through_the_immediate_gateway_and_interface() {
    // A next hop on a connected network is installed through itself, now
    // with its interface; one further away through the gateway of the
    // kernel route that resolves it (BIRD's `gateway recursive`, FRR).
    // An IPv6 route through a link-local gateway gives its interface.
    let mut rib = Rib::new(LOCAL_AS);
    kernel(
        &mut rib,
        table(&[
            connected("10.0.0.0/24", 2),
            via("192.0.2.0/24", "10.0.0.9", 3, 0),
            via("2001:db8:7::/48", "fe80::1", 3, 1024),
        ]),
    );
    let (e1, _) = two_peers(&mut rib);
    send(&mut rib, &e1, &["198.51.100.0/24"], &[65_001], "10.0.0.1");
    send(&mut rib, &e1, &["198.51.101.0/24"], &[65_001], "192.0.2.1");
    send(
        &mut rib,
        &e1,
        &["2001:db8:1::/48"],
        &[65_001],
        "2001:db8:7::5",
    );
    assert_eq!(
        rib.fib_routes().collect::<Vec<_>>(),
        vec![
            (p("198.51.100.0/24"), hop("10.0.0.1", Some(2))),
            (p("198.51.101.0/24"), hop("10.0.0.9", Some(3))),
            (p("2001:db8:1::/48"), hop("fe80::1", Some(3))),
        ]
    );
    assert_eq!(
        rib.fib_routes_after(Some(p("198.51.100.0/24")))
            .map(|(p, _)| p)
            .collect::<Vec<_>>(),
        vec![p("198.51.101.0/24"), p("2001:db8:1::/48")]
    );
}

#[test]
fn an_onlink_gateway_is_installed_onlink() {
    // An IGP's route over an unnumbered link: its gateway is on the link
    // though no route covers it (`onlink`), and the kernel takes a route
    // through such a gateway only so marked. A next hop the route covers
    // itself, as a device route's, is on the link by that route.
    let mut rib = Rib::new(LOCAL_AS);
    let onlink = |prefix: &str, gateway: Option<&str>| KernelRoute {
        prefix: p(prefix),
        metric: 20,
        via: Via::Unicast {
            gateway: gateway.map(ip),
            oif: 3,
            onlink: true,
        },
    };
    kernel(
        &mut rib,
        table(&[
            onlink("10.255.0.30/32", Some("192.168.77.1")),
            onlink("10.0.0.0/24", None),
        ]),
    );
    let (e1, _) = two_peers(&mut rib);
    send(&mut rib, &e1, &["203.0.113.0/24"], &[65_001], "10.255.0.30");
    send(&mut rib, &e1, &["198.51.100.0/24"], &[65_001], "10.0.0.1");
    let through = Hop {
        onlink: true,
        ..hop("192.168.77.1", Some(3))
    };
    assert_eq!(
        rib.fib_routes().collect::<Vec<_>>(),
        vec![
            (p("198.51.100.0/24"), hop("10.0.0.1", Some(3))),
            (p("203.0.113.0/24"), through),
        ]
    );
    let report = rib
        .next_hops()
        .into_iter()
        .find(|n| n.addr == ip("10.255.0.30"))
        .unwrap();
    assert_eq!(
        report.to_string(),
        "10.255.0.30 via 192.168.77.1 dev eth1 onlink"
    );
}

#[test]
fn a_moved_next_hop_changes_the_fib_and_sends_nothing() {
    // RFC 4271 §5.1.3: an external peer gets our address as the next
    // hop, an internal one the BGP next hop; neither sees the gateway, so
    // a move is the FIB's alone.
    let mut rib = Rib::new(LOCAL_AS);
    kernel(&mut rib, table(&[via("192.0.2.0/24", "10.0.0.9", 2, 0)]));
    let (e1, _) = two_peers(&mut rib);
    let i1 = peer("10.0.0.5", 65_000, 5);
    outputs(|o| rib.peer_up(i1.clone(), now(), o));
    send(&mut rib, &e1, &["198.51.100.0/24"], &[65_001], "192.0.2.1");
    let out = change(
        &mut rib,
        &[KernelChange::Route(via("192.0.2.0/24", "10.0.0.8", 3, 0))],
    );
    let r = report(&out);
    assert_eq!(
        (
            r.resolved,
            r.unresolved,
            r.moved,
            r.held,
            r.released,
            r.best_changed
        ),
        (0, 0, 1, 0, 0, 0)
    );
    assert_eq!(
        out[1..],
        [Output::Fib(FibChange {
            family: V4,
            prefix: p("198.51.100.0/24"),
            next_hop: Some(hop("10.0.0.8", Some(3))),
            previous: Some(hop("10.0.0.9", Some(2))),
        })]
    );
    // A more specific route through the same hop changes what resolves
    // the next hop, and nothing else.
    let out = change(
        &mut rib,
        &[KernelChange::Route(via("192.0.2.0/25", "10.0.0.8", 3, 0))],
    );
    assert_eq!(out, vec![]);
    assert_eq!(
        resolution(&rib, "192.0.2.1"),
        Resolution::Resolved {
            hop: hop("10.0.0.8", Some(3)),
            through: Some(p("192.0.2.0/25")),
        }
    );
}

fn vrps(list: &[(&str, u8, u32)]) -> VrpSet {
    list.iter()
        .map(|&(prefix, max, asn)| Vrp::new(p(prefix), max, Asn(asn)).unwrap())
        .collect()
}

fn all(set: VrpSet) -> ValidationChange {
    ValidationChange {
        source: Arc::new(set),
        affected: AffectedPrefixes::All,
    }
}

#[test]
fn rpki_holds_come_before_next_hop_holds() {
    // Policy and the operator's enforcement are Phase 1 (RFC 6811 §5);
    // resolvability is RFC 4271 §9.1.2's Phase 2 exclusion: a route held
    // for its validation state shows that reason whatever its next hop.
    let mut rib = Rib::new(LOCAL_AS);
    kernel(&mut rib, table(&[connected("10.0.0.0/24", 2)]));
    outputs(|o| rib.set_enforcement(Enforcement::DropInvalid, now(), o));
    let (e1, _) = two_peers(&mut rib);
    outputs(|o| {
        rib.validation_changed(all(vrps(&[("192.0.2.0/24", 24, 64_497)])), now(), o);
    });
    send(
        &mut rib,
        &e1,
        &["192.0.2.0/24"],
        &[65_001, 64_496],
        "203.0.113.99",
    );
    assert_eq!(
        kept(&rib, "192.0.2.0/24"),
        vec![(e1.addr, Some(Held::Enforcement))]
    );
    // Valid now: admitted by enforcement, held by its next hop.
    outputs(|o| {
        rib.validation_changed(all(vrps(&[("192.0.2.0/24", 24, 64_496)])), now(), o);
    });
    rib.check_next_hops();
    assert_eq!(
        kept(&rib, "192.0.2.0/24"),
        vec![(e1.addr, Some(Held::NextHop))]
    );
    let out = change(
        &mut rib,
        &[KernelChange::Route(via("203.0.113.0/24", "10.0.0.9", 2, 0))],
    );
    assert_eq!(report(&out).released, 1);
    assert_eq!(kept(&rib, "192.0.2.0/24"), vec![(e1.addr, None)]);
    // Invalid again, while it resolves: held for that.
    outputs(|o| {
        rib.validation_changed(all(vrps(&[("192.0.2.0/24", 24, 64_497)])), now(), o);
    });
    rib.check_next_hops();
    assert_eq!(
        kept(&rib, "192.0.2.0/24"),
        vec![(e1.addr, Some(Held::Enforcement))]
    );
    // Its next hop going changes nothing for it: no route moves.
    let out = change(
        &mut rib,
        &[KernelChange::Gone {
            prefix: p("203.0.113.0/24"),
            metric: 0,
        }],
    );
    let r = report(&out);
    assert_eq!(
        (r.unresolved, r.held, r.released, r.best_changed),
        (1, 0, 0, 0)
    );
    assert_eq!(
        kept(&rib, "192.0.2.0/24"),
        vec![(e1.addr, Some(Held::Enforcement))]
    );
}

/// `next-hop self` on import: every route's next hop becomes the
/// session's local address.
struct NextHopSelf;

impl Policies for NextHopSelf {
    fn import(
        &self,
        peer: &PeerInfo,
        _: AddressFamily,
        _: Prefix,
        a: &PathAttrs,
        _: RovState,
    ) -> Imported {
        let IpAddr::V4(local) = peer.local_addr else {
            return Verdict::Accept.into();
        };
        let mut a = a.clone();
        a.next_hop = NextHop::Ipv4(local);
        Verdict::Modified(a).into()
    }

    fn export(
        &self,
        _: &PeerInfo,
        _: AddressFamily,
        _: Prefix,
        _: &PathAttrs,
        _: RovState,
    ) -> Verdict {
        Verdict::Accept
    }
}

#[test]
fn the_next_hop_is_the_one_import_policy_set() {
    // The route is used with the attributes import policy gave it: its
    // next hop is the one to resolve, and a route held for it keeps them.
    let mut rib = Rib::with_policies(LOCAL_AS, Box::new(NextHopSelf));
    kernel(&mut rib, table(&[connected("10.0.0.0/24", 2)]));
    let (e1, _) = two_peers(&mut rib);
    let out = send(&mut rib, &e1, &["192.0.2.0/24"], &[65_001], "203.0.113.99");
    assert_eq!(fib(&out)[0].next_hop, Some(hop("10.0.0.254", Some(2))));
    let addrs: Vec<IpAddr> = rib.next_hops().iter().map(|r| r.addr).collect();
    assert_eq!(addrs, vec![ip("10.0.0.254")]);
    // The connected network goes: held, with the policy's next hop.
    let out = change(
        &mut rib,
        &[KernelChange::Gone {
            prefix: p("10.0.0.0/24"),
            metric: 0,
        }],
    );
    assert_eq!(report(&out).held, 1);
    let r = &rib.routes(V4, p("192.0.2.0/24"))[0];
    assert_eq!(r.held, Some(Held::NextHop));
    assert_eq!(r.attrs.next_hop_addr(), ip("10.0.0.254"));
}

/// Accepts every route, counting the questions import policy is asked.
struct Counting(Arc<Mutex<usize>>);

impl Policies for Counting {
    fn import(
        &self,
        _: &PeerInfo,
        _: AddressFamily,
        _: Prefix,
        _: &PathAttrs,
        _: RovState,
    ) -> Imported {
        *self.0.lock().unwrap() += 1;
        Verdict::Accept.into()
    }

    fn export(
        &self,
        _: &PeerInfo,
        _: AddressFamily,
        _: Prefix,
        _: &PathAttrs,
        _: RovState,
    ) -> Verdict {
        Verdict::Accept
    }
}

#[test]
fn only_destinations_of_the_changed_next_hop_are_decided_again() {
    let asked = Arc::new(Mutex::new(0));
    let mut rib = Rib::with_policies(LOCAL_AS, Box::new(Counting(Arc::clone(&asked))));
    kernel(
        &mut rib,
        table(&[
            connected("10.0.0.0/24", 2),
            via("192.0.2.0/24", "10.0.0.9", 2, 0),
        ]),
    );
    let (e1, e2) = two_peers(&mut rib);
    let e3 = peer("10.0.0.3", 65_003, 3);
    outputs(|o| rib.peer_up(e3.clone(), now(), o));
    send(
        &mut rib,
        &e1,
        &["198.51.100.0/24", "203.0.113.0/24"],
        &[65_001],
        "192.0.2.1",
    );
    send(
        &mut rib,
        &e3,
        &["100.64.0.0/24", "100.64.1.0/24"],
        &[65_003],
        "10.0.0.3",
    );
    let before: Vec<Arc<PathAttrs>> = ["100.64.0.0/24", "100.64.1.0/24"]
        .iter()
        .map(|d| Arc::clone(rib.routes(V4, p(d))[0].attrs))
        .collect();
    *asked.lock().unwrap() = 0;
    let out = change(
        &mut rib,
        &[KernelChange::Gone {
            prefix: p("192.0.2.0/24"),
            metric: 0,
        }],
    );
    // Policy is not asked: a next hop changes nothing it decided.
    assert_eq!(*asked.lock().unwrap(), 0);
    let changed: Vec<Prefix> = fib(&out).iter().map(|c| c.prefix).collect();
    assert_eq!(changed, vec![p("198.51.100.0/24"), p("203.0.113.0/24")]);
    assert_eq!(
        sent(&out, &e2).1,
        vec![p("198.51.100.0/24"), p("203.0.113.0/24")]
    );
    for (d, a) in ["100.64.0.0/24", "100.64.1.0/24"].iter().zip(&before) {
        let r = &rib.routes(V4, p(d))[0];
        assert!(Arc::ptr_eq(r.attrs, a), "{d}");
        assert_eq!(r.held, None);
    }
    // The other next hop's routes are untouched; its report is unchanged.
    assert!(resolution(&rib, "10.0.0.3").is_resolved());
}

#[test]
fn dry_run_previous_is_the_hop_the_fib_was_given() {
    // The FIB in dry-run reports each change against `previous`, which
    // must be what it was given last for the prefix: the hop before the
    // kernel change, not the one after.
    let mut rib = Rib::new(LOCAL_AS);
    kernel(&mut rib, table(&[via("192.0.2.0/24", "10.0.0.9", 2, 0)]));
    let (e1, _) = two_peers(&mut rib);
    let mut given: BTreeMap<Prefix, Hop> = BTreeMap::new();
    let mut follow = |out: &[Output]| {
        for c in fib(out) {
            assert_eq!(c.previous, given.get(&c.prefix).copied(), "{c:?}");
            match c.next_hop {
                Some(h) => given.insert(c.prefix, h),
                None => given.remove(&c.prefix),
            };
        }
    };
    follow(&send(
        &mut rib,
        &e1,
        &["198.51.100.0/24"],
        &[65_001],
        "192.0.2.1",
    ));
    for update in [
        vec![KernelChange::Route(via("192.0.2.0/24", "10.0.0.8", 3, 0))],
        vec![KernelChange::Gone {
            prefix: p("192.0.2.0/24"),
            metric: 0,
        }],
        vec![KernelChange::Route(via("192.0.2.0/24", "10.0.0.7", 2, 0))],
        vec![
            KernelChange::Route(blackhole("192.0.2.0/26")),
            KernelChange::Route(via("192.0.2.0/25", "10.0.0.6", 3, 0)),
        ],
    ] {
        follow(&change(&mut rib, &update));
    }
    follow(&kernel(
        &mut rib,
        table(&[via("192.0.2.0/24", "10.0.0.5", 2, 0)]),
    ));
    assert_eq!(
        given.into_iter().collect::<Vec<_>>(),
        rib.fib_routes().collect::<Vec<_>>()
    );
}

#[test]
fn a_table_resync_resolves_every_next_hop_again() {
    let mut rib = Rib::new(LOCAL_AS);
    kernel(
        &mut rib,
        table(&[
            connected("10.0.0.0/24", 2),
            via("192.0.2.0/24", "10.0.0.9", 2, 0),
        ]),
    );
    let (e1, _) = two_peers(&mut rib);
    send(&mut rib, &e1, &["198.51.100.0/24"], &[65_001], "192.0.2.1");
    send(&mut rib, &e1, &["198.51.101.0/24"], &[65_001], "10.0.0.7");
    send(
        &mut rib,
        &e1,
        &["198.51.102.0/24"],
        &[65_001],
        "203.0.113.1",
    );
    // The interface went: the table read again has neither route, and a
    // route to 203.0.113.0/24 appeared through another interface.
    let out = kernel(&mut rib, table(&[via("203.0.113.0/24", "10.1.0.1", 3, 0)]));
    let r = report(&out);
    assert_eq!(
        (
            r.resolved,
            r.unresolved,
            r.moved,
            r.held,
            r.released,
            r.best_changed
        ),
        (1, 2, 0, 2, 1, 3)
    );
    let shown: Vec<String> = r.next_hops.iter().map(ToString::to_string).collect();
    assert_eq!(
        shown,
        vec![
            "10.0.0.7 unresolved",
            "192.0.2.1 unresolved",
            "203.0.113.1 via 10.1.0.1 dev eth1",
        ]
    );
    assert_eq!(rib.kernel_routes(), Some(1));
    // The same table again changes nothing.
    let out = kernel(&mut rib, table(&[via("203.0.113.0/24", "10.1.0.1", 3, 0)]));
    assert_eq!(out, vec![]);
}

#[test]
fn withdrawals_go_at_once_and_returns_wait_for_the_interval() {
    // RFC 4271 §9.2.1.1: a change within the advertisement interval
    // waits for its end; bgpfc never holds a withdrawal back. A next hop
    // that flaps costs a neighbor one announcement per interval.
    let t0 = Instant::now();
    let mut rib = Rib::new(LOCAL_AS);
    let at = |rib: &mut Rib, s: u64, update: KernelUpdate| {
        let out = outputs(|o| rib.kernel(update, t0 + Duration::from_secs(s), o));
        rib.check_next_hops();
        out
    };
    at(&mut rib, 0, table(&[via("192.0.2.0/24", "10.0.0.9", 2, 0)]));
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = PeerInfo {
        advertisement_interval: Duration::from_secs(30),
        ..peer("10.0.0.2", 65_002, 2)
    };
    outputs(|o| rib.peer_up(e1.clone(), t0, o));
    outputs(|o| rib.peer_up(e2.clone(), t0, o));
    let out = outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["198.51.100.0/24"], &attrs(&[65_001], "192.0.2.1")),
            t0,
            o,
        );
    });
    assert_eq!(sent(&out, &e2).0, vec![p("198.51.100.0/24")]);
    let gone = KernelUpdate::Changes(vec![KernelChange::Gone {
        prefix: p("192.0.2.0/24"),
        metric: 0,
    }]);
    let back = KernelUpdate::Changes(vec![KernelChange::Route(via(
        "192.0.2.0/24",
        "10.0.0.9",
        2,
        0,
    ))]);
    let out = at(&mut rib, 1, gone.clone());
    assert_eq!(sent(&out, &e2), (vec![], vec![p("198.51.100.0/24")]));
    let out = at(&mut rib, 2, back.clone());
    assert_eq!(fib(&out).len(), 1, "installed at once");
    assert_eq!(
        sent(&out, &e2),
        (vec![], vec![]),
        "announced at the interval's end"
    );
    let out = at(&mut rib, 3, gone);
    assert_eq!(sent(&out, &e2), (vec![], vec![]), "it never had it");
    let out = at(&mut rib, 4, back);
    assert_eq!(sent(&out, &e2), (vec![], vec![]));
    // Nothing until the interval since the announcement at t0 ends.
    let mut announced = None;
    for s in 5..=40 {
        let out = outputs(|o| rib.flush(t0 + Duration::from_secs(s), o));
        let (nlri, withdrawn) = sent(&out, &e2);
        assert_eq!(withdrawn, vec![]);
        if !nlri.is_empty() {
            assert_eq!(nlri, vec![p("198.51.100.0/24")]);
            announced = Some(s);
            break;
        }
    }
    // 30 s after the announcement at t0: the withdrawal in between does
    // not end the interval early, and the flaps within it cost nothing.
    assert_eq!(announced, Some(30));
}

#[test]
fn held_counts_follow_next_hop_holds() {
    let mut rib = Rib::new(LOCAL_AS);
    kernel(&mut rib, table(&[connected("10.0.0.0/24", 2)]));
    let (e1, _) = two_peers(&mut rib);
    let held = |rib: &Rib| {
        let s = rib.peer_stats(e1.addr).unwrap();
        (s.received[0].1, s.held[0].1)
    };
    send(
        &mut rib,
        &e1,
        &["198.51.100.0/24", "198.51.101.0/24", "198.51.102.0/24"],
        &[65_001],
        "192.0.2.1",
    );
    assert_eq!(held(&rib), (3, 3));
    outputs(|o| rib.update(e1.addr, &withdraw(&["198.51.100.0/24"]), now(), o));
    rib.check_next_hops();
    assert_eq!(held(&rib), (2, 2));
    change(
        &mut rib,
        &[KernelChange::Route(connected("192.0.2.0/24", 3))],
    );
    assert_eq!(held(&rib), (2, 0));
    // One moves to a next hop that does not resolve.
    send(
        &mut rib,
        &e1,
        &["198.51.101.0/24"],
        &[65_001],
        "203.0.113.1",
    );
    assert_eq!(held(&rib), (2, 1));
    change(
        &mut rib,
        &[KernelChange::Gone {
            prefix: p("192.0.2.0/24"),
            metric: 0,
        }],
    );
    assert_eq!(held(&rib), (2, 2));
    outputs(|o| rib.peer_down(e1.addr, now(), o));
    rib.check_next_hops();
    assert_eq!(rib.next_hops(), vec![]);
}

// --- properties ------------------------------------------------------------

/// A kernel route from a few bits, so that random ones nest and collide.
fn kernel_route() -> impl Strategy<Value = KernelRoute> {
    (any::<u8>(), 1u8..=12, 0u32..3, prop::option::of(0u32..3)).prop_map(
        |(bits, len, metric, gateway)| KernelRoute {
            prefix: Prefix::new(IpAddr::from([bits & 0xf0, 0, 0, 0]), len).unwrap(),
            metric,
            via: match gateway {
                Some(g) => Via::Unicast {
                    gateway: Some(IpAddr::from([10, 9, 0, u8::try_from(g).unwrap()])),
                    oif: g + 2,
                    onlink: false,
                },
                None => Via::Unreachable,
            },
        },
    )
}

proptest! {
    /// The longest match and lowest metric, against a scan of every route.
    #[test]
    fn lookup_matches_a_linear_scan(
        routes in proptest::collection::vec((kernel_route(), any::<bool>()), 0..40),
        addrs in proptest::collection::vec(any::<u8>(), 1..16),
    ) {
        let mut k = Kernel::default();
        let mut model: BTreeMap<(Prefix, u32), Via> = BTreeMap::new();
        for (r, add) in routes {
            if add {
                k.insert(r);
                model.insert((r.prefix, r.metric), r.via);
            } else {
                k.remove(r.prefix, r.metric);
                model.remove(&(r.prefix, r.metric));
            }
        }
        prop_assert_eq!(k.len(), model.len());
        for a in addrs {
            let addr = IpAddr::from([a, 1, 2, 3]);
            let want = model
                .iter()
                .filter(|((p, _), _)| Prefix::new(addr, p.prefix_len()) == Some(*p))
                .max_by(|((p, m), _), ((q, n), _)| p.prefix_len().cmp(&q.prefix_len()).then(n.cmp(m)))
                .map(|((p, _), v)| (*p, *v));
            prop_assert_eq!(k.lookup(addr), want, "{}", addr);
        }
    }
}

/// One input to a RIB in the index property.
#[derive(Clone, Debug)]
enum Input {
    /// Peer `peer` announces `prefix` with next hop `nh` and an `AS_PATH` of
    /// `len` hops after its own.
    Announce {
        peer: usize,
        prefix: u8,
        nh: usize,
        len: usize,
    },
    Withdraw {
        peer: usize,
        prefix: u8,
    },
    /// Peer `peer` goes down and comes back up.
    Bounce(usize),
    /// The kernel route `route` of [`KERNEL`] is added, or removed.
    Kernel {
        route: usize,
        add: bool,
    },
    /// The whole table read again: the routes of [`KERNEL`] set in `mask`.
    Table(u8),
    /// Import policy sets the next hop to the session's local address, or
    /// leaves it, from now on.
    SelfPolicy(bool),
}

const NEXT_HOPS: [&str; 5] = [
    "10.0.0.7",
    "192.0.2.1",
    "192.0.2.130",
    "198.51.100.1",
    "203.0.113.1",
];

fn kernel_routes() -> Vec<KernelRoute> {
    vec![
        connected("10.0.0.0/24", 2),
        via("192.0.2.0/24", "10.0.0.9", 2, 0),
        via("192.0.2.0/24", "10.0.0.8", 3, 5),
        blackhole("192.0.2.128/25"),
        via("198.51.100.0/24", "10.0.0.9", 3, 0),
        via("192.0.2.0/23", "10.0.0.6", 2, 0),
    ]
}

fn input() -> impl Strategy<Value = Input> {
    prop_oneof![
        4 => (0usize..3, 0u8..4, 0usize..NEXT_HOPS.len(), 0usize..3)
            .prop_map(|(peer, prefix, nh, len)| Input::Announce { peer, prefix, nh, len }),
        2 => (0usize..3, 0u8..4).prop_map(|(peer, prefix)| Input::Withdraw { peer, prefix }),
        1 => (0usize..3).prop_map(Input::Bounce),
        3 => (0usize..6, any::<bool>()).prop_map(|(route, add)| Input::Kernel { route, add }),
        1 => any::<u8>().prop_map(Input::Table),
        1 => any::<bool>().prop_map(Input::SelfPolicy),
    ]
}

/// Import policy that sets the next hop to the session's local address
/// when `on`.
struct MaybeSelf(bool);

impl Policies for MaybeSelf {
    fn import(
        &self,
        peer: &PeerInfo,
        f: AddressFamily,
        p: Prefix,
        a: &PathAttrs,
        r: RovState,
    ) -> Imported {
        if self.0 {
            NextHopSelf.import(peer, f, p, a, r)
        } else {
            Verdict::Accept.into()
        }
    }

    fn export(
        &self,
        _: &PeerInfo,
        _: AddressFamily,
        _: Prefix,
        _: &PathAttrs,
        _: RovState,
    ) -> Verdict {
        Verdict::Accept
    }
}

fn index_peers() -> Vec<PeerInfo> {
    vec![
        peer("10.0.0.1", 65_001, 1),
        peer("10.0.0.2", 65_002, 2),
        peer("10.0.0.3", 65_000, 3),
    ]
}

fn index_prefix(i: u8) -> String {
    format!("100.64.{i}.0/24")
}

/// What a RIB ends with: every route with its peer, next hop and why it
/// is held, and the FIB's routes.
type Ending = (
    Vec<(Prefix, IpAddr, IpAddr, Option<Held>)>,
    Vec<(Prefix, Hop)>,
);

/// What a RIB holds after `inputs`: every route with its peer, next hop
/// and why it is held, and the FIB's routes; checking the index after
/// every input, and that the FIB changes chain.
fn run_inputs(inputs: &[Input], first: Option<&[KernelRoute]>) -> Ending {
    let infos = index_peers();
    let t = Instant::now();
    let mut rib = Rib::with_policies(LOCAL_AS, Box::new(MaybeSelf(false)));
    let mut given: BTreeMap<Prefix, Hop> = BTreeMap::new();
    let mut follow = |out: Vec<Output>| {
        for o in out {
            if let Output::Fib(c) = o {
                assert_eq!(c.previous, given.get(&c.prefix).copied(), "{c:?}");
                match c.next_hop {
                    Some(h) => given.insert(c.prefix, h),
                    None => given.remove(&c.prefix),
                };
            }
        }
    };
    if let Some(routes) = first {
        follow(outputs(|o| rib.kernel(table(routes), t, o)));
    }
    for info in &infos {
        follow(outputs(|o| rib.peer_up(info.clone(), t, o)));
    }
    let routes = kernel_routes();
    for input in inputs {
        let out = match input {
            Input::Announce {
                peer,
                prefix,
                nh,
                len,
            } => {
                let info = &infos[*peer];
                let mut path = vec![info.remote_as.0];
                if info.kind == PeerKind::Internal {
                    path.clear();
                }
                path.extend((0..*len).map(|i| 64_500 + u32::try_from(i).unwrap()));
                let a = attrs(&path, NEXT_HOPS[*nh]);
                outputs(|o| rib.update(info.addr, &announce(&[&index_prefix(*prefix)], &a), t, o))
            }
            Input::Withdraw { peer, prefix } => outputs(|o| {
                rib.update(
                    infos[*peer].addr,
                    &withdraw(&[&index_prefix(*prefix)]),
                    t,
                    o,
                );
            }),
            Input::Bounce(peer) => {
                let mut out = outputs(|o| rib.peer_down(infos[*peer].addr, t, o));
                out.extend(outputs(|o| rib.peer_up(infos[*peer].clone(), t, o)));
                out
            }
            Input::Kernel { route, add } => {
                let r = routes[*route];
                let c = if *add {
                    KernelChange::Route(r)
                } else {
                    KernelChange::Gone {
                        prefix: r.prefix,
                        metric: r.metric,
                    }
                };
                outputs(|o| rib.kernel(KernelUpdate::Changes(vec![c]), t, o))
            }
            Input::Table(mask) => {
                let set: Vec<KernelRoute> = (0..routes.len())
                    .filter(|i| mask & (1 << i) != 0)
                    .map(|i| routes[i])
                    .collect();
                outputs(|o| rib.kernel(table(&set), t, o))
            }
            Input::SelfPolicy(on) => {
                let mut out = Vec::new();
                rib.set_policies(Box::new(MaybeSelf(*on)), &[], t, &mut out);
                let addrs: Vec<IpAddr> = infos.iter().map(|i| i.addr).collect();
                rib.reimport(&addrs, t, &mut out);
                out
            }
        };
        follow(out);
        rib.check_next_hops();
    }
    let fib: Vec<(Prefix, Hop)> = rib.fib_routes().collect();
    assert_eq!(given.into_iter().collect::<Vec<_>>(), fib);
    let mut held = Vec::new();
    for i in 0..4u8 {
        let prefix = p(&index_prefix(i));
        for r in rib.routes(V4, prefix) {
            held.push((prefix, r.peer, r.attrs.next_hop_addr(), r.held));
        }
    }
    held.sort_by_key(|&(prefix, peer, nh, by)| (prefix, peer, nh, by.map(Held::as_str)));
    (held, fib)
}

proptest! {
    /// After any inputs, the index holds exactly the routes' next hops,
    /// each with the routes and destinations that use it, resolved as the
    /// copy of the kernel's table says (`Rib::check_next_hops`, after every
    /// input), and the FIB changes chain up to the FIB's routes.
    #[test]
    fn the_index_is_exactly_the_routes_next_hops(
        inputs in proptest::collection::vec(input(), 0..40),
        start in proptest::option::of(any::<u8>()),
    ) {
        let routes = kernel_routes();
        let first: Option<Vec<KernelRoute>> = start.map(|mask| {
            (0..routes.len()).filter(|i| mask & (1 << i) != 0).map(|i| routes[i]).collect()
        });
        run_inputs(&inputs, first.as_deref());
    }

    /// The Loc-RIB, held reasons and FIB routes are a function of the
    /// Adj-RIBs-In and the kernel's table (AGENTS.md §5's invariant, with
    /// the table): the same announcements and kernel changes, interleaved
    /// in any way, or the final table given first, end the same.
    #[test]
    fn the_loc_rib_is_a_function_of_the_kernel_table(
        announcements in proptest::collection::vec(
            (0usize..3, 0u8..4, 0usize..NEXT_HOPS.len(), 0usize..3), 0..12),
        changes in proptest::collection::vec((0usize..6, any::<bool>()), 0..12),
        order in proptest::collection::vec(any::<bool>(), 24),
    ) {
        let announce: Vec<Input> = announcements
            .iter()
            .map(|&(peer, prefix, nh, len)| Input::Announce { peer, prefix, nh, len })
            .collect();
        let kernel: Vec<Input> = changes
            .iter()
            .map(|&(route, add)| Input::Kernel { route, add })
            .collect();
        // Routes, then the kernel changes.
        let mut first = announce.clone();
        first.extend(kernel.iter().cloned());
        // The kernel changes, then the routes.
        let mut second = kernel.clone();
        second.extend(announce.iter().cloned());
        // Interleaved as `order` says.
        let (mut a, mut k) = (announce.iter(), kernel.iter());
        let mut mixed = Vec::new();
        for take_announce in order.iter().copied().chain(std::iter::repeat(true)) {
            let next = if take_announce { a.next().or_else(|| k.next()) } else { k.next().or_else(|| a.next()) };
            match next {
                Some(i) => mixed.push(i.clone()),
                None => break,
            }
        }
        // Each starts from an empty table, as bgpfcd gives one before any
        // route comes.
        let empty: &[KernelRoute] = &[];
        let a = run_inputs(&first, Some(empty));
        let b = run_inputs(&second, Some(empty));
        let c = run_inputs(&mixed, Some(empty));
        // The final table, given whole before the routes.
        let routes = kernel_routes();
        // Routes with one prefix and metric replace each other: the last
        // added stands, as in the kernel.
        let mut last: BTreeMap<(Prefix, u32), KernelRoute> = BTreeMap::new();
        for &(route, add) in &changes {
            let r = routes[route];
            if add {
                last.insert((r.prefix, r.metric), r);
            } else {
                last.remove(&(r.prefix, r.metric));
            }
        }
        let final_table: Vec<KernelRoute> = last.into_values().collect();
        let d = run_inputs(&announce, Some(&final_table));
        prop_assert_eq!(&a, &c);
        prop_assert_eq!(&a, &d);
        prop_assert_eq!(&a, &b);
    }
}

#[test]
fn a_destination_another_program_leaves_is_offered_again() {
    // The FIB installs a route only where no route of another program has
    // its destination and metric, and leaves it out while one has; when
    // that route goes, the best route there is offered again, with the
    // hop as new and previous both: installed if it was left out, nothing
    // asked if it is in.
    let mut rib = Rib::new(LOCAL_AS);
    let igp = via("198.51.100.0/24", "10.0.0.9", 2, 20);
    kernel(&mut rib, table(&[connected("10.0.0.0/24", 2), igp]));
    let (e1, _) = two_peers(&mut rib);
    send(&mut rib, &e1, &["198.51.100.0/24"], &[65_001], "10.0.0.1");
    let out = change(
        &mut rib,
        &[
            KernelChange::Gone {
                prefix: igp.prefix,
                metric: 20,
            },
            KernelChange::Gone {
                prefix: p("203.0.113.0/24"),
                metric: 20,
            },
        ],
    );
    let hop = hop("10.0.0.1", Some(2));
    assert_eq!(
        out,
        [Output::Fib(FibChange {
            family: V4,
            prefix: igp.prefix,
            next_hop: Some(hop),
            previous: Some(hop),
        })]
    );
    // A route that comes changes no place.
    assert_eq!(change(&mut rib, &[KernelChange::Route(igp)]), []);
}

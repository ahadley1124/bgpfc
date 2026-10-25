//! Decision-process tests per tie-break step (AGENTS.md §5, `bgpfc-rib`
//! row), export rules, update packing and RIB bookkeeping.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use bgpfc_wire::as_path::AsPath;
use bgpfc_wire::attribute::{Origin, PathAttribute};
use bgpfc_wire::community::Community;
use bgpfc_wire::header::HEADER_LEN;
use bgpfc_wire::mp::NextHop;
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::{AddressFamily, Asn, RouterId};
use bgpfc_wire::update::{DecodeContext, DecodedUpdate, PeerKind, UpdateMessage};

use crate::attrs::PathAttrs;
use crate::decision::{Candidate, Neighbor, best};
use crate::export::{Source, export};
use crate::peer::PeerInfo;
use crate::{FibChange, Output, Rib};

/// Run one RIB input and collect what it produced.
fn outputs(input: impl FnOnce(&mut Vec<Output>)) -> Vec<Output> {
    let mut out = Vec::new();
    input(&mut out);
    out
}

const V4: AddressFamily = AddressFamily::IPV4_UNICAST;
const V6: AddressFamily = AddressFamily::IPV6_UNICAST;
const LOCAL_AS: Asn = Asn(65_000);

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn p(s: &str) -> Prefix {
    s.parse().unwrap()
}

fn attrs(path: &[u32], next_hop: &str) -> PathAttrs {
    let next_hop = match ip(next_hop) {
        IpAddr::V4(a) => NextHop::Ipv4(a),
        IpAddr::V6(a) => NextHop::Ipv6 {
            global: a,
            link_local: None,
        },
    };
    PathAttrs {
        origin: Origin::Igp,
        as_path: AsPath::sequence(&path.iter().map(|a| Asn(*a)).collect::<Vec<_>>()),
        next_hop,
        med: None,
        local_pref: None,
        atomic_aggregate: false,
        aggregator: None,
        communities: Box::default(),
        ext_communities: Box::default(),
        large_communities: Box::default(),
        unknown: Box::default(),
    }
}

fn peer(addr: &str, remote_as: u32, router_id: u32) -> PeerInfo {
    let addr = ip(addr);
    let local_addr = match addr {
        IpAddr::V4(_) => ip("10.0.0.254"),
        IpAddr::V6(_) => ip("2001:db8::fe"),
    };
    PeerInfo {
        addr,
        local_addr,
        remote_as: Asn(remote_as),
        router_id: RouterId::new(router_id).unwrap(),
        kind: if remote_as == LOCAL_AS.0 {
            PeerKind::Internal
        } else {
            PeerKind::External
        },
        families: vec![V4, V6],
        four_octet_as: true,
        extended_messages: false,
    }
}

/// Phase 2 over routes given as (peer, attributes).
fn best_of(routes: &[(&PeerInfo, PathAttrs)]) -> Option<usize> {
    best(routes.len(), |i| Candidate {
        from: Neighbor::of(routes[i].0),
        attrs: &routes[i].1,
    })
}

fn announce(prefixes: &[&str], a: &PathAttrs) -> DecodedUpdate {
    let family = if prefixes[0].contains(':') { V6 } else { V4 };
    let message = a.to_update(family, prefixes.iter().map(|s| p(s)).collect());
    DecodedUpdate {
        message,
        treated_as_withdraw: None,
        discarded: Vec::new(),
    }
}

fn withdraw(prefixes: &[&str]) -> DecodedUpdate {
    let mut message = UpdateMessage::default();
    if prefixes[0].contains(':') {
        message.mp_unreach = Some(bgpfc_wire::mp::MpUnreach {
            family: V6,
            withdrawn: prefixes.iter().map(|s| p(s)).collect(),
        });
    } else {
        message.withdrawn = prefixes.iter().map(|s| p(s)).collect();
    }
    DecodedUpdate {
        message,
        treated_as_withdraw: None,
        discarded: Vec::new(),
    }
}

/// Decode what the RIB asked us to send to `to`.
fn decode_sent(messages: &[Vec<u8>], to: &PeerInfo) -> Vec<UpdateMessage> {
    let ctx = DecodeContext {
        four_octet_as: to.four_octet_as,
        peer: to.kind,
        allow_as_set: false,
    };
    messages
        .iter()
        .map(|m| {
            assert!(m.len() <= to.max_message_len(), "{} octets", m.len());
            UpdateMessage::decode(&m[HEADER_LEN..], &ctx)
                .unwrap()
                .message
        })
        .collect()
}

/// The type code of the first path attribute of a framed UPDATE.
fn first_attribute_type(message: &[u8]) -> Option<u8> {
    let body = &message[HEADER_LEN..];
    let withdrawn = usize::from(u16::from_be_bytes([body[0], body[1]]));
    // Total Path Attribute Length, then the first attribute's flags and
    // type (RFC 4271 §4.3).
    body[2 + withdrawn..].get(3).copied()
}

fn sends(out: &[Output], to: IpAddr) -> Vec<&Vec<Vec<u8>>> {
    out.iter()
        .filter_map(|o| match o {
            Output::Send { peer, messages } if *peer == to => Some(messages),
            _ => None,
        })
        .collect()
}

fn fib(out: &[Output]) -> Vec<FibChange> {
    out.iter()
        .filter_map(|o| match o {
            Output::Fib(c) => Some(c.clone()),
            _ => None,
        })
        .collect()
}

// --- RFC 4271 §9.1.2.2, one test per step -------------------------------

#[test]
fn degree_of_preference_wins_first() {
    let i1 = peer("10.0.0.1", 65_000, 1);
    let i2 = peer("10.0.0.2", 65_000, 2);
    let mut a = attrs(&[1, 2, 3], "10.0.0.1");
    a.local_pref = Some(200);
    let b = attrs(&[1], "10.0.0.2");
    // Longer path, but a higher LOCAL_PREF.
    let c = [(&i1, a), (&i2, b)];
    assert_eq!(best_of(&c), Some(0));
}

#[test]
fn shorter_as_path_wins() {
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_002, 2);
    let c = [
        (&e1, attrs(&[65_001, 7, 8], "10.0.0.1")),
        (&e2, attrs(&[65_002, 7], "10.0.0.2")),
    ];
    assert_eq!(best_of(&c), Some(1));
}

#[test]
fn as_set_counts_as_one_hop() {
    use bgpfc_wire::as_path::{AsPathSegment, SegmentType};
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_002, 2);
    let mut a = attrs(&[65_001], "10.0.0.1");
    a.as_path = AsPath::from_segments(&[
        AsPathSegment {
            kind: SegmentType::Sequence,
            asns: vec![Asn(65_001)],
        },
        AsPathSegment {
            kind: SegmentType::Set,
            asns: vec![Asn(1), Asn(2), Asn(3)],
        },
    ]);
    let b = attrs(&[65_002, 9, 9], "10.0.0.2");
    // a: 1 + 1 (the set) = 2 hops; b: 3 hops.
    let c = [(&e1, a), (&e2, b)];
    assert_eq!(best_of(&c), Some(0));
}

#[test]
fn lower_origin_wins() {
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_002, 2);
    let mut a = attrs(&[65_001], "10.0.0.1");
    a.origin = Origin::Incomplete;
    let mut b = attrs(&[65_002], "10.0.0.2");
    b.origin = Origin::Egp;
    let c = [(&e1, a), (&e2, b)];
    assert_eq!(best_of(&c), Some(1));
}

#[test]
fn med_compares_within_the_neighboring_as_only() {
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_001, 2);
    let e3 = peer("10.0.0.3", 65_003, 3);
    let mut first = attrs(&[65_001], "10.0.0.1");
    first.med = Some(50);
    let mut second = attrs(&[65_001], "10.0.0.2");
    second.med = Some(10);
    let mut third = attrs(&[65_003], "10.0.0.3");
    third.med = Some(5);
    // Same AS: b beats a on MED. Across ASes MED does not count, so b
    // and c3 go on to the router-id step, where b (id 2) wins.
    let c = [(&e1, first), (&e2, second), (&e3, third)];
    assert_eq!(best_of(&c), Some(1));
    // A missing MED is the lowest value.
    let mut no_med = attrs(&[65_001], "10.0.0.1");
    no_med.med = None;
    let mut zero_med = attrs(&[65_001], "10.0.0.2");
    zero_med.med = Some(0);
    let c = [(&e1, no_med), (&e2, zero_med)];
    // Equal MED (0): router id decides, e1 has the lower one.
    assert_eq!(best_of(&c), Some(0));
    let mut one_med = attrs(&[65_001], "10.0.0.2");
    one_med.med = Some(1);
    let c = [(&e2, one_med), (&e1, attrs(&[65_001], "10.0.0.1"))];
    assert_eq!(best_of(&c), Some(1));
}

#[test]
fn med_outcome_does_not_depend_on_candidate_order() {
    // Pairwise MED comparison is not transitive here: a beats b on MED
    // (same AS), b beats c on router id (different AS, MED not
    // compared), c beats a on router id. Ranking each route against all
    // routes of its AS first makes the winner the same in every order.
    let e1 = peer("10.0.0.1", 65_001, 3);
    let e2 = peer("10.0.0.2", 65_001, 1);
    let e3 = peer("10.0.0.3", 65_003, 2);
    let mut a = attrs(&[65_001], "10.0.0.1");
    a.med = Some(5);
    let mut b = attrs(&[65_001], "10.0.0.2");
    b.med = Some(10);
    let c = attrs(&[65_003], "10.0.0.3");
    let routes = [(&e1, a), (&e2, b), (&e3, c)];
    let winner = |order: [usize; 3]| {
        let r: Vec<_> = order.iter().map(|i| routes[*i].clone()).collect();
        order[best_of(&r).unwrap()]
    };
    // b is out on MED; of a and c, c has the lower router id.
    for order in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        assert_eq!(winner(order), 2, "{order:?}");
    }
}

#[test]
fn med_uses_the_leftmost_as_for_internal_routes() {
    // Two internal peers relaying routes from AS 65_001.
    let i1 = peer("10.0.0.1", 65_000, 1);
    let i2 = peer("10.0.0.2", 65_000, 2);
    let mut a = attrs(&[65_001, 5], "10.0.0.1");
    a.med = Some(20);
    let mut b = attrs(&[65_001, 6], "10.0.0.2");
    b.med = Some(10);
    let c = [(&i1, a), (&i2, b)];
    assert_eq!(best_of(&c), Some(1));
}

#[test]
fn external_beats_internal() {
    let i = peer("10.0.0.1", 65_000, 1);
    let e = peer("10.0.0.2", 65_002, 2);
    let c = [
        (&i, attrs(&[65_002], "10.0.0.1")),
        (&e, attrs(&[65_002], "10.0.0.2")),
    ];
    assert_eq!(best_of(&c), Some(1));
}

#[test]
fn lower_router_id_then_lower_peer_address() {
    let e1 = peer("10.0.0.9", 65_001, 5);
    let e2 = peer("10.0.0.2", 65_002, 7);
    let c = [
        (&e1, attrs(&[65_001], "10.0.0.9")),
        (&e2, attrs(&[65_002], "10.0.0.2")),
    ];
    assert_eq!(best_of(&c), Some(0));
    let e3 = peer("10.0.0.2", 65_002, 5);
    let c = [
        (&e1, attrs(&[65_001], "10.0.0.9")),
        (&e3, attrs(&[65_002], "10.0.0.2")),
    ];
    assert_eq!(best_of(&c), Some(1));
    assert_eq!(best_of(&[]), None);
}

// --- RFC 4271 §5.1, §9.2 export rules ----------------------------------

#[test]
fn export_to_external_peer_prepends_and_rewrites() {
    let from = peer("10.0.0.1", 65_001, 1);
    let to = peer("10.0.0.2", 65_002, 2);
    let mut a = attrs(&[65_001, 3], "10.0.0.1");
    a.med = Some(5);
    a.local_pref = Some(300);
    let src = Source {
        peer: from.addr,
        kind: from.kind,
    };
    let e = export(LOCAL_AS, V4, src, &a, &to).unwrap();
    assert_eq!(
        e.as_path.asns().collect::<Vec<_>>(),
        vec![LOCAL_AS, Asn(65_001), Asn(3)]
    );
    assert_eq!(e.next_hop, NextHop::Ipv4(Ipv4Addr::new(10, 0, 0, 254)));
    assert_eq!(e.med, None);
    assert_eq!(e.local_pref, None);
    // Not back to the source peer.
    assert!(export(LOCAL_AS, V4, src, &a, &from).is_none());
    // Not for a family the peer did not negotiate.
    let mut v4_only = to.clone();
    v4_only.families = vec![V4];
    assert!(export(LOCAL_AS, V6, src, &a, &v4_only).is_none());
}

#[test]
fn export_to_internal_peer_keeps_attributes_and_sets_local_pref() {
    let from = peer("10.0.0.1", 65_001, 1);
    let to = peer("10.0.0.2", 65_000, 2);
    let mut a = attrs(&[65_001], "10.0.0.1");
    a.med = Some(5);
    let src = Source {
        peer: from.addr,
        kind: from.kind,
    };
    let e = export(LOCAL_AS, V4, src, &a, &to).unwrap();
    assert_eq!(e.as_path, a.as_path);
    assert_eq!(e.next_hop, a.next_hop);
    assert_eq!(e.med, Some(5));
    assert_eq!(e.local_pref, Some(100));
    // Internal to internal: never.
    let ifrom = peer("10.0.0.3", 65_000, 3);
    let isrc = Source {
        peer: ifrom.addr,
        kind: ifrom.kind,
    };
    assert!(export(LOCAL_AS, V4, isrc, &a, &to).is_none());
}

#[test]
fn non_transitive_extended_communities_stay_in_the_as() {
    use bgpfc_wire::community::ExtendedCommunity;
    let from = peer("10.0.0.1", 65_001, 1);
    let ext = peer("10.0.0.2", 65_002, 2);
    let int = peer("10.0.0.3", 65_000, 3);
    let src = Source {
        peer: from.addr,
        kind: from.kind,
    };
    let mut a = attrs(&[65_001], "10.0.0.1");
    let transitive = ExtendedCommunity::two_octet_as(2, true, 1, 1);
    let local_only = ExtendedCommunity::two_octet_as(2, false, 1, 2);
    a.ext_communities = vec![transitive, local_only].into();
    a.normalise();
    let e = export(LOCAL_AS, V4, src, &a, &ext).unwrap();
    assert_eq!(*e.ext_communities, [transitive]);
    let i = export(LOCAL_AS, V4, src, &a, &int).unwrap();
    assert_eq!(i.ext_communities.len(), 2);
}

#[test]
fn well_known_communities_limit_export() {
    let from = peer("10.0.0.1", 65_001, 1);
    let ext = peer("10.0.0.2", 65_002, 2);
    let int = peer("10.0.0.3", 65_000, 3);
    let src = Source {
        peer: from.addr,
        kind: from.kind,
    };
    let mut a = attrs(&[65_001], "10.0.0.1");
    a.communities = vec![Community::NO_EXPORT].into();
    a.normalise();
    assert!(export(LOCAL_AS, V4, src, &a, &ext).is_none());
    assert!(export(LOCAL_AS, V4, src, &a, &int).is_some());
    a.communities = vec![Community::NO_ADVERTISE].into();
    assert!(export(LOCAL_AS, V4, src, &a, &ext).is_none());
    assert!(export(LOCAL_AS, V4, src, &a, &int).is_none());
}

#[test]
fn ipv6_next_hop_self_and_v4_over_v6_session() {
    let from = peer("2001:db8::1", 65_001, 1);
    let to = peer("2001:db8::2", 65_002, 2);
    let src = Source {
        peer: from.addr,
        kind: from.kind,
    };
    let a = attrs(&[65_001], "2001:db8::1");
    let e = export(LOCAL_AS, V6, src, &a, &to).unwrap();
    assert_eq!(
        e.next_hop,
        NextHop::Ipv6 {
            global: "2001:db8::fe".parse().unwrap(),
            link_local: None
        }
    );
    // IPv4 route over the IPv6 session: next hop left alone.
    let a4 = attrs(&[65_001], "192.0.2.1");
    let e = export(LOCAL_AS, V4, src, &a4, &to).unwrap();
    assert_eq!(e.next_hop, a4.next_hop);
}

// --- The RIB end to end --------------------------------------------------

#[test]
fn announce_withdraw_and_fib_changes() {
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_002, 2);
    assert_eq!(outputs(|o| rib.peer_up(e1.clone(), o)).len(), 0);
    assert_eq!(outputs(|o| rib.peer_up(e2.clone(), o)).len(), 0);
    let a = attrs(&[65_001, 7], "10.0.0.1");
    let out = outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24", "198.51.100.0/24"], &a),
            o,
        );
    });
    assert_eq!(
        fib(&out),
        vec![
            FibChange {
                family: V4,
                prefix: p("192.0.2.0/24"),
                next_hop: Some(ip("10.0.0.1")),
                previous: None,
            },
            FibChange {
                family: V4,
                prefix: p("198.51.100.0/24"),
                next_hop: Some(ip("10.0.0.1")),
                previous: None,
            },
        ]
    );
    // Sent to e2 only, not back to e1.
    assert_eq!(sends(&out, e1.addr).len(), 0);
    let m = decode_sent(sends(&out, e2.addr)[0], &e2);
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].nlri, vec![p("192.0.2.0/24"), p("198.51.100.0/24")]);
    assert_eq!(
        m[0].as_path().unwrap().asns().collect::<Vec<_>>(),
        vec![LOCAL_AS, Asn(65_001), Asn(7)]
    );
    assert_eq!(m[0].next_hop(), Some(Ipv4Addr::new(10, 0, 0, 254)));
    assert_eq!(
        rib.peer_stats(e1.addr).unwrap().received,
        vec![(V4, 2), (V6, 0)]
    );
    assert_eq!(
        rib.peer_stats(e2.addr).unwrap().advertised,
        vec![(V4, 2), (V6, 0)]
    );

    // Re-announcing the same thing changes nothing.
    let out = outputs(|o| rib.update(e1.addr, &announce(&["192.0.2.0/24"], &a), o));
    assert!(out.is_empty(), "{out:?}");

    // A better route from e2 (shorter path) replaces it: e1 is told,
    // e2 is not.
    let b = attrs(&[65_002], "10.0.0.2");
    let out = outputs(|o| rib.update(e2.addr, &announce(&["192.0.2.0/24"], &b), o));
    assert_eq!(fib(&out)[0].next_hop, Some(ip("10.0.0.2")));
    assert_eq!(fib(&out)[0].previous, Some(ip("10.0.0.1")));
    let m = decode_sent(sends(&out, e1.addr)[0], &e1);
    assert_eq!(m[0].nlri, vec![p("192.0.2.0/24")]);
    // e2 had e1's route; its own is not sent back, so it is withdrawn.
    let m = decode_sent(sends(&out, e2.addr)[0], &e2);
    assert_eq!(m[0].withdrawn, vec![p("192.0.2.0/24")]);
    assert_eq!(m[0].nlri.len(), 0);
    assert_eq!(rib.loc_rib(V4).count(), 2);
    assert_eq!(rib.candidates(V4, p("192.0.2.0/24")).count(), 2);

    // Withdraw from e2: back to e1's route; e2 gets it, e1 gets a withdraw.
    let out = outputs(|o| rib.update(e2.addr, &withdraw(&["192.0.2.0/24"]), o));
    assert_eq!(fib(&out)[0].next_hop, Some(ip("10.0.0.1")));
    assert_eq!(fib(&out)[0].previous, Some(ip("10.0.0.2")));
    // What the FIB is given when it reconciles in full, in prefix order.
    assert_eq!(
        rib.fib_routes().collect::<Vec<_>>(),
        vec![
            (p("192.0.2.0/24"), ip("10.0.0.1")),
            (p("198.51.100.0/24"), ip("10.0.0.1"))
        ]
    );
    let m = decode_sent(sends(&out, e1.addr)[0], &e1);
    assert_eq!(m[0].withdrawn, vec![p("192.0.2.0/24")]);
    let m = decode_sent(sends(&out, e2.addr)[0], &e2);
    assert_eq!(m[0].nlri, vec![p("192.0.2.0/24")]);

    // Peer down: everything from e1 goes.
    let out = outputs(|o| rib.peer_down(e1.addr, o));
    let f = fib(&out);
    assert_eq!(f.len(), 2);
    assert!(f.iter().all(|c| c.next_hop.is_none()));
    assert!(f.iter().all(|c| c.previous == Some(ip("10.0.0.1"))));
    assert_eq!(rib.fib_routes().count(), 0);
    let m = decode_sent(sends(&out, e2.addr)[0], &e2);
    assert_eq!(m[0].withdrawn.len(), 2);
    assert_eq!(rib.loc_rib(V4).count(), 0);
    assert_eq!(rib.adj_rib_out(e2.addr, V4).len(), 0);
    assert_eq!(rib.peers().count(), 1);
}

#[test]
fn leftmost_as_must_be_the_external_peer() {
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    let i1 = peer("10.0.0.3", 65_000, 3);
    outputs(|o| rib.peer_up(e1.clone(), o));
    outputs(|o| rib.peer_up(i1.clone(), o));
    // RFC 7606 §7.2: an external route not starting with the peer's AS is
    // treated as withdrawn.
    let out = outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_009], "10.0.0.1")),
            o,
        );
    });
    assert_eq!(fib(&out).len(), 0);
    assert_eq!(rib.loc_rib(V4).count(), 0);
    // An empty path from an external peer likewise.
    let out = outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[], "10.0.0.1")),
            o,
        );
    });
    assert_eq!(fib(&out).len(), 0);
    // Internal peers may relay any path, including an empty one.
    let mut a = attrs(&[65_009], "10.0.0.3");
    a.local_pref = Some(100);
    let out = outputs(|o| rib.update(i1.addr, &announce(&["192.0.2.0/24"], &a), o));
    assert_eq!(fib(&out).len(), 1);
}

#[test]
fn prefix_in_both_withdrawn_and_nlri_is_announced() {
    // RFC 4271 §4.3: a prefix in both Withdrawn Routes and NLRI is treated
    // as not withdrawn.
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    outputs(|o| rib.peer_up(e1.clone(), o));
    let mut u = announce(&["192.0.2.0/24"], &attrs(&[65_001], "10.0.0.1"));
    u.message.withdrawn = vec![p("192.0.2.0/24")];
    let out = outputs(|o| rib.update(e1.addr, &u, o));
    assert_eq!(fib(&out).len(), 1);
    assert_eq!(fib(&out)[0].next_hop, Some(ip("10.0.0.1")));
    assert_eq!(rib.loc_rib(V4).count(), 1);
}

#[test]
fn as_loop_routes_are_excluded() {
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    outputs(|o| rib.peer_up(e1.clone(), o));
    let a = attrs(&[65_001, LOCAL_AS.0, 7], "10.0.0.1");
    let out = outputs(|o| rib.update(e1.addr, &announce(&["192.0.2.0/24"], &a), o));
    assert_eq!(out.len(), 0);
    assert_eq!(rib.loc_rib(V4).count(), 0);
    // A replacement with a loop withdraws the earlier good route.
    let good = attrs(&[65_001], "10.0.0.1");
    outputs(|o| rib.update(e1.addr, &announce(&["192.0.2.0/24"], &good), o));
    assert_eq!(rib.loc_rib(V4).count(), 1);
    let out = outputs(|o| rib.update(e1.addr, &announce(&["192.0.2.0/24"], &a), o));
    assert_eq!(fib(&out)[0].next_hop, None);
}

#[test]
fn new_peer_receives_the_loc_rib_and_route_refresh_resends_it() {
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    outputs(|o| rib.peer_up(e1.clone(), o));
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_001], "10.0.0.1")),
            o,
        );
    });
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["2001:db8:1::/48"], &attrs(&[65_001], "2001:db8::1")),
            o,
        );
    });
    let i = peer("10.0.0.3", 65_000, 3);
    let out = outputs(|o| rib.peer_up(i.clone(), o));
    let s = sends(&out, i.addr);
    assert_eq!(s.len(), 2, "one batch per family");
    let v4 = decode_sent(s[0], &i);
    assert_eq!(v4[0].nlri, vec![p("192.0.2.0/24")]);
    assert_eq!(v4[0].attribute(5), Some(&PathAttribute::LocalPref(100)));
    let v6 = decode_sent(s[1], &i);
    let r = v6[0].mp_reach.as_ref().unwrap();
    assert_eq!(r.family, V6);
    assert_eq!(r.nlri, vec![p("2001:db8:1::/48")]);
    // Refresh: the same again, no FIB change.
    let out = outputs(|o| rib.refresh(i.addr, V6, o));
    assert_eq!(fib(&out).len(), 0);
    let v6 = decode_sent(sends(&out, i.addr)[0], &i);
    assert_eq!(
        v6[0].mp_reach.as_ref().unwrap().nlri,
        vec![p("2001:db8:1::/48")]
    );
    // A family the peer does not speak: nothing.
    let mut v4_only = peer("10.0.0.4", 65_004, 4);
    v4_only.families = vec![V4];
    let out = outputs(|o| rib.peer_up(v4_only.clone(), o));
    assert_eq!(sends(&out, v4_only.addr).len(), 1);
    assert_eq!(outputs(|o| rib.refresh(v4_only.addr, V6, o)).len(), 0);
    assert_eq!(outputs(|o| rib.refresh(ip("10.9.9.9"), V4, o)).len(), 0);
}

#[test]
fn family_disable_drops_that_family_only() {
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    outputs(|o| rib.peer_up(e1.clone(), o));
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_001], "10.0.0.1")),
            o,
        );
    });
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["2001:db8:1::/48"], &attrs(&[65_001], "2001:db8::1")),
            o,
        );
    });
    let out = outputs(|o| rib.family_disabled(e1.addr, V6, o));
    assert_eq!(fib(&out).len(), 1);
    assert_eq!(rib.loc_rib(V6).count(), 0);
    assert_eq!(rib.loc_rib(V4).count(), 1);
    // Later IPv6 announcements are ignored.
    let out = outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["2001:db8:2::/48"], &attrs(&[65_001], "2001:db8::1")),
            o,
        );
    });
    assert_eq!(out.len(), 0);
    // Unknown peers are ignored everywhere.
    let out = outputs(|o| rib.update(ip("10.9.9.9"), &withdraw(&["192.0.2.0/24"]), o));
    assert_eq!(out.len(), 0);
    assert_eq!(outputs(|o| rib.peer_down(ip("10.9.9.9"), o)).len(), 0);
    assert_eq!(
        outputs(|o| rib.family_disabled(ip("10.9.9.9"), V4, o)).len(),
        0
    );
}

#[test]
fn large_batches_are_packed_within_the_message_limit() {
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    let mut e2 = peer("10.0.0.2", 65_002, 2);
    e2.four_octet_as = false;
    outputs(|o| rib.peer_up(e1.clone(), o));
    outputs(|o| rib.peer_up(e2.clone(), o));
    // 3000 /24s: more than fit in one 4096-octet UPDATE.
    let prefixes: Vec<String> = (0..3000u32)
        .map(|i| format!("10.{}.{}.0/24", (i >> 8) + 1, i & 0xff))
        .collect();
    let refs: Vec<&str> = prefixes.iter().map(String::as_str).collect();
    let a = attrs(&[65_001, 4_200_000_000], "10.0.0.1");
    let out = outputs(|o| rib.update(e1.addr, &announce(&refs, &a), o));
    let s = sends(&out, e2.addr);
    assert_eq!(s.len(), 1);
    let msgs = decode_sent(s[0], &e2);
    assert!(msgs.len() > 1, "{} messages", msgs.len());
    let total: usize = msgs.iter().map(|m| m.nlri.len()).sum();
    assert_eq!(total, 3000);
    // Two-octet peer: AS_TRANS on the wire, reconstructed from AS4_PATH.
    assert_eq!(
        msgs[0].as_path().unwrap().asns().collect::<Vec<_>>(),
        vec![LOCAL_AS, Asn(65_001), Asn(4_200_000_000)]
    );
    // Withdrawing them all packs likewise.
    let out = outputs(|o| rib.peer_down(e1.addr, o));
    let msgs = decode_sent(sends(&out, e2.addr)[0], &e2);
    assert!(msgs.len() > 1);
    let total: usize = msgs.iter().map(|m| m.withdrawn.len()).sum();
    assert_eq!(total, 3000);
    // Nothing uses an attribute set any more, and none is kept.
    assert_eq!(rib.attribute_sets(), 0);
}

#[test]
fn each_update_carries_one_kind_of_route_with_mp_attributes_first() {
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("2001:db8::1", 65_001, 1);
    let e2 = peer("2001:db8::2", 65_002, 2);
    outputs(|o| rib.peer_up(e1.clone(), o));
    outputs(|o| rib.peer_up(e2.clone(), o));
    let v4 = attrs(&[65_001], "10.0.0.1");
    let v6 = attrs(&[65_001], "2001:db8::1");
    outputs(|o| rib.update(e1.addr, &announce(&["192.0.2.0/24"], &v4), o));
    outputs(|o| rib.update(e1.addr, &announce(&["2001:db8:1::/48"], &v6), o));
    // One UPDATE with all four, as RFC 7606 §5.1 says we must accept.
    let mut message = v4.to_update(V4, vec![p("198.51.100.0/24")]);
    message.withdrawn = vec![p("192.0.2.0/24")];
    message.mp_reach = v6.to_update(V6, vec![p("2001:db8:2::/48")]).mp_reach;
    message.mp_unreach = Some(bgpfc_wire::mp::MpUnreach {
        family: V6,
        withdrawn: vec![p("2001:db8:1::/48")],
    });
    let update = DecodedUpdate {
        message,
        treated_as_withdraw: None,
        discarded: Vec::new(),
    };
    let out = outputs(|o| rib.update(e1.addr, &update, o));
    // RFC 7606 §5.1: what we send carries at most one of withdrawn
    // routes, NLRI, MP_REACH_NLRI and MP_UNREACH_NLRI, and an MP
    // attribute comes first.
    let mut kinds = Vec::new();
    for messages in sends(&out, e2.addr) {
        for (raw, m) in messages.iter().zip(decode_sent(messages, &e2)) {
            let present = [
                !m.withdrawn.is_empty(),
                !m.nlri.is_empty(),
                m.mp_reach.is_some(),
                m.mp_unreach.is_some(),
            ];
            assert_eq!(present.iter().filter(|k| **k).count(), 1, "{m:?}");
            let kind = present.iter().position(|k| *k).unwrap();
            // MP_REACH_NLRI is type 14, MP_UNREACH_NLRI 15 (RFC 4760 §3, §4).
            let mp_type = [None, None, Some(14), Some(15)][kind];
            if mp_type.is_some() {
                assert_eq!(first_attribute_type(raw), mp_type);
            }
            kinds.push(kind);
        }
    }
    kinds.sort_unstable();
    assert_eq!(kinds, vec![0, 1, 2, 3]);
}

#[test]
fn attributes_round_trip_through_an_update() {
    let mut a = attrs(&[65_001], "10.0.0.1");
    a.med = Some(7);
    a.local_pref = Some(50);
    a.atomic_aggregate = true;
    a.aggregator = Some(bgpfc_wire::attribute::Aggregator {
        asn: Asn(65_001),
        address: Ipv4Addr::new(1, 1, 1, 1),
    });
    a.communities = vec![Community::new(65_001, 2), Community::new(65_001, 1)].into();
    a.large_communities = vec![bgpfc_wire::community::LargeCommunity {
        global: 1,
        local1: 2,
        local2: 3,
    }]
    .into();
    a.unknown = vec![crate::attrs::UnknownAttribute {
        flags: 0xc0,
        code: 200,
        value: vec![1, 2],
    }]
    .into();
    a.normalise();
    let m = a.to_update(V4, vec![p("192.0.2.0/24")]);
    let back = PathAttrs::from_update(&m, V4).unwrap();
    assert_eq!(
        *back.communities,
        [Community::new(65_001, 1), Community::new(65_001, 2)]
    );
    // The Partial bit is set on the forwarded unknown attribute.
    assert_eq!(back.unknown[0].flags, 0xe0);
    let mut expect = a.clone();
    expect.unknown[0].flags = 0xe0;
    assert_eq!(back, expect);
    assert!(PathAttrs::from_update(&UpdateMessage::default(), V4).is_none());
    assert!(a.has_community(Community::new(65_001, 2)));
    assert_eq!(a.next_hop_afi(), bgpfc_wire::types::Afi::Ipv4);
}

#[test]
fn interner_shares_and_sweeps() {
    let mut i = crate::attrs::Interner::default();
    let a = i.intern(attrs(&[1], "10.0.0.1"));
    let b = i.intern(attrs(&[1], "10.0.0.1"));
    assert!(Arc::ptr_eq(&a, &b));
    assert_eq!(i.len(), 1);
    drop(a);
    drop(b);
    i.sweep();
    assert_eq!(i.len(), 0);
}

#[test]
fn reexport_sends_only_the_difference() {
    use crate::{Policies, Verdict};
    struct DropOdd;
    impl Policies for DropOdd {
        fn import(&self, _: &PeerInfo, _: AddressFamily, _: Prefix, _: &PathAttrs) -> Verdict {
            Verdict::Accept
        }
        fn export(&self, _: &PeerInfo, _: AddressFamily, p: Prefix, _: &PathAttrs) -> Verdict {
            if p == self::p("192.0.2.0/24") {
                Verdict::Reject
            } else {
                Verdict::Accept
            }
        }
    }
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_002, 2);
    outputs(|o| rib.peer_up(e1.clone(), o));
    outputs(|o| rib.peer_up(e2.clone(), o));
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(
                &["192.0.2.0/24", "198.51.100.0/24"],
                &attrs(&[65_001], "10.0.0.1"),
            ),
            o,
        );
    });
    assert_eq!(rib.adj_rib_out(e2.addr, V4).len(), 2);
    // The same policies again: nothing sent.
    let out = outputs(|o| rib.set_policies(Box::new(crate::AcceptAll), &[e2.addr], o));
    assert_eq!(out.len(), 0);
    let out = outputs(|o| rib.set_policies(Box::new(DropOdd), &[e2.addr], o));
    let m = decode_sent(sends(&out, e2.addr)[0], &e2);
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].withdrawn, vec![p("192.0.2.0/24")]);
    assert_eq!(m[0].nlri.len(), 0);
    assert_eq!(rib.adj_rib_out(e2.addr, V4).len(), 1);
    assert_eq!(
        rib.peer_stats(e2.addr).unwrap().advertised,
        vec![(V4, 1), (V6, 0)]
    );
    // And back: the route is announced again.
    let out = outputs(|o| rib.set_policies(Box::new(crate::AcceptAll), &[e2.addr], o));
    let m = decode_sent(sends(&out, e2.addr)[0], &e2);
    assert_eq!(m[0].nlri, vec![p("192.0.2.0/24")]);
    assert_eq!(
        rib.peer_stats(e2.addr).unwrap().advertised,
        vec![(V4, 2), (V6, 0)]
    );
    assert!(rib.peer(e2.addr).is_some());
    assert!(rib.peer(ip("10.9.9.9")).is_none());
    let out = outputs(|o| rib.set_policies(Box::new(DropOdd), &[ip("10.9.9.9")], o));
    assert_eq!(out.len(), 0);
}

#[test]
fn peer_down_leaves_no_route_for_the_next_peer_in_its_slot() {
    let mut rib = Rib::new(LOCAL_AS);
    let mut e1 = peer("10.0.0.1", 65_001, 1);
    e1.families = vec![V4];
    outputs(|o| rib.peer_up(e1.clone(), o));
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_001], "10.0.0.1")),
            o,
        );
    });
    // A family the session did not negotiate: still stored (the decoder
    // does not filter by family), so peer down must look there too.
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["2001:db8:1::/48"], &attrs(&[65_001], "2001:db8::1")),
            o,
        );
    });
    assert_eq!(rib.loc_rib(V6).count(), 1);
    let out = outputs(|o| rib.peer_down(e1.addr, o));
    assert_eq!(fib(&out).len(), 2);
    assert_eq!(rib.loc_rib(V4).count(), 0);
    assert_eq!(rib.loc_rib(V6).count(), 0);
    // The next peer takes the free slot and inherits nothing.
    let e2 = peer("10.0.0.2", 65_002, 2);
    outputs(|o| rib.peer_up(e2.clone(), o));
    assert_eq!(rib.candidates(V6, p("2001:db8:1::/48")).count(), 0);
    outputs(|o| {
        rib.update(
            e2.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_002], "10.0.0.2")),
            o,
        );
    });
    let routes: Vec<IpAddr> = rib
        .candidates(V4, p("192.0.2.0/24"))
        .map(|r| r.peer)
        .collect();
    assert_eq!(routes, vec![e2.addr]);
    assert_eq!(
        rib.peer_stats(e2.addr).unwrap().received,
        vec![(V4, 1), (V6, 0)]
    );
}

#[test]
fn best_route_is_listed_first() {
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_002, 2);
    let e3 = peer("10.0.0.3", 65_003, 3);
    for e in [&e1, &e2, &e3] {
        outputs(|o| rib.peer_up(e.clone(), o));
    }
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_001, 7, 8], "10.0.0.1")),
            o,
        );
    });
    outputs(|o| {
        rib.update(
            e2.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_002], "10.0.0.2")),
            o,
        );
    });
    outputs(|o| {
        rib.update(
            e3.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_003, 7], "10.0.0.3")),
            o,
        );
    });
    let order = |rib: &Rib| -> Vec<IpAddr> {
        rib.candidates(V4, p("192.0.2.0/24"))
            .map(|r| r.peer)
            .collect()
    };
    assert_eq!(order(&rib)[0], e2.addr);
    assert_eq!(order(&rib).len(), 3);
    assert_eq!(rib.loc_rib(V4).next().unwrap().1.peer, e2.addr);
    // The best goes: the next best (shorter path) takes its place.
    let out = outputs(|o| rib.update(e2.addr, &withdraw(&["192.0.2.0/24"]), o));
    assert_eq!(fib(&out)[0].next_hop, Some(ip("10.0.0.3")));
    assert_eq!(order(&rib), vec![e3.addr, e1.addr]);
    // A non-best route going changes nothing.
    let out = outputs(|o| rib.update(e1.addr, &withdraw(&["192.0.2.0/24"]), o));
    assert!(out.is_empty(), "{out:?}");
    assert_eq!(order(&rib), vec![e3.addr]);
}

#[test]
fn interner_releases_a_set_with_its_last_holder() {
    let mut i = crate::attrs::Interner::default();
    let a = i.intern(attrs(&[1], "10.0.0.1"));
    let b = i.intern(attrs(&[1], "10.0.0.1"));
    // Another holder remains: the set stays.
    i.release(a);
    assert_eq!(i.len(), 1);
    i.release(b);
    assert_eq!(i.len(), 0);
    // Equal attributes in an allocation the interner does not hold leave
    // its entry alone.
    let held = i.intern(attrs(&[2], "10.0.0.1"));
    let stranger = Arc::new(attrs(&[2], "10.0.0.1"));
    i.release(Arc::clone(&stranger));
    assert_eq!(i.len(), 1);
    drop(stranger);
    i.release(held);
    assert_eq!(i.len(), 0);
}

#[test]
fn attribute_sets_go_with_their_last_route() {
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_002, 2);
    let i3 = peer("10.0.0.3", 65_000, 3);
    for p in [&e1, &e2, &i3] {
        outputs(|o| rib.peer_up(p.clone(), o));
    }
    let a = attrs(&[65_001, 7], "10.0.0.1");
    let b = attrs(&[65_002], "10.0.0.2");
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24", "198.51.100.0/24"], &a),
            o,
        );
    });
    outputs(|o| rib.update(e2.addr, &announce(&["192.0.2.0/24"], &b), o));
    // Received sets a and b; the peers they are sent to get them
    // rewritten when encoded, not as sets of their own.
    assert_eq!(rib.attribute_sets(), 2);
    // Replacing a route lets its old set go once nothing uses it.
    let a2 = attrs(&[65_001, 8], "10.0.0.1");
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24", "198.51.100.0/24"], &a2),
            o,
        );
    });
    let held = rib.attribute_sets();
    outputs(|o| rib.update(e2.addr, &withdraw(&["192.0.2.0/24"]), o));
    assert!(rib.attribute_sets() < held);
    outputs(|o| {
        rib.update(e1.addr, &withdraw(&["192.0.2.0/24", "198.51.100.0/24"]), o);
    });
    assert_eq!(rib.attribute_sets(), 0);

    // The same through peer down, including what the peer was sent.
    outputs(|o| rib.update(e1.addr, &announce(&["192.0.2.0/24"], &a), o));
    outputs(|o| rib.update(e2.addr, &announce(&["198.51.100.0/24"], &b), o));
    assert!(rib.attribute_sets() > 0);
    outputs(|o| rib.peer_down(e1.addr, o));
    outputs(|o| rib.peer_down(e2.addr, o));
    assert_eq!(rib.attribute_sets(), 0);
}

#[test]
fn a_prefix_listed_twice_in_an_update_changes_once() {
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_002, 2);
    outputs(|o| rib.peer_up(e1.clone(), o));
    outputs(|o| rib.peer_up(e2.clone(), o));
    let a = attrs(&[65_001], "10.0.0.1");
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24", "198.51.100.0/24"], &a),
            o,
        );
    });
    // Withdrawn and announced again unchanged, in one UPDATE: the best
    // route before and after is the same, so nothing follows.
    let mut again = announce(&["192.0.2.0/24"], &a);
    again.message.withdrawn = vec![p("192.0.2.0/24")];
    let out = outputs(|o| rib.update(e1.addr, &again, o));
    assert!(out.is_empty(), "{out:?}");
    // The same with new attributes, the prefix twice in the NLRI too:
    // one FIB change, one announcement to e2.
    let longer = attrs(&[65_001, 9], "10.0.0.9");
    let mut twice = announce(
        &["192.0.2.0/24", "198.51.100.0/24", "192.0.2.0/24"],
        &longer,
    );
    twice.message.withdrawn = vec![p("192.0.2.0/24")];
    let out = outputs(|o| rib.update(e1.addr, &twice, o));
    let changes = fib(&out);
    assert_eq!(changes.len(), 2, "{changes:?}");
    assert_eq!(changes[0].prefix, p("192.0.2.0/24"));
    assert_eq!(changes[0].next_hop, Some(ip("10.0.0.9")));
    let sent = decode_sent(sends(&out, e2.addr)[0], &e2);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].withdrawn.len(), 0);
    assert_eq!(sent[0].nlri, vec![p("192.0.2.0/24"), p("198.51.100.0/24")]);
    assert_eq!(rib.loc_rib(V4).count(), 2);
}

#[test]
fn attribute_hash_follows_every_field() {
    use bgpfc_wire::community::{ExtendedCommunity, LargeCommunity};
    use std::hash::BuildHasher;
    let hasher = std::collections::hash_map::RandomState::new();
    let mut base = attrs(&[65_001, 7], "10.0.0.1");
    base.med = Some(5);
    base.local_pref = Some(100);
    base.aggregator = Some(bgpfc_wire::attribute::Aggregator {
        asn: Asn(65_001),
        address: Ipv4Addr::new(1, 1, 1, 1),
    });
    base.communities = vec![Community::new(65_001, 1)].into();
    base.ext_communities = vec![ExtendedCommunity::two_octet_as(2, true, 1, 1)].into();
    base.large_communities = vec![LargeCommunity {
        global: 1,
        local1: 2,
        local2: 3,
    }]
    .into();
    base.unknown = vec![crate::attrs::UnknownAttribute {
        flags: 0xc0,
        code: 200,
        value: vec![1, 2],
    }]
    .into();
    assert_eq!(hasher.hash_one(&base), hasher.hash_one(base.clone()));
    let changes: Vec<fn(&mut PathAttrs)> = vec![
        |a| a.origin = Origin::Egp,
        |a| a.as_path = AsPath::sequence(&[Asn(65_001), Asn(8)]),
        |a| a.as_path = AsPath::sequence(&[Asn(65_001)]),
        |a| a.next_hop = NextHop::Ipv4(Ipv4Addr::new(10, 0, 0, 2)),
        |a| a.med = None,
        |a| a.local_pref = Some(5),
        |a| a.atomic_aggregate = true,
        |a| a.aggregator = None,
        |a| {
            a.communities = [&a.communities[..], &[Community::new(65_001, 2)]]
                .concat()
                .into();
        },
        |a| a.ext_communities = Box::default(),
        |a| a.large_communities[0].local2 = 4,
        |a| a.unknown[0].value.push(3),
        |a| {
            a.next_hop = NextHop::Ipv6 {
                global: "2001:db8::1".parse().unwrap(),
                link_local: Some("fe80::1".parse().unwrap()),
            };
        },
    ];
    for (i, change) in changes.iter().enumerate() {
        let mut other = base.clone();
        change(&mut other);
        assert_ne!(other, base, "change {i}");
        assert_ne!(
            hasher.hash_one(&other),
            hasher.hash_one(&base),
            "change {i}"
        );
    }
}

#[test]
fn interner_gives_its_table_back_when_emptied() {
    let mut i = crate::attrs::Interner::default();
    let held: Vec<_> = (0..1000u32)
        .map(|n| i.intern(attrs(&[n + 1], "10.0.0.1")))
        .collect();
    let full = i.capacity();
    assert!(full >= 1000);
    for a in held {
        i.release(a);
    }
    assert_eq!(i.len(), 0);
    assert!(i.capacity() < full / 4, "{} of {full}", i.capacity());
}

#[test]
fn peers_are_sent_rewritten_sets_without_a_copy_per_peer() {
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_002, 2);
    let i1 = peer("10.0.0.3", LOCAL_AS.0, 3);
    let mut rib = Rib::new(LOCAL_AS);
    let _ = outputs(|o| {
        rib.peer_up(e1.clone(), o);
        rib.peer_up(e2.clone(), o);
        rib.peer_up(i1.clone(), o);
    });
    let prefixes = ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"];
    let a = attrs(&[65_001, 64_500], "10.0.0.1");
    let out = outputs(|o| rib.update(e1.addr, &announce(&prefixes, &a), o));
    // RFC 4271 §5.1: what each peer is sent is rewritten for its session.
    let m = decode_sent(sends(&out, e2.addr)[0], &e2);
    assert_eq!(m[0].nlri.len(), 3);
    assert_eq!(m[0].as_path().unwrap().first_asn(), Some(LOCAL_AS));
    assert_eq!(m[0].next_hop(), Some(Ipv4Addr::new(10, 0, 0, 254)));
    let m = decode_sent(sends(&out, i1.addr)[0], &i1);
    assert_eq!(m[0].as_path().unwrap().first_asn(), Some(Asn(65_001)));
    assert_eq!(m[0].next_hop(), Some(Ipv4Addr::new(10, 0, 0, 1)));
    // The Adj-RIBs-Out hold the Loc-RIB's own set, not a copy per peer;
    // so does that of a peer that comes up later and is sent the table.
    let e3 = peer("10.0.0.4", 65_003, 4);
    let out = outputs(|o| rib.peer_up(e3.clone(), o));
    let m = decode_sent(sends(&out, e3.addr)[0], &e3);
    assert_eq!(m[0].as_path().unwrap().first_asn(), Some(LOCAL_AS));
    let held = Arc::clone(rib.loc_rib(V4).next().unwrap().1.attrs);
    for to in [&e2, &i1, &e3] {
        assert_eq!(rib.adj_rib_out(to.addr, V4).len(), 3);
        assert!(
            rib.adj_rib_out(to.addr, V4)
                .iter()
                .all(|(_, x)| Arc::ptr_eq(x, &held))
        );
    }
    assert_eq!(rib.s.cx.interner.len(), 1);
    drop(held);
    // Withdrawn, the set goes with its last route.
    let _ = outputs(|o| rib.update(e1.addr, &withdraw(&prefixes), o));
    assert_eq!(rib.adj_rib_out(e2.addr, V4).len(), 0);
    assert_eq!(rib.s.cx.interner.len(), 0);
}

#[test]
fn a_change_the_session_rewrite_hides_is_not_sent() {
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_002, 2);
    let i1 = peer("10.0.0.3", LOCAL_AS.0, 3);
    let mut rib = Rib::new(LOCAL_AS);
    let _ = outputs(|o| {
        rib.peer_up(e1.clone(), o);
        rib.peer_up(e2.clone(), o);
        rib.peer_up(i1.clone(), o);
    });
    let a = attrs(&[65_001], "10.0.0.1");
    let _ = outputs(|o| rib.update(e1.addr, &announce(&["192.0.2.0/24"], &a), o));
    // Another next hop and MED: an external peer gets ours and no MED
    // (RFC 4271 §5.1.3, §5.1.4), so nothing it would see changed; an
    // internal peer gets both as received.
    let mut b = attrs(&[65_001], "10.0.0.9");
    b.med = Some(5);
    let out = outputs(|o| rib.update(e1.addr, &announce(&["192.0.2.0/24"], &b), o));
    assert!(sends(&out, e2.addr).is_empty(), "{out:?}");
    let m = decode_sent(sends(&out, i1.addr)[0], &i1);
    assert_eq!(m[0].next_hop(), Some(Ipv4Addr::new(10, 0, 0, 9)));
    // The Adj-RIB-Out follows the new set all the same.
    let held = Arc::clone(rib.loc_rib(V4).next().unwrap().1.attrs);
    assert!(
        rib.adj_rib_out(e2.addr, V4)
            .iter()
            .all(|(_, x)| Arc::ptr_eq(x, &held))
    );
    // A change it does see is sent.
    let c = attrs(&[65_001, 7], "10.0.0.9");
    let out = outputs(|o| rib.update(e1.addr, &announce(&["192.0.2.0/24"], &c), o));
    assert_eq!(sends(&out, e2.addr).len(), 1);
}

#[test]
fn colliding_sets_are_not_shared_and_nothing_is_lost() {
    use std::hash::{BuildHasherDefault, Hasher};
    // Every set hashes alike: only the first is kept in the table.
    #[derive(Default)]
    struct Zero;
    impl Hasher for Zero {
        fn finish(&self) -> u64 {
            0
        }
        fn write(&mut self, _: &[u8]) {}
    }
    let mut i = crate::attrs::Interner::with_hasher(BuildHasherDefault::<Zero>::default());
    let a1 = i.intern(attrs(&[1], "10.0.0.1"));
    let b1 = i.intern(attrs(&[2], "10.0.0.1"));
    let a2 = i.intern(attrs(&[1], "10.0.0.1"));
    let b2 = i.intern(attrs(&[2], "10.0.0.1"));
    assert!(Arc::ptr_eq(&a1, &a2));
    assert!(!Arc::ptr_eq(&b1, &b2), "a colliding set is not shared");
    assert_eq!(*b1, *b2);
    assert_eq!(i.len(), 1);
    // Releasing a set that is not the table's leaves the table's alone.
    i.release(b1);
    i.release(b2);
    assert_eq!(i.len(), 1);
    i.release(a1);
    i.release(a2);
    assert_eq!(i.len(), 0);
}

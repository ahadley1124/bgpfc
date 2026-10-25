//! Decision-process tests per tie-break step (AGENTS.md §5, `bgpfc-rib`
//! row), export rules, update packing and RIB bookkeeping.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bgpfc_rpki::{AspaState, RovState};
use bgpfc_wire::as_path::AsPath;
use bgpfc_wire::attribute::{Origin, PathAttribute};
use bgpfc_wire::community::Community;
use bgpfc_wire::header::HEADER_LEN;
use bgpfc_wire::mp::NextHop;
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::{AddressFamily, Asn, RouterId};
use bgpfc_wire::update::{DecodeContext, DecodedUpdate, PeerKind, UpdateMessage};

use crate::attrs::{PathAttrs, announced};
use crate::decision::{Candidate, Neighbor, best};
use crate::export::{Source, export};
use crate::peer::PeerInfo;
use crate::{FibChange, Output, Rib};

mod add_path;
mod adj_rib_in;
mod validation;

/// The routes the Adj-RIB-In holds for `prefix`, candidates first, each
/// with the address of the peer it came from.
fn routes(rib: &Rib, family: AddressFamily, prefix: Prefix) -> Vec<(IpAddr, crate::store::Route)> {
    rib.tables
        .get(family)
        .and_then(|t| t.get(prefix))
        .map(|d| {
            d.iter()
                .map(|(r, _)| (rib.s.peer(r.peer).info.addr, r.clone()))
                .collect()
        })
        .unwrap_or_default()
}

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
        receive_families: vec![V4, V6],
        four_octet_as: true,
        extended_messages: false,
        extended_next_hop: Vec::new(),
        // Pacing off: these tests are about what is sent; the RFC 4271
        // §9.2.1.1 tests below are about when.
        advertisement_interval: Duration::ZERO,
        prefix_limits: Vec::new(),
        add_path_receive: Vec::new(),
        add_path_send: Vec::new(),
    }
}

fn now() -> Instant {
    Instant::now()
}

/// Phase 2 over routes given as (peer, attributes).
fn best_of(routes: &[(&PeerInfo, PathAttrs)]) -> Option<usize> {
    best(routes.len(), |i| Candidate {
        from: Neighbor::of(routes[i].0),
        attrs: &routes[i].1,
        path_id: 0,
    })
}

fn announce(prefixes: &[&str], a: &PathAttrs) -> DecodedUpdate {
    let family = if prefixes[0].contains(':') { V6 } else { V4 };
    let message = a.to_update(family, prefixes.iter().map(|s| p(s)).collect());
    DecodedUpdate {
        message,
        treated_as_withdraw: None,
        discarded: Vec::new(),
        disabled: Vec::new(),
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
        disabled: Vec::new(),
    }
}

/// Decode what the RIB asked us to send to `to`.
fn decode_sent(messages: &[Vec<u8>], to: &PeerInfo) -> Vec<UpdateMessage> {
    let ctx = DecodeContext {
        four_octet_as: to.four_octet_as,
        peer: to.kind,
        allow_as_set: false,
        extended_next_hop: to.extended_next_hop.contains(&V4),
        add_path: bgpfc_wire::update::AddPathFamilies::NONE,
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

#[test]
fn link_local_next_hops_are_never_passed_on() {
    // RFC 2545 §3: a link-local address only where we share a subnet with
    // the next hop and the peer, which bgpfc cannot tell; §3 lets it go
    // towards an internal peer.
    let from = peer("2001:db8::1", 65_001, 1);
    let src = Source {
        peer: from.addr,
        kind: from.kind,
    };
    let mut a = attrs(&[65_001], "2001:db8::1");
    a.next_hop = v6_next_hop("2001:db8:1::1", "fe80::1");
    let global = NextHop::Ipv6 {
        global: "2001:db8:1::1".parse().unwrap(),
        link_local: None,
    };
    // To an internal peer, whatever its session.
    for to in [
        peer("2001:db8::5", LOCAL_AS.0, 5),
        peer("10.0.0.6", LOCAL_AS.0, 6),
    ] {
        let e = export(LOCAL_AS, V6, src, &a, &to).unwrap();
        assert_eq!(e.next_hop, global, "{}", to.addr);
    }
    // An IPv6 route to an external peer over IPv4 keeps its next hop
    // (RFC 4271 §5.1.3 has no address of ours to put there), without the
    // link-local address.
    let e = export(LOCAL_AS, V6, src, &a, &peer("10.0.0.4", 65_004, 4)).unwrap();
    assert_eq!(e.next_hop, global);
    // Over IPv6 it is our own global address.
    let e = export(LOCAL_AS, V6, src, &a, &peer("2001:db8::3", 65_003, 3)).unwrap();
    assert_eq!(
        e.next_hop,
        NextHop::Ipv6 {
            global: "2001:db8::fe".parse().unwrap(),
            link_local: None
        }
    );
    // End to end: what an internal peer is sent carries 16 octets of
    // next hop.
    let mut rib = Rib::new(LOCAL_AS);
    let int = peer("2001:db8::5", LOCAL_AS.0, 5);
    outputs(|o| rib.peer_up(from.clone(), now(), o));
    outputs(|o| rib.peer_up(int.clone(), now(), o));
    let out = outputs(|o| rib.update(from.addr, &announce(&["2001:db8:9::/48"], &a), now(), o));
    let sent = decode_sent(sends(&out, int.addr)[0], &int);
    assert_eq!(sent[0].mp_reach.as_ref().unwrap().next_hop, global);
    // The FIB still gets the global address.
    assert_eq!(fib(&out)[0].next_hop, Some(ip("2001:db8:1::1")));
}

/// `info` with RFC 8950 extended next hop negotiated for IPv4 unicast.
fn enh(mut info: PeerInfo) -> PeerInfo {
    info.extended_next_hop = vec![V4];
    info
}

/// An IPv6 next hop with a link-local address (RFC 2545 §3).
fn v6_next_hop(global: &str, link_local: &str) -> NextHop {
    NextHop::Ipv6 {
        global: global.parse().unwrap(),
        link_local: Some(link_local.parse().unwrap()),
    }
}

#[test]
fn rfc8950_export_rules() {
    let from = enh(peer("2001:db8::1", 65_001, 1));
    let src = Source {
        peer: from.addr,
        kind: from.kind,
    };
    let ext6_enh = enh(peer("2001:db8::2", 65_002, 2));
    let ext6 = peer("2001:db8::3", 65_003, 3);
    let ext4 = peer("10.0.0.4", 65_004, 4);
    let int_enh = enh(peer("10.0.0.5", LOCAL_AS.0, 5));
    let int = peer("10.0.0.6", LOCAL_AS.0, 6);
    let self6 = NextHop::Ipv6 {
        global: "2001:db8::fe".parse().unwrap(),
        link_local: None,
    };
    // An IPv4 route learned with an IPv6 next hop (RFC 8950 §3).
    let mut a = attrs(&[65_001], "2001:db8::1");
    a.next_hop = v6_next_hop("2001:db8::1", "fe80::1");
    // External, over IPv6 with RFC 8950: our IPv6 address (§5).
    let e = export(LOCAL_AS, V4, src, &a, &ext6_enh).unwrap();
    assert_eq!(e.next_hop, self6);
    // External over IPv4: our IPv4 address (RFC 4271 §5.1.3).
    let e = export(LOCAL_AS, V4, src, &a, &ext4).unwrap();
    assert_eq!(e.next_hop, NextHop::Ipv4(Ipv4Addr::new(10, 0, 0, 254)));
    // External over IPv6 without RFC 8950: we have no next hop it may
    // take, so the route is not advertised (§4).
    assert_eq!(export(LOCAL_AS, V4, src, &a, &ext6), None);
    // Internal: the next hop is passed on with its encoding, and only to
    // a peer that takes it (§5); its link-local address stays behind (RFC
    // 2545 §3).
    let e = export(LOCAL_AS, V4, src, &a, &int_enh).unwrap();
    assert_eq!(
        e.next_hop,
        NextHop::Ipv6 {
            global: "2001:db8::1".parse().unwrap(),
            link_local: None
        }
    );
    assert_eq!(export(LOCAL_AS, V4, src, &a, &int), None);
    // An IPv4 next hop: with RFC 8950 on an IPv6 session our own address
    // is the IPv6 one (§5); without it the received one stays.
    let a4 = attrs(&[65_001], "192.0.2.1");
    let e = export(LOCAL_AS, V4, src, &a4, &ext6_enh).unwrap();
    assert_eq!(e.next_hop, self6);
    let e = export(LOCAL_AS, V4, src, &a4, &ext6).unwrap();
    assert_eq!(e.next_hop, a4.next_hop);
    let e = export(LOCAL_AS, V4, src, &a4, &int).unwrap();
    assert_eq!(e.next_hop, a4.next_hop);
    // IPv6 routes are not affected.
    assert!(ext6.takes_next_hop(V6, &self6));
    assert!(!ext6.takes_next_hop(V4, &self6));
    assert!(ext6_enh.takes_next_hop(V4, &self6));
    assert!(ext6.takes_next_hop(V4, &a4.next_hop));
}

#[test]
fn rfc8950_ipv4_routes_with_ipv6_next_hops_end_to_end() {
    let mut rib = Rib::new(LOCAL_AS);
    let pa = enh(peer("2001:db8::1", 65_001, 1));
    let pb = enh(peer("2001:db8::2", 65_002, 2));
    let pc = peer("2001:db8::3", 65_003, 3);
    let pd = peer("10.0.0.4", 65_004, 4);
    for info in [&pa, &pb, &pc, &pd] {
        outputs(|o| rib.peer_up(info.clone(), now(), o));
    }
    let dst = p("192.0.2.0/24");
    // D's route with an IPv4 next hop reaches all three, C included.
    let out = outputs(|o| {
        rib.update(
            pd.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_004, 7], "10.0.0.4")),
            now(),
            o,
        );
    });
    let to_c = decode_sent(sends(&out, pc.addr)[0], &pc);
    assert_eq!(to_c[0].nlri, vec![dst]);
    assert_eq!(to_c[0].next_hop(), Some(Ipv4Addr::new(10, 0, 0, 4)));
    let to_b = decode_sent(sends(&out, pb.addr)[0], &pb);
    let r = to_b[0].mp_reach.as_ref().unwrap();
    assert_eq!(
        (r.family, r.next_hop),
        (
            V4,
            NextHop::Ipv6 {
                global: "2001:db8::fe".parse().unwrap(),
                link_local: None
            }
        )
    );
    // A's shorter route with an IPv6 next hop wins (RFC 8950 §3).
    let mut via6 = attrs(&[65_001], "2001:db8::1");
    via6.next_hop = v6_next_hop("2001:db8::1", "fe80::1");
    let out = outputs(|o| rib.update(pa.addr, &announce(&["192.0.2.0/24"], &via6), now(), o));
    // The FIB gets the global IPv6 address (RFC 2545 §3).
    assert_eq!(
        fib(&out),
        vec![FibChange {
            family: V4,
            prefix: dst,
            next_hop: Some(ip("2001:db8::1")),
            previous: Some(ip("10.0.0.4")),
        }]
    );
    // B: MP_REACH_NLRI for IPv4 with our IPv6 address, no NEXT_HOP.
    let to_b = decode_sent(sends(&out, pb.addr)[0], &pb);
    let r = to_b[0].mp_reach.as_ref().unwrap();
    assert_eq!(r.family, V4);
    assert_eq!(r.nlri, vec![dst]);
    assert_eq!(
        r.next_hop,
        NextHop::Ipv6 {
            global: "2001:db8::fe".parse().unwrap(),
            link_local: None
        }
    );
    assert_eq!(to_b[0].next_hop(), None);
    // C cannot take the new best route: what it had is withdrawn
    // (RFC 8950 §4, §5).
    let to_c = decode_sent(sends(&out, pc.addr)[0], &pc);
    assert_eq!(to_c.len(), 1);
    assert_eq!(to_c[0].withdrawn, vec![dst]);
    assert!(to_c[0].mp_reach.is_none() && to_c[0].nlri.is_empty());
    assert_eq!(rib.adj_rib_out(pc.addr, V4).count(), 0);
    // D, over IPv4: plain NLRI with our IPv4 address.
    let to_d = decode_sent(sends(&out, pd.addr)[0], &pd);
    assert_eq!(to_d[0].nlri, vec![dst]);
    assert_eq!(to_d[0].next_hop(), Some(Ipv4Addr::new(10, 0, 0, 254)));
    // A route refresh to C still leaves it out.
    let out = outputs(|o| rib.refresh(pc.addr, V4, now(), o));
    assert_eq!(sends(&out, pc.addr).len(), 0);
}

#[test]
fn an_update_with_both_ipv4_fields_keeps_each_next_hop() {
    // RFC 7606 §5.1: IPv4 routes in the NLRI field and in MP_REACH_NLRI
    // at once. RFC 4760 §3: each part has its own next hop, NEXT_HOP for
    // the NLRI field and the attribute's for the rest, IPv6 under RFC 8950.
    let mut rib = Rib::new(LOCAL_AS);
    let a = enh(peer("2001:db8::1", 65_001, 1));
    outputs(|o| rib.peer_up(a.clone(), now(), o));
    let mut d = announce(&["198.51.100.0/24"], &attrs(&[65_001], "192.0.2.1"));
    d.message.mp_reach = Some(bgpfc_wire::mp::MpReach {
        family: V4,
        next_hop: v6_next_hop("2001:db8::1", "fe80::1"),
        nlri: vec![p("203.0.113.0/24")],
    });
    let parts: Vec<_> = announced(&d).collect();
    assert_eq!(parts.len(), 2);
    outputs(|o| rib.update(a.addr, &d, now(), o));
    let nh = |prefix| rib.candidates(V4, p(prefix))[0].attrs.next_hop;
    assert_eq!(
        nh("198.51.100.0/24"),
        NextHop::Ipv4(Ipv4Addr::new(192, 0, 2, 1))
    );
    assert_eq!(nh("203.0.113.0/24"), v6_next_hop("2001:db8::1", "fe80::1"));
    // Treated as withdraw: nothing is announced.
    d.treated_as_withdraw = Some(bgpfc_wire::error::DecodeError::update(
        bgpfc_wire::error::UpdateSubcode::InvalidOrigin,
        vec![],
    ));
    assert_eq!(announced(&d).count(), 0);
}

// --- The RIB end to end --------------------------------------------------

#[test]
fn announce_withdraw_and_fib_changes() {
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_002, 2);
    assert_eq!(outputs(|o| rib.peer_up(e1.clone(), now(), o)).len(), 0);
    assert_eq!(outputs(|o| rib.peer_up(e2.clone(), now(), o)).len(), 0);
    let a = attrs(&[65_001, 7], "10.0.0.1");
    let out = outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24", "198.51.100.0/24"], &a),
            now(),
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
    let out = outputs(|o| rib.update(e1.addr, &announce(&["192.0.2.0/24"], &a), now(), o));
    assert!(out.is_empty(), "{out:?}");

    // A better route from e2 (shorter path) replaces it: e1 is told,
    // e2 is not.
    let b = attrs(&[65_002], "10.0.0.2");
    let out = outputs(|o| rib.update(e2.addr, &announce(&["192.0.2.0/24"], &b), now(), o));
    assert_eq!(fib(&out)[0].next_hop, Some(ip("10.0.0.2")));
    let m = decode_sent(sends(&out, e1.addr)[0], &e1);
    assert_eq!(m[0].nlri, vec![p("192.0.2.0/24")]);
    // e2 had e1's route; its own is not sent back, so it is withdrawn.
    let m = decode_sent(sends(&out, e2.addr)[0], &e2);
    assert_eq!(m[0].withdrawn, vec![p("192.0.2.0/24")]);
    assert_eq!(m[0].nlri.len(), 0);
    assert_eq!(rib.loc_rib(V4).count(), 2);
    assert_eq!(rib.candidates(V4, p("192.0.2.0/24")).len(), 2);

    // Withdraw from e2: back to e1's route; e2 gets it, e1 gets a withdraw.
    let out = outputs(|o| rib.update(e2.addr, &withdraw(&["192.0.2.0/24"]), now(), o));
    assert_eq!(fib(&out)[0].next_hop, Some(ip("10.0.0.1")));
    let m = decode_sent(sends(&out, e1.addr)[0], &e1);
    assert_eq!(m[0].withdrawn, vec![p("192.0.2.0/24")]);
    let m = decode_sent(sends(&out, e2.addr)[0], &e2);
    assert_eq!(m[0].nlri, vec![p("192.0.2.0/24")]);

    // Peer down: everything from e1 goes.
    let out = outputs(|o| rib.peer_down(e1.addr, now(), o));
    let f = fib(&out);
    assert_eq!(f.len(), 2);
    assert!(f.iter().all(|c| c.next_hop.is_none()));
    let m = decode_sent(sends(&out, e2.addr)[0], &e2);
    assert_eq!(m[0].withdrawn.len(), 2);
    assert_eq!(rib.loc_rib(V4).count(), 0);
    assert_eq!(rib.adj_rib_out(e2.addr, V4).count(), 0);
    assert_eq!(rib.peers().count(), 1);
}

#[test]
fn leftmost_as_must_be_the_external_peer() {
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    let i1 = peer("10.0.0.3", 65_000, 3);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    outputs(|o| rib.peer_up(i1.clone(), now(), o));
    // RFC 7606 §7.2: an external route not starting with the peer's AS is
    // treated as withdrawn.
    let out = outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_009], "10.0.0.1")),
            now(),
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
            now(),
            o,
        );
    });
    assert_eq!(fib(&out).len(), 0);
    // Internal peers may relay any path, including an empty one.
    let mut a = attrs(&[65_009], "10.0.0.3");
    a.local_pref = Some(100);
    let out = outputs(|o| rib.update(i1.addr, &announce(&["192.0.2.0/24"], &a), now(), o));
    assert_eq!(fib(&out).len(), 1);
}

#[test]
fn a_next_hop_that_is_our_own_address_is_ignored() {
    // RFC 4271 §6.3 a): semantically incorrect, so the route is ignored and
    // reported for the log, with no NOTIFICATION. Our address on e1's
    // session is 10.0.0.254.
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_002, 2);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    outputs(|o| rib.peer_up(e2.clone(), now(), o));
    let dst = p("192.0.2.0/24");
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_001], "10.0.0.1")),
            now(),
            o,
        );
    });
    assert_eq!(rib.loc_rib(V4).count(), 1);
    // The destination again, via our own address: the route e1 had goes
    // too, since the new announcement replaced it.
    let own = attrs(&[65_001], "10.0.0.254");
    let out = outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24", "198.51.100.0/24"], &own),
            now(),
            o,
        );
    });
    assert_eq!(
        out[0],
        Output::InvalidNextHop {
            peer: e1.addr,
            family: V4,
            next_hop: NextHop::Ipv4(Ipv4Addr::new(10, 0, 0, 254)),
            prefixes: vec![dst, p("198.51.100.0/24")],
        }
    );
    assert_eq!(
        fib(&out),
        vec![FibChange {
            family: V4,
            prefix: dst,
            next_hop: None,
            previous: Some(ip("10.0.0.1")),
        }]
    );
    assert_eq!(
        decode_sent(sends(&out, e2.addr)[0], &e2)[0].withdrawn,
        vec![dst]
    );
    assert_eq!(
        rib.peer_stats(e1.addr).unwrap().received,
        vec![(V4, 0), (V6, 0)]
    );
    // The session goes on, and the peer's next good route is taken.
    let out = outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_001], "10.0.0.1")),
            now(),
            o,
        );
    });
    assert_eq!(fib(&out)[0].next_hop, Some(ip("10.0.0.1")));
}

#[test]
fn own_address_next_hops_per_part_family_and_limit() {
    // RFC 4760 §3: the RFC 4271 §6.3 a) rule holds for MP_REACH_NLRI next
    // hops, an IPv4-mapped one included, and each part of an UPDATE is
    // judged by its own next hop.
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    let own = attrs(&[65_001], "10.0.0.254");
    let mut d = announce(&["203.0.113.0/24"], &own);
    d.message.mp_reach = Some(bgpfc_wire::mp::MpReach {
        family: V6,
        next_hop: NextHop::Ipv6 {
            global: "::ffff:10.0.0.254".parse().unwrap(),
            link_local: None,
        },
        nlri: vec![p("2001:db8:1::/48")],
    });
    let out = outputs(|o| rib.update(e1.addr, &d, now(), o));
    let ignored: Vec<_> = out
        .iter()
        .filter_map(|o| match o {
            Output::InvalidNextHop {
                family, prefixes, ..
            } => Some((*family, prefixes.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(
        ignored,
        vec![
            (V4, vec![p("203.0.113.0/24")]),
            (V6, vec![p("2001:db8:1::/48")])
        ]
    );
    assert_eq!(fib(&out), vec![]);
    if let Some(r) = &mut d.message.mp_reach {
        r.next_hop = v6_next_hop("2001:db8::1", "fe80::1");
    }
    let out = outputs(|o| rib.update(e1.addr, &d, now(), o));
    assert!(matches!(out[0], Output::InvalidNextHop { family: V4, .. }));
    assert_eq!(fib(&out)[0].prefix, p("2001:db8:1::/48"));
    // Over IPv6, the global address is the one compared.
    let e6 = peer("2001:db8::1", 65_006, 6);
    outputs(|o| rib.peer_up(e6.clone(), now(), o));
    let d = announce(&["2001:db8:6::/48"], &attrs(&[65_006], "2001:db8::fe"));
    assert!(matches!(
        outputs(|o| rib.update(e6.addr, &d, now(), o))[0],
        Output::InvalidNextHop { family: V6, .. }
    ));
    // Ignored routes do not count towards a prefix limit (RFC 4271 §6.7).
    let e3 = limited(peer("10.0.0.3", 65_003, 3), V4, 1);
    outputs(|o| rib.peer_up(e3.clone(), now(), o));
    let out = outputs(|o| {
        rib.update(
            e3.addr,
            &announce(
                &["192.0.2.0/24", "198.51.100.0/24"],
                &attrs(&[65_003], "10.0.0.254"),
            ),
            now(),
            o,
        );
    });
    assert_eq!(limit_hits(&out), vec![]);
    assert!(rib.peer(e3.addr).is_some());
}

#[test]
fn prefix_in_both_withdrawn_and_nlri_is_announced() {
    // RFC 4271 §4.3: a prefix in both Withdrawn Routes and NLRI is treated
    // as not withdrawn.
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    let mut u = announce(&["192.0.2.0/24"], &attrs(&[65_001], "10.0.0.1"));
    u.message.withdrawn = vec![p("192.0.2.0/24")];
    let out = outputs(|o| rib.update(e1.addr, &u, now(), o));
    assert_eq!(fib(&out).len(), 1);
    assert_eq!(fib(&out)[0].next_hop, Some(ip("10.0.0.1")));
    assert_eq!(rib.loc_rib(V4).count(), 1);
}

#[test]
fn routes_of_a_family_we_did_not_advertise_are_ignored() {
    // RFC 4760 §8: we advertised IPv4 unicast only to e1, so IPv6 routes
    // are not e1's to send.
    let mut rib = Rib::new(LOCAL_AS);
    let mut e1 = peer("10.0.0.1", 65_001, 1);
    e1.families = vec![V4];
    e1.receive_families = vec![V4];
    let e2 = peer("10.0.0.2", 65_002, 2);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    outputs(|o| rib.peer_up(e2.clone(), now(), o));
    let v6 = announce(&["2001:db8:1::/48"], &attrs(&[65_001], "2001:db8::1"));
    assert_eq!(outputs(|o| rib.update(e1.addr, &v6, now(), o)), vec![]);
    assert!(rib.candidates(V6, p("2001:db8:1::/48")).is_empty());
    // e2 has it, and e1's withdrawal of it means nothing either.
    let from_e2 = announce(&["2001:db8:1::/48"], &attrs(&[65_002], "2001:db8::2"));
    assert_eq!(
        fib(&outputs(|o| rib.update(e2.addr, &from_e2, now(), o))).len(),
        1
    );
    assert_eq!(
        outputs(|o| rib.update(e1.addr, &withdraw(&["2001:db8:1::/48"]), now(), o)),
        vec![]
    );
    assert_eq!(rib.loc_rib(V6).count(), 1);
    // IPv4 goes on as usual, and nothing of e1 is left once it is down.
    let v4 = announce(&["192.0.2.0/24"], &attrs(&[65_001], "10.0.0.1"));
    assert_eq!(
        fib(&outputs(|o| rib.update(e1.addr, &v4, now(), o))).len(),
        1
    );
    outputs(|o| rib.peer_down(e1.addr, now(), o));
    assert_eq!(rib.loc_rib(V4).count(), 0);
    assert!(
        rib.loc_rib(V6).all(|(_, b)| b.peer == e2.addr),
        "a route of e1 outlived its session"
    );
}

#[test]
fn routes_of_a_family_only_we_advertised_are_taken_and_go_with_the_session() {
    // RFC 4760 §8: e1 did not advertise IPv6 unicast, we did. Both sides
    // must advertise a family only for a bi-directional exchange; our
    // capability lets e1 send IPv6 routes (RFC 5492 §3), but e1 is sent
    // none.
    let mut rib = Rib::new(LOCAL_AS);
    let mut e1 = peer("10.0.0.1", 65_001, 1);
    e1.families = vec![V4];
    e1.receive_families = vec![V4, V6];
    e1.prefix_limits = vec![(V6, 2)];
    let e2 = peer("10.0.0.2", 65_002, 2);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    outputs(|o| rib.peer_up(e2.clone(), now(), o));
    let v6 = announce(&["2001:db8:1::/48"], &attrs(&[65_001], "2001:db8::1"));
    let out = outputs(|o| rib.update(e1.addr, &v6, now(), o));
    assert_eq!(fib(&out).len(), 1);
    assert_eq!(sends(&out, e2.addr).len(), 1);
    assert_eq!(sends(&out, e1.addr).len(), 0);
    // e2's IPv6 routes do not go to e1.
    let from_e2 = announce(&["2001:db8:2::/48"], &attrs(&[65_002], "2001:db8::2"));
    let out = outputs(|o| rib.update(e2.addr, &from_e2, now(), o));
    assert_eq!(fib(&out).len(), 1);
    assert_eq!(sends(&out, e1.addr).len(), 0);
    let stats = rib.peer_stats(e1.addr).unwrap();
    assert_eq!(stats.received, vec![(V4, 0), (V6, 1)]);
    assert_eq!(stats.advertised, vec![(V4, 0)]);
    // The prefix limit counts them (RFC 4271 §6.7).
    let more = announce(
        &["2001:db8:3::/48", "2001:db8:4::/48"],
        &attrs(&[65_001], "2001:db8::1"),
    );
    let out = outputs(|o| rib.update(e1.addr, &more, now(), o));
    assert!(out.contains(&Output::PrefixLimitExceeded {
        peer: e1.addr,
        family: V6,
        limit: 2
    }));
    assert!(rib.candidates(V6, p("2001:db8:1::/48")).is_empty());
    // Withdrawn with the session, like any other: none outlives it.
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    outputs(|o| rib.update(e1.addr, &v6, now(), o));
    let out = outputs(|o| rib.peer_down(e1.addr, now(), o));
    assert_eq!(
        fib(&out),
        vec![FibChange {
            family: V6,
            prefix: p("2001:db8:1::/48"),
            next_hop: None,
            previous: Some(ip("2001:db8::1")),
        }]
    );
    assert!(rib.loc_rib(V6).all(|(_, b)| b.peer == e2.addr));
}

#[test]
fn as_loop_routes_are_excluded() {
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    let a = attrs(&[65_001, LOCAL_AS.0, 7], "10.0.0.1");
    let out = outputs(|o| rib.update(e1.addr, &announce(&["192.0.2.0/24"], &a), now(), o));
    assert_eq!(out.len(), 0);
    assert_eq!(rib.loc_rib(V4).count(), 0);
    // A replacement with a loop withdraws the earlier good route.
    let good = attrs(&[65_001], "10.0.0.1");
    outputs(|o| rib.update(e1.addr, &announce(&["192.0.2.0/24"], &good), now(), o));
    assert_eq!(rib.loc_rib(V4).count(), 1);
    let out = outputs(|o| rib.update(e1.addr, &announce(&["192.0.2.0/24"], &a), now(), o));
    assert_eq!(fib(&out)[0].next_hop, None);
}

#[test]
fn new_peer_receives_the_loc_rib_and_route_refresh_resends_it() {
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_001], "10.0.0.1")),
            now(),
            o,
        );
    });
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["2001:db8:1::/48"], &attrs(&[65_001], "2001:db8::1")),
            now(),
            o,
        );
    });
    let i = peer("10.0.0.3", 65_000, 3);
    let out = outputs(|o| rib.peer_up(i.clone(), now(), o));
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
    let out = outputs(|o| rib.refresh(i.addr, V6, now(), o));
    assert_eq!(fib(&out).len(), 0);
    let v6 = decode_sent(sends(&out, i.addr)[0], &i);
    assert_eq!(
        v6[0].mp_reach.as_ref().unwrap().nlri,
        vec![p("2001:db8:1::/48")]
    );
    // A family the peer does not speak: nothing.
    let mut v4_only = peer("10.0.0.4", 65_004, 4);
    v4_only.families = vec![V4];
    let out = outputs(|o| rib.peer_up(v4_only.clone(), now(), o));
    assert_eq!(sends(&out, v4_only.addr).len(), 1);
    assert_eq!(
        outputs(|o| rib.refresh(v4_only.addr, V6, now(), o)).len(),
        0
    );
    assert_eq!(
        outputs(|o| rib.refresh(ip("10.9.9.9"), V4, now(), o)).len(),
        0
    );
}

/// `d` as decoded with an incorrect MP attribute for `family` in it
/// (RFC 4760 §7).
fn disabling(family: AddressFamily, mut d: DecodedUpdate) -> DecodedUpdate {
    d.disabled.push(bgpfc_wire::update::DisabledFamily {
        family,
        error: bgpfc_wire::error::DecodeError::update(
            bgpfc_wire::error::UpdateSubcode::OptionalAttributeError,
            Vec::new(),
        ),
    });
    d
}

#[test]
fn an_incorrect_mp_attribute_disables_its_family_for_the_session() {
    // RFC 4760 §7: every route of the family from the peer goes, and the
    // family is ignored until the session ends; the rest of the UPDATE and
    // the other families are used as usual.
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_002, 2);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    outputs(|o| rib.peer_up(e2.clone(), now(), o));
    let v4 = |prefix: &str| announce(&[prefix], &attrs(&[65_001], "10.0.0.1"));
    let v6 = |prefixes: &[&str]| announce(prefixes, &attrs(&[65_001], "2001:db8::1"));
    outputs(|o| rib.update(e1.addr, &v4("192.0.2.0/24"), now(), o));
    outputs(|o| {
        rib.update(
            e1.addr,
            &v6(&["2001:db8:1::/48", "2001:db8:2::/48"]),
            now(),
            o,
        );
    });
    let backup = attrs(&[65_002, 9], "2001:db8::2");
    outputs(|o| rib.update(e2.addr, &announce(&["2001:db8:1::/48"], &backup), now(), o));
    assert_eq!(rib.loc_rib(V6).count(), 2);
    // The UPDATE that disables IPv6 announces an IPv4 route too.
    let out = outputs(|o| rib.update(e1.addr, &disabling(V6, v4("198.51.100.0/24")), now(), o));
    let changes = fib(&out);
    assert_eq!(changes.len(), 3, "{changes:?}");
    for (prefix, next_hop) in [
        ("2001:db8:1::/48", Some(ip("2001:db8::2"))),
        ("2001:db8:2::/48", None),
        ("198.51.100.0/24", Some(ip("10.0.0.1"))),
    ] {
        assert!(
            changes
                .iter()
                .any(|c| c.prefix == p(prefix) && c.next_hop == next_hop),
            "{prefix}: {changes:?}"
        );
    }
    assert_eq!(
        rib.peer_stats(e1.addr).unwrap().received,
        vec![(V4, 2), (V6, 0)]
    );
    // Later IPv6 announcements are ignored; IPv4 goes on.
    assert_eq!(
        outputs(|o| rib.update(e1.addr, &v6(&["2001:db8:3::/48"]), now(), o)),
        vec![]
    );
    assert_eq!(
        fib(&outputs(|o| rib.update(
            e1.addr,
            &v4("203.0.113.0/24"),
            now(),
            o
        )))
        .len(),
        1
    );
    // Disabling it again, or a family the RIB holds nothing of, changes
    // nothing.
    let vpn = AddressFamily {
        afi: bgpfc_wire::types::Afi::Ipv4,
        safi: bgpfc_wire::types::Safi::Unknown(128),
    };
    for family in [V6, vpn] {
        let out = outputs(|o| {
            rib.update(
                e1.addr,
                &disabling(family, DecodedUpdate::default()),
                now(),
                o,
            );
        });
        assert_eq!(out, vec![]);
    }
    // For the duration of the session only: a new one takes IPv6 again.
    outputs(|o| rib.peer_down(e1.addr, now(), o));
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    assert_eq!(
        fib(&outputs(|o| rib.update(
            e1.addr,
            &v6(&["2001:db8:3::/48"]),
            now(),
            o
        )))
        .len(),
        1
    );
    // Unknown peers are ignored everywhere.
    let out = outputs(|o| {
        rib.update(
            ip("10.9.9.9"),
            &disabling(V4, withdraw(&["192.0.2.0/24"])),
            now(),
            o,
        );
    });
    assert_eq!(out.len(), 0);
    assert_eq!(
        outputs(|o| rib.peer_down(ip("10.9.9.9"), now(), o)).len(),
        0
    );
}

#[test]
fn large_batches_are_packed_within_the_message_limit() {
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    let mut e2 = peer("10.0.0.2", 65_002, 2);
    e2.four_octet_as = false;
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    outputs(|o| rib.peer_up(e2.clone(), now(), o));
    // 3000 /24s: more than fit in one 4096-octet UPDATE.
    let prefixes: Vec<String> = (0..3000u32)
        .map(|i| format!("10.{}.{}.0/24", (i >> 8) + 1, i & 0xff))
        .collect();
    let refs: Vec<&str> = prefixes.iter().map(String::as_str).collect();
    let a = attrs(&[65_001, 4_200_000_000], "10.0.0.1");
    let out = outputs(|o| rib.update(e1.addr, &announce(&refs, &a), now(), o));
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
    let out = outputs(|o| rib.peer_down(e1.addr, now(), o));
    let msgs = decode_sent(sends(&out, e2.addr)[0], &e2);
    assert!(msgs.len() > 1);
    let total: usize = msgs.iter().map(|m| m.withdrawn.len()).sum();
    assert_eq!(total, 3000);
    assert_eq!(rib.attribute_sets(), 0);
}

#[test]
fn each_update_carries_one_kind_of_route_with_mp_attributes_first() {
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("2001:db8::1", 65_001, 1);
    let e2 = peer("2001:db8::2", 65_002, 2);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    outputs(|o| rib.peer_up(e2.clone(), now(), o));
    let v4 = attrs(&[65_001], "10.0.0.1");
    let v6 = attrs(&[65_001], "2001:db8::1");
    outputs(|o| rib.update(e1.addr, &announce(&["192.0.2.0/24"], &v4), now(), o));
    outputs(|o| rib.update(e1.addr, &announce(&["2001:db8:1::/48"], &v6), now(), o));
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
        disabled: Vec::new(),
    };
    let out = outputs(|o| rib.update(e1.addr, &update, now(), o));
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
    let d = announce(&["192.0.2.0/24"], &a);
    let parts: Vec<_> = announced(&d).collect();
    assert_eq!(parts.len(), 1);
    let (family, next_hop, prefixes, _) = parts[0];
    assert_eq!((family, prefixes), (V4, &[p("192.0.2.0/24")][..]));
    let back = PathAttrs::from_update(&d.message, next_hop);
    assert_eq!(
        *back.communities,
        [Community::new(65_001, 1), Community::new(65_001, 2)]
    );
    // The Partial bit is set on the forwarded unknown attribute.
    assert_eq!(back.unknown[0].flags, 0xe0);
    let mut expect = a.clone();
    expect.unknown[0].flags = 0xe0;
    assert_eq!(back, expect);
    assert_eq!(announced(&withdraw(&["192.0.2.0/24"])).count(), 0);
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
        fn import(
            &self,
            _: &PeerInfo,
            _: AddressFamily,
            _: Prefix,
            _: &PathAttrs,
            _: RovState,
        ) -> Verdict {
            Verdict::Accept
        }
        fn export(
            &self,
            _: &PeerInfo,
            _: AddressFamily,
            p: Prefix,
            _: &PathAttrs,
            _: RovState,
        ) -> Verdict {
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
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    outputs(|o| rib.peer_up(e2.clone(), now(), o));
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(
                &["192.0.2.0/24", "198.51.100.0/24"],
                &attrs(&[65_001], "10.0.0.1"),
            ),
            now(),
            o,
        );
    });
    assert_eq!(rib.adj_rib_out(e2.addr, V4).len(), 2);
    // The same policies again: nothing sent.
    let out = outputs(|o| rib.set_policies(Box::new(crate::AcceptAll), &[e2.addr], now(), o));
    assert_eq!(out.len(), 0);
    let out = outputs(|o| rib.set_policies(Box::new(DropOdd), &[e2.addr], now(), o));
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
    let out = outputs(|o| rib.set_policies(Box::new(crate::AcceptAll), &[e2.addr], now(), o));
    let m = decode_sent(sends(&out, e2.addr)[0], &e2);
    assert_eq!(m[0].nlri, vec![p("192.0.2.0/24")]);
    assert_eq!(
        rib.peer_stats(e2.addr).unwrap().advertised,
        vec![(V4, 2), (V6, 0)]
    );
    assert!(rib.peer(e2.addr).is_some());
    assert!(rib.peer(ip("10.9.9.9")).is_none());
    let out = outputs(|o| rib.set_policies(Box::new(DropOdd), &[ip("10.9.9.9")], now(), o));
    assert_eq!(out.len(), 0);
}

// --- RFC 4271 §6.7 prefix limit -------------------------------------------

fn limited(mut info: PeerInfo, family: AddressFamily, limit: u32) -> PeerInfo {
    info.prefix_limits.push((family, limit));
    info
}

fn limit_hits(out: &[Output]) -> Vec<(IpAddr, AddressFamily, u32)> {
    out.iter()
        .filter_map(|o| match o {
            Output::PrefixLimitExceeded {
                peer,
                family,
                limit,
            } => Some((*peer, *family, *limit)),
            _ => None,
        })
        .collect()
}

/// Import policy that rejects one prefix.
struct RejectOne(Prefix);

impl crate::Policies for RejectOne {
    fn import(
        &self,
        _: &PeerInfo,
        _: AddressFamily,
        p: Prefix,
        _: &PathAttrs,
        _: RovState,
    ) -> crate::Verdict {
        if p == self.0 {
            crate::Verdict::Reject
        } else {
            crate::Verdict::Accept
        }
    }
    fn export(
        &self,
        _: &PeerInfo,
        _: AddressFamily,
        _: Prefix,
        _: &PathAttrs,
        _: RovState,
    ) -> crate::Verdict {
        crate::Verdict::Accept
    }
}

#[test]
fn prefix_limit_counts_accepted_routes_and_ends_the_session() {
    let mut rib = Rib::with_policies(LOCAL_AS, Box::new(RejectOne(p("192.0.2.128/25"))));
    let e1 = limited(peer("10.0.0.1", 65_001, 1), V4, 2);
    let e2 = peer("10.0.0.2", 65_002, 2);
    assert_eq!(e1.prefix_limit(V4), Some(2));
    assert_eq!(e1.prefix_limit(V6), None);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    outputs(|o| rib.peer_up(e2.clone(), now(), o));
    let a = attrs(&[65_001], "10.0.0.1");
    // Up to the limit is fine: RFC 4271 §6.7 acts when it is exceeded.
    let out = outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24", "198.51.100.0/24"], &a),
            now(),
            o,
        );
    });
    assert_eq!(limit_hits(&out), vec![]);
    // Not counted: a replacement, routes the RIB does not keep (import
    // policy rejects, an AS loop, a leftmost AS that is not the peer's),
    // and another family's routes.
    let routes: [(&str, &[u32]); 4] = [
        ("192.0.2.0/24", &[65_001, 9]),
        ("192.0.2.128/25", &[65_001]),
        ("203.0.113.0/24", &[65_001, LOCAL_AS.0]),
        ("203.0.113.0/24", &[65_009]),
    ];
    for (prefix, path) in routes {
        let out = outputs(|o| {
            rib.update(
                e1.addr,
                &announce(&[prefix], &attrs(path, "10.0.0.1")),
                now(),
                o,
            );
        });
        assert_eq!(limit_hits(&out), vec![], "{prefix} {path:?}");
    }
    let v6 = attrs(&[65_001], "2001:db8::1");
    let v6_prefixes = ["2001:db8:1::/48", "2001:db8:2::/48", "2001:db8:3::/48"];
    outputs(|o| rib.update(e1.addr, &announce(&v6_prefixes, &v6), now(), o));
    assert_eq!(
        rib.peer_stats(e1.addr).unwrap().received,
        vec![(V4, 2), (V6, 3)]
    );
    // A withdrawal makes room again.
    outputs(|o| rib.update(e1.addr, &withdraw(&["198.51.100.0/24"]), now(), o));
    let out = outputs(|o| rib.update(e1.addr, &announce(&["198.51.100.0/24"], &a), now(), o));
    assert_eq!(limit_hits(&out), vec![]);
    // One route over: the session ends (RFC 4271 §6.7 (b)), which is
    // reported first, and every route from e1 goes at once, in both
    // families, from the FIB and from e2.
    let out = outputs(|o| rib.update(e1.addr, &announce(&["203.0.113.0/24"], &a), now(), o));
    assert_eq!(limit_hits(&out), vec![(e1.addr, V4, 2)]);
    assert!(matches!(out[0], Output::PrefixLimitExceeded { .. }));
    let f = fib(&out);
    assert_eq!(f.len(), 5);
    assert!(f.iter().all(|c| c.next_hop.is_none()));
    let to_e2 = sends(&out, e2.addr);
    assert_eq!(to_e2.len(), 2);
    let m = decode_sent(to_e2[0], &e2);
    assert_eq!(
        m[0].withdrawn,
        vec![p("192.0.2.0/24"), p("198.51.100.0/24")]
    );
    let m = decode_sent(to_e2[1], &e2);
    assert_eq!(m[0].mp_unreach.as_ref().unwrap().withdrawn.len(), 3);
    assert_eq!(rib.loc_rib(V4).count(), 0);
    assert_eq!(rib.loc_rib(V6).count(), 0);
    assert_eq!(rib.candidates(V4, p("203.0.113.0/24")).len(), 0);
    assert!(rib.peer(e1.addr).is_none());
    assert_eq!(rib.peer_stats(e1.addr), None);
    // Nothing of e1 is left.
    assert!(rib.tables.values().all(crate::store::PrefixMap::is_empty));
    // What e1 sends until its session is down is ignored, and the end of
    // the session has nothing left to remove.
    let out = outputs(|o| rib.update(e1.addr, &announce(&["192.0.2.0/24"], &a), now(), o));
    assert_eq!(out, vec![]);
    assert_eq!(outputs(|o| rib.peer_down(e1.addr, now(), o)), vec![]);
    // The next session starts counting from zero.
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    let out = outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24", "198.51.100.0/24"], &a),
            now(),
            o,
        );
    });
    assert_eq!(limit_hits(&out), vec![]);
    assert_eq!(rib.loc_rib(V4).count(), 2);
}

#[test]
fn prefix_limit_crossed_inside_one_update_passes_nothing_on() {
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = limited(peer("10.0.0.1", 65_001, 1), V4, 2);
    let e2 = peer("10.0.0.2", 65_002, 2);
    let e3 = peer("10.0.0.3", 65_003, 3);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    outputs(|o| rib.peer_up(e2.clone(), now(), o));
    outputs(|o| rib.peer_up(e3.clone(), now(), o));
    // e2 already has a route to one of the destinations.
    outputs(|o| {
        rib.update(
            e2.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_002, 7, 7], "10.0.0.2")),
            now(),
            o,
        );
    });
    // e1's UPDATE carries three routes against a limit of two, with a
    // better path to e2's destination: none of them may reach the
    // Loc-RIB, the FIB or another peer, even for a moment.
    let out = outputs(|o| {
        rib.update(
            e1.addr,
            &announce(
                &["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"],
                &attrs(&[65_001], "10.0.0.1"),
            ),
            now(),
            o,
        );
    });
    assert_eq!(
        out,
        vec![Output::PrefixLimitExceeded {
            peer: e1.addr,
            family: V4,
            limit: 2
        }]
    );
    let loc: Vec<_> = rib.loc_rib(V4).map(|(p, b)| (p, b.peer)).collect();
    assert_eq!(loc, vec![(p("192.0.2.0/24"), e2.addr)]);
    for prefix in ["198.51.100.0/24", "203.0.113.0/24"] {
        assert_eq!(rib.candidates(V4, p(prefix)).len(), 0, "{prefix}");
    }
    assert_eq!(rib.adj_rib_out(e3.addr, V4).count(), 1);
}

#[test]
fn prefix_limits_follow_a_reload() {
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(
                &["192.0.2.0/24", "198.51.100.0/24"],
                &attrs(&[65_001], "10.0.0.1"),
            ),
            now(),
            o,
        );
    });
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(
                &["2001:db8:1::/48", "2001:db8:2::/48", "2001:db8:3::/48"],
                &attrs(&[65_001], "2001:db8::1"),
            ),
            now(),
            o,
        );
    });
    // At or above the count: nothing happens, and the limit is kept.
    let out = outputs(|o| rib.set_prefix_limits(e1.addr, vec![(V4, 2), (V6, 10)], now(), o));
    assert_eq!(out, vec![]);
    assert_eq!(rib.peer(e1.addr).unwrap().prefix_limit(V4), Some(2));
    let out = outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["203.0.113.0/24"], &attrs(&[65_001], "10.0.0.1")),
            now(),
            o,
        );
    });
    assert_eq!(limit_hits(&out), vec![(e1.addr, V4, 2)]);
    // Below the count: as if the limit had just been exceeded.
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(
                &["2001:db8:1::/48", "2001:db8:2::/48", "2001:db8:3::/48"],
                &attrs(&[65_001], "2001:db8::1"),
            ),
            now(),
            o,
        );
    });
    let out = outputs(|o| rib.set_prefix_limits(e1.addr, vec![(V4, 2), (V6, 2)], now(), o));
    assert_eq!(limit_hits(&out), vec![(e1.addr, V6, 2)]);
    assert_eq!(fib(&out).len(), 3);
    assert!(rib.peer(e1.addr).is_none());
    // An unknown peer: nothing.
    assert_eq!(
        outputs(|o| rib.set_prefix_limits(ip("10.9.9.9"), vec![], now(), o)),
        vec![]
    );
}

// --- RFC 4271 §9.2.1.1 MinRouteAdvertisementIntervalTimer -------------

const EBGP_IV: Duration = Duration::from_secs(30);

fn paced(addr: &str, remote_as: u32, router_id: u32, interval: Duration) -> PeerInfo {
    let mut info = peer(addr, remote_as, router_id);
    info.advertisement_interval = interval;
    info
}

/// The announcements (`Some`) and withdrawals (`None`) of `prefix` sent
/// to `to`, with the AS path of each announcement.
fn sent_for(out: &[Output], to: &PeerInfo, prefix: Prefix) -> Vec<Option<Vec<Asn>>> {
    let mut v = Vec::new();
    for messages in sends(out, to.addr) {
        for m in decode_sent(messages, to) {
            if m.withdrawn.contains(&prefix) {
                v.push(None);
            }
            if m.nlri.contains(&prefix) {
                v.push(Some(m.as_path().unwrap().asns().collect()));
            }
        }
    }
    v
}

fn secs(t0: Instant, s: u64) -> Instant {
    t0 + Duration::from_secs(s)
}

/// When the next held destination may go out, leaving out the sweeps
/// that [`Rib::next_deadline`] reports too.
fn release_at(rib: &Rib) -> Option<Instant> {
    let std::cmp::Reverse(d) = rib.s.deadlines.peek()?;
    rib.s.clock?.instant(d.at)
}

/// The IPv4 pacing state of the peer at `addr`.
fn pacing(rib: &Rib, addr: IpAddr) -> &crate::pacing::Pacing {
    let id = rib.s.id(addr).unwrap();
    rib.s.peer(id).pacing.get(V4).unwrap()
}

#[test]
fn mrai_flapping_route_goes_out_once_per_interval_and_the_latest_wins() {
    let t0 = Instant::now();
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = paced("10.0.0.2", 65_002, 2, EBGP_IV);
    outputs(|o| rib.peer_up(e1.clone(), t0, o));
    outputs(|o| rib.peer_up(e2.clone(), t0, o));
    let dst = p("192.0.2.0/24");
    // The first advertisement of a destination is not held.
    let out = outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_001, 1], "10.0.0.1")),
            t0,
            o,
        );
    });
    assert_eq!(
        sent_for(&out, &e2, dst),
        vec![Some(vec![LOCAL_AS, Asn(65_001), Asn(1)])]
    );
    assert_eq!(release_at(&rib), None);
    // Three changes inside the interval: the decision process and the FIB
    // follow each (§9.2.1.1 limits advertisement, not selection), e2 hears
    // nothing yet.
    for (s, last) in [(1u64, 2u32), (2, 3), (3, 4)] {
        let out = outputs(|o| {
            rib.update(
                e1.addr,
                &announce(&["192.0.2.0/24"], &attrs(&[65_001, last], "10.0.0.1")),
                secs(t0, s),
                o,
            );
        });
        assert_eq!(fib(&out).len(), 1);
        assert!(sends(&out, e2.addr).is_empty(), "{out:?}");
    }
    assert_eq!(release_at(&rib), Some(secs(t0, 30)));
    assert_eq!(outputs(|o| rib.flush(secs(t0, 29), o)).len(), 0);
    // At the end of the interval, the last route selected goes out once.
    let out = outputs(|o| rib.flush(secs(t0, 30), o));
    assert_eq!(
        sent_for(&out, &e2, dst),
        vec![Some(vec![LOCAL_AS, Asn(65_001), Asn(4)])]
    );
    assert_eq!(outputs(|o| rib.flush(secs(t0, 31), o)).len(), 0);
    assert_eq!(release_at(&rib), None);

    // A long flap, one change a second, flushing whenever the RIB asks:
    // never two advertisements of the destination within an interval.
    let mut announced_at = vec![30u64];
    for s in 31..300u64 {
        let a = attrs(&[65_001, u32::try_from(s).unwrap()], "10.0.0.1");
        let mut out =
            outputs(|o| rib.update(e1.addr, &announce(&["192.0.2.0/24"], &a), secs(t0, s), o));
        out.extend(outputs(|o| rib.flush(secs(t0, s), o)));
        for sent in sent_for(&out, &e2, dst) {
            assert!(sent.is_some(), "only announcements here");
            announced_at.push(s);
        }
    }
    for w in announced_at.windows(2) {
        assert!(w[1] - w[0] >= 30, "{announced_at:?}");
    }
    assert!(announced_at.len() >= 9, "{announced_at:?}");
    // What the peer ends up with is the latest route, as exported: the
    // Adj-RIB-Out holds it before the session rewrite.
    let out = outputs(|o| rib.flush(secs(t0, 400), o));
    let last = rib.adj_rib_out(e2.addr, V4).next().map(|(_, a)| a.clone());
    assert_eq!(
        last.unwrap().as_path.asns().collect::<Vec<_>>(),
        vec![Asn(65_001), Asn(299)]
    );
    assert!(sends(&out, e2.addr).len() <= 1);
}

#[test]
fn mrai_does_not_delay_withdrawals() {
    let t0 = Instant::now();
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = paced("10.0.0.2", 65_002, 2, EBGP_IV);
    outputs(|o| rib.peer_up(e1.clone(), t0, o));
    outputs(|o| rib.peer_up(e2.clone(), t0, o));
    let dst = p("192.0.2.0/24");
    let a = attrs(&[65_001], "10.0.0.1");
    outputs(|o| rib.update(e1.addr, &announce(&["192.0.2.0/24"], &a), t0, o));
    // Inside the interval, the withdrawal still goes out at once (issue
    // #66; COMPLIANCE.md 9.2.1.1 deviates).
    let out = outputs(|o| rib.update(e1.addr, &withdraw(&["192.0.2.0/24"]), secs(t0, 1), o));
    assert_eq!(sent_for(&out, &e2, dst), vec![None]);
    // The route comes back: paced from the advertisement at t0.
    let out = outputs(|o| rib.update(e1.addr, &announce(&["192.0.2.0/24"], &a), secs(t0, 2), o));
    assert_eq!(sends(&out, e2.addr).len(), 0);
    let out = outputs(|o| rib.flush(secs(t0, 30), o));
    assert_eq!(sent_for(&out, &e2, dst).len(), 1);
    // A held change, then a withdrawal: the withdrawal goes out at once
    // and, the route being gone, nothing is left to advertise later.
    let b = attrs(&[65_001, 9], "10.0.0.1");
    let out = outputs(|o| rib.update(e1.addr, &announce(&["192.0.2.0/24"], &b), secs(t0, 31), o));
    assert_eq!(sends(&out, e2.addr).len(), 0);
    let out = outputs(|o| rib.update(e1.addr, &withdraw(&["192.0.2.0/24"]), secs(t0, 32), o));
    assert_eq!(sent_for(&out, &e2, dst), vec![None]);
    assert_eq!(
        sends(&outputs(|o| rib.flush(secs(t0, 120), o)), e2.addr).len(),
        0
    );
    assert_eq!(rib.adj_rib_out(e2.addr, V4).count(), 0);
    // Peer down withdraws everything at once too.
    outputs(|o| rib.update(e1.addr, &announce(&["192.0.2.0/24"], &a), secs(t0, 121), o));
    let out = outputs(|o| rib.peer_down(e1.addr, secs(t0, 122), o));
    assert_eq!(sent_for(&out, &e2, dst), vec![None]);
}

#[test]
fn mrai_is_kept_per_destination() {
    let t0 = Instant::now();
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = paced("10.0.0.2", 65_002, 2, EBGP_IV);
    outputs(|o| rib.peer_up(e1.clone(), t0, o));
    outputs(|o| rib.peer_up(e2.clone(), t0, o));
    let (one, two) = (p("192.0.2.0/24"), p("198.51.100.0/24"));
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_001], "10.0.0.1")),
            t0,
            o,
        );
    });
    // The first destination flaps and is held...
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_001, 2], "10.0.0.1")),
            secs(t0, 1),
            o,
        );
    });
    // ...which does not hold back another destination's first route,
    let out = outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["198.51.100.0/24"], &attrs(&[65_001, 3], "10.0.0.1")),
            secs(t0, 5),
            o,
        );
    });
    assert_eq!(sent_for(&out, &e2, two).len(), 1);
    assert_eq!(sent_for(&out, &e2, one).len(), 0);
    // ...and the release at t0 + 30 carries only the held one.
    let out = outputs(|o| rib.flush(secs(t0, 30), o));
    assert_eq!(sent_for(&out, &e2, one).len(), 1);
    assert_eq!(sent_for(&out, &e2, two).len(), 0);
    // The second destination's own interval runs from t0 + 5.
    let out = outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["198.51.100.0/24"], &attrs(&[65_001, 4], "10.0.0.1")),
            secs(t0, 20),
            o,
        );
    });
    assert_eq!(sent_for(&out, &e2, two).len(), 0);
    assert_eq!(release_at(&rib), Some(secs(t0, 35)));
    assert_eq!(
        sent_for(&outputs(|o| rib.flush(secs(t0, 35), o)), &e2, two).len(),
        1
    );
}

#[test]
fn mrai_is_kept_per_peer_with_the_rfc_defaults() {
    use crate::pacing::default_interval;
    let t0 = Instant::now();
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = paced("10.0.0.2", 65_002, 2, default_interval(PeerKind::External));
    let i3 = paced("10.0.0.3", 65_000, 3, default_interval(PeerKind::Internal));
    assert_eq!(e2.advertisement_interval, Duration::from_secs(30));
    assert_eq!(i3.advertisement_interval, Duration::from_secs(5));
    for info in [&e1, &e2, &i3] {
        outputs(|o| rib.peer_up(info.clone(), t0, o));
    }
    let dst = p("192.0.2.0/24");
    let out = outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_001], "10.0.0.1")),
            t0,
            o,
        );
    });
    assert_eq!(sent_for(&out, &e2, dst).len(), 1);
    assert_eq!(sent_for(&out, &i3, dst).len(), 1);
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_001, 2], "10.0.0.1")),
            secs(t0, 1),
            o,
        );
    });
    // RFC 4271 §9.2.1.1 (a): the internal peer hears first.
    let out = outputs(|o| rib.flush(secs(t0, 5), o));
    assert_eq!(sent_for(&out, &i3, dst).len(), 1);
    assert_eq!(sent_for(&out, &e2, dst).len(), 0);
    let out = outputs(|o| rib.flush(secs(t0, 30), o));
    assert_eq!(sent_for(&out, &e2, dst).len(), 1);
    assert_eq!(sent_for(&out, &i3, dst).len(), 0);
}

#[test]
fn mrai_zero_sends_every_change_at_once() {
    let t0 = Instant::now();
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = paced("10.0.0.2", 65_002, 2, Duration::ZERO);
    outputs(|o| rib.peer_up(e1.clone(), t0, o));
    outputs(|o| rib.peer_up(e2.clone(), t0, o));
    let dst = p("192.0.2.0/24");
    for i in 0..5u32 {
        let out = outputs(|o| {
            rib.update(
                e1.addr,
                &announce(&["192.0.2.0/24"], &attrs(&[65_001, i + 1], "10.0.0.1")),
                t0,
                o,
            );
        });
        assert_eq!(sent_for(&out, &e2, dst).len(), 1, "change {i}");
        let out = outputs(|o| rib.update(e1.addr, &withdraw(&["192.0.2.0/24"]), t0, o));
        assert_eq!(sent_for(&out, &e2, dst), vec![None]);
    }
    assert_eq!(release_at(&rib), None);
}

#[test]
fn mrai_route_refresh_and_policy_changes_go_through_the_pacing() {
    use crate::{Policies, Verdict};
    /// Exports everything with a community.
    struct Tag;
    impl Policies for Tag {
        fn import(
            &self,
            _: &PeerInfo,
            _: AddressFamily,
            _: Prefix,
            _: &PathAttrs,
            _: RovState,
        ) -> Verdict {
            Verdict::Accept
        }
        fn export(
            &self,
            _: &PeerInfo,
            _: AddressFamily,
            _: Prefix,
            a: &PathAttrs,
            _: RovState,
        ) -> Verdict {
            let mut m = a.clone();
            m.communities = vec![Community::new(65_000, 42)].into();
            Verdict::Modified(m)
        }
    }
    let t0 = Instant::now();
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = paced("10.0.0.2", 65_002, 2, EBGP_IV);
    outputs(|o| rib.peer_up(e1.clone(), t0, o));
    outputs(|o| rib.peer_up(e2.clone(), t0, o));
    let dst = p("192.0.2.0/24");
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_001], "10.0.0.1")),
            t0,
            o,
        );
    });
    // An export policy change inside the interval is held like any other.
    let out = outputs(|o| rib.set_policies(Box::new(Tag), &[e2.addr], secs(t0, 2), o));
    assert_eq!(sends(&out, e2.addr).len(), 0);
    assert_eq!(release_at(&rib), Some(secs(t0, 30)));
    // The peer asks for everything again (RFC 2918 §4): it gets the held
    // route as it is now, and the interval restarts.
    let out = outputs(|o| rib.refresh(e2.addr, V4, secs(t0, 10), o));
    let m = decode_sent(sends(&out, e2.addr)[0], &e2);
    assert_eq!(m[0].nlri, vec![dst]);
    assert!(m[0].attribute(8).is_some(), "COMMUNITIES from the policy");
    assert_eq!(
        sends(&outputs(|o| rib.flush(secs(t0, 30), o)), e2.addr).len(),
        0
    );
    let out = outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_001, 5], "10.0.0.1")),
            secs(t0, 20),
            o,
        );
    });
    assert_eq!(sends(&out, e2.addr).len(), 0);
    assert_eq!(release_at(&rib), Some(secs(t0, 40)));
    assert_eq!(
        sent_for(&outputs(|o| rib.flush(secs(t0, 40), o)), &e2, dst).len(),
        1
    );
}

#[test]
fn mrai_new_interval_applies_to_held_destinations() {
    let t0 = Instant::now();
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = paced("10.0.0.2", 65_002, 2, EBGP_IV);
    outputs(|o| rib.peer_up(e1.clone(), t0, o));
    outputs(|o| rib.peer_up(e2.clone(), t0, o));
    let dst = p("192.0.2.0/24");
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_001], "10.0.0.1")),
            t0,
            o,
        );
    });
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_001, 2], "10.0.0.1")),
            secs(t0, 1),
            o,
        );
    });
    // Shorter: the held route moves to t0 + 10.
    assert_eq!(
        outputs(|o| rib.set_advertisement_interval(
            e2.addr,
            Duration::from_secs(10),
            secs(t0, 2),
            o
        ))
        .len(),
        0
    );
    assert_eq!(
        rib.peer(e2.addr).unwrap().advertisement_interval,
        Duration::from_secs(10)
    );
    assert_eq!(
        sent_for(&outputs(|o| rib.flush(secs(t0, 10), o)), &e2, dst).len(),
        1
    );
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_001, 3], "10.0.0.1")),
            secs(t0, 11),
            o,
        );
    });
    // Off: it goes out right away.
    let out = outputs(|o| rib.set_advertisement_interval(e2.addr, Duration::ZERO, secs(t0, 12), o));
    assert_eq!(sent_for(&out, &e2, dst).len(), 1);
    // Same value, or an unknown peer: nothing.
    assert_eq!(
        outputs(|o| rib.set_advertisement_interval(e2.addr, Duration::ZERO, secs(t0, 13), o)).len(),
        0
    );
    assert_eq!(
        outputs(|o| rib.set_advertisement_interval(ip("10.9.9.9"), EBGP_IV, secs(t0, 13), o)).len(),
        0
    );
}

#[test]
fn mrai_churn_at_scale_is_released_once_and_packed() {
    // 20 000 destinations, each changed three times inside the interval:
    // one wake-up each (not three), one release, UPDATEs within the
    // message size. The bench `mrai_churn` runs this at full-table size.
    const N: u32 = 20_000;
    let t0 = Instant::now();
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = paced("10.0.0.2", 65_002, 2, EBGP_IV);
    outputs(|o| rib.peer_up(e1.clone(), t0, o));
    outputs(|o| rib.peer_up(e2.clone(), t0, o));
    let prefixes: Vec<String> = (0..N)
        .map(|i| format!("10.{}.{}.0/24", i >> 8, i & 0xff))
        .collect();
    let refs: Vec<&str> = prefixes.iter().map(String::as_str).collect();
    let out = outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&refs, &attrs(&[65_001], "10.0.0.1")),
            t0,
            o,
        );
    });
    let first: usize = decode_sent(sends(&out, e2.addr)[0], &e2)
        .iter()
        .map(|m| m.nlri.len())
        .sum();
    assert_eq!(first, refs.len());
    for s in 1..=3u32 {
        let a = attrs(&[65_001, s], "10.0.0.1");
        let out = outputs(|o| rib.update(e1.addr, &announce(&refs, &a), secs(t0, u64::from(s)), o));
        assert_eq!(sends(&out, e2.addr).len(), 0);
    }
    assert_eq!(rib.s.deadlines.len(), refs.len());
    let out = outputs(|o| rib.flush(secs(t0, 30), o));
    let s = sends(&out, e2.addr);
    assert_eq!(s.len(), 1);
    let msgs = decode_sent(s[0], &e2);
    let total: usize = msgs.iter().map(|m| m.nlri.len()).sum();
    assert_eq!(total, refs.len());
    assert!(msgs.iter().all(|m| {
        m.as_path().unwrap().asns().collect::<Vec<_>>() == vec![LOCAL_AS, Asn(65_001), Asn(3)]
    }));
    assert_eq!(rib.s.deadlines.len(), 0);
    assert_eq!(release_at(&rib), None);
}

#[test]
fn mrai_wake_ups_stay_one_per_destination_however_it_flaps() {
    // A destination that changes and changes back, or is withdrawn and
    // announced again, many times inside one interval: the queue holds a
    // bounded number of wake-ups for it, not one per flap, and what is
    // sent is still paced (AGENTS.md §3: memory must not grow with churn).
    const FLAPS: u64 = 5_000;
    let t0 = Instant::now();
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = paced("10.0.0.2", 65_002, 2, EBGP_IV);
    outputs(|o| rib.peer_up(e1.clone(), t0, o));
    outputs(|o| rib.peer_up(e2.clone(), t0, o));
    let dst = p("192.0.2.0/24");
    let a = attrs(&[65_001], "10.0.0.1");
    let b = attrs(&[65_001, 7], "10.0.0.1");
    let first = outputs(|o| rib.update(e1.addr, &announce(&["192.0.2.0/24"], &a), t0, o));
    assert_eq!(sent_for(&first, &e2, dst).len(), 1);
    let mut sent = 0;
    for i in 0..FLAPS {
        let at = t0 + Duration::from_millis(i);
        // A change and its revert, then a withdrawal and the route back.
        for d in [
            announce(&["192.0.2.0/24"], &b),
            announce(&["192.0.2.0/24"], &a),
            withdraw(&["192.0.2.0/24"]),
            announce(&["192.0.2.0/24"], &a),
        ] {
            sent += sent_for(&outputs(|o| rib.update(e1.addr, &d, at, o)), &e2, dst).len();
        }
    }
    // One withdrawal went out; every re-announcement waits.
    assert_eq!(sent, 1);
    assert!(
        rib.s.deadlines.len() <= 2,
        "{} wake-ups",
        rib.s.deadlines.len()
    );
    // The interval ends: the route goes out once, and the queue empties.
    let out = outputs(|o| rib.flush(secs(t0, 31), o));
    assert_eq!(
        sent_for(&out, &e2, dst),
        vec![Some(vec![LOCAL_AS, Asn(65_001)])]
    );
    let out = outputs(|o| rib.flush(secs(t0, 61), o));
    assert_eq!(sent_for(&out, &e2, dst), vec![]);
    assert_eq!(rib.s.deadlines.len(), 0);
}

#[test]
fn mrai_state_stays_bounded_under_churn_of_new_destinations() {
    // Ever new destinations, each announced and withdrawn inside one
    // interval, while the peer never has more than one: what pacing
    // remembers stays within a bound, and is given back afterwards.
    const N: u32 = 20_000;
    let t0 = Instant::now();
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = paced("10.0.0.2", 65_002, 2, EBGP_IV);
    outputs(|o| rib.peer_up(e1.clone(), t0, o));
    outputs(|o| rib.peer_up(e2.clone(), t0, o));
    let a = attrs(&[65_001], "10.0.0.1");
    for i in 0..N {
        let prefix = format!("10.{}.{}.0/24", i >> 8, i & 0xff);
        let out = outputs(|o| rib.update(e1.addr, &announce(&[&prefix], &a), t0, o));
        assert_eq!(sent_for(&out, &e2, p(&prefix)).len(), 1);
        let out = outputs(|o| rib.update(e1.addr, &withdraw(&[&prefix]), t0, o));
        assert_eq!(sent_for(&out, &e2, p(&prefix)), vec![None]);
    }
    let cap = crate::pacing::MIN_WAITING;
    assert!(
        rib.s.deadlines.len() <= cap,
        "{} wake-ups",
        rib.s.deadlines.len()
    );
    let adj = pacing(&rib, e2.addr);
    assert!(
        adj.remembered() <= 3 * cap,
        "{} remembered",
        adj.remembered()
    );
    // Remembered ones are still paced: the first comes back, and waits.
    let out = outputs(|o| rib.update(e1.addr, &announce(&["10.0.0.0/24"], &a), t0, o));
    assert_eq!(sent_for(&out, &e2, p("10.0.0.0/24")), vec![]);
    // When the interval is over everything is forgotten and given back,
    // but for the advertisement its end made, once its own interval is
    // over: the sweeps see to that with no further input.
    outputs(|o| rib.flush(secs(t0, 31), o));
    assert_eq!(rib.s.deadlines.len(), 0);
    assert!(
        rib.s.deadlines.capacity() <= 4 * cap,
        "{}",
        rib.s.deadlines.capacity()
    );
    assert_eq!(pacing(&rib, e2.addr).remembered(), 1);
    while let Some(d) = rib.next_deadline() {
        assert!(d <= secs(t0, 62), "{:?}", d - t0);
        outputs(|o| rib.flush(d, o));
    }
    assert_eq!(pacing(&rib, e2.addr).remembered(), 0);
}

#[test]
fn mrai_advertisements_are_forgotten_by_a_peer_that_hears_no_more() {
    // A table sent one destination at a time is remembered for an
    // interval to pace what follows, then forgotten without further
    // input: the RIB asks to be woken for that.
    let t0 = Instant::now();
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = paced("10.0.0.2", 65_002, 2, EBGP_IV);
    outputs(|o| rib.peer_up(e1.clone(), t0, o));
    outputs(|o| rib.peer_up(e2.clone(), t0, o));
    let prefixes: Vec<String> = (0..2000u32)
        .map(|i| format!("10.{}.{}.0/24", i >> 8, i & 0xff))
        .collect();
    let refs: Vec<&str> = prefixes.iter().map(String::as_str).collect();
    let a = attrs(&[65_001], "10.0.0.1");
    let half = Duration::from_millis(500);
    outputs(|o| rib.update(e1.addr, &announce(&refs[..1000], &a), t0 + half, o));
    // The daemon flushes at every deadline.
    while let Some(d) = rib.next_deadline()
        && d <= secs(t0, 2)
    {
        outputs(|o| rib.flush(d, o));
    }
    outputs(|o| rib.update(e1.addr, &announce(&refs[1000..], &a), secs(t0, 2) + half, o));
    assert_eq!(pacing(&rib, e2.addr).remembered(), 2000);
    assert_eq!(release_at(&rib), None);
    // The second being filled is sorted once it is over.
    assert_eq!(rib.next_deadline(), Some(secs(t0, 3)));
    outputs(|o| rib.flush(secs(t0, 3), o));
    // Each second is forgotten an interval after it.
    assert_eq!(rib.next_deadline(), Some(secs(t0, 31)));
    outputs(|o| rib.flush(secs(t0, 31), o));
    assert_eq!(pacing(&rib, e2.addr).remembered(), 1000);
    // Until then a change is still held back.
    let b = attrs(&[65_001, 7], "10.0.0.1");
    let out = outputs(|o| rib.update(e1.addr, &announce(&[refs[1999]], &b), secs(t0, 32), o));
    assert_eq!(sends(&out, e2.addr).len(), 0);
    assert_eq!(release_at(&rib), Some(secs(t0, 33)));
    let out = outputs(|o| rib.flush(secs(t0, 33), o));
    assert_eq!(sends(&out, e2.addr).len(), 1);
    // The release itself is remembered for an interval, sorted at once.
    assert_eq!(pacing(&rib, e2.addr).remembered(), 1);
    assert_eq!(rib.next_deadline(), Some(secs(t0, 63)));
    outputs(|o| rib.flush(secs(t0, 63), o));
    assert_eq!(pacing(&rib, e2.addr).remembered(), 0);
    assert_eq!(rib.next_deadline(), None);
}

// --- Storage and interning (from the RIB rework) --------------------------

#[test]
fn peer_down_leaves_no_route_for_the_next_peer_in_its_slot() {
    let mut rib = Rib::new(LOCAL_AS);
    let mut e1 = peer("10.0.0.1", 65_001, 1);
    e1.families = vec![V4];
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_001], "10.0.0.1")),
            now(),
            o,
        );
    });
    // A family the session did not negotiate: still stored (the decoder
    // does not filter by family), so peer down must look there too.
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["2001:db8:1::/48"], &attrs(&[65_001], "2001:db8::1")),
            now(),
            o,
        );
    });
    assert_eq!(rib.loc_rib(V6).count(), 1);
    let out = outputs(|o| rib.peer_down(e1.addr, now(), o));
    assert_eq!(fib(&out).len(), 2);
    assert_eq!(rib.loc_rib(V4).count(), 0);
    assert_eq!(rib.loc_rib(V6).count(), 0);
    // The next peer takes the free slot and inherits nothing.
    let e2 = peer("10.0.0.2", 65_002, 2);
    outputs(|o| rib.peer_up(e2.clone(), now(), o));
    assert_eq!(rib.candidates(V6, p("2001:db8:1::/48")).len(), 0);
    outputs(|o| {
        rib.update(
            e2.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_002], "10.0.0.2")),
            now(),
            o,
        );
    });
    let routes: Vec<IpAddr> = rib
        .candidates(V4, p("192.0.2.0/24"))
        .iter()
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
        outputs(|o| rib.peer_up(e.clone(), now(), o));
    }
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_001, 7, 8], "10.0.0.1")),
            now(),
            o,
        );
    });
    outputs(|o| {
        rib.update(
            e2.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_002], "10.0.0.2")),
            now(),
            o,
        );
    });
    outputs(|o| {
        rib.update(
            e3.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_003, 7], "10.0.0.3")),
            now(),
            o,
        );
    });
    let order = |rib: &Rib| -> Vec<IpAddr> {
        rib.candidates(V4, p("192.0.2.0/24"))
            .iter()
            .map(|r| r.peer)
            .collect()
    };
    assert_eq!(order(&rib)[0], e2.addr);
    assert_eq!(order(&rib).len(), 3);
    assert_eq!(rib.loc_rib(V4).next().unwrap().1.peer, e2.addr);
    // The best goes: the next best (shorter path) takes its place.
    let out = outputs(|o| rib.update(e2.addr, &withdraw(&["192.0.2.0/24"]), now(), o));
    assert_eq!(fib(&out)[0].next_hop, Some(ip("10.0.0.3")));
    assert_eq!(order(&rib), vec![e3.addr, e1.addr]);
    // A non-best route going changes nothing.
    let out = outputs(|o| rib.update(e1.addr, &withdraw(&["192.0.2.0/24"]), now(), o));
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
        outputs(|o| rib.peer_up(p.clone(), now(), o));
    }
    let a = attrs(&[65_001, 7], "10.0.0.1");
    let b = attrs(&[65_002], "10.0.0.2");
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24", "198.51.100.0/24"], &a),
            now(),
            o,
        );
    });
    outputs(|o| rib.update(e2.addr, &announce(&["192.0.2.0/24"], &b), now(), o));
    // Received sets a and b; the peers they are sent to get them
    // rewritten when encoded, not as sets of their own.
    assert_eq!(rib.attribute_sets(), 2);
    // Replacing a route lets its old set go once nothing uses it.
    let a2 = attrs(&[65_001, 8], "10.0.0.1");
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24", "198.51.100.0/24"], &a2),
            now(),
            o,
        );
    });
    let held = rib.attribute_sets();
    outputs(|o| rib.update(e2.addr, &withdraw(&["192.0.2.0/24"]), now(), o));
    assert!(rib.attribute_sets() < held);
    outputs(|o| {
        rib.update(
            e1.addr,
            &withdraw(&["192.0.2.0/24", "198.51.100.0/24"]),
            now(),
            o,
        );
    });
    assert_eq!(rib.attribute_sets(), 0);

    // The same through peer down, including what the peer was sent.
    outputs(|o| rib.update(e1.addr, &announce(&["192.0.2.0/24"], &a), now(), o));
    outputs(|o| rib.update(e2.addr, &announce(&["198.51.100.0/24"], &b), now(), o));
    assert!(rib.attribute_sets() > 0);
    outputs(|o| rib.peer_down(e1.addr, now(), o));
    outputs(|o| rib.peer_down(e2.addr, now(), o));
    assert_eq!(rib.attribute_sets(), 0);
}

#[test]
fn a_prefix_listed_twice_in_an_update_changes_once() {
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_002, 2);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    outputs(|o| rib.peer_up(e2.clone(), now(), o));
    let a = attrs(&[65_001], "10.0.0.1");
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24", "198.51.100.0/24"], &a),
            now(),
            o,
        );
    });
    // Withdrawn and announced again unchanged, in one UPDATE: the best
    // route before and after is the same, so nothing follows.
    let mut again = announce(&["192.0.2.0/24"], &a);
    again.message.withdrawn = vec![p("192.0.2.0/24")];
    let out = outputs(|o| rib.update(e1.addr, &again, now(), o));
    assert!(out.is_empty(), "{out:?}");
    // The same with new attributes, the prefix twice in the NLRI too:
    // one FIB change, one announcement to e2.
    let longer = attrs(&[65_001, 9], "10.0.0.9");
    let mut twice = announce(
        &["192.0.2.0/24", "198.51.100.0/24", "192.0.2.0/24"],
        &longer,
    );
    twice.message.withdrawn = vec![p("192.0.2.0/24")];
    let out = outputs(|o| rib.update(e1.addr, &twice, now(), o));
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
        rib.peer_up(e1.clone(), now(), o);
        rib.peer_up(e2.clone(), now(), o);
        rib.peer_up(i1.clone(), now(), o);
    });
    let prefixes = ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"];
    let a = attrs(&[65_001, 64_500], "10.0.0.1");
    let out = outputs(|o| rib.update(e1.addr, &announce(&prefixes, &a), now(), o));
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
    let out = outputs(|o| rib.peer_up(e3.clone(), now(), o));
    let m = decode_sent(sends(&out, e3.addr)[0], &e3);
    assert_eq!(m[0].as_path().unwrap().first_asn(), Some(LOCAL_AS));
    let held = Arc::clone(rib.loc_rib(V4).next().unwrap().1.attrs);
    for to in [&e2, &i1, &e3] {
        assert_eq!(rib.adj_rib_out(to.addr, V4).len(), 3);
        assert!(
            rib.adj_rib_out(to.addr, V4)
                .all(|(_, x)| Arc::ptr_eq(&x, &held))
        );
    }
    assert_eq!(rib.s.cx.interner.len(), 1);
    drop(held);
    // Withdrawn, the set goes with its last route.
    let _ = outputs(|o| rib.update(e1.addr, &withdraw(&prefixes), now(), o));
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
        rib.peer_up(e1.clone(), now(), o);
        rib.peer_up(e2.clone(), now(), o);
        rib.peer_up(i1.clone(), now(), o);
    });
    let a = attrs(&[65_001], "10.0.0.1");
    let _ = outputs(|o| rib.update(e1.addr, &announce(&["192.0.2.0/24"], &a), now(), o));
    // Another next hop and MED: an external peer gets ours and no MED
    // (RFC 4271 §5.1.3, §5.1.4), so nothing it would see changed; an
    // internal peer gets both as received.
    let mut b = attrs(&[65_001], "10.0.0.9");
    b.med = Some(5);
    let out = outputs(|o| rib.update(e1.addr, &announce(&["192.0.2.0/24"], &b), now(), o));
    assert!(sends(&out, e2.addr).is_empty(), "{out:?}");
    let m = decode_sent(sends(&out, i1.addr)[0], &i1);
    assert_eq!(m[0].next_hop(), Some(Ipv4Addr::new(10, 0, 0, 9)));
    // The Adj-RIB-Out follows the new set all the same.
    let held = Arc::clone(rib.loc_rib(V4).next().unwrap().1.attrs);
    assert!(
        rib.adj_rib_out(e2.addr, V4)
            .all(|(_, x)| Arc::ptr_eq(&x, &held))
    );
    // A change it does see is sent.
    let c = attrs(&[65_001, 7], "10.0.0.9");
    let out = outputs(|o| rib.update(e1.addr, &announce(&["192.0.2.0/24"], &c), now(), o));
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

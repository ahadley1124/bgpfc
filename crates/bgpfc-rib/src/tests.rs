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
use crate::decision::{Candidate, best};
use crate::export::{Source, export, prepend};
use crate::peer::PeerInfo;
use crate::{FibChange, Output, Rib};

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
        communities: Vec::new(),
        ext_communities: Vec::new(),
        large_communities: Vec::new(),
        unknown: Vec::new(),
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

fn candidate(info: &PeerInfo, a: PathAttrs) -> Candidate {
    Candidate {
        peer: info.addr,
        kind: info.kind,
        router_id: info.router_id.to_u32(),
        remote_as: info.remote_as,
        attrs: Arc::new(a),
    }
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
    let c = [candidate(&i1, a), candidate(&i2, b)];
    assert_eq!(best(&c), Some(0));
}

#[test]
fn shorter_as_path_wins() {
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_002, 2);
    let c = [
        candidate(&e1, attrs(&[65_001, 7, 8], "10.0.0.1")),
        candidate(&e2, attrs(&[65_002, 7], "10.0.0.2")),
    ];
    assert_eq!(best(&c), Some(1));
}

#[test]
fn as_set_counts_as_one_hop() {
    use bgpfc_wire::as_path::{AsPathSegment, SegmentType};
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_002, 2);
    let mut a = attrs(&[65_001], "10.0.0.1");
    a.as_path.segments.push(AsPathSegment {
        kind: SegmentType::Set,
        asns: vec![Asn(1), Asn(2), Asn(3)],
    });
    let b = attrs(&[65_002, 9, 9], "10.0.0.2");
    // a: 1 + 1 (the set) = 2 hops; b: 3 hops.
    let c = [candidate(&e1, a), candidate(&e2, b)];
    assert_eq!(best(&c), Some(0));
}

#[test]
fn lower_origin_wins() {
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_002, 2);
    let mut a = attrs(&[65_001], "10.0.0.1");
    a.origin = Origin::Incomplete;
    let mut b = attrs(&[65_002], "10.0.0.2");
    b.origin = Origin::Egp;
    let c = [candidate(&e1, a), candidate(&e2, b)];
    assert_eq!(best(&c), Some(1));
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
    let c = [
        candidate(&e1, first),
        candidate(&e2, second),
        candidate(&e3, third),
    ];
    assert_eq!(best(&c), Some(1));
    // A missing MED is the lowest value.
    let mut no_med = attrs(&[65_001], "10.0.0.1");
    no_med.med = None;
    let mut zero_med = attrs(&[65_001], "10.0.0.2");
    zero_med.med = Some(0);
    let c = [candidate(&e1, no_med), candidate(&e2, zero_med)];
    // Equal MED (0): router id decides, e1 has the lower one.
    assert_eq!(best(&c), Some(0));
    let mut one_med = attrs(&[65_001], "10.0.0.2");
    one_med.med = Some(1);
    let c = [
        candidate(&e2, one_med),
        candidate(&e1, attrs(&[65_001], "10.0.0.1")),
    ];
    assert_eq!(best(&c), Some(1));
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
    let c = [candidate(&i1, a), candidate(&i2, b)];
    assert_eq!(best(&c), Some(1));
}

#[test]
fn external_beats_internal() {
    let i = peer("10.0.0.1", 65_000, 1);
    let e = peer("10.0.0.2", 65_002, 2);
    let c = [
        candidate(&i, attrs(&[65_002], "10.0.0.1")),
        candidate(&e, attrs(&[65_002], "10.0.0.2")),
    ];
    assert_eq!(best(&c), Some(1));
}

#[test]
fn lower_router_id_then_lower_peer_address() {
    let e1 = peer("10.0.0.9", 65_001, 5);
    let e2 = peer("10.0.0.2", 65_002, 7);
    let c = [
        candidate(&e1, attrs(&[65_001], "10.0.0.9")),
        candidate(&e2, attrs(&[65_002], "10.0.0.2")),
    ];
    assert_eq!(best(&c), Some(0));
    let e3 = peer("10.0.0.2", 65_002, 5);
    let c = [
        candidate(&e1, attrs(&[65_001], "10.0.0.9")),
        candidate(&e3, attrs(&[65_002], "10.0.0.2")),
    ];
    assert_eq!(best(&c), Some(1));
    assert_eq!(best(&[]), None);
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
    a.ext_communities = vec![transitive, local_only];
    a.normalise();
    let e = export(LOCAL_AS, V4, src, &a, &ext).unwrap();
    assert_eq!(e.ext_communities, vec![transitive]);
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
    a.communities = vec![Community::NO_EXPORT];
    a.normalise();
    assert!(export(LOCAL_AS, V4, src, &a, &ext).is_none());
    assert!(export(LOCAL_AS, V4, src, &a, &int).is_some());
    a.communities = vec![Community::NO_ADVERTISE];
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
fn prepend_respects_segment_limit_and_sets() {
    use bgpfc_wire::as_path::{AsPathSegment, SegmentType};
    let p1 = prepend(&AsPath::empty(), Asn(1));
    assert_eq!(p1.asns().collect::<Vec<_>>(), vec![Asn(1)]);
    let p2 = prepend(&p1, Asn(2));
    assert_eq!(p2.segments.len(), 1);
    assert_eq!(p2.asns().collect::<Vec<_>>(), vec![Asn(2), Asn(1)]);
    let full = AsPath::sequence(&vec![Asn(9); 255]);
    let p3 = prepend(&full, Asn(1));
    assert_eq!(p3.segments.len(), 2);
    assert_eq!(p3.segments[0].asns, vec![Asn(1)]);
    let set = AsPath {
        segments: vec![AsPathSegment {
            kind: SegmentType::Set,
            asns: vec![Asn(5)],
        }],
    };
    let p4 = prepend(&set, Asn(1));
    assert_eq!(p4.segments[0].kind, SegmentType::Sequence);
    assert_eq!(p4.segments.len(), 2);
}

// --- The RIB end to end --------------------------------------------------

#[test]
fn announce_withdraw_and_fib_changes() {
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_002, 2);
    assert_eq!(rib.peer_up(e1.clone()).len(), 0);
    assert_eq!(rib.peer_up(e2.clone()).len(), 0);
    let a = attrs(&[65_001, 7], "10.0.0.1");
    let out = rib.update(e1.addr, &announce(&["192.0.2.0/24", "198.51.100.0/24"], &a));
    assert_eq!(
        fib(&out),
        vec![
            FibChange {
                family: V4,
                prefix: p("192.0.2.0/24"),
                next_hop: Some(ip("10.0.0.1"))
            },
            FibChange {
                family: V4,
                prefix: p("198.51.100.0/24"),
                next_hop: Some(ip("10.0.0.1"))
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
    let out = rib.update(e1.addr, &announce(&["192.0.2.0/24"], &a));
    assert!(out.is_empty(), "{out:?}");

    // A better route from e2 (shorter path) replaces it: e1 is told,
    // e2 is not.
    let b = attrs(&[65_002], "10.0.0.2");
    let out = rib.update(e2.addr, &announce(&["192.0.2.0/24"], &b));
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
    let out = rib.update(e2.addr, &withdraw(&["192.0.2.0/24"]));
    assert_eq!(fib(&out)[0].next_hop, Some(ip("10.0.0.1")));
    let m = decode_sent(sends(&out, e1.addr)[0], &e1);
    assert_eq!(m[0].withdrawn, vec![p("192.0.2.0/24")]);
    let m = decode_sent(sends(&out, e2.addr)[0], &e2);
    assert_eq!(m[0].nlri, vec![p("192.0.2.0/24")]);

    // Peer down: everything from e1 goes.
    let out = rib.peer_down(e1.addr);
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
    rib.peer_up(e1.clone());
    rib.peer_up(i1.clone());
    // RFC 7606 §7.2: an external route not starting with the peer's AS is
    // treated as withdrawn.
    let out = rib.update(
        e1.addr,
        &announce(&["192.0.2.0/24"], &attrs(&[65_009], "10.0.0.1")),
    );
    assert_eq!(fib(&out).len(), 0);
    assert_eq!(rib.loc_rib(V4).count(), 0);
    // An empty path from an external peer likewise.
    let out = rib.update(
        e1.addr,
        &announce(&["192.0.2.0/24"], &attrs(&[], "10.0.0.1")),
    );
    assert_eq!(fib(&out).len(), 0);
    // Internal peers may relay any path, including an empty one.
    let mut a = attrs(&[65_009], "10.0.0.3");
    a.local_pref = Some(100);
    let out = rib.update(i1.addr, &announce(&["192.0.2.0/24"], &a));
    assert_eq!(fib(&out).len(), 1);
}

#[test]
fn prefix_in_both_withdrawn_and_nlri_is_announced() {
    // RFC 4271 §4.3: a prefix in both Withdrawn Routes and NLRI is treated
    // as not withdrawn.
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    rib.peer_up(e1.clone());
    let mut u = announce(&["192.0.2.0/24"], &attrs(&[65_001], "10.0.0.1"));
    u.message.withdrawn = vec![p("192.0.2.0/24")];
    let out = rib.update(e1.addr, &u);
    assert_eq!(fib(&out).len(), 1);
    assert_eq!(fib(&out)[0].next_hop, Some(ip("10.0.0.1")));
    assert_eq!(rib.loc_rib(V4).count(), 1);
}

#[test]
fn as_loop_routes_are_excluded() {
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    rib.peer_up(e1.clone());
    let a = attrs(&[65_001, LOCAL_AS.0, 7], "10.0.0.1");
    let out = rib.update(e1.addr, &announce(&["192.0.2.0/24"], &a));
    assert_eq!(out.len(), 0);
    assert_eq!(rib.loc_rib(V4).count(), 0);
    // A replacement with a loop withdraws the earlier good route.
    let good = attrs(&[65_001], "10.0.0.1");
    rib.update(e1.addr, &announce(&["192.0.2.0/24"], &good));
    assert_eq!(rib.loc_rib(V4).count(), 1);
    let out = rib.update(e1.addr, &announce(&["192.0.2.0/24"], &a));
    assert_eq!(fib(&out)[0].next_hop, None);
}

#[test]
fn new_peer_receives_the_loc_rib_and_route_refresh_resends_it() {
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    rib.peer_up(e1.clone());
    rib.update(
        e1.addr,
        &announce(&["192.0.2.0/24"], &attrs(&[65_001], "10.0.0.1")),
    );
    rib.update(
        e1.addr,
        &announce(&["2001:db8:1::/48"], &attrs(&[65_001], "2001:db8::1")),
    );
    let i = peer("10.0.0.3", 65_000, 3);
    let out = rib.peer_up(i.clone());
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
    let out = rib.refresh(i.addr, V6);
    assert_eq!(fib(&out).len(), 0);
    let v6 = decode_sent(sends(&out, i.addr)[0], &i);
    assert_eq!(
        v6[0].mp_reach.as_ref().unwrap().nlri,
        vec![p("2001:db8:1::/48")]
    );
    // A family the peer does not speak: nothing.
    let mut v4_only = peer("10.0.0.4", 65_004, 4);
    v4_only.families = vec![V4];
    let out = rib.peer_up(v4_only.clone());
    assert_eq!(sends(&out, v4_only.addr).len(), 1);
    assert_eq!(rib.refresh(v4_only.addr, V6).len(), 0);
    assert_eq!(rib.refresh(ip("10.9.9.9"), V4).len(), 0);
}

#[test]
fn family_disable_drops_that_family_only() {
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    rib.peer_up(e1.clone());
    rib.update(
        e1.addr,
        &announce(&["192.0.2.0/24"], &attrs(&[65_001], "10.0.0.1")),
    );
    rib.update(
        e1.addr,
        &announce(&["2001:db8:1::/48"], &attrs(&[65_001], "2001:db8::1")),
    );
    let out = rib.family_disabled(e1.addr, V6);
    assert_eq!(fib(&out).len(), 1);
    assert_eq!(rib.loc_rib(V6).count(), 0);
    assert_eq!(rib.loc_rib(V4).count(), 1);
    // Later IPv6 announcements are ignored.
    let out = rib.update(
        e1.addr,
        &announce(&["2001:db8:2::/48"], &attrs(&[65_001], "2001:db8::1")),
    );
    assert_eq!(out.len(), 0);
    // Unknown peers are ignored everywhere.
    let out = rib.update(ip("10.9.9.9"), &withdraw(&["192.0.2.0/24"]));
    assert_eq!(out.len(), 0);
    assert_eq!(rib.peer_down(ip("10.9.9.9")).len(), 0);
    assert_eq!(rib.family_disabled(ip("10.9.9.9"), V4).len(), 0);
}

#[test]
fn large_batches_are_packed_within_the_message_limit() {
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    let mut e2 = peer("10.0.0.2", 65_002, 2);
    e2.four_octet_as = false;
    rib.peer_up(e1.clone());
    rib.peer_up(e2.clone());
    // 3000 /24s: more than fit in one 4096-octet UPDATE.
    let prefixes: Vec<String> = (0..3000u32)
        .map(|i| format!("10.{}.{}.0/24", (i >> 8) + 1, i & 0xff))
        .collect();
    let refs: Vec<&str> = prefixes.iter().map(String::as_str).collect();
    let a = attrs(&[65_001, 4_200_000_000], "10.0.0.1");
    let out = rib.update(e1.addr, &announce(&refs, &a));
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
    let out = rib.peer_down(e1.addr);
    let msgs = decode_sent(sends(&out, e2.addr)[0], &e2);
    assert!(msgs.len() > 1);
    let total: usize = msgs.iter().map(|m| m.withdrawn.len()).sum();
    assert_eq!(total, 3000);
    assert!(rib.attribute_sets() >= 1);
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
    a.communities = vec![Community::new(65_001, 2), Community::new(65_001, 1)];
    a.large_communities = vec![bgpfc_wire::community::LargeCommunity {
        global: 1,
        local1: 2,
        local2: 3,
    }];
    a.unknown = vec![crate::attrs::UnknownAttribute {
        flags: 0xc0,
        code: 200,
        value: vec![1, 2],
    }];
    a.normalise();
    let m = a.to_update(V4, vec![p("192.0.2.0/24")]);
    let back = PathAttrs::from_update(&m, V4).unwrap();
    assert_eq!(
        back.communities,
        vec![Community::new(65_001, 1), Community::new(65_001, 2)]
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

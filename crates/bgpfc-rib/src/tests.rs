//! Decision-process tests per tie-break step (AGENTS.md §5, `bgpfc-rib`
//! row), export rules, update packing and RIB bookkeeping.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bgpfc_wire::as_path::AsPath;
use bgpfc_wire::attribute::{Origin, PathAttribute};
use bgpfc_wire::community::Community;
use bgpfc_wire::header::HEADER_LEN;
use bgpfc_wire::mp::NextHop;
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::{AddressFamily, Asn, RouterId};
use bgpfc_wire::update::{DecodeContext, DecodedUpdate, PeerKind, UpdateMessage};

use crate::attrs::{PathAttrs, announced};
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
        extended_next_hop: Vec::new(),
        // Pacing off: these tests are about what is sent; the RFC 4271
        // §9.2.1.1 tests below are about when.
        advertisement_interval: Duration::ZERO,
        prefix_limits: Vec::new(),
    }
}

fn now() -> Instant {
    Instant::now()
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
        extended_next_hop: to.extended_next_hop.contains(&V4),
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
    // Internal: the next hop is passed on unchanged with its encoding,
    // and only to a peer that takes it (§5).
    let e = export(LOCAL_AS, V4, src, &a, &int_enh).unwrap();
    assert_eq!(e.next_hop, a.next_hop);
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
        rib.peer_up(info.clone(), now());
    }
    let dst = p("192.0.2.0/24");
    // D's route with an IPv4 next hop reaches all three, C included.
    let out = rib.update(
        pd.addr,
        &announce(&["192.0.2.0/24"], &attrs(&[65_004, 7], "10.0.0.4")),
        now(),
    );
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
    let out = rib.update(pa.addr, &announce(&["192.0.2.0/24"], &via6), now());
    // The FIB gets the global IPv6 address (RFC 2545 §3).
    assert_eq!(
        fib(&out),
        vec![FibChange {
            family: V4,
            prefix: dst,
            next_hop: Some(ip("2001:db8::1")),
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
    let out = rib.refresh(pc.addr, V4, now());
    assert_eq!(sends(&out, pc.addr).len(), 0);
}

#[test]
fn an_update_with_both_ipv4_fields_keeps_each_next_hop() {
    // RFC 7606 §5.1: IPv4 routes in the NLRI field and in MP_REACH_NLRI
    // at once. RFC 4760 §3: each part has its own next hop, NEXT_HOP for
    // the NLRI field and the attribute's for the rest, IPv6 under RFC 8950.
    let mut rib = Rib::new(LOCAL_AS);
    let a = enh(peer("2001:db8::1", 65_001, 1));
    rib.peer_up(a.clone(), now());
    let mut d = announce(&["198.51.100.0/24"], &attrs(&[65_001], "192.0.2.1"));
    d.message.mp_reach = Some(bgpfc_wire::mp::MpReach {
        family: V4,
        next_hop: v6_next_hop("2001:db8::1", "fe80::1"),
        nlri: vec![p("203.0.113.0/24")],
    });
    let parts = announced(&d);
    assert_eq!(parts.len(), 2);
    rib.update(a.addr, &d, now());
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
    assert_eq!(announced(&d).len(), 0);
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
    assert_eq!(rib.peer_up(e1.clone(), now()).len(), 0);
    assert_eq!(rib.peer_up(e2.clone(), now()).len(), 0);
    let a = attrs(&[65_001, 7], "10.0.0.1");
    let out = rib.update(
        e1.addr,
        &announce(&["192.0.2.0/24", "198.51.100.0/24"], &a),
        now(),
    );
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
    let out = rib.update(e1.addr, &announce(&["192.0.2.0/24"], &a), now());
    assert!(out.is_empty(), "{out:?}");

    // A better route from e2 (shorter path) replaces it: e1 is told,
    // e2 is not.
    let b = attrs(&[65_002], "10.0.0.2");
    let out = rib.update(e2.addr, &announce(&["192.0.2.0/24"], &b), now());
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
    let out = rib.update(e2.addr, &withdraw(&["192.0.2.0/24"]), now());
    assert_eq!(fib(&out)[0].next_hop, Some(ip("10.0.0.1")));
    let m = decode_sent(sends(&out, e1.addr)[0], &e1);
    assert_eq!(m[0].withdrawn, vec![p("192.0.2.0/24")]);
    let m = decode_sent(sends(&out, e2.addr)[0], &e2);
    assert_eq!(m[0].nlri, vec![p("192.0.2.0/24")]);

    // Peer down: everything from e1 goes.
    let out = rib.peer_down(e1.addr, now());
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
    rib.peer_up(e1.clone(), now());
    rib.peer_up(i1.clone(), now());
    // RFC 7606 §7.2: an external route not starting with the peer's AS is
    // treated as withdrawn.
    let out = rib.update(
        e1.addr,
        &announce(&["192.0.2.0/24"], &attrs(&[65_009], "10.0.0.1")),
        now(),
    );
    assert_eq!(fib(&out).len(), 0);
    assert_eq!(rib.loc_rib(V4).count(), 0);
    // An empty path from an external peer likewise.
    let out = rib.update(
        e1.addr,
        &announce(&["192.0.2.0/24"], &attrs(&[], "10.0.0.1")),
        now(),
    );
    assert_eq!(fib(&out).len(), 0);
    // Internal peers may relay any path, including an empty one.
    let mut a = attrs(&[65_009], "10.0.0.3");
    a.local_pref = Some(100);
    let out = rib.update(i1.addr, &announce(&["192.0.2.0/24"], &a), now());
    assert_eq!(fib(&out).len(), 1);
}

#[test]
fn prefix_in_both_withdrawn_and_nlri_is_announced() {
    // RFC 4271 §4.3: a prefix in both Withdrawn Routes and NLRI is treated
    // as not withdrawn.
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    rib.peer_up(e1.clone(), now());
    let mut u = announce(&["192.0.2.0/24"], &attrs(&[65_001], "10.0.0.1"));
    u.message.withdrawn = vec![p("192.0.2.0/24")];
    let out = rib.update(e1.addr, &u, now());
    assert_eq!(fib(&out).len(), 1);
    assert_eq!(fib(&out)[0].next_hop, Some(ip("10.0.0.1")));
    assert_eq!(rib.loc_rib(V4).count(), 1);
}

#[test]
fn as_loop_routes_are_excluded() {
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    rib.peer_up(e1.clone(), now());
    let a = attrs(&[65_001, LOCAL_AS.0, 7], "10.0.0.1");
    let out = rib.update(e1.addr, &announce(&["192.0.2.0/24"], &a), now());
    assert_eq!(out.len(), 0);
    assert_eq!(rib.loc_rib(V4).count(), 0);
    // A replacement with a loop withdraws the earlier good route.
    let good = attrs(&[65_001], "10.0.0.1");
    rib.update(e1.addr, &announce(&["192.0.2.0/24"], &good), now());
    assert_eq!(rib.loc_rib(V4).count(), 1);
    let out = rib.update(e1.addr, &announce(&["192.0.2.0/24"], &a), now());
    assert_eq!(fib(&out)[0].next_hop, None);
}

#[test]
fn new_peer_receives_the_loc_rib_and_route_refresh_resends_it() {
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    rib.peer_up(e1.clone(), now());
    rib.update(
        e1.addr,
        &announce(&["192.0.2.0/24"], &attrs(&[65_001], "10.0.0.1")),
        now(),
    );
    rib.update(
        e1.addr,
        &announce(&["2001:db8:1::/48"], &attrs(&[65_001], "2001:db8::1")),
        now(),
    );
    let i = peer("10.0.0.3", 65_000, 3);
    let out = rib.peer_up(i.clone(), now());
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
    let out = rib.refresh(i.addr, V6, now());
    assert_eq!(fib(&out).len(), 0);
    let v6 = decode_sent(sends(&out, i.addr)[0], &i);
    assert_eq!(
        v6[0].mp_reach.as_ref().unwrap().nlri,
        vec![p("2001:db8:1::/48")]
    );
    // A family the peer does not speak: nothing.
    let mut v4_only = peer("10.0.0.4", 65_004, 4);
    v4_only.families = vec![V4];
    let out = rib.peer_up(v4_only.clone(), now());
    assert_eq!(sends(&out, v4_only.addr).len(), 1);
    assert_eq!(rib.refresh(v4_only.addr, V6, now()).len(), 0);
    assert_eq!(rib.refresh(ip("10.9.9.9"), V4, now()).len(), 0);
}

#[test]
fn family_disable_drops_that_family_only() {
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    rib.peer_up(e1.clone(), now());
    rib.update(
        e1.addr,
        &announce(&["192.0.2.0/24"], &attrs(&[65_001], "10.0.0.1")),
        now(),
    );
    rib.update(
        e1.addr,
        &announce(&["2001:db8:1::/48"], &attrs(&[65_001], "2001:db8::1")),
        now(),
    );
    let out = rib.family_disabled(e1.addr, V6, now());
    assert_eq!(fib(&out).len(), 1);
    assert_eq!(rib.loc_rib(V6).count(), 0);
    assert_eq!(rib.loc_rib(V4).count(), 1);
    // Later IPv6 announcements are ignored.
    let out = rib.update(
        e1.addr,
        &announce(&["2001:db8:2::/48"], &attrs(&[65_001], "2001:db8::1")),
        now(),
    );
    assert_eq!(out.len(), 0);
    // Unknown peers are ignored everywhere.
    let out = rib.update(ip("10.9.9.9"), &withdraw(&["192.0.2.0/24"]), now());
    assert_eq!(out.len(), 0);
    assert_eq!(rib.peer_down(ip("10.9.9.9"), now()).len(), 0);
    assert_eq!(rib.family_disabled(ip("10.9.9.9"), V4, now()).len(), 0);
}

#[test]
fn large_batches_are_packed_within_the_message_limit() {
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    let mut e2 = peer("10.0.0.2", 65_002, 2);
    e2.four_octet_as = false;
    rib.peer_up(e1.clone(), now());
    rib.peer_up(e2.clone(), now());
    // 3000 /24s: more than fit in one 4096-octet UPDATE.
    let prefixes: Vec<String> = (0..3000u32)
        .map(|i| format!("10.{}.{}.0/24", (i >> 8) + 1, i & 0xff))
        .collect();
    let refs: Vec<&str> = prefixes.iter().map(String::as_str).collect();
    let a = attrs(&[65_001, 4_200_000_000], "10.0.0.1");
    let out = rib.update(e1.addr, &announce(&refs, &a), now());
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
    let out = rib.peer_down(e1.addr, now());
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
    let d = announce(&["192.0.2.0/24"], &a);
    let parts = announced(&d);
    assert_eq!(parts.len(), 1);
    let (family, next_hop, prefixes) = parts[0];
    assert_eq!((family, prefixes), (V4, &[p("192.0.2.0/24")][..]));
    let back = PathAttrs::from_update(&d.message, next_hop);
    assert_eq!(
        back.communities,
        vec![Community::new(65_001, 1), Community::new(65_001, 2)]
    );
    // The Partial bit is set on the forwarded unknown attribute.
    assert_eq!(back.unknown[0].flags, 0xe0);
    let mut expect = a.clone();
    expect.unknown[0].flags = 0xe0;
    assert_eq!(back, expect);
    assert_eq!(announced(&withdraw(&["192.0.2.0/24"])).len(), 0);
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
    rib.peer_up(e1.clone(), now());
    rib.peer_up(e2.clone(), now());
    rib.update(
        e1.addr,
        &announce(
            &["192.0.2.0/24", "198.51.100.0/24"],
            &attrs(&[65_001], "10.0.0.1"),
        ),
        now(),
    );
    assert_eq!(rib.adj_rib_out(e2.addr, V4).count(), 2);
    // Nothing changed: nothing sent.
    assert_eq!(rib.reexport(e2.addr, V4, now()).len(), 0);
    rib.set_policies(Box::new(DropOdd));
    let out = rib.reexport(e2.addr, V4, now());
    let m = decode_sent(sends(&out, e2.addr)[0], &e2);
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].withdrawn, vec![p("192.0.2.0/24")]);
    assert_eq!(m[0].nlri.len(), 0);
    assert_eq!(rib.adj_rib_out(e2.addr, V4).count(), 1);
    assert!(rib.peer(e2.addr).is_some());
    assert!(rib.peer(ip("10.9.9.9")).is_none());
    assert_eq!(rib.reexport(ip("10.9.9.9"), V4, now()).len(), 0);
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
    fn import(&self, _: &PeerInfo, _: AddressFamily, p: Prefix, _: &PathAttrs) -> crate::Verdict {
        if p == self.0 {
            crate::Verdict::Reject
        } else {
            crate::Verdict::Accept
        }
    }
    fn export(&self, _: &PeerInfo, _: AddressFamily, _: Prefix, _: &PathAttrs) -> crate::Verdict {
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
    rib.peer_up(e1.clone(), now());
    rib.peer_up(e2.clone(), now());
    let a = attrs(&[65_001], "10.0.0.1");
    // Up to the limit is fine: RFC 4271 §6.7 acts when it is exceeded.
    let out = rib.update(
        e1.addr,
        &announce(&["192.0.2.0/24", "198.51.100.0/24"], &a),
        now(),
    );
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
        let out = rib.update(
            e1.addr,
            &announce(&[prefix], &attrs(path, "10.0.0.1")),
            now(),
        );
        assert_eq!(limit_hits(&out), vec![], "{prefix} {path:?}");
    }
    let v6 = attrs(&[65_001], "2001:db8::1");
    let v6_prefixes = ["2001:db8:1::/48", "2001:db8:2::/48", "2001:db8:3::/48"];
    rib.update(e1.addr, &announce(&v6_prefixes, &v6), now());
    assert_eq!(
        rib.peer_stats(e1.addr).unwrap().received,
        vec![(V4, 2), (V6, 3)]
    );
    // A withdrawal makes room again.
    rib.update(e1.addr, &withdraw(&["198.51.100.0/24"]), now());
    let out = rib.update(e1.addr, &announce(&["198.51.100.0/24"], &a), now());
    assert_eq!(limit_hits(&out), vec![]);
    // One route over: the session ends (RFC 4271 §6.7 (b)), which is
    // reported first, and every route from e1 goes at once, in both
    // families, from the FIB and from e2.
    let out = rib.update(e1.addr, &announce(&["203.0.113.0/24"], &a), now());
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
    // What e1 sends until its session is down is ignored, and the end of
    // the session has nothing left to remove.
    let out = rib.update(e1.addr, &announce(&["192.0.2.0/24"], &a), now());
    assert_eq!(out, vec![]);
    assert_eq!(rib.peer_down(e1.addr, now()), vec![]);
    // The next session starts counting from zero.
    rib.peer_up(e1.clone(), now());
    let out = rib.update(
        e1.addr,
        &announce(&["192.0.2.0/24", "198.51.100.0/24"], &a),
        now(),
    );
    assert_eq!(limit_hits(&out), vec![]);
    assert_eq!(rib.loc_rib(V4).count(), 2);
}

#[test]
fn prefix_limit_crossed_inside_one_update_passes_nothing_on() {
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = limited(peer("10.0.0.1", 65_001, 1), V4, 2);
    let e2 = peer("10.0.0.2", 65_002, 2);
    let e3 = peer("10.0.0.3", 65_003, 3);
    rib.peer_up(e1.clone(), now());
    rib.peer_up(e2.clone(), now());
    rib.peer_up(e3.clone(), now());
    // e2 already has a route to one of the destinations.
    rib.update(
        e2.addr,
        &announce(&["192.0.2.0/24"], &attrs(&[65_002, 7, 7], "10.0.0.2")),
        now(),
    );
    // e1's UPDATE carries three routes against a limit of two, with a
    // better path to e2's destination: none of them may reach the
    // Loc-RIB, the FIB or another peer, even for a moment.
    let out = rib.update(
        e1.addr,
        &announce(
            &["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"],
            &attrs(&[65_001], "10.0.0.1"),
        ),
        now(),
    );
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
    rib.peer_up(e1.clone(), now());
    rib.update(
        e1.addr,
        &announce(
            &["192.0.2.0/24", "198.51.100.0/24"],
            &attrs(&[65_001], "10.0.0.1"),
        ),
        now(),
    );
    rib.update(
        e1.addr,
        &announce(
            &["2001:db8:1::/48", "2001:db8:2::/48", "2001:db8:3::/48"],
            &attrs(&[65_001], "2001:db8::1"),
        ),
        now(),
    );
    // At or above the count: nothing happens, and the limit is kept.
    let out = rib.set_prefix_limits(e1.addr, vec![(V4, 2), (V6, 10)], now());
    assert_eq!(out, vec![]);
    assert_eq!(rib.peer(e1.addr).unwrap().prefix_limit(V4), Some(2));
    let out = rib.update(
        e1.addr,
        &announce(&["203.0.113.0/24"], &attrs(&[65_001], "10.0.0.1")),
        now(),
    );
    assert_eq!(limit_hits(&out), vec![(e1.addr, V4, 2)]);
    // Below the count: as if the limit had just been exceeded.
    rib.peer_up(e1.clone(), now());
    rib.update(
        e1.addr,
        &announce(
            &["2001:db8:1::/48", "2001:db8:2::/48", "2001:db8:3::/48"],
            &attrs(&[65_001], "2001:db8::1"),
        ),
        now(),
    );
    let out = rib.set_prefix_limits(e1.addr, vec![(V4, 2), (V6, 2)], now());
    assert_eq!(limit_hits(&out), vec![(e1.addr, V6, 2)]);
    assert_eq!(fib(&out).len(), 3);
    assert!(rib.peer(e1.addr).is_none());
    // An unknown peer: nothing.
    assert_eq!(rib.set_prefix_limits(ip("10.9.9.9"), vec![], now()), vec![]);
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

#[test]
fn mrai_flapping_route_goes_out_once_per_interval_and_the_latest_wins() {
    let t0 = Instant::now();
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = paced("10.0.0.2", 65_002, 2, EBGP_IV);
    rib.peer_up(e1.clone(), t0);
    rib.peer_up(e2.clone(), t0);
    let dst = p("192.0.2.0/24");
    // The first advertisement of a destination is not held.
    let out = rib.update(
        e1.addr,
        &announce(&["192.0.2.0/24"], &attrs(&[65_001, 1], "10.0.0.1")),
        t0,
    );
    assert_eq!(
        sent_for(&out, &e2, dst),
        vec![Some(vec![LOCAL_AS, Asn(65_001), Asn(1)])]
    );
    assert_eq!(rib.next_deadline(), None);
    // Three changes inside the interval: the decision process and the FIB
    // follow each (§9.2.1.1 limits advertisement, not selection), e2 hears
    // nothing yet.
    for (s, last) in [(1u64, 2u32), (2, 3), (3, 4)] {
        let out = rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_001, last], "10.0.0.1")),
            secs(t0, s),
        );
        assert_eq!(fib(&out).len(), 1);
        assert!(sends(&out, e2.addr).is_empty(), "{out:?}");
    }
    assert_eq!(rib.next_deadline(), Some(secs(t0, 30)));
    assert_eq!(rib.flush(secs(t0, 29)).len(), 0);
    // At the end of the interval, the last route selected goes out once.
    let out = rib.flush(secs(t0, 30));
    assert_eq!(
        sent_for(&out, &e2, dst),
        vec![Some(vec![LOCAL_AS, Asn(65_001), Asn(4)])]
    );
    assert_eq!(rib.flush(secs(t0, 31)).len(), 0);
    assert_eq!(rib.next_deadline(), None);

    // A long flap, one change a second, flushing whenever the RIB asks:
    // never two advertisements of the destination within an interval.
    let mut announced_at = vec![30u64];
    for s in 31..300u64 {
        let a = attrs(&[65_001, u32::try_from(s).unwrap()], "10.0.0.1");
        let mut out = rib.update(e1.addr, &announce(&["192.0.2.0/24"], &a), secs(t0, s));
        out.extend(rib.flush(secs(t0, s)));
        for sent in sent_for(&out, &e2, dst) {
            assert!(sent.is_some(), "only announcements here");
            announced_at.push(s);
        }
    }
    for w in announced_at.windows(2) {
        assert!(w[1] - w[0] >= 30, "{announced_at:?}");
    }
    assert!(announced_at.len() >= 9, "{announced_at:?}");
    // What the peer ends up with is the latest route.
    let out = rib.flush(secs(t0, 400));
    let last = rib.adj_rib_out(e2.addr, V4).next().map(|(_, a)| a.clone());
    assert_eq!(
        last.unwrap().as_path.asns().collect::<Vec<_>>(),
        vec![LOCAL_AS, Asn(65_001), Asn(299)]
    );
    assert!(sends(&out, e2.addr).len() <= 1);
}

#[test]
fn mrai_does_not_delay_withdrawals() {
    let t0 = Instant::now();
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = paced("10.0.0.2", 65_002, 2, EBGP_IV);
    rib.peer_up(e1.clone(), t0);
    rib.peer_up(e2.clone(), t0);
    let dst = p("192.0.2.0/24");
    let a = attrs(&[65_001], "10.0.0.1");
    rib.update(e1.addr, &announce(&["192.0.2.0/24"], &a), t0);
    // Inside the interval, the withdrawal still goes out at once (issue
    // #66; COMPLIANCE.md 9.2.1.1 deviates).
    let out = rib.update(e1.addr, &withdraw(&["192.0.2.0/24"]), secs(t0, 1));
    assert_eq!(sent_for(&out, &e2, dst), vec![None]);
    // The route comes back: paced from the advertisement at t0.
    let out = rib.update(e1.addr, &announce(&["192.0.2.0/24"], &a), secs(t0, 2));
    assert_eq!(sends(&out, e2.addr).len(), 0);
    let out = rib.flush(secs(t0, 30));
    assert_eq!(sent_for(&out, &e2, dst).len(), 1);
    // A held change, then a withdrawal: the withdrawal goes out at once
    // and, the route being gone, nothing is left to advertise later.
    let b = attrs(&[65_001, 9], "10.0.0.1");
    let out = rib.update(e1.addr, &announce(&["192.0.2.0/24"], &b), secs(t0, 31));
    assert_eq!(sends(&out, e2.addr).len(), 0);
    let out = rib.update(e1.addr, &withdraw(&["192.0.2.0/24"]), secs(t0, 32));
    assert_eq!(sent_for(&out, &e2, dst), vec![None]);
    assert_eq!(sends(&rib.flush(secs(t0, 120)), e2.addr).len(), 0);
    assert_eq!(rib.adj_rib_out(e2.addr, V4).count(), 0);
    // Peer down withdraws everything at once too.
    rib.update(e1.addr, &announce(&["192.0.2.0/24"], &a), secs(t0, 121));
    let out = rib.peer_down(e1.addr, secs(t0, 122));
    assert_eq!(sent_for(&out, &e2, dst), vec![None]);
}

#[test]
fn mrai_is_kept_per_destination() {
    let t0 = Instant::now();
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = paced("10.0.0.2", 65_002, 2, EBGP_IV);
    rib.peer_up(e1.clone(), t0);
    rib.peer_up(e2.clone(), t0);
    let (one, two) = (p("192.0.2.0/24"), p("198.51.100.0/24"));
    rib.update(
        e1.addr,
        &announce(&["192.0.2.0/24"], &attrs(&[65_001], "10.0.0.1")),
        t0,
    );
    // The first destination flaps and is held...
    rib.update(
        e1.addr,
        &announce(&["192.0.2.0/24"], &attrs(&[65_001, 2], "10.0.0.1")),
        secs(t0, 1),
    );
    // ...which does not hold back another destination's first route,
    let out = rib.update(
        e1.addr,
        &announce(&["198.51.100.0/24"], &attrs(&[65_001, 3], "10.0.0.1")),
        secs(t0, 5),
    );
    assert_eq!(sent_for(&out, &e2, two).len(), 1);
    assert_eq!(sent_for(&out, &e2, one).len(), 0);
    // ...and the release at t0 + 30 carries only the held one.
    let out = rib.flush(secs(t0, 30));
    assert_eq!(sent_for(&out, &e2, one).len(), 1);
    assert_eq!(sent_for(&out, &e2, two).len(), 0);
    // The second destination's own interval runs from t0 + 5.
    let out = rib.update(
        e1.addr,
        &announce(&["198.51.100.0/24"], &attrs(&[65_001, 4], "10.0.0.1")),
        secs(t0, 20),
    );
    assert_eq!(sent_for(&out, &e2, two).len(), 0);
    assert_eq!(rib.next_deadline(), Some(secs(t0, 35)));
    assert_eq!(sent_for(&rib.flush(secs(t0, 35)), &e2, two).len(), 1);
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
        rib.peer_up(info.clone(), t0);
    }
    let dst = p("192.0.2.0/24");
    let out = rib.update(
        e1.addr,
        &announce(&["192.0.2.0/24"], &attrs(&[65_001], "10.0.0.1")),
        t0,
    );
    assert_eq!(sent_for(&out, &e2, dst).len(), 1);
    assert_eq!(sent_for(&out, &i3, dst).len(), 1);
    rib.update(
        e1.addr,
        &announce(&["192.0.2.0/24"], &attrs(&[65_001, 2], "10.0.0.1")),
        secs(t0, 1),
    );
    // RFC 4271 §9.2.1.1 (a): the internal peer hears first.
    let out = rib.flush(secs(t0, 5));
    assert_eq!(sent_for(&out, &i3, dst).len(), 1);
    assert_eq!(sent_for(&out, &e2, dst).len(), 0);
    let out = rib.flush(secs(t0, 30));
    assert_eq!(sent_for(&out, &e2, dst).len(), 1);
    assert_eq!(sent_for(&out, &i3, dst).len(), 0);
}

#[test]
fn mrai_zero_sends_every_change_at_once() {
    let t0 = Instant::now();
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = paced("10.0.0.2", 65_002, 2, Duration::ZERO);
    rib.peer_up(e1.clone(), t0);
    rib.peer_up(e2.clone(), t0);
    let dst = p("192.0.2.0/24");
    for i in 0..5u32 {
        let out = rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_001, i + 1], "10.0.0.1")),
            t0,
        );
        assert_eq!(sent_for(&out, &e2, dst).len(), 1, "change {i}");
        let out = rib.update(e1.addr, &withdraw(&["192.0.2.0/24"]), t0);
        assert_eq!(sent_for(&out, &e2, dst), vec![None]);
    }
    assert_eq!(rib.next_deadline(), None);
}

#[test]
fn mrai_route_refresh_and_policy_changes_go_through_the_pacing() {
    use crate::{Policies, Verdict};
    /// Exports everything with a community.
    struct Tag;
    impl Policies for Tag {
        fn import(&self, _: &PeerInfo, _: AddressFamily, _: Prefix, _: &PathAttrs) -> Verdict {
            Verdict::Accept
        }
        fn export(&self, _: &PeerInfo, _: AddressFamily, _: Prefix, a: &PathAttrs) -> Verdict {
            let mut m = a.clone();
            m.communities = vec![Community::new(65_000, 42)];
            Verdict::Modified(m)
        }
    }
    let t0 = Instant::now();
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = paced("10.0.0.2", 65_002, 2, EBGP_IV);
    rib.peer_up(e1.clone(), t0);
    rib.peer_up(e2.clone(), t0);
    let dst = p("192.0.2.0/24");
    rib.update(
        e1.addr,
        &announce(&["192.0.2.0/24"], &attrs(&[65_001], "10.0.0.1")),
        t0,
    );
    // An export policy change inside the interval is held like any other.
    rib.set_policies(Box::new(Tag));
    let out = rib.reexport(e2.addr, V4, secs(t0, 2));
    assert_eq!(sends(&out, e2.addr).len(), 0);
    assert_eq!(rib.next_deadline(), Some(secs(t0, 30)));
    // The peer asks for everything again (RFC 2918 §4): it gets the held
    // route as it is now, and the interval restarts.
    let out = rib.refresh(e2.addr, V4, secs(t0, 10));
    let m = decode_sent(sends(&out, e2.addr)[0], &e2);
    assert_eq!(m[0].nlri, vec![dst]);
    assert!(m[0].attribute(8).is_some(), "COMMUNITIES from the policy");
    assert_eq!(sends(&rib.flush(secs(t0, 30)), e2.addr).len(), 0);
    let out = rib.update(
        e1.addr,
        &announce(&["192.0.2.0/24"], &attrs(&[65_001, 5], "10.0.0.1")),
        secs(t0, 20),
    );
    assert_eq!(sends(&out, e2.addr).len(), 0);
    assert_eq!(rib.next_deadline(), Some(secs(t0, 40)));
    assert_eq!(sent_for(&rib.flush(secs(t0, 40)), &e2, dst).len(), 1);
}

#[test]
fn mrai_new_interval_applies_to_held_destinations() {
    let t0 = Instant::now();
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = paced("10.0.0.2", 65_002, 2, EBGP_IV);
    rib.peer_up(e1.clone(), t0);
    rib.peer_up(e2.clone(), t0);
    let dst = p("192.0.2.0/24");
    rib.update(
        e1.addr,
        &announce(&["192.0.2.0/24"], &attrs(&[65_001], "10.0.0.1")),
        t0,
    );
    rib.update(
        e1.addr,
        &announce(&["192.0.2.0/24"], &attrs(&[65_001, 2], "10.0.0.1")),
        secs(t0, 1),
    );
    // Shorter: the held route moves to t0 + 10.
    assert_eq!(
        rib.set_advertisement_interval(e2.addr, Duration::from_secs(10), secs(t0, 2))
            .len(),
        0
    );
    assert_eq!(
        rib.peer(e2.addr).unwrap().advertisement_interval,
        Duration::from_secs(10)
    );
    assert_eq!(sent_for(&rib.flush(secs(t0, 10)), &e2, dst).len(), 1);
    rib.update(
        e1.addr,
        &announce(&["192.0.2.0/24"], &attrs(&[65_001, 3], "10.0.0.1")),
        secs(t0, 11),
    );
    // Off: it goes out right away.
    let out = rib.set_advertisement_interval(e2.addr, Duration::ZERO, secs(t0, 12));
    assert_eq!(sent_for(&out, &e2, dst).len(), 1);
    // Same value, or an unknown peer: nothing.
    assert_eq!(
        rib.set_advertisement_interval(e2.addr, Duration::ZERO, secs(t0, 13))
            .len(),
        0
    );
    assert_eq!(
        rib.set_advertisement_interval(ip("10.9.9.9"), EBGP_IV, secs(t0, 13))
            .len(),
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
    rib.peer_up(e1.clone(), t0);
    rib.peer_up(e2.clone(), t0);
    let prefixes: Vec<String> = (0..N)
        .map(|i| format!("10.{}.{}.0/24", i >> 8, i & 0xff))
        .collect();
    let refs: Vec<&str> = prefixes.iter().map(String::as_str).collect();
    let out = rib.update(e1.addr, &announce(&refs, &attrs(&[65_001], "10.0.0.1")), t0);
    let first: usize = decode_sent(sends(&out, e2.addr)[0], &e2)
        .iter()
        .map(|m| m.nlri.len())
        .sum();
    assert_eq!(first, refs.len());
    for s in 1..=3u32 {
        let a = attrs(&[65_001, s], "10.0.0.1");
        let out = rib.update(e1.addr, &announce(&refs, &a), secs(t0, u64::from(s)));
        assert_eq!(sends(&out, e2.addr).len(), 0);
    }
    assert_eq!(rib.deadlines.len(), refs.len());
    let out = rib.flush(secs(t0, 30));
    let s = sends(&out, e2.addr);
    assert_eq!(s.len(), 1);
    let msgs = decode_sent(s[0], &e2);
    let total: usize = msgs.iter().map(|m| m.nlri.len()).sum();
    assert_eq!(total, refs.len());
    assert!(msgs.iter().all(|m| {
        m.as_path().unwrap().asns().collect::<Vec<_>>() == vec![LOCAL_AS, Asn(65_001), Asn(3)]
    }));
    assert_eq!(rib.deadlines.len(), 0);
    assert_eq!(rib.next_deadline(), None);
}

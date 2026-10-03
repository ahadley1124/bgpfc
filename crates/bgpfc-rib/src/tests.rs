//! Decision-process tests per tie-break step (AGENTS.md §5, `bgpfc-rib`
//! row) and attribute-set handling.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use bgpfc_wire::as_path::AsPath;
use bgpfc_wire::attribute::Origin;
use bgpfc_wire::community::Community;
use bgpfc_wire::mp::NextHop;
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::{AddressFamily, Asn, RouterId};
use bgpfc_wire::update::{PeerKind, UpdateMessage};

use crate::attrs::PathAttrs;
use crate::decision::{Candidate, best};
use crate::peer::PeerInfo;

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

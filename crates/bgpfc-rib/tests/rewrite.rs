//! Property: Phase 3 decides whether a peer must be sent a changed route
//! by comparing the export policy's sets field by field
//! (`export::same_rewrite`), without rewriting them. That must agree with
//! rewriting both for the session (RFC 4271 §5.1) and comparing: a false
//! "same" would leave the peer with an old route.
#![cfg(not(miri))]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use bgpfc_rib::attrs::UnknownAttribute;
use bgpfc_rib::export::{rewrite, same_rewrite};
use bgpfc_rib::{PathAttrs, PeerInfo};
use bgpfc_wire::as_path::{AsPath, AsPathSegment, SegmentType};
use bgpfc_wire::attribute::{Aggregator, Origin};
use bgpfc_wire::community::{Community, ExtendedCommunity, LargeCommunity};
use bgpfc_wire::mp::NextHop;
use bgpfc_wire::types::{AddressFamily, Asn, RouterId};
use bgpfc_wire::update::PeerKind;
use proptest::prelude::*;

const LOCAL_AS: Asn = Asn(65_000);

/// Sorted and unique, as normalised sets are.
fn list<T: Ord + Clone + std::fmt::Debug>(
    items: impl Strategy<Value = T>,
) -> impl Strategy<Value = Box<[T]>> {
    proptest::collection::btree_set(items, 0..3).prop_map(|s| s.into_iter().collect())
}

fn as_path() -> impl Strategy<Value = AsPath> {
    // Segments are never empty on the wire.
    let segment =
        (any::<bool>(), proptest::collection::vec(1u32..4, 1..3)).prop_map(|(set, asns)| {
            AsPathSegment {
                kind: if set {
                    SegmentType::Set
                } else {
                    SegmentType::Sequence
                },
                asns: asns.into_iter().map(Asn).collect(),
            }
        });
    proptest::collection::vec(segment, 0..3).prop_map(|segments| AsPath::from_segments(&segments))
}

fn attrs() -> impl Strategy<Value = PathAttrs> {
    let next_hop = prop_oneof![
        Just(NextHop::Ipv4(Ipv4Addr::new(192, 0, 2, 1))),
        Just(NextHop::Ipv4(Ipv4Addr::new(192, 0, 2, 2))),
        Just(NextHop::Ipv6 {
            global: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            link_local: None,
        }),
        // The same global address with a link-local one, which no rewrite
        // passes on (RFC 2545 §3).
        Just(NextHop::Ipv6 {
            global: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            link_local: Some(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
        }),
    ];
    let ext =
        (1u16..3, any::<bool>()).prop_map(|(n, t)| ExtendedCommunity::two_octet_as(2, t, n, 1));
    let large = (1u32..3).prop_map(|n| LargeCommunity {
        global: n,
        local1: 0,
        local2: 0,
    });
    // Unknown attributes by type code, sorted as normalised sets are.
    let unknown = list(200u8..202).prop_map(|codes| {
        codes
            .iter()
            .map(|&code| UnknownAttribute {
                flags: 0xc0,
                code,
                value: vec![code],
            })
            .collect::<Box<[_]>>()
    });
    (
        (0u8..2, as_path(), next_hop, proptest::option::of(0u32..2)),
        (
            proptest::option::of(prop_oneof![Just(100u32), Just(200)]),
            any::<bool>(),
            proptest::option::of(Just(Aggregator {
                asn: Asn(1),
                address: Ipv4Addr::new(192, 0, 2, 9),
            })),
        ),
        (
            list((1u32..3).prop_map(Community)),
            list(ext),
            list(large),
            unknown,
        ),
    )
        .prop_map(
            |((origin, as_path, next_hop, med), (local_pref, atomic, aggregator), (c, e, l, u))| {
                PathAttrs {
                    origin: Origin::from_u8(origin).unwrap(),
                    as_path,
                    next_hop,
                    med,
                    local_pref,
                    atomic_aggregate: atomic,
                    aggregator,
                    communities: c,
                    ext_communities: e,
                    large_communities: l,
                    unknown: u,
                }
            },
        )
}

/// External over IPv4, over IPv6 without and with RFC 8950 Extended Next
/// Hop Encoding for IPv4, or internal.
fn peer() -> impl Strategy<Value = PeerInfo> {
    (0u8..4).prop_map(|k| PeerInfo {
        addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        local_addr: if k == 1 || k == 3 {
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xfe))
        } else {
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 254))
        },
        remote_as: if k == 2 { LOCAL_AS } else { Asn(65_002) },
        router_id: RouterId::new(2).unwrap(),
        kind: if k == 2 {
            PeerKind::Internal
        } else {
            PeerKind::External
        },
        families: vec![AddressFamily::IPV4_UNICAST, AddressFamily::IPV6_UNICAST],
        receive_families: vec![AddressFamily::IPV4_UNICAST, AddressFamily::IPV6_UNICAST],
        four_octet_as: true,
        extended_messages: false,
        extended_next_hop: if k == 3 {
            vec![AddressFamily::IPV4_UNICAST]
        } else {
            Vec::new()
        },
        advertisement_interval: Duration::ZERO,
        prefix_limits: Vec::new(),
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    #[test]
    fn same_rewrite_is_comparing_the_rewrites(
        a in attrs(),
        other in attrs(),
        mask in any::<u16>(),
        to in peer(),
        v6 in any::<bool>(),
    ) {
        // b is a with some fields from another set: often equal but for a
        // field or two, as the routes Phase 3 compares are.
        let b = mix(&a, &other, mask);
        let family = if v6 {
            AddressFamily::IPV6_UNICAST
        } else {
            AddressFamily::IPV4_UNICAST
        };
        let equal = rewrite(LOCAL_AS, family, &a, &to) == rewrite(LOCAL_AS, family, &b, &to);
        prop_assert_eq!(same_rewrite(family, &a, &b, &to), equal);
        prop_assert!(same_rewrite(family, &a, &a, &to));
    }
}

/// `a` with the fields whose bit is set in `mask` taken from `b`.
fn mix(a: &PathAttrs, b: &PathAttrs, mask: u16) -> PathAttrs {
    let take = |bit: u16| mask & (1 << bit) != 0;
    let mut m = a.clone();
    if take(0) {
        m.origin = b.origin;
    }
    if take(1) {
        m.as_path.clone_from(&b.as_path);
    }
    if take(2) {
        m.next_hop = b.next_hop;
    }
    if take(3) {
        m.med = b.med;
    }
    if take(4) {
        m.local_pref = b.local_pref;
    }
    if take(5) {
        m.atomic_aggregate = b.atomic_aggregate;
    }
    if take(6) {
        m.aggregator = b.aggregator;
    }
    if take(7) {
        m.communities.clone_from(&b.communities);
    }
    if take(8) {
        m.ext_communities.clone_from(&b.ext_communities);
    }
    if take(9) {
        m.large_communities.clone_from(&b.large_communities);
    }
    if take(10) {
        m.unknown.clone_from(&b.unknown);
    }
    m
}

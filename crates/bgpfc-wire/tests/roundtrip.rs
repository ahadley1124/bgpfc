//! Property tests for the codec (AGENTS.md §5, `bgpfc-wire` row):
//!
//! - `decode(encode(x)) == x` for every message and attribute type;
//! - `encode(decode(b)) == b` for canonical inputs, i.e. bytes produced by
//!   the encoder;
//! - no decoder panics on arbitrary or corrupted input.
//!
//! Not run under Miri: proptest's case counts would take hours, and the
//! unit tests already cover the same code paths there.
#![cfg(not(miri))]

use std::net::{Ipv4Addr, Ipv6Addr};

use bgpfc_wire::as_path::{AsPath, AsPathSegment, Segment, SegmentType};
use bgpfc_wire::attribute::{Aggregator, Origin, PathAttribute, code};
use bgpfc_wire::capability::{
    AddPathMode, AddPathTuple, Capability, GracefulRestart, GracefulRestartFamily, NextHopEncoding,
};
use bgpfc_wire::community::{Community, ExtendedCommunity, LargeCommunity};
use bgpfc_wire::error::ErrorCode;
use bgpfc_wire::error::UpdateSubcode;
use bgpfc_wire::header::{Header, MessageType, frame};
use bgpfc_wire::mp::{MpReach, MpUnreach, NextHop, is_global_ipv6, is_host_ipv4};
use bgpfc_wire::notification::NotificationMessage;
use bgpfc_wire::open::OpenMessage;
use bgpfc_wire::prefix::{
    Ipv4Key, Prefix, decode_prefixes, decode_prefixes_with_ids, encode_prefixes_with_ids,
};
use bgpfc_wire::reader::Reader;
use bgpfc_wire::role::Role;
use bgpfc_wire::route_refresh::RouteRefreshMessage;
use bgpfc_wire::types::{AddressFamily, Afi, Asn, HoldTime, PathId, RestartTime, RouterId, Safi};
use bgpfc_wire::update::{
    AddPathFamilies, DecodeContext, EncodeContext, PathIds, PeerKind, UpdateMessage,
};
use proptest::collection::vec;
use proptest::prelude::*;

// ---------------------------------------------------------------- strategies

fn asn() -> impl Strategy<Value = Asn> {
    // AS 0 is malformed everywhere (RFC 7607), so it is never generated.
    prop_oneof![
        3 => (1u32..=65_535).prop_map(Asn),
        1 => (65_536u32..=u32::MAX).prop_map(Asn),
    ]
}

fn prefix_v4() -> impl Strategy<Value = Prefix> {
    (any::<u32>(), 0u8..=32)
        .prop_map(|(a, len)| Prefix::new(Ipv4Addr::from(a).into(), len).unwrap())
}

fn prefix_v6() -> impl Strategy<Value = Prefix> {
    (any::<u128>(), 0u8..=128)
        .prop_map(|(a, len)| Prefix::new(Ipv6Addr::from(a).into(), len).unwrap())
}

fn segment_type(confed: bool) -> impl Strategy<Value = SegmentType> {
    if confed {
        prop_oneof![
            Just(SegmentType::Sequence),
            Just(SegmentType::Set),
            Just(SegmentType::ConfedSequence),
            Just(SegmentType::ConfedSet),
        ]
        .boxed()
    } else {
        prop_oneof![Just(SegmentType::Sequence), Just(SegmentType::Set)].boxed()
    }
}

/// `confed`: allow confederation segments. A two-octet session cannot round
/// trip them next to non-mappable ASNs (RFC 6793 §4.2.2 strips them from
/// `AS4_PATH`), so the two-octet properties generate paths without them.
fn as_path(confed: bool) -> impl Strategy<Value = AsPath> {
    vec(
        (segment_type(confed), vec(asn(), 1..=6))
            .prop_map(|(kind, asns)| AsPathSegment { kind, asns }),
        0..=4,
    )
    .prop_map(|segments| AsPath::from_segments(&segments))
}

fn address_family() -> impl Strategy<Value = AddressFamily> {
    (any::<u16>(), any::<u8>()).prop_map(|(a, s)| AddressFamily {
        afi: Afi::from_u16(a),
        safi: Safi::from_u8(s),
    })
}

/// RFC 8950 §4 triples: mostly the values the RFC allows, sometimes any.
fn next_hop_encoding() -> impl Strategy<Value = NextHopEncoding> {
    prop_oneof![
        3 => prop_oneof![Just(1u16), Just(2), Just(4), Just(128), Just(129)].prop_map(|safi| {
            NextHopEncoding {
                nlri_safi: safi,
                ..NextHopEncoding::IPV4_UNICAST_VIA_IPV6
            }
        }),
        1 => (any::<u16>(), any::<u16>(), any::<u16>()).prop_map(|(afi, safi, nh)| {
            NextHopEncoding {
                nlri_afi: Afi::from_u16(afi),
                nlri_safi: safi,
                next_hop_afi: Afi::from_u16(nh),
            }
        }),
    ]
}

/// RFC 7911 §4 tuples: any family, a Send/Receive value of 1 to 3.
fn add_path_tuple() -> impl Strategy<Value = AddPathTuple> {
    (address_family(), 1u8..=3).prop_map(|(family, mode)| AddPathTuple {
        family,
        mode: AddPathMode::from_u8(mode).unwrap(),
    })
}

/// RFC 4724 §3 and RFC 8538 §2: any flags, any Restart Time of twelve bits,
/// and at most 63 tuples of any family, with or without the Forwarding
/// State bit.
fn graceful_restart() -> impl Strategy<Value = GracefulRestart> {
    (
        any::<bool>(),
        any::<bool>(),
        0u16..=4095,
        vec((address_family(), any::<bool>()), 0..=63),
    )
        .prop_map(
            |(restarting, notification, secs, families)| GracefulRestart {
                restarting,
                notification,
                restart_time: RestartTime::new(secs).unwrap(),
                families: families
                    .into_iter()
                    .map(|(family, forwarding)| GracefulRestartFamily { family, forwarding })
                    .collect(),
            },
        )
}

fn capability() -> impl Strategy<Value = Capability> {
    prop_oneof![
        address_family().prop_map(Capability::Multiprotocol),
        Just(Capability::RouteRefresh),
        Just(Capability::ExtendedMessage),
        any::<u32>().prop_map(|a| Capability::FourOctetAs(Asn(a))),
        // RFC 9234 §4.1: any Role Value, assigned or not.
        any::<u8>().prop_map(|v| Capability::Role(Role::from_u8(v))),
        // RFC 8950 §4: at most 42 six-octet triples fit the length octet.
        vec(next_hop_encoding(), 0..=42).prop_map(Capability::ExtendedNextHop),
        // RFC 7911 §4: at most 63 four-octet tuples fit the length octet.
        vec(add_path_tuple(), 0..=63).prop_map(Capability::AddPath),
        graceful_restart().prop_map(Capability::GracefulRestart),
        (
            any::<u8>().prop_filter("known code", |c| !matches!(
                c,
                1 | 2 | 5 | 6 | 9 | 64 | 65 | 69
            )),
            vec(any::<u8>(), 0..=255)
        )
            .prop_map(|(code, value)| Capability::Unknown { code, value }),
    ]
}

fn open_message() -> impl Strategy<Value = OpenMessage> {
    (
        1u16..=u16::MAX,
        prop_oneof![Just(0u16), 3u16..=u16::MAX],
        1u32..=u32::MAX,
        vec(capability(), 0..=8),
    )
        .prop_map(|(my_as, hold, rid, capabilities)| OpenMessage {
            my_as,
            hold_time: HoldTime::new(hold).unwrap(),
            router_id: RouterId::new(rid).unwrap(),
            capabilities,
        })
}

fn notification() -> impl Strategy<Value = NotificationMessage> {
    (any::<u8>(), any::<u8>(), vec(any::<u8>(), 0..=300)).prop_map(|(c, s, data)| {
        NotificationMessage {
            code: ErrorCode::from_u8(c),
            subcode: s,
            data,
        }
    })
}

/// An IPv4 host address (RFC 4271 §6.3), as a valid next hop must be.
fn host_v4() -> impl Strategy<Value = Ipv4Addr> {
    any::<u32>()
        .prop_map(Ipv4Addr::from)
        .prop_filter("host address", |a| is_host_ipv4(*a))
}

/// An IPv4 address that is no host's: `0/8`, `127/8`, `224/4`, `240/4`.
fn non_host_v4() -> impl Strategy<Value = Ipv4Addr> {
    prop_oneof![
        0u32..=0x00ff_ffff,
        0x7f00_0000u32..=0x7fff_ffff,
        0xe000_0000u32..=u32::MAX,
    ]
    .prop_map(Ipv4Addr::from)
}

/// The global address that comes first in an IPv6 next hop (RFC 2545 §3).
fn global_v6() -> impl Strategy<Value = Ipv6Addr> {
    any::<u128>()
        .prop_map(Ipv6Addr::from)
        .prop_filter("global address", |a| is_global_ipv6(*a))
}

/// A link-local address, `fe80::/10` (RFC 4291 §2.5.6).
fn link_local_v6() -> impl Strategy<Value = Ipv6Addr> {
    any::<u128>().prop_map(|a| Ipv6Addr::from((0x3fa << 118) | (a & ((1 << 118) - 1))))
}

/// What cannot come first in an IPv6 next hop: unspecified, loopback,
/// multicast or link-local (RFC 4291 §2.5.2, §2.5.3, §2.7, §2.5.6).
fn non_global_v6() -> impl Strategy<Value = Ipv6Addr> {
    prop_oneof![
        Just(Ipv6Addr::UNSPECIFIED),
        Just(Ipv6Addr::LOCALHOST),
        any::<u128>().prop_map(|a| Ipv6Addr::from((0xff << 120) | (a >> 8))),
        link_local_v6(),
    ]
}

/// A valid next hop for NLRI of `afi` (RFC 4271 §6.3, RFC 4760 §3,
/// RFC 2545 §3, RFC 8950 §3).
fn next_hop(afi: Afi) -> BoxedStrategy<NextHop> {
    let v6 = (global_v6(), proptest::option::of(link_local_v6()))
        .prop_map(|(global, link_local)| NextHop::Ipv6 { global, link_local });
    match afi {
        Afi::Ipv4 => prop_oneof![host_v4().prop_map(NextHop::Ipv4), v6].boxed(),
        _ => v6.boxed(),
    }
}

/// A next hop of the same form as `nh` that is no host's.
fn invalid_like(nh: NextHop) -> BoxedStrategy<NextHop> {
    match nh {
        NextHop::Ipv4(_) => non_host_v4().prop_map(NextHop::Ipv4).boxed(),
        NextHop::Ipv6 { link_local, .. } => non_global_v6()
            .prop_map(move |global| NextHop::Ipv6 { global, link_local })
            .boxed(),
    }
}

fn mp_reach() -> impl Strategy<Value = MpReach> {
    prop_oneof![Just(Afi::Ipv4), Just(Afi::Ipv6)].prop_flat_map(|afi| {
        let prefixes = match afi {
            Afi::Ipv4 => vec(prefix_v4(), 0..=5).boxed(),
            _ => vec(prefix_v6(), 0..=5).boxed(),
        };
        (next_hop(afi), prefixes).prop_map(move |(next_hop, nlri)| MpReach {
            family: AddressFamily {
                afi,
                safi: Safi::Unicast,
            },
            next_hop,
            nlri,
        })
    })
}

fn mp_unreach() -> impl Strategy<Value = MpUnreach> {
    prop_oneof![
        vec(prefix_v4(), 0..=5).prop_map(|withdrawn| MpUnreach {
            family: AddressFamily::IPV4_UNICAST,
            withdrawn
        }),
        vec(prefix_v6(), 0..=5).prop_map(|withdrawn| MpUnreach {
            family: AddressFamily::IPV6_UNICAST,
            withdrawn
        }),
    ]
}

fn unknown_code() -> impl Strategy<Value = u8> {
    prop_oneof![9u8..=13, 19u8..=31, 33u8..=34, 36u8..=255]
}

/// The optional attributes, each present or not.
fn optional_attributes() -> impl Strategy<Value = Vec<PathAttribute>> {
    (
        proptest::option::of(any::<u32>().prop_map(PathAttribute::MultiExitDisc)),
        proptest::option::of(any::<u32>().prop_map(PathAttribute::LocalPref)),
        proptest::option::of(Just(PathAttribute::AtomicAggregate)),
        proptest::option::of((asn(), any::<u32>()).prop_map(|(asn, a)| {
            PathAttribute::Aggregator(Aggregator {
                asn,
                address: Ipv4Addr::from(a),
            })
        })),
        proptest::option::of(
            vec(any::<u32>().prop_map(Community), 1..=6).prop_map(PathAttribute::Communities),
        ),
        proptest::option::of(
            vec(any::<[u8; 8]>().prop_map(ExtendedCommunity), 1..=6)
                .prop_map(PathAttribute::ExtendedCommunities),
        ),
        proptest::option::of(
            proptest::collection::btree_set((any::<u32>(), any::<u32>(), any::<u32>()), 1..=6)
                .prop_map(|set| {
                    // Duplicates are removed on receipt (RFC 8092 §3); the
                    // decoder keeps first occurrences, so sorted unique input
                    // round-trips exactly.
                    PathAttribute::LargeCommunities(
                        set.into_iter()
                            .map(|(global, local1, local2)| LargeCommunity {
                                global,
                                local1,
                                local2,
                            })
                            .collect(),
                    )
                }),
        ),
        proptest::option::of(any::<u32>().prop_map(|a| PathAttribute::OnlyToCustomer(Asn(a)))),
        proptest::option::of(
            (unknown_code(), any::<bool>(), vec(any::<u8>(), 0..=300)).prop_map(
                |(code, partial, value)| PathAttribute::Unknown {
                    flags: 0xc0 | if partial { 0x20 } else { 0 },
                    code,
                    value,
                },
            ),
        ),
    )
        .prop_map(|(med, lp, aa, agg, cs, ecs, lcs, otc, unk)| {
            [med, lp, aa, agg, cs, ecs, lcs, otc, unk]
                .into_iter()
                .flatten()
                .collect()
        })
}

fn update_message(confed: bool) -> impl Strategy<Value = UpdateMessage> {
    (
        vec(prefix_v4(), 0..=5),
        vec(prefix_v4(), 0..=5),
        proptest::option::of(mp_reach()),
        proptest::option::of(mp_unreach()),
        prop_oneof![
            Just(Origin::Igp),
            Just(Origin::Egp),
            Just(Origin::Incomplete)
        ],
        as_path(confed),
        host_v4(),
        optional_attributes(),
    )
        .prop_map(
            |(withdrawn, nlri, mp_reach, mp_unreach, origin, path, nh, mut optional)| {
                // The mandatory three are always present so the message is
                // valid whether or not it announces anything.
                let mut attributes = vec![
                    PathAttribute::Origin(origin),
                    PathAttribute::AsPath(path),
                    PathAttribute::NextHop(nh),
                ];
                attributes.append(&mut optional);
                attributes.sort_by_key(PathAttribute::code);
                UpdateMessage {
                    withdrawn,
                    nlri,
                    mp_reach,
                    mp_unreach,
                    attributes,
                    path_ids: None,
                }
            },
        )
}

/// Which of IPv4 and IPv6 unicast have ADD-PATH (RFC 7911 §5), any
/// combination.
fn add_path_families() -> impl Strategy<Value = AddPathFamilies> {
    (any::<bool>(), any::<bool>()).prop_map(|(v4, v6)| {
        let mut on = Vec::new();
        if v4 {
            on.push(AddressFamily::IPV4_UNICAST);
        }
        if v6 {
            on.push(AddressFamily::IPV6_UNICAST);
        }
        AddPathFamilies::of(&on)
    })
}

/// `m` with a Path Identifier from `pool` for each prefix of the lists
/// whose family is in `on`, and none for the others (RFC 7911 §3, §5).
fn with_path_ids(mut m: UpdateMessage, on: AddPathFamilies, pool: &[u32]) -> UpdateMessage {
    let mut next = pool.iter().cycle();
    let mut ids = |family: AddressFamily, n: usize| -> Vec<PathId> {
        if on.contains(family) {
            (0..n).map(|_| PathId(*next.next().unwrap())).collect()
        } else {
            Vec::new()
        }
    };
    let v4 = AddressFamily::IPV4_UNICAST;
    let ids = PathIds {
        withdrawn: ids(v4, m.withdrawn.len()),
        nlri: ids(v4, m.nlri.len()),
        mp_reach: m
            .mp_reach
            .as_ref()
            .map_or(Vec::new(), |r| ids(r.family, r.nlri.len())),
        mp_unreach: m
            .mp_unreach
            .as_ref()
            .map_or(Vec::new(), |u| ids(u.family, u.withdrawn.len())),
    };
    m.path_ids = (!ids.is_empty()).then(|| Box::new(ids));
    m
}

/// The round trips negotiate RFC 8950 so that IPv4 NLRI may carry an IPv6
/// next hop; `ipv6_next_hop_for_ipv4_only_when_negotiated` covers the rest.
const IBGP4: DecodeContext = DecodeContext {
    four_octet_as: true,
    peer: PeerKind::Internal,
    allow_as_set: true,
    extended_next_hop: true,
    add_path: AddPathFamilies::NONE,
};
const IBGP2: DecodeContext = DecodeContext {
    four_octet_as: false,
    ..IBGP4
};
const EBGP4: DecodeContext = DecodeContext {
    peer: PeerKind::External,
    allow_as_set: false,
    ..IBGP4
};
const ENC4: EncodeContext = EncodeContext {
    four_octet_as: true,
    extended_next_hop: true,
    add_path: AddPathFamilies::NONE,
};
const ENC2: EncodeContext = EncodeContext {
    four_octet_as: false,
    extended_next_hop: true,
    add_path: AddPathFamilies::NONE,
};

// ---------------------------------------------------------------- round trips

/// The order `Prefix` had when it was derived: variant, then the address
/// octets, then the length.
fn field_order(p: &Prefix) -> (u8, Vec<u8>, u8) {
    match p.addr() {
        std::net::IpAddr::V4(a) => (0, a.octets().to_vec(), p.prefix_len()),
        std::net::IpAddr::V6(a) => (1, a.octets().to_vec(), p.prefix_len()),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    #[test]
    fn prefix_order_is_variant_then_address_then_length(
        a in prop_oneof![prefix_v4(), prefix_v6()],
        b in prop_oneof![prefix_v4(), prefix_v6()],
    ) {
        prop_assert_eq!(a.cmp(&b), field_order(&a).cmp(&field_order(&b)));
        prop_assert_eq!(a.partial_cmp(&b), Some(a.cmp(&b)));
        prop_assert_eq!(a.cmp(&b) == std::cmp::Ordering::Equal, a == b);
    }

    #[test]
    fn ipv4_key_orders_and_converts_like_its_prefix(a in prefix_v4(), b in prefix_v4()) {
        let (ka, kb) = (Ipv4Key::new(a).unwrap(), Ipv4Key::new(b).unwrap());
        prop_assert_eq!(ka.prefix(), a);
        prop_assert_eq!(ka.cmp(&kb), a.cmp(&b));
        prop_assert_eq!(ka == kb, a == b);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn prefix_round_trip(p in prop_oneof![prefix_v4(), prefix_v6()]) {
        let mut wire = Vec::new();
        p.encode(&mut wire);
        let mut r = Reader::new(&wire);
        prop_assert_eq!(Prefix::decode(&mut r, p.afi()).unwrap(), p);
        prop_assert!(r.is_empty());
        prop_assert_eq!(p.to_string().parse::<Prefix>().unwrap(), p);
    }

    #[test]
    fn prefix_list_round_trip(ps in vec(prefix_v6(), 0..=10)) {
        let mut wire = Vec::new();
        bgpfc_wire::prefix::encode_prefixes(&ps, &mut wire);
        prop_assert_eq!(decode_prefixes(&wire, Afi::Ipv6).unwrap(), ps);
    }

    #[test]
    fn extended_prefix_list_round_trip(
        entries in vec((prefix_v4(), any::<u32>()), 0..=10),
        entries6 in vec((prefix_v6(), any::<u32>()), 0..=10),
    ) {
        // RFC 7911 §3: Path Identifier, then the tuple, per prefix; the
        // same prefix may recur with other identifiers.
        for (afi, entries) in [(Afi::Ipv4, entries), (Afi::Ipv6, entries6)] {
            let (ps, ids): (Vec<Prefix>, Vec<PathId>) =
                entries.into_iter().map(|(p, id)| (p, PathId(id))).unzip();
            let mut wire = Vec::new();
            encode_prefixes_with_ids(&ps, &ids, &mut wire);
            let (back, back_ids) = decode_prefixes_with_ids(&wire, afi).unwrap();
            prop_assert_eq!(back, ps);
            prop_assert_eq!(back_ids, ids);
        }
    }

    #[test]
    fn as_path_round_trip(p in as_path(true), four in any::<bool>()) {
        let mut wire = Vec::new();
        p.encode(four, &mut wire).unwrap();
        let back = AsPath::decode(&wire, four).unwrap();
        if four || !p.has_non_mappable() {
            prop_assert_eq!(&back, &p);
        } else {
            // RFC 6793 §4.2.2: non-mappable ASNs become AS_TRANS; the shape
            // and the mappable ASNs survive.
            prop_assert_eq!(back.hop_count(), p.hop_count());
            prop_assert_eq!(back.segments().count(), p.segments().count());
            for (a, b) in back.asns().zip(p.asns()) {
                prop_assert_eq!(a, if b.is_mappable() { b } else { Asn::TRANS });
            }
        }
        let mut again = Vec::new();
        back.encode(four, &mut again).unwrap();
        prop_assert_eq!(again, wire);
    }

    #[test]
    fn as_path_holds_its_segments_and_prepends_like_a_vector_of_them(
        segments in vec(
            (
                segment_type(true),
                // Short segments, and full ones to cross the 255 limit.
                prop_oneof![vec(asn(), 1..=6), vec(asn(), 254..=255)],
            )
                .prop_map(|(kind, asns)| AsPathSegment { kind, asns }),
            0..=3,
        ),
        asn in asn(),
    ) {
        let p = AsPath::from_segments(&segments);
        let back: Vec<AsPathSegment> = p.segments().map(Segment::into_owned).collect();
        prop_assert_eq!(&back, &segments);
        prop_assert_eq!(p.heap_size(), 4 * segments.iter().map(|s| 1 + s.asns.len()).sum::<usize>());
        // RFC 4271 §5.1.2 b, c, as the Vec-of-segments form did it.
        let mut expected = segments.clone();
        match expected.first_mut() {
            Some(s) if s.kind == SegmentType::Sequence && s.asns.len() < 255 => s.asns.insert(0, asn),
            _ => expected.insert(0, AsPathSegment { kind: SegmentType::Sequence, asns: vec![asn] }),
        }
        let prepended = p.prepend(asn);
        prop_assert_eq!(&prepended, &AsPath::from_segments(&expected));
        prop_assert_eq!(prepended.heap_size(), 4 * expected.iter().map(|s| 1 + s.asns.len()).sum::<usize>());
    }

    #[test]
    fn as4_merge_restores_a_four_octet_path(p in as_path(false)) {
        // What an OLD speaker forwards unchanged: the two-octet AS_PATH it
        // received and the AS4_PATH it does not understand.
        let mut two = Vec::new();
        p.encode(false, &mut two).unwrap();
        let as_path = AsPath::decode(&two, false).unwrap();
        prop_assert_eq!(AsPath::merge_as4(&as_path, &p), p);
    }

    #[test]
    fn capability_round_trip(c in capability()) {
        let mut wire = Vec::new();
        c.encode(&mut wire).unwrap();
        let mut r = Reader::new(&wire);
        prop_assert_eq!(Capability::decode(&mut r).unwrap(), c);
        prop_assert!(r.is_empty());
    }

    #[test]
    fn extended_next_hop_accepts_exactly_whole_triples(value in vec(any::<u8>(), 0..=255)) {
        // RFC 8950 §4 / RFC 4271 §6.2: whole six-octet triples decode, and
        // re-encode to the same octets; anything else is malformed.
        let mut wire = vec![5, u8::try_from(value.len()).unwrap()];
        wire.extend_from_slice(&value);
        let decoded = Capability::decode(&mut Reader::new(&wire));
        if value.len() % 6 == 0 {
            let c = decoded.unwrap();
            prop_assert!(matches!(&c, Capability::ExtendedNextHop(t) if t.len() == value.len() / 6));
            let mut again = Vec::new();
            c.encode(&mut again).unwrap();
            prop_assert_eq!(again, wire);
        } else {
            prop_assert_eq!(decoded.unwrap_err().code, ErrorCode::Open);
        }
    }

    #[test]
    fn add_path_accepts_exactly_whole_tuples(value in vec(any::<u8>(), 0..=255)) {
        // RFC 7911 §4: whole four-octet tuples decode and re-encode to the
        // same octets, as an ADD-PATH capability when every Send/Receive
        // value is 1 to 3 and as an unknown one otherwise; anything else is
        // malformed.
        let mut wire = vec![69, u8::try_from(value.len()).unwrap()];
        wire.extend_from_slice(&value);
        let decoded = Capability::decode(&mut Reader::new(&wire));
        if value.len() % 4 == 0 {
            let c = decoded.unwrap();
            let understood = value.chunks(4).all(|t| (1..=3).contains(&t[3]));
            prop_assert_eq!(matches!(c, Capability::AddPath(_)), understood);
            let mut again = Vec::new();
            c.encode(&mut again).unwrap();
            prop_assert_eq!(again, wire);
        } else {
            prop_assert_eq!(decoded.unwrap_err().code, ErrorCode::Open);
        }
    }

    #[test]
    fn graceful_restart_accepts_exactly_two_plus_whole_tuples(value in vec(any::<u8>(), 0..=255)) {
        // RFC 4724 §3: two octets of flags and Restart Time, then whole
        // four-octet tuples; anything else is malformed (RFC 4271 §6.2).
        // The reserved bits are ignored on receipt, so the capability
        // re-encodes to the octets received with them cleared.
        let mut wire = vec![64, u8::try_from(value.len()).unwrap()];
        wire.extend_from_slice(&value);
        let decoded = Capability::decode(&mut Reader::new(&wire));
        if value.len() >= 2 && (value.len() - 2) % 4 == 0 {
            let c = decoded.unwrap();
            prop_assert!(matches!(&c, Capability::GracefulRestart(g) if g.families.len() == (value.len() - 2) / 4));
            let mut cleared = wire.clone();
            cleared[2] &= 0xcf;
            for tuple in cleared[4..].chunks_mut(4) {
                tuple[3] &= 0x80;
            }
            let mut again = Vec::new();
            c.encode(&mut again).unwrap();
            prop_assert_eq!(again, cleared);
        } else {
            prop_assert_eq!(decoded.unwrap_err().code, ErrorCode::Open);
        }
    }

    #[test]
    fn role_capability_accepts_exactly_one_octet(value in vec(any::<u8>(), 0..=8)) {
        // RFC 9234 §4.1: length 1; any Role Value, assigned or not, is
        // kept and re-encoded as received. Any other length is malformed
        // (RFC 4271 §6.2, OPEN Message Error / Unspecific).
        let mut wire = vec![9, u8::try_from(value.len()).unwrap()];
        wire.extend_from_slice(&value);
        let decoded = Capability::decode(&mut Reader::new(&wire));
        if let [v] = value[..] {
            let c = decoded.unwrap();
            prop_assert_eq!(&c, &Capability::Role(Role::from_u8(v)));
            let mut again = Vec::new();
            c.encode(&mut again).unwrap();
            prop_assert_eq!(again, wire);
        } else {
            prop_assert_eq!(decoded.unwrap_err().code, ErrorCode::Open);
        }
    }

    #[test]
    fn end_of_rib_round_trip(
        v6 in any::<bool>(),
        add_path in any::<bool>(),
        extended_next_hop in any::<bool>(),
    ) {
        // RFC 4724 §2: the marker of either family encodes and decodes to
        // itself, whatever else was negotiated, and names its family; it
        // is never taken for anything announced or withdrawn.
        let family = if v6 { AddressFamily::IPV6_UNICAST } else { AddressFamily::IPV4_UNICAST };
        let paths = if add_path { AddPathFamilies::of(&[family]) } else { AddPathFamilies::NONE };
        let wire = UpdateMessage::end_of_rib(family)
            .encode(&EncodeContext { four_octet_as: true, extended_next_hop, add_path: paths })
            .unwrap();
        let d = UpdateMessage::decode(&wire, &DecodeContext {
            four_octet_as: true,
            peer: PeerKind::External,
            allow_as_set: false,
            extended_next_hop,
            add_path: paths,
        })
        .unwrap();
        prop_assert_eq!(d.message.end_of_rib_family(), Some(family));
        prop_assert_eq!(d.announcements().count() + d.withdrawals().count(), 0);
        prop_assert!(d.disabled.is_empty() && d.discarded.is_empty());
        prop_assert_eq!(d.message.encode(&EncodeContext {
            four_octet_as: true,
            extended_next_hop,
            add_path: paths,
        }).unwrap(), wire);
    }

    #[test]
    fn open_round_trip(m in open_message(), force_extended in any::<bool>()) {
        let wire = m.encode_with(force_extended).unwrap();
        let back = OpenMessage::decode(&wire).unwrap();
        prop_assert_eq!(&back, &m);
        prop_assert_eq!(back.encode_with(force_extended).unwrap(), wire.clone());
        // Framed, the header decoder accepts it as an OPEN.
        let framed = frame(MessageType::Open, &wire).unwrap();
        let h = Header::decode(&framed, false).unwrap();
        prop_assert_eq!(h.kind, MessageType::Open);
        prop_assert_eq!(h.body_len(), wire.len());
    }

    #[test]
    fn open_new_sets_as_trans_and_asn(asn in asn(), hold in 3u16..=u16::MAX, rid in 1u32..=u32::MAX) {
        let m = OpenMessage::new(asn, HoldTime::new(hold).unwrap(), RouterId::new(rid).unwrap(), vec![]);
        prop_assert_eq!(m.asn(), asn);
        prop_assert_eq!(m.my_as, asn.to_two_octet());
        prop_assert_eq!(OpenMessage::decode(&m.encode().unwrap()).unwrap().asn(), asn);
    }

    #[test]
    fn notification_round_trip(m in notification()) {
        let wire = m.encode(true).unwrap();
        prop_assert_eq!(NotificationMessage::decode(&wire).unwrap(), m);
    }

    #[test]
    fn hard_reset_carries_any_notification(m in notification()) {
        // RFC 8538 §3.1: a Hard Reset encapsulates another NOTIFICATION in
        // its data portion, whatever that is, and gives it back.
        let outer = NotificationMessage::hard_reset(&m);
        prop_assert!(outer.is_hard_reset());
        prop_assert_eq!(outer.hard_reset_inner(), Some(m.clone()));
        let wire = outer.encode(true).unwrap();
        prop_assert_eq!(NotificationMessage::decode(&wire).unwrap(), outer);
        // And no other NOTIFICATION is one.
        prop_assert_eq!(m.is_hard_reset(), m.code == ErrorCode::Cease && m.subcode == 9);
    }

    #[test]
    fn route_refresh_round_trip(f in address_family()) {
        let m = RouteRefreshMessage { family: f };
        prop_assert_eq!(RouteRefreshMessage::decode(&m.encode()).unwrap(), m);
    }

    #[test]
    fn header_round_trip(kind in 1u8..=5, extra in 0usize..=4096) {
        let kind = MessageType::from_u8(kind).unwrap();
        let min = usize::from(kind.min_len()) - 19;
        let body_len = (min + extra).min(usize::from(kind.max_len(true)) - 19);
        let h = Header::encode(kind, body_len).unwrap();
        let back = Header::decode(&h, true).unwrap();
        prop_assert_eq!(back.kind, kind);
        prop_assert_eq!(back.body_len(), body_len);
        prop_assert_eq!(Header::encode(kind, back.body_len()).unwrap(), h);
    }

    #[test]
    fn mp_reach_round_trip(m in mp_reach()) {
        let mut wire = Vec::new();
        m.encode(&mut wire);
        prop_assert_eq!(MpReach::decode(&wire, true).unwrap(), m);
    }

    #[test]
    fn ipv6_next_hop_for_ipv4_only_when_negotiated(m in update_message(true)) {
        // RFC 8950 §4 on send, RFC 7606 §7.11 on receipt: without the
        // capability an IPv4 MP_REACH_NLRI with an IPv6 next hop is
        // neither encoded nor accepted, and IPv4 unicast is disabled (RFC
        // 4760 §7); the rest of the message is unaffected.
        let v6_for_v4 = m.mp_reach.as_ref().is_some_and(|r| {
            r.family.afi == Afi::Ipv4 && matches!(r.next_hop, NextHop::Ipv6 { .. })
        });
        let plain = EncodeContext { extended_next_hop: false, ..ENC4 };
        let wire = m.encode(&ENC4).unwrap();
        let dec = DecodeContext { extended_next_hop: false, ..IBGP4 };
        let d = UpdateMessage::decode(&wire, &dec);
        if v6_for_v4 {
            prop_assert_eq!(
                m.encode(&plain),
                Err(bgpfc_wire::error::EncodeError::NextHopNotNegotiated(AddressFamily::IPV4_UNICAST))
            );
            let d = d.unwrap();
            prop_assert_eq!(
                d.disabled.iter().map(|x| x.family).collect::<Vec<_>>(),
                vec![AddressFamily::IPV4_UNICAST]
            );
            prop_assert_eq!(&d.message, &UpdateMessage { mp_reach: None, ..m.clone() });
            prop_assert_eq!(d.announcements().count(), 0);
            let v6_withdrawn = m
                .mp_unreach
                .as_ref()
                .filter(|u| u.family == AddressFamily::IPV6_UNICAST)
                .map_or(0, |u| u.withdrawn.len());
            prop_assert_eq!(d.withdrawals().count(), v6_withdrawn);
        } else {
            prop_assert_eq!(m.encode(&plain).unwrap(), wire);
            prop_assert_eq!(d.unwrap().message, m);
        }
    }

    #[test]
    fn mp_unreach_round_trip(m in mp_unreach()) {
        let mut wire = Vec::new();
        m.encode(&mut wire);
        prop_assert_eq!(MpUnreach::decode(&wire).unwrap(), m);
    }

    #[test]
    fn update_round_trip_four_octet(m in update_message(true)) {
        let wire = m.encode(&ENC4).unwrap();
        let d = UpdateMessage::decode(&wire, &IBGP4).unwrap();
        prop_assert_eq!(&d.treated_as_withdraw, &None);
        prop_assert_eq!(&d.discarded, &vec![]);
        prop_assert_eq!(&d.message, &m);
        prop_assert_eq!(d.message.encode(&ENC4).unwrap(), wire);
        // Announced and withdrawn route counts match the fields.
        let announced = m.nlri.len() + m.mp_reach.as_ref().map_or(0, |r| r.nlri.len());
        let withdrawn = m.withdrawn.len() + m.mp_unreach.as_ref().map_or(0, |u| u.withdrawn.len());
        prop_assert_eq!(d.announcements().count(), announced);
        prop_assert_eq!(d.withdrawals().count(), withdrawn);
    }

    #[test]
    fn update_with_path_ids_round_trip(
        m in update_message(true),
        on in add_path_families(),
        pool in vec(any::<u32>(), 1..8),
    ) {
        // RFC 7911 §3, §5: the families negotiated for ADD-PATH carry a
        // Path Identifier before each tuple, in all four lists, and the
        // others do not.
        let m = with_path_ids(m, on, &pool);
        let enc = EncodeContext { add_path: on, ..ENC4 };
        let dec = DecodeContext { add_path: on, ..IBGP4 };
        let wire = m.encode(&enc).unwrap();
        let d = UpdateMessage::decode(&wire, &dec).unwrap();
        prop_assert_eq!(&d.treated_as_withdraw, &None);
        prop_assert_eq!(&d.discarded, &vec![]);
        prop_assert_eq!(&d.disabled, &vec![]);
        prop_assert_eq!(&d.message, &m);
        prop_assert_eq!(d.message.encode(&enc).unwrap(), wire);
        // The withdrawals name the identifiers the fields carried.
        let mut expected: Vec<(AddressFamily, Prefix, PathId)> = Vec::new();
        let ids = |l: &[PathId], i: usize| l.get(i).copied().unwrap_or_default();
        expected.extend(m.withdrawn.iter().enumerate().map(|(i, p)| {
            (AddressFamily::IPV4_UNICAST, *p, ids(m.withdrawn_ids(), i))
        }));
        if let Some(u) = &m.mp_unreach {
            expected.extend(
                u.withdrawn.iter().enumerate().map(|(i, p)| (u.family, *p, ids(m.mp_unreach_ids(), i))),
            );
        }
        prop_assert_eq!(d.withdrawn_paths().collect::<Vec<_>>(), expected);
        // The same message is not an UPDATE a session without ADD-PATH
        // for a family would be sent.
        if !on.is_empty() && m.path_ids.is_some() {
            prop_assert!(m.encode(&ENC4).is_err());
        }
    }

    #[test]
    fn a_family_with_add_path_needs_an_identifier_for_each_prefix(
        m in update_message(true),
        pool in vec(any::<u32>(), 1..8),
    ) {
        // RFC 7911 §5: "the speaker MUST generate a route update for the
        // <AFI, SAFI> based on the combination of the address prefix and
        // the Path Identifier": a prefix without one is not encoded, and
        // a plain session is never sent one.
        let both = AddPathFamilies::of(&[AddressFamily::IPV4_UNICAST, AddressFamily::IPV6_UNICAST]);
        let enc = EncodeContext { add_path: both, ..ENC4 };
        let with = with_path_ids(m.clone(), both, &pool);
        let lists_with_prefixes = routes(&m) > 0;
        if lists_with_prefixes {
            prop_assert!(m.encode(&enc).is_err(), "no identifiers at all");
            prop_assert!(with.encode(&ENC4).is_err(), "identifiers on a plain session");
            // One too few in the first non-empty list.
            let mut short = (*with.path_ids.clone().unwrap()).clone();
            for list in [&mut short.withdrawn, &mut short.nlri, &mut short.mp_reach, &mut short.mp_unreach] {
                if !list.is_empty() {
                    list.pop();
                    break;
                }
            }
            let short = UpdateMessage { path_ids: Some(Box::new(short)), ..with };
            prop_assert!(short.encode(&enc).is_err(), "one identifier short");
        } else {
            prop_assert!(m.encode(&enc).is_ok());
        }
    }

    #[test]
    fn a_route_treated_as_withdrawn_is_withdrawn_by_its_path_identifier(
        m in update_message(true),
        on in add_path_families(),
        pool in vec(any::<u32>(), 1..8),
        bad in non_host_v4(),
    ) {
        // RFC 7606 §2 with RFC 7911 §3: what an UPDATE announced is
        // treated as withdrawn, a path at a time.
        let mut m = with_path_ids(m, on, &pool);
        for a in &mut m.attributes {
            if let PathAttribute::NextHop(n) = a {
                *n = bad;
            }
        }
        let enc = EncodeContext { add_path: on, ..ENC4 };
        let dec = DecodeContext { add_path: on, ..IBGP4 };
        let d = UpdateMessage::decode(&m.encode(&enc).unwrap(), &dec).unwrap();
        if !m.nlri.is_empty() {
            prop_assert!(d.treated_as_withdraw.is_some());
            prop_assert_eq!(d.announcements().count(), 0);
            // Withdrawn Routes, MP_UNREACH_NLRI, then what the NLRI field
            // and MP_REACH_NLRI announced, each by its own identifier.
            let all = |family, prefixes: &[Prefix], ids: &[PathId]| {
                prefixes
                    .iter()
                    .enumerate()
                    .map(|(i, p)| (family, *p, ids.get(i).copied().unwrap_or_default()))
                    .collect::<Vec<_>>()
            };
            let mut wanted = all(AddressFamily::IPV4_UNICAST, &m.withdrawn, m.withdrawn_ids());
            if let Some(u) = &m.mp_unreach {
                wanted.extend(all(u.family, &u.withdrawn, m.mp_unreach_ids()));
            }
            wanted.extend(all(AddressFamily::IPV4_UNICAST, &m.nlri, m.nlri_ids()));
            if let Some(r) = &m.mp_reach {
                wanted.extend(all(r.family, &r.nlri, m.mp_reach_ids()));
            }
            prop_assert_eq!(d.withdrawn_paths().collect::<Vec<_>>(), wanted);
        }
    }

    #[test]
    fn update_round_trip_two_octet(m in update_message(false)) {
        // RFC 6793 §4.2.2 / §4.2.3: AS4_PATH and AS4_AGGREGATOR carry the
        // four-octet information across a two-octet session and are merged
        // back on receipt, so the decoded message equals the original.
        let wire = m.encode(&ENC2).unwrap();
        let d = UpdateMessage::decode(&wire, &IBGP2).unwrap();
        prop_assert_eq!(d.treated_as_withdraw, None);
        prop_assert_eq!(d.discarded, vec![]);
        prop_assert_eq!(&d.message, &m);
        prop_assert_eq!(d.message.encode(&ENC2).unwrap(), wire);
    }

    #[test]
    fn update_attributes_are_in_type_order(m in update_message(true)) {
        let wire = m.encode(&ENC4).unwrap();
        let w = withdrawn_len(&wire);
        let attrs_len = usize::from(u16::from_be_bytes([wire[2 + w], wire[3 + w]]));
        let start = 4 + w;
        let mut r = Reader::new(&wire[start..start + attrs_len]);
        let mut codes = Vec::new();
        while !r.is_empty() {
            codes.push(bgpfc_wire::attribute::parse_raw(&mut r).unwrap().code);
        }
        // MP attributes first (RFC 7606 §5.1), then ascending (RFC 4271 §5).
        let mp: Vec<u8> = codes.iter().copied().filter(|c| matches!(c, 14 | 15)).collect();
        let rest: Vec<u8> = codes.iter().copied().filter(|c| !matches!(c, 14 | 15)).collect();
        prop_assert_eq!(&codes[..mp.len()], &mp[..]);
        prop_assert!(rest.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn a_next_hop_that_is_no_host_withdraws_the_routes(m in update_message(true), bad in non_host_v4()) {
        // RFC 4271 §6.3 with RFC 7606 §3 e): treat-as-withdraw, but only
        // when NEXT_HOP serves routes in the NLRI field (RFC 4760 §3).
        let mut m = m;
        for a in &mut m.attributes {
            if let PathAttribute::NextHop(n) = a {
                *n = bad;
            }
        }
        let d = UpdateMessage::decode(&m.encode(&ENC4).unwrap(), &IBGP4).unwrap();
        if m.nlri.is_empty() {
            prop_assert_eq!(&d.treated_as_withdraw, &None);
            prop_assert_eq!(&d.message, &m);
        } else {
            prop_assert_eq!(
                d.treated_as_withdraw.as_ref().map(|e| e.subcode),
                Some(UpdateSubcode::InvalidNextHop as u8)
            );
            prop_assert_eq!(d.announcements().count(), 0);
            prop_assert_eq!(d.withdrawals().count(), routes(&m));
        }
    }

    #[test]
    fn only_to_customer_is_four_octets_or_the_routes_are_withdrawn(
        m in update_message(true),
        value in vec(any::<u8>(), 0..=9),
    ) {
        // RFC 9234 §5: an OTC attribute of any length other than 4 is
        // malformed and treat-as-withdraw (RFC 7606 §5.2 makes it a reset
        // only where the UPDATE announces nothing); one of length 4 is kept
        // with its value.
        let mut m = m;
        m.attributes.retain(|a| a.code() != code::ONLY_TO_CUSTOMER);
        let mut wire = m.encode(&ENC4).unwrap();
        let mut attr = vec![0xc0, code::ONLY_TO_CUSTOMER, u8::try_from(value.len()).unwrap()];
        attr.extend_from_slice(&value);
        // After the attributes, before the NLRI: it is the last of the
        // path attributes, which any order allows (RFC 4271 §5).
        let nlri_len = {
            let mut nlri = Vec::new();
            bgpfc_wire::prefix::encode_prefixes(&m.nlri, &mut nlri);
            nlri.len()
        };
        let at = wire.len() - nlri_len;
        let total = u16::from_be_bytes([wire[withdrawn_len(&wire) + 2], wire[withdrawn_len(&wire) + 3]]);
        wire.splice(at..at, attr.iter().copied());
        let off = withdrawn_len(&wire) + 2;
        let total = total + u16::try_from(attr.len()).unwrap();
        wire[off..off + 2].copy_from_slice(&total.to_be_bytes());
        match value[..] {
            [a, b, c, e] => {
                let d = UpdateMessage::decode(&wire, &IBGP4).unwrap();
                prop_assert_eq!(&d.treated_as_withdraw, &None);
                prop_assert_eq!(
                    d.message.attribute(code::ONLY_TO_CUSTOMER),
                    Some(&PathAttribute::OnlyToCustomer(Asn(u32::from_be_bytes([a, b, c, e]))))
                );
            }
            _ if m.has_reachable() => {
                let d = UpdateMessage::decode(&wire, &IBGP4).unwrap();
                prop_assert_eq!(
                    d.treated_as_withdraw.as_ref().map(|e| e.subcode),
                    Some(UpdateSubcode::AttributeLengthError as u8)
                );
                prop_assert_eq!(d.announcements().count(), 0);
                prop_assert_eq!(d.withdrawals().count(), routes(&m));
            }
            _ => {
                // RFC 7606 §5.2: nothing reachable to withdraw, so the
                // routes of the message cannot be trusted to have been
                // parsed, and the session resets.
                let e = UpdateMessage::decode(&wire, &IBGP4).unwrap_err();
                prop_assert_eq!(e.notification.subcode, UpdateSubcode::AttributeLengthError as u8);
            }
        }
    }

    #[test]
    fn an_mp_reach_next_hop_that_is_no_host_withdraws_the_routes(
        (m, bad) in update_message(true)
            .prop_filter("an MP_REACH_NLRI", |m| m.mp_reach.is_some())
            .prop_flat_map(|m| {
                let nh = m.mp_reach.as_ref().map(|r| r.next_hop);
                (Just(m), invalid_like(nh.unwrap_or(NextHop::Ipv4(Ipv4Addr::UNSPECIFIED))))
            })
    ) {
        // RFC 4760 §3: the NEXT_HOP rules hold for MP_REACH_NLRI too.
        let mut m = m;
        if let Some(r) = &mut m.mp_reach {
            r.next_hop = bad;
        }
        let with_routes = m.mp_reach.as_ref().is_some_and(|r| !r.nlri.is_empty());
        let d = UpdateMessage::decode(&m.encode(&ENC4).unwrap(), &IBGP4).unwrap();
        if with_routes {
            prop_assert_eq!(
                d.treated_as_withdraw.as_ref().map(|e| e.subcode),
                Some(UpdateSubcode::InvalidNextHop as u8)
            );
            prop_assert_eq!(d.announcements().count(), 0);
            prop_assert_eq!(d.withdrawals().count(), routes(&m));
        } else {
            prop_assert_eq!(&d.treated_as_withdraw, &None);
        }
    }
}

/// Every route an UPDATE carries, announced or withdrawn.
fn routes(m: &UpdateMessage) -> usize {
    m.withdrawn.len()
        + m.nlri.len()
        + m.mp_reach.as_ref().map_or(0, |r| r.nlri.len())
        + m.mp_unreach.as_ref().map_or(0, |u| u.withdrawn.len())
}

/// Withdrawn Routes Length of an encoded UPDATE body.
fn withdrawn_len(wire: &[u8]) -> usize {
    usize::from(u16::from_be_bytes([wire[0], wire[1]]))
}

// ---------------------------------------------------------------- robustness

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    #[test]
    fn decoders_never_panic_on_arbitrary_bytes(bytes in vec(any::<u8>(), 0..=600), flag in any::<bool>()) {
        let _ = Header::decode(&bytes, flag);
        let _ = OpenMessage::decode(&bytes);
        let _ = NotificationMessage::decode(&bytes);
        let _ = RouteRefreshMessage::decode(&bytes);
        let _ = UpdateMessage::decode(&bytes, &IBGP4);
        let _ = UpdateMessage::decode(&bytes, &IBGP2);
        let _ = UpdateMessage::decode(&bytes, &EBGP4);
        // ... and with ADD-PATH on for either family or both (RFC 7911 §3).
        for on in [
            &[AddressFamily::IPV4_UNICAST][..],
            &[AddressFamily::IPV6_UNICAST][..],
            &[AddressFamily::IPV4_UNICAST, AddressFamily::IPV6_UNICAST][..],
        ] {
            let ctx = DecodeContext { add_path: AddPathFamilies::of(on), ..IBGP4 };
            let _ = UpdateMessage::decode(&bytes, &ctx);
            let _ = MpReach::decode_with(&bytes, flag, ctx.add_path);
            let _ = MpUnreach::decode_with(&bytes, ctx.add_path);
        }
        let _ = Capability::decode(&mut Reader::new(&bytes));
        let _ = AsPath::decode(&bytes, flag);
        let _ = decode_prefixes(&bytes, Afi::Ipv4);
        let _ = decode_prefixes(&bytes, Afi::Ipv6);
        let _ = decode_prefixes_with_ids(&bytes, Afi::Ipv4);
        let _ = decode_prefixes_with_ids(&bytes, Afi::Ipv6);
        let _ = MpReach::decode(&bytes, flag);
        let _ = MpUnreach::decode(&bytes);
    }

    #[test]
    fn corrupted_updates_never_panic(
        m in update_message(true),
        flips in vec((any::<usize>(), any::<u8>()), 1..=4),
        truncate in any::<Option<usize>>(),
    ) {
        let mut wire = m.encode(&ENC4).unwrap();
        for (at, byte) in flips {
            let i = at % wire.len();
            wire[i] = byte;
        }
        if let Some(t) = truncate {
            wire.truncate(t % (wire.len() + 1));
        }
        for ctx in [IBGP4, IBGP2, EBGP4] {
            let _ = UpdateMessage::decode(&wire, &ctx);
        }
    }

    #[test]
    fn corrupted_opens_never_panic(
        m in open_message(),
        flips in vec((any::<usize>(), any::<u8>()), 1..=4),
    ) {
        let mut wire = m.encode().unwrap();
        for (at, byte) in flips {
            let i = at % wire.len();
            wire[i] = byte;
        }
        let _ = OpenMessage::decode(&wire);
    }
}

#[test]
fn ebgp_context_rejects_local_pref_but_keeps_the_rest() {
    // A fixed sanity check that the eBGP context is exercised by the
    // robustness tests with the expected behaviour.
    let m = UpdateMessage {
        nlri: vec!["10.0.0.0/8".parse().unwrap()],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::sequence(&[Asn(65_001)])),
            PathAttribute::NextHop(Ipv4Addr::new(192, 0, 2, 1)),
            PathAttribute::LocalPref(100),
        ],
        ..UpdateMessage::default()
    };
    let d = UpdateMessage::decode(&m.encode(&ENC4).unwrap(), &EBGP4).unwrap();
    assert_eq!(d.message.attribute(code::LOCAL_PREF), None);
    assert_eq!(d.message.attributes.len(), 3);
}

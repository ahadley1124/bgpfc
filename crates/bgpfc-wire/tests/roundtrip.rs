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

use bgpfc_wire::as_path::{AsPath, AsPathSegment, SegmentType};
use bgpfc_wire::attribute::{Aggregator, Origin, PathAttribute, code};
use bgpfc_wire::capability::Capability;
use bgpfc_wire::community::{Community, ExtendedCommunity, LargeCommunity};
use bgpfc_wire::error::ErrorCode;
use bgpfc_wire::header::{Header, MessageType, frame};
use bgpfc_wire::mp::{MpReach, MpUnreach, NextHop};
use bgpfc_wire::notification::NotificationMessage;
use bgpfc_wire::open::OpenMessage;
use bgpfc_wire::prefix::{Prefix, decode_prefixes};
use bgpfc_wire::reader::Reader;
use bgpfc_wire::route_refresh::RouteRefreshMessage;
use bgpfc_wire::types::{AddressFamily, Afi, Asn, HoldTime, RouterId, Safi};
use bgpfc_wire::update::{DecodeContext, EncodeContext, PeerKind, UpdateMessage};
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
    .prop_map(|segments| AsPath { segments })
}

fn address_family() -> impl Strategy<Value = AddressFamily> {
    (any::<u16>(), any::<u8>()).prop_map(|(a, s)| AddressFamily {
        afi: Afi::from_u16(a),
        safi: Safi::from_u8(s),
    })
}

fn capability() -> impl Strategy<Value = Capability> {
    prop_oneof![
        address_family().prop_map(Capability::Multiprotocol),
        Just(Capability::RouteRefresh),
        Just(Capability::ExtendedMessage),
        any::<u32>().prop_map(|a| Capability::FourOctetAs(Asn(a))),
        (
            any::<u8>().prop_filter("known code", |c| !matches!(c, 1 | 2 | 6 | 65)),
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

fn next_hop(afi: Afi) -> BoxedStrategy<NextHop> {
    let v6 =
        (any::<u128>(), proptest::option::of(any::<u128>())).prop_map(|(g, ll)| NextHop::Ipv6 {
            global: Ipv6Addr::from(g),
            link_local: ll.map(Ipv6Addr::from),
        });
    match afi {
        Afi::Ipv4 => prop_oneof![
            any::<u32>().prop_map(|a| NextHop::Ipv4(Ipv4Addr::from(a))),
            v6
        ]
        .boxed(),
        _ => v6.boxed(),
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
    prop_oneof![9u8..=13, 19u8..=31, 33u8..=255]
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
        .prop_map(|(med, lp, aa, agg, cs, ecs, lcs, unk)| {
            [med, lp, aa, agg, cs, ecs, lcs, unk]
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
        any::<u32>(),
        optional_attributes(),
    )
        .prop_map(
            |(withdrawn, nlri, mp_reach, mp_unreach, origin, path, nh, mut optional)| {
                // The mandatory three are always present so the message is
                // valid whether or not it announces anything.
                let mut attributes = vec![
                    PathAttribute::Origin(origin),
                    PathAttribute::AsPath(path),
                    PathAttribute::NextHop(Ipv4Addr::from(nh)),
                ];
                attributes.append(&mut optional);
                attributes.sort_by_key(PathAttribute::code);
                UpdateMessage {
                    withdrawn,
                    nlri,
                    mp_reach,
                    mp_unreach,
                    attributes,
                }
            },
        )
}

const IBGP4: DecodeContext = DecodeContext {
    four_octet_as: true,
    peer: PeerKind::Internal,
    allow_as_set: true,
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
};
const ENC2: EncodeContext = EncodeContext {
    four_octet_as: false,
};

// ---------------------------------------------------------------- round trips

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
            prop_assert_eq!(back.segments.len(), p.segments.len());
            for (a, b) in back.asns().zip(p.asns()) {
                prop_assert_eq!(a, if b.is_mappable() { b } else { Asn::TRANS });
            }
        }
        let mut again = Vec::new();
        back.encode(four, &mut again).unwrap();
        prop_assert_eq!(again, wire);
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
        prop_assert_eq!(MpReach::decode(&wire).unwrap(), m);
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
        let _ = Capability::decode(&mut Reader::new(&bytes));
        let _ = AsPath::decode(&bytes, flag);
        let _ = decode_prefixes(&bytes, Afi::Ipv4);
        let _ = decode_prefixes(&bytes, Afi::Ipv6);
        let _ = MpReach::decode(&bytes);
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

//! ADD-PATH messages as real speakers send them (AGENTS.md §5, `bgpfc-wire`
//! row: byte vectors from real captures). RFC 7911 has no examples of its
//! own, so these were recorded from BIRD 2.14 (`add paths tx`) and FRR 8.4
//! (`addpath-tx-all-paths`) peering with a passive speaker that advertised
//! ADD-PATH for receiving; the addresses are those of the lab (the speaker
//! 10.99.0.2, AS 65002 for BIRD and 65003 for FRR). Kept as whole messages,
//! header included, so that each is checked as it came off the wire.

use std::net::Ipv4Addr;

use bgpfc_wire::attribute::PathAttribute;
use bgpfc_wire::capability::{AddPathMode, AddPathTuple, Capability, add_path_abilities};
use bgpfc_wire::error::UpdateSubcode;
use bgpfc_wire::header::{HEADER_LEN, Header, MessageType};
use bgpfc_wire::open::OpenMessage;
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::{AddressFamily, Asn, PathId};
use bgpfc_wire::update::{
    AddPathFamilies, DecodeContext, DecodedUpdate, EncodeContext, PeerKind, UpdateMessage,
};

const V4: AddressFamily = AddressFamily::IPV4_UNICAST;
const V6: AddressFamily = AddressFamily::IPV6_UNICAST;

// BIRD in AS 65002 with IPv4 and IPv6 unicast, `add paths tx` for both.
/// Its OPEN: MP IPv4 and IPv6, route refresh, graceful restart, 4-octet AS,
/// ADD-PATH `<1, 1, 2>` and `<2, 1, 2>` (send), enhanced route refresh and
/// long-lived graceful restart.
const BIRD_OPEN: &str = "ffffffffffffffffffffffffffffffff00450104fdea001e0a63000228022601040001000101040002000102004002007841040000fdea4508000101020002010246004700";
/// 192.0.2.0/24 as path 2, AS path 65002.
const BIRD_PATH_2: &str = "ffffffffffffffffffffffffffffffff003302000000144001010040020602010000fdea4003040a6300020000000218c00002";
/// The same prefix as path 3, AS path 65002 64999.
const BIRD_PATH_3: &str = "ffffffffffffffffffffffffffffffff003702000000184001010040020a02020000fdea0000fde74003040a6300020000000318c00002";
/// End-of-RIB for IPv4 unicast: an empty UPDATE, as without ADD-PATH.
const BIRD_EOR_V4: &str = "ffffffffffffffffffffffffffffffff00170200000000";
/// `MP_UNREACH_NLRI` for IPv6 unicast withdrawing `2001:db8::/32` as paths 4
/// and 5, with the extended-length flag on.
const BIRD_UNREACH_V6: &str = "ffffffffffffffffffffffffffffffff00300200000019900f0015000201000000042020010db8000000052020010db8";
/// End-of-RIB for IPv6 unicast: `MP_UNREACH_NLRI` with no withdrawn routes.
const BIRD_EOR_V6: &str = "ffffffffffffffffffffffffffffffff001d0200000006800f03000201";
/// The Withdrawn Routes field naming path 3 of 192.0.2.0/24 (`disable long`).
const BIRD_WITHDRAW_3: &str = "ffffffffffffffffffffffffffffffff001f0200080000000318c000020000";
/// `MP_UNREACH_NLRI` for path 5 of `2001:db8::/32`.
const BIRD_UNREACH_5: &str =
    "ffffffffffffffffffffffffffffffff00270200000010900f000c000201000000052020010db8";

// FRR in AS 65003, IPv4 unicast, `addpath-tx-all-paths`.
/// Its OPEN: one optional parameter per capability, ADD-PATH `<1, 1, 3>`.
const FRR_OPEN: &str = "ffffffffffffffffffffffffffffffff005f0104fdeb001e0a630002420206010400010001020280000202020002024600020641040000fdeb02020600020645040001010302074905036672720002044002c0780209470700010180000000";
/// 198.51.100.0/24 as path 2, with a MED of 0 and the extended-length flag
/// on the `AS_PATH`.
const FRR_PATH_2: &str = "ffffffffffffffffffffffffffffffff003b020000001c400101005002000602010000fdeb4003040a630002800404000000000000000218c63364";

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// The body of the captured message, after checking its header.
fn body(s: &str, kind: MessageType) -> Vec<u8> {
    let m = hex(s);
    let h = Header::decode(&m, false).unwrap();
    assert_eq!(h.kind, kind);
    assert_eq!(usize::from(h.length), m.len());
    m[HEADER_LEN..].to_vec()
}

fn p(s: &str) -> Prefix {
    s.parse().unwrap()
}

fn ctx(families: &[AddressFamily]) -> DecodeContext {
    DecodeContext {
        four_octet_as: true,
        peer: PeerKind::External,
        allow_as_set: false,
        extended_next_hop: false,
        add_path: AddPathFamilies::of(families),
    }
}

fn decode(s: &str, families: &[AddressFamily]) -> DecodedUpdate {
    let d = UpdateMessage::decode(&body(s, MessageType::Update), &ctx(families)).unwrap();
    assert_eq!(d.treated_as_withdraw, None);
    assert_eq!(d.disabled, vec![]);
    assert_eq!(d.discarded, vec![]);
    d
}

fn as_numbers(m: &UpdateMessage) -> Vec<u32> {
    let Some(PathAttribute::AsPath(path)) = m.attribute(2) else {
        panic!("no AS_PATH");
    };
    path.segments()
        .flat_map(bgpfc_wire::Segment::asns)
        .map(|a| a.0)
        .collect()
}

#[test]
fn bird_opens_with_add_path_to_send_for_both_families() {
    // RFC 7911 §4: one capability, a tuple per family, Send/Receive 2.
    let open = OpenMessage::decode(&body(BIRD_OPEN, MessageType::Open)).unwrap();
    assert_eq!(open.asn(), Asn(65_002));
    assert_eq!(open.hold_time.secs(), 30);
    assert_eq!(open.router_id.to_string(), "10.99.0.2");
    let tuples = open
        .capabilities
        .iter()
        .find_map(|c| match c {
            Capability::AddPath(t) => Some(t.clone()),
            _ => None,
        })
        .expect("ADD-PATH");
    assert_eq!(
        tuples,
        vec![
            AddPathTuple {
                family: V4,
                mode: AddPathMode::Send
            },
            AddPathTuple {
                family: V6,
                mode: AddPathMode::Send
            },
        ]
    );
    for family in [V4, V6] {
        assert_eq!(
            add_path_abilities(&open.capabilities, family),
            (false, true)
        );
        assert!(open.has(&Capability::Multiprotocol(family)));
    }
    assert!(open.has(&Capability::FourOctetAs(Asn(65_002))));
    // The capability goes back to the octets BIRD sent.
    let mut out = Vec::new();
    Capability::AddPath(tuples).encode(&mut out).unwrap();
    assert_eq!(out, hex("45080001010200020102"));
}

#[test]
fn frr_opens_with_add_path_for_both_directions_in_a_parameter_of_its_own() {
    // RFC 5492 §4: FRR sends each capability in a parameter of its own.
    let open = OpenMessage::decode(&body(FRR_OPEN, MessageType::Open)).unwrap();
    assert_eq!(open.asn(), Asn(65_003));
    assert!(open.has(&Capability::Multiprotocol(V4)));
    assert!(open.has(&Capability::FourOctetAs(Asn(65_003))));
    assert!(open.has(&Capability::AddPath(vec![AddPathTuple {
        family: V4,
        mode: AddPathMode::Both
    }])));
    assert_eq!(add_path_abilities(&open.capabilities, V4), (true, true));
    assert_eq!(add_path_abilities(&open.capabilities, V6), (false, false));
}

#[test]
fn bird_announces_each_path_of_a_prefix_under_its_own_identifier() {
    // RFC 7911 §3: Path Identifier, Length, Prefix in the NLRI field.
    let two = decode(BIRD_PATH_2, &[V4]);
    let three = decode(BIRD_PATH_3, &[V4]);
    for (d, id, path) in [(&two, 2, vec![65_002]), (&three, 3, vec![65_002, 64_999])] {
        let m = &d.message;
        assert_eq!(m.nlri, vec![p("192.0.2.0/24")]);
        assert_eq!(m.nlri_ids(), [PathId(id)]);
        assert_eq!(m.next_hop(), Some(Ipv4Addr::new(10, 99, 0, 2)));
        assert_eq!(as_numbers(m), path);
        assert_eq!(d.announcements().count(), 1);
    }
    // The same prefix twice is two paths: neither replaces the other.
    assert_eq!(two.message.nlri, three.message.nlri);
    assert_ne!(two.message.nlri_ids(), three.message.nlri_ids());
    // What we encode is what BIRD sent.
    let enc = EncodeContext {
        four_octet_as: true,
        extended_next_hop: false,
        add_path: AddPathFamilies::of(&[V4]),
    };
    assert_eq!(
        two.message.encode(&enc).unwrap(),
        body(BIRD_PATH_2, MessageType::Update)
    );
    assert_eq!(
        three.message.encode(&enc).unwrap(),
        body(BIRD_PATH_3, MessageType::Update)
    );
}

#[test]
fn the_same_octets_without_the_capability_are_a_broken_nlri() {
    // RFC 7911 §6: the only indication of the encoding is the capability
    // exchange. Without it the identifier reads as zero-length prefixes and
    // then as a length of 192 (RFC 7606 §5.3: session reset).
    let e = UpdateMessage::decode(&body(BIRD_PATH_2, MessageType::Update), &ctx(&[])).unwrap_err();
    assert_eq!(
        e.notification.subcode,
        UpdateSubcode::InvalidNetworkField as u8
    );
    // And for the other family it is no different.
    assert!(UpdateMessage::decode(&body(BIRD_PATH_2, MessageType::Update), &ctx(&[V6])).is_err());
}

#[test]
fn bird_withdraws_a_path_by_its_identifier() {
    // RFC 7911 §5: the Withdrawn Routes field names prefix and identifier.
    let d = decode(BIRD_WITHDRAW_3, &[V4]);
    assert_eq!(
        d.withdrawn_paths().collect::<Vec<_>>(),
        vec![(V4, p("192.0.2.0/24"), PathId(3))]
    );
    let enc = EncodeContext {
        four_octet_as: true,
        extended_next_hop: false,
        add_path: AddPathFamilies::of(&[V4]),
    };
    assert_eq!(
        d.message.encode(&enc).unwrap(),
        body(BIRD_WITHDRAW_3, MessageType::Update)
    );
}

#[test]
fn bird_withdraws_ipv6_paths_in_mp_unreach_nlri() {
    // RFC 7911 §3, §5: the same prefix withdrawn as two paths in one
    // attribute, and as one in another.
    let d = decode(BIRD_UNREACH_V6, &[V4, V6]);
    assert_eq!(
        d.withdrawn_paths().collect::<Vec<_>>(),
        vec![
            (V6, p("2001:db8::/32"), PathId(4)),
            (V6, p("2001:db8::/32"), PathId(5))
        ]
    );
    let d = decode(BIRD_UNREACH_5, &[V6]);
    assert_eq!(
        d.withdrawn_paths().collect::<Vec<_>>(),
        vec![(V6, p("2001:db8::/32"), PathId(5))]
    );
    // BIRD sets the extended-length flag where one octet would do; the
    // message decodes back to itself all the same.
    let enc = EncodeContext {
        four_octet_as: true,
        extended_next_hop: false,
        add_path: AddPathFamilies::of(&[V6]),
    };
    let again = UpdateMessage::decode(
        &d.message.encode(&enc).unwrap(),
        &DecodeContext {
            add_path: AddPathFamilies::of(&[V6]),
            ..ctx(&[])
        },
    )
    .unwrap();
    assert_eq!(again.message, d.message);
}

#[test]
fn end_of_rib_is_the_same_with_add_path() {
    // RFC 4724 §2: an empty UPDATE for IPv4 unicast, an `MP_UNREACH_NLRI`
    // with no withdrawn routes for IPv6; neither has a Path Identifier.
    for (s, family) in [(BIRD_EOR_V4, V4), (BIRD_EOR_V6, V6)] {
        let d = decode(s, &[V4, V6]);
        assert_eq!(d.withdrawn_paths().count(), 0);
        assert_eq!(d.announcements().count(), 0);
        assert!(d.message.path_ids.is_none());
        if family == V6 {
            assert_eq!(d.message.mp_unreach.as_ref().unwrap().family, V6);
        }
    }
}

#[test]
fn frr_announces_a_path_with_its_identifier() {
    let d = decode(FRR_PATH_2, &[V4]);
    let m = &d.message;
    assert_eq!(m.nlri, vec![p("198.51.100.0/24")]);
    assert_eq!(m.nlri_ids(), [PathId(2)]);
    assert_eq!(m.next_hop(), Some(Ipv4Addr::new(10, 99, 0, 2)));
    assert_eq!(as_numbers(m), vec![65_003]);
    assert_eq!(m.attribute(4), Some(&PathAttribute::MultiExitDisc(0)));
    // FRR flags the `AS_PATH` as extended-length; the encoder does not, so
    // compare the decoded message rather than the octets.
    let enc = EncodeContext {
        four_octet_as: true,
        extended_next_hop: false,
        add_path: AddPathFamilies::of(&[V4]),
    };
    let again = UpdateMessage::decode(&m.encode(&enc).unwrap(), &ctx(&[V4])).unwrap();
    assert_eq!(&again.message, m);
}

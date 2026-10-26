//! Graceful Restart (RFC 4724, RFC 8538) as real speakers send it
//! (AGENTS.md §5, `bgpfc-wire` row: byte vectors from real captures). The
//! RFCs have no worked examples, so these were recorded from BIRD 2.14 and
//! FRR 8.4 peering with a passive speaker in the interop lab; the addresses
//! are the lab's (the speaker 10.99.0.2, AS 65002 for BIRD and 65003 for
//! FRR). Kept as whole messages, header included, so that each is checked
//! as it came off the wire.

use bgpfc_wire::capability::{Capability, GracefulRestart, graceful_restart};
use bgpfc_wire::header::{HEADER_LEN, Header, MessageType, frame};
use bgpfc_wire::open::OpenMessage;
use bgpfc_wire::types::{AddressFamily, Asn, RestartTime};
use bgpfc_wire::update::{AddPathFamilies, DecodeContext, EncodeContext, PeerKind, UpdateMessage};

const V4: AddressFamily = AddressFamily::IPV4_UNICAST;
const V6: AddressFamily = AddressFamily::IPV6_UNICAST;

/// BIRD in AS 65002 with IPv4 and IPv6 unicast: its default `graceful
/// restart` is `aware`, and it advertises the capability with no family.
const BIRD_OPEN: &str = "ffffffffffffffffffffffffffffffff00450104fdea001e0a63000228022601040001000101040002000102004002007841040000fdea4508000101020002010246004700";
/// FRR in AS 65003 with IPv4 unicast, just started: Restart State and
/// Graceful Notification bits on, a Restart Time of 120 s, no family.
const FRR_OPEN: &str = "ffffffffffffffffffffffffffffffff005f0104fdeb001e0a630002420206010400010001020280000202020002024600020641040000fdeb02020600020645040001010302074905036672720002044002c0780209470700010180000000";
/// BIRD's End-of-RIB for IPv4 unicast: an empty UPDATE, 23 octets.
const BIRD_EOR_V4: &str = "ffffffffffffffffffffffffffffffff00170200000000";
/// BIRD's End-of-RIB for IPv6 unicast: `MP_UNREACH_NLRI` with no withdrawn
/// routes.
const BIRD_EOR_V6: &str = "ffffffffffffffffffffffffffffffff001d0200000006800f03000201";

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

fn ctx(families: &[AddressFamily]) -> DecodeContext {
    DecodeContext {
        four_octet_as: true,
        peer: PeerKind::External,
        allow_as_set: false,
        extended_next_hop: false,
        add_path: AddPathFamilies::of(families),
    }
}

fn enc(families: &[AddressFamily]) -> EncodeContext {
    EncodeContext {
        four_octet_as: true,
        extended_next_hop: false,
        add_path: AddPathFamilies::of(families),
    }
}

#[test]
fn bird_and_frr_advertise_the_capability_with_no_family() {
    // RFC 4724 §3: no <AFI, SAFI> means the speaker cannot preserve its
    // forwarding state but follows the Receiving Speaker procedures.
    let bird = OpenMessage::decode(&body(BIRD_OPEN, MessageType::Open)).unwrap();
    assert_eq!(bird.asn(), Asn(65_002));
    assert_eq!(
        graceful_restart(&bird.capabilities),
        Some(&GracefulRestart {
            restarting: false,
            notification: false,
            restart_time: RestartTime::new(120).unwrap(),
            families: vec![],
        })
    );
    // RFC 8538 §2: FRR sets the Graceful Notification bit, and, having
    // just started, the Restart State bit of RFC 4724 §3.
    let frr = OpenMessage::decode(&body(FRR_OPEN, MessageType::Open)).unwrap();
    assert_eq!(frr.asn(), Asn(65_003));
    assert_eq!(
        graceful_restart(&frr.capabilities),
        Some(&GracefulRestart {
            restarting: true,
            notification: true,
            restart_time: RestartTime::new(120).unwrap(),
            families: vec![],
        })
    );
    // Each goes back to the octets the speaker sent.
    for (open, want) in [(&bird, "40020078"), (&frr, "4002c078")] {
        let cap = open
            .capabilities
            .iter()
            .find(|c| matches!(c, Capability::GracefulRestart(_)))
            .unwrap();
        let mut out = Vec::new();
        cap.encode(&mut out).unwrap();
        assert_eq!(out, hex(want));
    }
}

#[test]
fn bird_ends_each_family_with_an_end_of_rib() {
    // RFC 4724 §2: the empty UPDATE for IPv4 unicast, the empty
    // MP_UNREACH_NLRI for any other family.
    for (wire, family) in [(BIRD_EOR_V4, V4), (BIRD_EOR_V6, V6)] {
        let body = body(wire, MessageType::Update);
        let d = UpdateMessage::decode(&body, &ctx(&[])).unwrap();
        assert_eq!(d.message.end_of_rib_family(), Some(family), "{wire}");
        assert_eq!(d.announcements().count() + d.withdrawals().count(), 0);
        assert_eq!(d.disabled, vec![]);
        // What we send is what BIRD sent.
        let ours = UpdateMessage::end_of_rib(family).encode(&enc(&[])).unwrap();
        assert_eq!(frame(MessageType::Update, &ours).unwrap(), hex(wire));
    }
}

#[test]
fn an_end_of_rib_is_the_same_on_an_add_path_session() {
    // RFC 7911 §3 puts an identifier before each prefix; a marker has none,
    // so the capability changes nothing about it.
    for (wire, family) in [(BIRD_EOR_V4, V4), (BIRD_EOR_V6, V6)] {
        let body = body(wire, MessageType::Update);
        let d = UpdateMessage::decode(&body, &ctx(&[V4, V6])).unwrap();
        assert_eq!(d.message.end_of_rib_family(), Some(family));
        let ours = UpdateMessage::end_of_rib(family)
            .encode(&enc(&[V4, V6]))
            .unwrap();
        assert_eq!(ours, body);
    }
}

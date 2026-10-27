//! RFC 7606 §5.1 on every UPDATE the RIB sends: the `MP_REACH_NLRI` or
//! `MP_UNREACH_NLRI` attribute, when present, "SHALL be encoded as the very
//! first path attribute", and an UPDATE "MUST NOT contain more than one"
//! of a non-empty Withdrawn Routes field, a non-empty NLRI field,
//! `MP_REACH_NLRI` and `MP_UNREACH_NLRI`. `Batch::encode` is where every
//! UPDATE bgpfc sends is made, so random churn across IPv4 and IPv6, over
//! IPv4 and IPv6 sessions with and without RFC 8950, to external and
//! internal peers, must never produce anything else.
#![cfg(not(miri))]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use bgpfc_rib::{Output, PeerInfo, Rib};
use bgpfc_wire::as_path::AsPath;
use bgpfc_wire::attribute::{Origin, PathAttribute, code, parse_raw};
use bgpfc_wire::header::HEADER_LEN;
use bgpfc_wire::mp::{MpReach, MpUnreach, NextHop};
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::reader::Reader;
use bgpfc_wire::types::{AddressFamily, Asn, RouterId};
use bgpfc_wire::update::{DecodedUpdate, PeerKind, UpdateMessage};
use proptest::prelude::*;

/// Run one RIB input and collect what it produced.
fn outputs(input: impl FnOnce(&mut Vec<Output>)) -> Vec<Output> {
    let mut out = Vec::new();
    input(&mut out);
    out
}

const LOCAL_AS: Asn = Asn(65_000);
const V4: AddressFamily = AddressFamily::IPV4_UNICAST;
const V6: AddressFamily = AddressFamily::IPV6_UNICAST;

/// An external IPv4 session, an external IPv6 session with RFC 8950, an
/// internal IPv4 session, and an external IPv6 session without RFC 8950.
fn peers() -> Vec<PeerInfo> {
    let peer = |addr: &str, local: &str, asn: u32, id: u32, enh: bool| PeerInfo {
        addr: addr.parse().unwrap(),
        local_addr: local.parse().unwrap(),
        remote_as: Asn(asn),
        router_id: RouterId::new(id).unwrap(),
        kind: if Asn(asn) == LOCAL_AS {
            PeerKind::Internal
        } else {
            PeerKind::External
        },
        families: vec![V4, V6],
        receive_families: vec![V4, V6],
        four_octet_as: true,
        extended_messages: false,
        route_refresh: true,
        extended_next_hop: if enh { vec![V4] } else { Vec::new() },
        advertisement_interval: Duration::ZERO,
        prefix_limits: Vec::new(),
    };
    vec![
        peer("10.0.0.1", "10.0.0.254", 65_001, 1, false),
        peer("2001:db8::2", "2001:db8::fe", 65_002, 2, true),
        peer("10.0.0.3", "10.0.0.254", 65_000, 3, false),
        peer("2001:db8::4", "2001:db8::fe", 65_004, 4, false),
    ]
}

#[derive(Clone, Debug)]
struct Step {
    peer: usize,
    v6: bool,
    /// The first of `count` consecutive prefixes.
    first: u16,
    count: u16,
    /// `None` withdraws.
    path: Option<Vec<u16>>,
    /// IPv4 routes with an IPv6 next hop (RFC 8950), where the peer may.
    v6_next_hop: bool,
}

fn prefixes(step: &Step) -> Vec<Prefix> {
    (step.first..step.first.saturating_add(step.count))
        .map(|i| {
            let [hi, lo] = i.to_be_bytes();
            if step.v6 {
                let a = Ipv6Addr::new(0x2001, 0xdb8, i, 0, 0, 0, 0, 0);
                Prefix::new(IpAddr::V6(a), 48).unwrap()
            } else {
                Prefix::new(IpAddr::V4(Ipv4Addr::new(100, hi, lo, 0)), 24).unwrap()
            }
        })
        .collect()
}

fn update(step: &Step, info: &PeerInfo) -> DecodedUpdate {
    let family = if step.v6 { V6 } else { V4 };
    let routes = prefixes(step);
    let mut message = UpdateMessage::default();
    let Some(path) = &step.path else {
        if family == V4 {
            message.withdrawn = routes;
        } else {
            message.mp_unreach = Some(MpUnreach {
                family,
                withdrawn: routes,
            });
        }
        return DecodedUpdate {
            message,
            ..DecodedUpdate::default()
        };
    };
    let mut asns: Vec<Asn> = path.iter().map(|a| Asn(u32::from(*a))).collect();
    if info.kind == PeerKind::External {
        asns.insert(0, info.remote_as);
    }
    message.attributes = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath::sequence(&asns)),
    ];
    if info.kind == PeerKind::Internal {
        message.attributes.push(PathAttribute::LocalPref(100));
    }
    // A next hop of the peer's own: never ours, always a host address.
    let last = match info.addr {
        IpAddr::V4(a) => a.octets()[3],
        IpAddr::V6(a) => a.octets()[15],
    };
    let v6_next_hop = NextHop::Ipv6 {
        global: Ipv6Addr::new(0x2001, 0xdb8, 0xffff, 0, 0, 0, 0, u16::from(last)),
        link_local: None,
    };
    if family == V6 || (step.v6_next_hop && info.extended_next_hop.contains(&V4)) {
        message.mp_reach = Some(MpReach {
            family,
            next_hop: v6_next_hop,
            nlri: routes,
        });
    } else {
        message
            .attributes
            .push(PathAttribute::NextHop(Ipv4Addr::new(192, 0, 2, last)));
        message.nlri = routes;
    }
    DecodedUpdate {
        message,
        ..DecodedUpdate::default()
    }
}

fn step() -> impl Strategy<Value = Step> {
    (
        0usize..4,
        any::<bool>(),
        0u16..64,
        prop_oneof![4 => 1u16..8, 1 => 200u16..700],
        proptest::option::weighted(0.75, proptest::collection::vec(1u16..5, 0..3)),
        any::<bool>(),
    )
        .prop_map(|(peer, v6, first, count, path, v6_next_hop)| Step {
            peer,
            v6,
            first,
            count,
            path,
            v6_next_hop,
        })
}

/// The type codes of the path attributes of an UPDATE `body`, in order,
/// and whether its Withdrawn Routes and NLRI fields are empty.
fn layout(body: &[u8]) -> (Vec<u8>, bool, bool) {
    let w = usize::from(u16::from_be_bytes([body[0], body[1]]));
    let a = usize::from(u16::from_be_bytes([body[2 + w], body[3 + w]]));
    let mut r = Reader::new(&body[4 + w..4 + w + a]);
    let mut codes = Vec::new();
    while !r.is_empty() {
        codes.push(parse_raw(&mut r).unwrap().code);
    }
    (codes, w > 0, body.len() > 4 + w + a)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn every_sent_update_carries_one_kind_of_field_with_mp_first(
        steps in proptest::collection::vec(step(), 1..24),
    ) {
        let infos = peers();
        let now = Instant::now();
        let mut rib = Rib::new(LOCAL_AS);
        let mut sent = 0usize;
        let mut all = Vec::new();
        for info in &infos {
            all.extend(outputs(|o| rib.peer_up(info.clone(), now, o)));
        }
        for s in &steps {
            let info = &infos[s.peer];
            all.extend(outputs(|o| rib.update(info.addr, &update(s, info), now, o)));
        }
        for out in all {
            let Output::Send { messages, .. } = out else {
                continue;
            };
            for m in messages {
                let (codes, withdrawn, nlri) = layout(&m[HEADER_LEN..]);
                let reach = codes.contains(&code::MP_REACH_NLRI);
                let unreach = codes.contains(&code::MP_UNREACH_NLRI);
                let kinds = [withdrawn, nlri, reach, unreach].iter().filter(|k| **k).count();
                prop_assert_eq!(kinds, 1, "{:?}", codes);
                if reach || unreach {
                    prop_assert!(
                        matches!(codes[0], code::MP_REACH_NLRI | code::MP_UNREACH_NLRI),
                        "{:?}", codes
                    );
                }
                sent += 1;
            }
        }
        // The peers hear of the routes, so there was something to check.
        prop_assert!(sent > 0 || steps.iter().all(|s| s.path.is_none()));
    }
}

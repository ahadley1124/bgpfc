//! The RFC 4271 §6.7 prefix limit against a naive model: whatever the
//! sequence of announcements, re-announcements, looped routes and
//! withdrawals, the RIB ends the session exactly at the first UPDATE after
//! which the peer holds more routes in the Adj-RIB-In than its limit,
//! those import policy rejects included, and until then it counts exactly
//! the routes the model holds.
#![cfg(not(miri))]

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use bgpfc_rib::{Output, PathAttrs, PeerInfo, Policies, Rib, Verdict};
use bgpfc_wire::as_path::AsPath;
use bgpfc_wire::attribute::{Origin, PathAttribute};
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::{AddressFamily, Asn, RouterId};
use bgpfc_wire::update::{DecodedUpdate, PeerKind, UpdateMessage};
use proptest::prelude::*;

const LOCAL_AS: Asn = Asn(65_000);
const PEER_AS: Asn = Asn(65_001);
const V4: AddressFamily = AddressFamily::IPV4_UNICAST;

#[derive(Clone, Debug)]
enum Op {
    /// Announce these prefixes in one UPDATE, with an AS path that
    /// contains our AS when `looped` (RFC 4271 §9.1.2: not accepted).
    Announce { prefixes: Vec<u8>, looped: bool },
    /// Withdraw these prefixes in one UPDATE.
    Withdraw(Vec<u8>),
}

fn info(limit: u32) -> PeerInfo {
    PeerInfo {
        addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        local_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 254)),
        remote_as: PEER_AS,
        router_id: RouterId::new(1).unwrap(),
        kind: PeerKind::External,
        families: vec![V4],
        receive_families: vec![V4],
        four_octet_as: true,
        extended_messages: false,
        extended_next_hop: Vec::new(),
        advertisement_interval: Duration::ZERO,
        prefix_limits: vec![(V4, limit)],
    }
}

fn prefix(i: u8) -> Prefix {
    Prefix::new(IpAddr::V4(Ipv4Addr::new(192, 0, i, 0)), 24).unwrap()
}

/// Whether import policy rejects the route for `prefix(i)`.
fn rejected(i: u8) -> bool {
    i.is_multiple_of(3)
}

/// Import policy that rejects the prefixes [`rejected`] names.
struct RejectSome;

impl Policies for RejectSome {
    fn import(&self, _: &PeerInfo, _: AddressFamily, p: Prefix, _: &PathAttrs) -> Verdict {
        if (0..12).any(|i| rejected(i) && prefix(i) == p) {
            Verdict::Reject
        } else {
            Verdict::Accept
        }
    }

    fn export(&self, _: &PeerInfo, _: AddressFamily, _: Prefix, _: &PathAttrs) -> Verdict {
        Verdict::Accept
    }
}

fn update(op: &Op) -> DecodedUpdate {
    let mut message = UpdateMessage::default();
    match op {
        Op::Announce { prefixes, looped } => {
            message.nlri = prefixes.iter().map(|i| prefix(*i)).collect();
            let path = if *looped {
                vec![PEER_AS, LOCAL_AS]
            } else {
                vec![PEER_AS]
            };
            message.attributes = vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::sequence(&path)),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 1)),
            ];
        }
        Op::Withdraw(prefixes) => {
            message.withdrawn = prefixes.iter().map(|i| prefix(*i)).collect();
        }
    }
    DecodedUpdate {
        message,
        treated_as_withdraw: None,
        discarded: Vec::new(),
        disabled: Vec::new(),
    }
}

fn op() -> impl Strategy<Value = Op> {
    let prefixes = || proptest::collection::vec(0u8..12, 1..5);
    prop_oneof![
        3 => (prefixes(), proptest::bool::weighted(0.2))
            .prop_map(|(prefixes, looped)| Op::Announce { prefixes, looped }),
        1 => prefixes().prop_map(Op::Withdraw),
    ]
}

proptest! {
    #[test]
    fn the_limit_trips_exactly_when_the_model_exceeds_it(
        limit in 0u32..8,
        ops in proptest::collection::vec(op(), 1..40),
    ) {
        let peer = info(limit);
        let now = Instant::now();
        let mut rib = Rib::with_policies(LOCAL_AS, Box::new(RejectSome));
        rib.peer_up(peer.clone(), now);
        let mut model: BTreeSet<u8> = BTreeSet::new();
        for op in &ops {
            // The model: routes held after the UPDATE, one prefix at a
            // time in NLRI order, stopping at the first one over. What
            // import policy rejects is held and counted like the rest.
            let mut over = false;
            match op {
                Op::Withdraw(ps) => {
                    for p in ps {
                        model.remove(p);
                    }
                }
                Op::Announce { prefixes, looped } => {
                    for p in prefixes {
                        if *looped {
                            // A looped re-announcement replaces, and so
                            // removes, the route held before.
                            model.remove(p);
                        } else {
                            model.insert(*p);
                        }
                        if model.len() > limit as usize {
                            over = true;
                            break;
                        }
                    }
                }
            }
            let out = rib.update(peer.addr, &update(op), now);
            let hits = out
                .iter()
                .filter(|o| matches!(o, Output::PrefixLimitExceeded { .. }))
                .count();
            if over {
                prop_assert_eq!(
                    out.first(),
                    Some(&Output::PrefixLimitExceeded { peer: peer.addr, family: V4, limit })
                );
                prop_assert_eq!(hits, 1);
                prop_assert!(rib.peer(peer.addr).is_none());
                prop_assert_eq!(rib.loc_rib(V4).count(), 0);
                return Ok(());
            }
            prop_assert_eq!(hits, 0);
            let held = rib.peer_stats(peer.addr).unwrap().received;
            prop_assert_eq!(held, vec![(V4, model.len())]);
            let loc: BTreeSet<Prefix> = rib.loc_rib(V4).map(|(p, _)| p).collect();
            let expected: BTreeSet<Prefix> = model
                .iter()
                .filter(|i| !rejected(**i))
                .map(|i| prefix(*i))
                .collect();
            prop_assert_eq!(loc, expected);
        }
    }
}

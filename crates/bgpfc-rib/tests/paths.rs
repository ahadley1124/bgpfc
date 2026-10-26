//! With ADD-PATH the Adj-RIBs-In are keyed by peer, prefix and Path
//! Identifier (RFC 7911 §2, §5), and the Loc-RIB is still a function of
//! them alone: whatever order the same announcements and withdrawals of
//! paths arrive in, the candidates and the best route are the same, the
//! best is what the decision process picks among all of the paths
//! (RFC 4271 §9.1), and the FIB changes chain up to the one best path of
//! each prefix (AGENTS.md §5, `bgpfc-rib` row).
#![cfg(not(miri))]

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use bgpfc_rib::decision::{Candidate, Neighbor, best};
use bgpfc_rib::{Output, PeerInfo, Rib};
use bgpfc_wire::as_path::AsPath;
use bgpfc_wire::attribute::{Origin, PathAttribute};
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::{AddressFamily, Asn, PathId, RouterId};
use bgpfc_wire::update::{DecodedUpdate, PathIds, PeerKind, UpdateMessage};
use proptest::prelude::*;

const LOCAL_AS: Asn = Asn(65_000);
const V4: AddressFamily = AddressFamily::IPV4_UNICAST;

#[derive(Clone, Debug)]
struct Step {
    peer: u8,
    prefix: u8,
    /// The Path Identifier; zero for the peers without ADD-PATH.
    path: u32,
    /// `None` withdraws.
    route: Option<Route>,
}

#[derive(Clone, Debug)]
struct Route {
    path: Vec<u16>,
    origin: u8,
    med: Option<u32>,
}

/// Peers 0 and 1 are external with ADD-PATH, 2 is external without, 3 is
/// internal with it.
fn peers() -> Vec<PeerInfo> {
    (0..4u8)
        .map(|i| PeerInfo {
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, i + 1)),
            local_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 254)),
            remote_as: match i {
                0 | 1 => Asn(65_001 + u32::from(i)),
                2 => Asn(65_003),
                _ => LOCAL_AS,
            },
            router_id: RouterId::new(u32::from(i) + 1).unwrap(),
            kind: if i < 3 {
                PeerKind::External
            } else {
                PeerKind::Internal
            },
            families: vec![V4],
            receive_families: vec![V4],
            four_octet_as: true,
            extended_messages: false,
            extended_next_hop: Vec::new(),
            advertisement_interval: Duration::ZERO,
            prefix_limits: Vec::new(),
            add_path_receive: if i == 2 { Vec::new() } else { vec![V4] },
            add_path_send: Vec::new(),
            role: None,
        })
        .collect()
}

fn prefix(i: u8) -> Prefix {
    Prefix::new(IpAddr::V4(Ipv4Addr::new(192, 0, i, 0)), 24).unwrap()
}

fn update(step: &Step, info: &PeerInfo) -> DecodedUpdate {
    let mut message = UpdateMessage::default();
    let with_ids = !info.add_path_receive.is_empty();
    let ids = PathIds {
        withdrawn: if with_ids && step.route.is_none() {
            vec![PathId(step.path)]
        } else {
            Vec::new()
        },
        nlri: if with_ids && step.route.is_some() {
            vec![PathId(step.path)]
        } else {
            Vec::new()
        },
        ..PathIds::default()
    };
    match &step.route {
        None => message.withdrawn = vec![prefix(step.prefix)],
        Some(r) => {
            message.nlri = vec![prefix(step.prefix)];
            let mut path: Vec<Asn> = r.path.iter().map(|a| Asn(u32::from(*a))).collect();
            if info.kind == PeerKind::External {
                path.insert(0, info.remote_as);
            }
            message.attributes = vec![
                PathAttribute::Origin(Origin::from_u8(r.origin).unwrap()),
                PathAttribute::AsPath(AsPath::sequence(&path)),
                PathAttribute::NextHop(match info.addr {
                    IpAddr::V4(a) => a,
                    IpAddr::V6(_) => unreachable!(),
                }),
            ];
            if let Some(m) = r.med {
                message.attributes.push(PathAttribute::MultiExitDisc(m));
            }
            if info.kind == PeerKind::Internal {
                message.attributes.push(PathAttribute::LocalPref(100));
            }
        }
    }
    if with_ids {
        message.path_ids = Some(Box::new(ids));
    }
    DecodedUpdate {
        message,
        treated_as_withdraw: None,
        discarded: Vec::new(),
        disabled: Vec::new(),
    }
}

fn route() -> impl Strategy<Value = Route> {
    (
        proptest::collection::vec(1u16..5, 0..3),
        0u8..3,
        proptest::option::of(0u32..3),
    )
        .prop_map(|(path, origin, med)| Route { path, origin, med })
}

fn step() -> impl Strategy<Value = Step> {
    (
        0u8..4,
        0u8..3,
        0u32..4,
        proptest::option::weighted(0.8, route()),
    )
        .prop_map(|(peer, prefix, path, route)| Step {
            peer,
            prefix,
            // A peer without ADD-PATH has one route per prefix.
            path: if peer == 2 { 0 } else { path },
            route,
        })
}

/// One prefix at the end: its candidates and its best.
type Prefixes = (
    Vec<(IpAddr, Option<u32>, usize)>,
    Option<(IpAddr, Option<u32>)>,
);

/// What a RIB ends with, per prefix: its candidates as (peer, path
/// identifier, AS path length) and the best of them. On the way, checks
/// that the FIB changes chain up: each names as previous the next hop the
/// one before gave the prefix, and together they end at the routes of a
/// full reconcile.
fn run(steps: &[Step]) -> Vec<Prefixes> {
    let infos = peers();
    let now = Instant::now();
    let mut rib = Rib::new(LOCAL_AS);
    for info in &infos {
        rib.peer_up(info.clone(), now, &mut Vec::new());
    }
    let mut fib = BTreeMap::new();
    for s in steps {
        let info = &infos[usize::from(s.peer)];
        let mut out = Vec::new();
        rib.update(info.addr, &update(s, info), now, &mut out);
        for o in out {
            if let Output::Fib(c) = o {
                assert_eq!(c.previous, fib.get(&c.prefix).copied(), "{c:?}");
                match c.next_hop {
                    Some(n) => fib.insert(c.prefix, n),
                    None => fib.remove(&c.prefix),
                };
            }
        }
    }
    assert_eq!(rib.fib_routes().collect::<BTreeMap<_, _>>(), fib);
    (0..3)
        .map(|i| {
            let candidates = rib.candidates(V4, prefix(i));
            // The best is the decision process over every path.
            let chosen = best(candidates.len(), |k| {
                let c = &candidates[k];
                let info = infos.iter().find(|p| p.addr == c.peer).unwrap();
                Candidate {
                    from: Neighbor::of(info),
                    attrs: c.attrs,
                    path_id: c.path_id.map_or(0, |p| p.0),
                    demoted: false,
                }
            });
            let in_rib = rib.loc_rib(V4).find(|(p, _)| *p == prefix(i));
            assert_eq!(
                chosen.map(|k| (candidates[k].peer, candidates[k].path_id)),
                in_rib.map(|(_, r)| (r.peer, r.path_id)),
                "prefix {i}"
            );
            let mut all: Vec<_> = candidates
                .iter()
                .map(|c| (c.peer, c.path_id.map(|p| p.0), c.attrs.as_path.hop_count()))
                .collect();
            all.sort_unstable();
            (all, in_rib.map(|(_, r)| (r.peer, r.path_id.map(|p| p.0))))
        })
        .collect()
}

/// Keep only each (peer, prefix, path)'s last word, in the given order.
fn last_words(steps: &[Step]) -> Vec<Step> {
    let mut out: Vec<Step> = Vec::new();
    for s in steps {
        out.retain(|o| !(o.peer == s.peer && o.prefix == s.prefix && o.path == s.path));
        out.push(s.clone());
    }
    out
}

/// `items` in an order drawn from `seed`.
fn shuffle<T>(items: &mut [T], seed: u64) {
    let mut x = seed | 1;
    for i in (1..items.len()).rev() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let j = usize::try_from(x % (i as u64 + 1)).unwrap();
        items.swap(i, j);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn candidates_and_best_are_independent_of_arrival_order(
        steps in proptest::collection::vec(step(), 0..24),
        seed in any::<u64>(),
    ) {
        let reference = run(&steps);
        let mut shuffled = last_words(&steps);
        shuffle(&mut shuffled, seed);
        prop_assert_eq!(reference, run(&shuffled));
    }

    #[test]
    fn the_candidates_are_the_paths_last_announced_and_not_withdrawn(
        steps in proptest::collection::vec(step(), 0..24),
    ) {
        // The model: the last word on each (peer, prefix, path).
        let mut model: BTreeMap<(u8, u8, u32), usize> = BTreeMap::new();
        for s in last_words(&steps) {
            if let Some(r) = &s.route {
                let hops = r.path.len() + usize::from(s.peer != 3);
                model.insert((s.peer, s.prefix, s.path), hops);
            }
        }
        let got = run(&steps);
        for (i, (candidates, _)) in got.iter().enumerate() {
            let expected = model
                .iter()
                .filter(|((_, p, _), _)| usize::from(*p) == i)
                .count();
            prop_assert_eq!(candidates.len(), expected, "prefix {}", i);
        }
    }
}

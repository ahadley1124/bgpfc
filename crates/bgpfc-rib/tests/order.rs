//! Loc-RIB is a function of the Adj-RIBs-In alone: whatever order the
//! same announcements and withdrawals arrive in, the best routes and the
//! final Adj-RIBs-Out are the same (AGENTS.md §5, `bgpfc-rib` row).
#![cfg(not(miri))]

use std::net::{IpAddr, Ipv4Addr};

use bgpfc_rib::{PeerInfo, Rib};
use bgpfc_wire::as_path::AsPath;
use bgpfc_wire::attribute::{Origin, PathAttribute};
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::{AddressFamily, Asn, RouterId};
use bgpfc_wire::update::{DecodedUpdate, PeerKind, UpdateMessage};
use proptest::prelude::*;

const LOCAL_AS: Asn = Asn(65_000);
const V4: AddressFamily = AddressFamily::IPV4_UNICAST;

#[derive(Clone, Debug)]
struct Step {
    peer: u8,
    prefix: u8,
    /// `None` withdraws.
    route: Option<Route>,
}

#[derive(Clone, Debug)]
struct Route {
    path: Vec<u16>,
    origin: u8,
    med: Option<u32>,
    local_pref: Option<u32>,
}

fn peers() -> Vec<PeerInfo> {
    (0..4u8)
        .map(|i| PeerInfo {
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, i + 1)),
            local_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 254)),
            // Peers 0 and 1 are external (different ASes), 2 and 3 internal.
            remote_as: if i < 2 {
                Asn(65_001 + u32::from(i))
            } else {
                LOCAL_AS
            },
            router_id: RouterId::new(u32::from(i) + 1).unwrap(),
            kind: if i < 2 {
                PeerKind::External
            } else {
                PeerKind::Internal
            },
            families: vec![V4],
            four_octet_as: true,
            extended_messages: false,
        })
        .collect()
}

fn prefix(i: u8) -> Prefix {
    Prefix::new(IpAddr::V4(Ipv4Addr::new(192, 0, i, 0)), 24).unwrap()
}

fn update(step: &Step, info: &PeerInfo) -> DecodedUpdate {
    let mut message = UpdateMessage::default();
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
                message
                    .attributes
                    .push(PathAttribute::LocalPref(r.local_pref.unwrap_or(100)));
            }
        }
    }
    DecodedUpdate {
        message,
        treated_as_withdraw: None,
        discarded: Vec::new(),
    }
}

fn route() -> impl Strategy<Value = Route> {
    (
        proptest::collection::vec(1u16..5, 0..3),
        0u8..3,
        proptest::option::of(0u32..3),
        proptest::option::of(prop_oneof![Just(50u32), Just(100), Just(200)]),
    )
        .prop_map(|(path, origin, med, local_pref)| Route {
            path,
            origin,
            med,
            local_pref,
        })
}

fn step() -> impl Strategy<Value = Step> {
    (0u8..4, 0u8..3, proptest::option::weighted(0.8, route())).prop_map(|(peer, prefix, route)| {
        Step {
            peer,
            prefix,
            route,
        }
    })
}

/// The final state: best route per prefix and each peer's Adj-RIB-Out.
fn run(steps: &[Step]) -> (Vec<(Prefix, IpAddr)>, Vec<Vec<Prefix>>) {
    let infos = peers();
    let mut rib = Rib::new(LOCAL_AS);
    for info in &infos {
        rib.peer_up(info.clone());
    }
    for s in steps {
        let info = &infos[usize::from(s.peer)];
        rib.update(info.addr, &update(s, info));
    }
    let best = rib.loc_rib(V4).map(|(p, b)| (p, b.peer)).collect();
    let outs = infos
        .iter()
        .map(|i| {
            let mut v: Vec<Prefix> = rib.adj_rib_out(i.addr, V4).map(|(p, _)| p).collect();
            v.sort();
            v
        })
        .collect();
    (best, outs)
}

/// Keep only each peer's last word on each prefix, in the given order.
fn last_words(steps: &[Step]) -> Vec<Step> {
    let mut out: Vec<Step> = Vec::new();
    for s in steps {
        out.retain(|o| !(o.peer == s.peer && o.prefix == s.prefix));
        out.push(s.clone());
    }
    out
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn loc_rib_is_independent_of_arrival_order(
        steps in proptest::collection::vec(step(), 0..12),
        seed in any::<u64>(),
    ) {
        let reference = run(&steps);
        // The same final Adj-RIBs-In, reached by a different order of
        // the decisive updates.
        let mut shuffled = last_words(&steps);
        let mut x = seed | 1;
        for i in (1..shuffled.len()).rev() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let j = usize::try_from(x % (i as u64 + 1)).unwrap();
            shuffled.swap(i, j);
        }
        let other = run(&shuffled);
        prop_assert_eq!(reference, other);
    }
}

//! Property: the RIB applies the Only to Customer procedures of RFC 9234
//! §5 as the RFC writes them. A model written straight from the text of §5
//! (by the neighbor's Role, as the RFC states the rules, not by ours as
//! the code does) says which routes each neighbor's last UPDATE leaves in
//! the Adj-RIB-In and with which attribute; the RIB's candidates must be
//! those. And what each neighbor has been sent, applying every UPDATE it
//! got to a table of its own, must be what the model says export makes of
//! the Loc-RIB's best routes, on the wire.
#![cfg(not(miri))]

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use bgpfc_rib::attrs::announced;
use bgpfc_rib::{Output, PathAttrs, PeerInfo, Rib};
use bgpfc_wire::as_path::AsPath;
use bgpfc_wire::attribute::{Origin, PathAttribute};
use bgpfc_wire::header::HEADER_LEN;
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::role::Role;
use bgpfc_wire::types::{AddressFamily, Asn, RouterId};
use bgpfc_wire::update::{DecodeContext, DecodedUpdate, PeerKind, UpdateMessage};
use proptest::prelude::*;

const LOCAL_AS: Asn = Asn(65_000);
const V4: AddressFamily = AddressFamily::IPV4_UNICAST;
/// Five external neighbors with Roles of their own and one internal.
const PEERS: u8 = 6;

fn remote_as(i: u8) -> Asn {
    if i < 5 {
        Asn(65_001 + u32::from(i))
    } else {
        LOCAL_AS
    }
}

fn peers(roles: &[Option<Role>]) -> Vec<PeerInfo> {
    (0..PEERS)
        .map(|i| PeerInfo {
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, i + 1)),
            local_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 254)),
            remote_as: remote_as(i),
            router_id: RouterId::new(u32::from(i) + 1).unwrap(),
            kind: if i < 5 {
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
            // RFC 9234 §4: Roles are for external sessions.
            role: if i < 5 { roles[usize::from(i)] } else { None },
        })
        .collect()
}

fn prefix(i: u8) -> Prefix {
    Prefix::new(IpAddr::V4(Ipv4Addr::new(192, 0, i, 0)), 24).unwrap()
}

#[derive(Clone, Debug)]
enum Step {
    Announce {
        peer: u8,
        prefix: u8,
        /// The attribute as the neighbor sends it.
        otc: Option<Asn>,
    },
    Withdraw {
        peer: u8,
        prefix: u8,
    },
    Reset {
        peer: u8,
    },
}

fn otc() -> impl Strategy<Value = Option<Asn>> {
    // Absent, a neighbor's own AS (several of them), someone else's, ours.
    proptest::option::weighted(
        0.6,
        prop_oneof![
            (65_001u32..65_007).prop_map(Asn),
            Just(Asn(65_099)),
            Just(LOCAL_AS),
        ],
    )
}

fn step() -> impl Strategy<Value = Step> {
    prop_oneof![
        8 => (0..PEERS, 0u8..3, otc())
            .prop_map(|(peer, prefix, otc)| Step::Announce { peer, prefix, otc }),
        3 => (0..PEERS, 0u8..3).prop_map(|(peer, prefix)| Step::Withdraw { peer, prefix }),
        1 => (0..PEERS).prop_map(|peer| Step::Reset { peer }),
    ]
}

fn role() -> impl Strategy<Value = Option<Role>> {
    proptest::option::of(prop_oneof![
        Just(Role::Provider),
        Just(Role::RouteServer),
        Just(Role::RouteServerClient),
        Just(Role::Customer),
        Just(Role::Peer),
    ])
}

fn update(info: &PeerInfo, prefix: Prefix, otc: Option<Asn>) -> DecodedUpdate {
    let mut asns = vec![Asn(65_555)];
    if info.kind == PeerKind::External {
        asns.insert(0, info.remote_as);
    }
    let IpAddr::V4(next_hop) = info.addr else {
        unreachable!()
    };
    let mut attributes = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath::sequence(&asns)),
        PathAttribute::NextHop(next_hop),
    ];
    if info.kind == PeerKind::Internal {
        attributes.push(PathAttribute::LocalPref(100));
    }
    if let Some(a) = otc {
        attributes.push(PathAttribute::OnlyToCustomer(a));
    }
    attributes.sort_by_key(PathAttribute::code);
    DecodedUpdate {
        message: UpdateMessage {
            attributes,
            nlri: vec![prefix],
            ..UpdateMessage::default()
        },
        treated_as_withdraw: None,
        discarded: Vec::new(),
        disabled: Vec::new(),
    }
}

/// The Role the neighbor has, from ours (RFC 9234 §4.2, Table 2).
fn neighbors_role(ours: Role) -> Role {
    match ours {
        Role::Provider => Role::Customer,
        Role::Customer => Role::Provider,
        Role::RouteServer => Role::RouteServerClient,
        Role::RouteServerClient => Role::RouteServer,
        Role::Peer => Role::Peer,
        Role::Unknown(_) => unreachable!("never generated"),
    }
}

/// What the model says becomes of a route: not kept or sent, or kept or
/// sent with an attribute that may be none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fate {
    No,
    With(Option<Asn>),
}

/// RFC 9234 §5, "ingress procedure", as the RFC states it, for a route
/// with `otc` received from a neighbor in `remote` that has Role `theirs`:
/// not kept if it is a leak, else the attribute it has once received.
fn ingress(theirs: Role, remote: Asn, otc: Option<Asn>) -> Fate {
    match (theirs, otc) {
        // 1. From a Customer or an RS-Client, with the attribute.
        (Role::Customer | Role::RouteServerClient, Some(_)) => Fate::No,
        // 2. From a Peer, with an AS other than the Peer's.
        (Role::Peer, Some(v)) if v != remote => Fate::No,
        // 3. From a Provider, a Peer or an RS, without it: added.
        (Role::Provider | Role::Peer | Role::RouteServer, None) => Fate::With(Some(remote)),
        (_, otc) => Fate::With(otc),
    }
}

/// RFC 9234 §5, "egress procedure", for a route with `otc` to a neighbor
/// that has Role `theirs`: not sent, or the attribute it is sent with.
fn egress(theirs: Role, otc: Option<Asn>) -> Fate {
    // 2. A route that has it is not propagated to Providers, Peers, RSes.
    if otc.is_some() && matches!(theirs, Role::Provider | Role::Peer | Role::RouteServer) {
        return Fate::No;
    }
    // 1. To a Customer, a Peer or an RS-Client, without it: ours added.
    if otc.is_none()
        && matches!(
            theirs,
            Role::Customer | Role::Peer | Role::RouteServerClient
        )
    {
        return Fate::With(Some(LOCAL_AS));
    }
    Fate::With(otc)
}

/// Apply what the RIB asked to send to each peer to that peer's table.
fn deliver(out: Vec<Output>, infos: &[PeerInfo], views: &mut [BTreeMap<Prefix, PathAttrs>]) {
    for o in out {
        let Output::Send { peer, messages } = o else {
            continue;
        };
        let i = infos.iter().position(|p| p.addr == peer).unwrap();
        let ctx = DecodeContext {
            four_octet_as: true,
            peer: infos[i].kind,
            allow_as_set: false,
            extended_next_hop: false,
        };
        for m in messages {
            let d = UpdateMessage::decode(&m[HEADER_LEN..], &ctx).unwrap();
            for (_, p) in d.withdrawals() {
                views[i].remove(&p);
            }
            for (_, next_hop, prefixes) in announced(&d) {
                for &p in prefixes {
                    views[i].insert(p, PathAttrs::from_update(&d.message, next_hop));
                }
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn the_rib_follows_the_rfc_9234_procedures(
        roles in proptest::collection::vec(role(), 5),
        steps in proptest::collection::vec(step(), 0..30),
    ) {
        let infos = peers(&roles);
        let now = Instant::now();
        let mut rib = Rib::new(LOCAL_AS);
        let mut views = vec![BTreeMap::new(); infos.len()];
        for info in &infos {
            let mut out = Vec::new();
            rib.peer_up(info.clone(), now, &mut out);
            deliver(out, &infos, &mut views);
        }
        // What each neighbor last said about each prefix.
        let mut said: BTreeMap<(u8, u8), Option<Asn>> = BTreeMap::new();
        for s in &steps {
            let mut out = Vec::new();
            match s {
                Step::Announce { peer, prefix: n, otc } => {
                    let info = &infos[usize::from(*peer)];
                    rib.update(info.addr, &update(info, prefix(*n), *otc), now, &mut out);
                    said.insert((*peer, *n), *otc);
                    // A leak is reported, with the attribute and the prefix.
                    let leaked = info.role.is_some_and(|ours| {
                        ingress(neighbors_role(ours), info.remote_as, *otc) == Fate::No
                    });
                    let reported: Vec<_> = out.iter().filter_map(|o| match o {
                        Output::RouteLeak { peer, otc, routes, first, .. } => {
                            Some((*peer, *otc, *routes, *first))
                        }
                        _ => None,
                    }).collect();
                    if leaked {
                        prop_assert_eq!(reported, vec![(info.addr, otc.unwrap(), 1, prefix(*n))]);
                    } else {
                        prop_assert_eq!(reported, vec![]);
                    }
                }
                Step::Withdraw { peer, prefix: n } => {
                    let u = DecodedUpdate {
                        message: UpdateMessage {
                            withdrawn: vec![prefix(*n)],
                            ..UpdateMessage::default()
                        },
                        treated_as_withdraw: None,
                        discarded: Vec::new(),
                        disabled: Vec::new(),
                    };
                    rib.update(infos[usize::from(*peer)].addr, &u, now, &mut out);
                    said.remove(&(*peer, *n));
                }
                Step::Reset { peer } => {
                    let i = usize::from(*peer);
                    rib.peer_down(infos[i].addr, now, &mut out);
                    views[i].clear();
                    deliver(std::mem::take(&mut out), &infos, &mut views);
                    views[i].clear();
                    said.retain(|(p, _), _| p != peer);
                    rib.peer_up(infos[i].clone(), now, &mut out);
                }
            }
            deliver(out, &infos, &mut views);
        }

        for n in 0..3u8 {
            // The Adj-RIBs-In: the routes the neighbors' last words leave.
            let mut expected: Vec<(IpAddr, Option<Asn>)> = said
                .iter()
                .filter(|((_, p), _)| *p == n)
                .filter_map(|((peer, _), otc)| {
                    let info = &infos[usize::from(*peer)];
                    match info.role {
                        Some(ours) => match ingress(neighbors_role(ours), info.remote_as, *otc) {
                            Fate::No => None,
                            Fate::With(kept) => Some((info.addr, kept)),
                        },
                        None => Some((info.addr, *otc)),
                    }
                })
                .collect();
            let mut held: Vec<(IpAddr, Option<Asn>)> = rib
                .candidates(V4, prefix(n))
                .iter()
                .map(|r| (r.peer, r.attrs.otc))
                .collect();
            expected.sort();
            held.sort();
            prop_assert_eq!(&held, &expected, "candidates for {}", prefix(n));

            // What every neighbor has been sent of the best route.
            let best = rib.loc_rib(V4).find(|(p, _)| *p == prefix(n)).map(|(_, r)| (r.peer, r.attrs.otc));
            for (i, info) in infos.iter().enumerate() {
                let want = match best {
                    None => Fate::No,
                    // Never back to the neighbor it came from, and not from
                    // one internal neighbor to another (RFC 4271 §9.2);
                    // there is a single internal neighbor here.
                    Some((from, _))
                        if from == info.addr
                            || (from == infos[5].addr && info.kind == PeerKind::Internal) =>
                    {
                        Fate::No
                    }
                    Some((_, otc)) => match info.role {
                        Some(ours) => egress(neighbors_role(ours), otc),
                        None => Fate::With(otc),
                    },
                };
                let got = views[i].get(&prefix(n)).map_or(Fate::No, |a| Fate::With(a.otc));
                prop_assert_eq!(got, want, "neighbor {} role {:?} prefix {}", info.addr, info.role, prefix(n));
            }
        }
    }
}

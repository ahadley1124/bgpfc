//! Property: what each peer has been sent adds up to the RIB's view of
//! its Adj-RIB-Out. The RIB does not store an Adj-RIB-Out per peer; it
//! works out what a peer was last told from the Loc-RIB and export, which
//! is right only if every change reached the peer as an UPDATE. So: run
//! random announcements, withdrawals, session resets and export policy
//! changes over four peers, apply the UPDATEs each peer is sent to a table
//! of its own, and compare it at the end with the export of the Loc-RIB,
//! rewritten for the session (RFC 4271 §5.1).
#![cfg(not(miri))]

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use bgpfc_rib::attrs::announced;
use bgpfc_rib::export::rewrite;
use bgpfc_rib::{Output, PathAttrs, PeerInfo, Policies, Rib, RovState, Verdict};
use bgpfc_wire::as_path::AsPath;
use bgpfc_wire::attribute::{Origin, PathAttribute};
use bgpfc_wire::community::Community;
use bgpfc_wire::header::HEADER_LEN;
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::{AddressFamily, Asn, RouterId};
use bgpfc_wire::update::{DecodeContext, DecodedUpdate, PeerKind, UpdateMessage};
use proptest::prelude::*;

const LOCAL_AS: Asn = Asn(65_000);
const V4: AddressFamily = AddressFamily::IPV4_UNICAST;

fn peers() -> Vec<PeerInfo> {
    (0..4u8)
        .map(|i| PeerInfo {
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, i + 1)),
            local_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 254)),
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
            receive_families: vec![V4],
            four_octet_as: true,
            extended_messages: false,
            extended_next_hop: Vec::new(),
            // Pacing off: the property is about what is sent, which pacing
            // only delays; tests/pacing.rs is about when.
            advertisement_interval: Duration::ZERO,
            prefix_limits: Vec::new(),
            add_path_receive: Vec::new(),
            add_path_send: Vec::new(),
            role: None,
        })
        .collect()
}

fn prefix(i: u8) -> Prefix {
    Prefix::new(IpAddr::V4(Ipv4Addr::new(192, 0, i, 0)), 24).unwrap()
}

/// An export policy that depends on the prefix and the peer: one of two,
/// so that a change between them re-exports.
struct Picky(bool);

impl Policies for Picky {
    fn import(
        &self,
        _: &PeerInfo,
        _: AddressFamily,
        _: Prefix,
        _: &PathAttrs,
        _: RovState,
    ) -> Verdict {
        Verdict::Accept
    }

    fn export(
        &self,
        peer: &PeerInfo,
        _: AddressFamily,
        p: Prefix,
        attrs: &PathAttrs,
        _: RovState,
    ) -> Verdict {
        let octet = match p.addr() {
            IpAddr::V4(a) => a.octets()[2],
            IpAddr::V6(_) => 0,
        };
        let last = match peer.addr {
            IpAddr::V4(a) => a.octets()[3],
            IpAddr::V6(_) => 0,
        };
        match (octet + last + u8::from(self.0)) % 4 {
            0 => Verdict::Reject,
            1 => {
                let mut a = attrs.clone();
                a.communities = [Community::new(65_000, u16::from(octet))].into();
                Verdict::Modified(a)
            }
            _ => Verdict::Accept,
        }
    }
}

#[derive(Clone, Debug)]
enum Step {
    Announce {
        peer: u8,
        prefix: u8,
        path: Vec<u16>,
        med: Option<u32>,
    },
    Withdraw {
        peer: u8,
        prefix: u8,
    },
    Reset {
        peer: u8,
    },
    Policy(bool),
}

fn step() -> impl Strategy<Value = Step> {
    prop_oneof![
        6 => (0u8..4, 0u8..4, proptest::collection::vec(1u16..4, 0..3), proptest::option::of(0u32..2))
            .prop_map(|(peer, prefix, path, med)| Step::Announce { peer, prefix, path, med }),
        3 => (0u8..4, 0u8..4).prop_map(|(peer, prefix)| Step::Withdraw { peer, prefix }),
        1 => (0u8..4).prop_map(|peer| Step::Reset { peer }),
        1 => any::<bool>().prop_map(Step::Policy),
    ]
}

fn update(info: &PeerInfo, prefix: Prefix, path: &[u16], med: Option<u32>) -> DecodedUpdate {
    let mut asns: Vec<Asn> = path.iter().map(|a| Asn(u32::from(*a))).collect();
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
    if let Some(m) = med {
        attributes.push(PathAttribute::MultiExitDisc(m));
    }
    if info.kind == PeerKind::Internal {
        attributes.push(PathAttribute::LocalPref(100));
    }
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
            add_path: bgpfc_wire::update::AddPathFamilies::NONE,
        };
        for m in messages {
            let d = UpdateMessage::decode(&m[HEADER_LEN..], &ctx).unwrap();
            for (_, p) in d.withdrawals() {
                views[i].remove(&p);
            }
            for (_, next_hop, prefixes, _) in announced(&d) {
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
    fn what_peers_were_sent_is_what_the_rib_says_they_have(
        steps in proptest::collection::vec(step(), 0..24),
    ) {
        let infos = peers();
        let now = Instant::now();
        let mut rib = Rib::with_policies(LOCAL_AS, Box::new(Picky(false)));
        let mut views = vec![BTreeMap::new(); infos.len()];
        for (i, info) in infos.iter().enumerate() {
            let mut out = Vec::new();
            rib.peer_up(info.clone(), now, &mut out);
            views[i].clear();
            deliver(out, &infos, &mut views);
        }
        let everyone: Vec<IpAddr> = infos.iter().map(|p| p.addr).collect();
        for s in &steps {
            let mut out = Vec::new();
            match s {
                Step::Announce { peer, prefix: n, path, med } => {
                    let info = &infos[usize::from(*peer)];
                    rib.update(info.addr, &update(info, prefix(*n), path, *med), now, &mut out);
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
                }
                Step::Reset { peer } => {
                    // The session goes down and comes back: the peer
                    // starts from nothing and is sent the table again.
                    let i = usize::from(*peer);
                    rib.peer_down(infos[i].addr, now, &mut out);
                    views[i].clear();
                    deliver(std::mem::take(&mut out), &infos, &mut views);
                    views[i].clear();
                    rib.peer_up(infos[i].clone(), now, &mut out);
                }
                Step::Policy(which) => {
                    rib.set_policies(Box::new(Picky(*which)), &everyone, now, &mut out);
                }
            }
            deliver(out, &infos, &mut views);
        }
        for (i, info) in infos.iter().enumerate() {
            let expected: BTreeMap<Prefix, PathAttrs> = rib
                .adj_rib_out(info.addr, V4)
                .map(|(p, a)| (p, rewrite(LOCAL_AS, V4, &a, info)))
                .collect();
            prop_assert_eq!(&views[i], &expected, "peer {}", info.addr);
            let advertised = rib.peer_stats(info.addr).unwrap().advertised;
            prop_assert_eq!(advertised, vec![(V4, expected.len())]);
        }
    }
}

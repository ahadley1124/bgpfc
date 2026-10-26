//! Property: what a peer sent several paths (RFC 7911 §5) has received
//! over the wire is what the RIB says it has been sent, which is the
//! paths of each destination export policy lets through, all of them or
//! the `n` best by the decision process; each path keeps its identifier
//! while it is sent, and identifiers are unique per prefix.
//!
//! Random announcements, withdrawals, resets, route refreshes, policy
//! changes and changes of `n` run over three sources and two peers that
//! take paths. The UPDATEs each of those is sent are decoded with
//! ADD-PATH and applied to a table of its own, keyed by prefix and
//! identifier. Without pacing the table must equal the RIB's after every
//! step. With it, withdrawals still go at once and only announcements wait,
//! so the table never holds a path the RIB would not send, and holds all
//! of them once the intervals have passed.
#![cfg(not(miri))]

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use bgpfc_rib::attrs::announced;
use bgpfc_rib::decision::{Candidate, Neighbor, best};
use bgpfc_rib::export::rewrite;
use bgpfc_rib::{Output, PathAttrs, PathLimit, PeerInfo, Policies, Rib, RovState, Verdict};
use bgpfc_wire::as_path::AsPath;
use bgpfc_wire::attribute::{Origin, PathAttribute};
use bgpfc_wire::community::Community;
use bgpfc_wire::header::HEADER_LEN;
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::{AddressFamily, Asn, PathId, RouterId};
use bgpfc_wire::update::{
    AddPathFamilies, DecodeContext, DecodedUpdate, PathIds, PeerKind, UpdateMessage,
};
use proptest::prelude::*;

const LOCAL_AS: Asn = Asn(65_000);
const V4: AddressFamily = AddressFamily::IPV4_UNICAST;

/// Sources 0 and 1 send paths with identifiers, 2 does not; 3 and 4 are
/// sent several, 5 is sent the best path only.
const SOURCES: u8 = 3;
const TARGETS: std::ops::Range<u8> = 3..5;
const PEERS: u8 = 6;

fn peers(interval: Duration, limits: [PathLimit; 2]) -> Vec<PeerInfo> {
    (0..PEERS)
        .map(|i| PeerInfo {
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, i + 1)),
            local_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 254)),
            remote_as: Asn(65_001 + u32::from(i)),
            router_id: RouterId::new(u32::from(i) + 1).unwrap(),
            kind: PeerKind::External,
            families: vec![V4],
            receive_families: vec![V4],
            four_octet_as: true,
            extended_messages: false,
            extended_next_hop: Vec::new(),
            advertisement_interval: interval,
            prefix_limits: Vec::new(),
            add_path_receive: if i < 2 { vec![V4] } else { Vec::new() },
            add_path_send: match i {
                3 => vec![(V4, limits[0])],
                4 => vec![(V4, limits[1])],
                _ => Vec::new(),
            },
            role: None,
            restart: None,
            enhanced_refresh: None,
        })
        .collect()
}

fn prefix(i: u8) -> Prefix {
    Prefix::new(IpAddr::V4(Ipv4Addr::new(192, 0, i, 0)), 24).unwrap()
}

/// Export policy that depends on the prefix, the peer and a switch, so
/// that changing the switch changes which paths are sent: rejects some
/// prefixes, tags others, and passes the rest.
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
        // Some paths of a prefix only: the ones that come through an odd
        // last AS are held back from one switch setting.
        let odd = attrs
            .as_path
            .segments()
            .last()
            .and_then(|s| s.asns().last())
            .is_some_and(|a| a.0 % 2 == 1);
        match (octet + last + u8::from(self.0)) % 5 {
            0 => Verdict::Reject,
            1 if odd && self.0 => Verdict::Reject,
            2 => {
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
        path: u32,
        med: Option<u32>,
        hops: u16,
    },
    Withdraw {
        peer: u8,
        prefix: u8,
        path: u32,
    },
    Reset {
        peer: u8,
    },
    Refresh {
        peer: u8,
    },
    Policy(bool),
    Limit {
        peer: u8,
        limit: PathLimit,
    },
}

fn limit() -> impl Strategy<Value = PathLimit> {
    prop_oneof![Just(PathLimit::All), (1u32..4).prop_map(PathLimit::Best),]
}

fn step() -> impl Strategy<Value = Step> {
    prop_oneof![
        8 => (0..SOURCES, 0u8..3, 0u32..4, proptest::option::of(0u32..2), 0u16..3).prop_map(
            |(peer, prefix, path, med, hops)| Step::Announce {
                peer,
                prefix,
                path: if peer == 2 { 0 } else { path },
                med,
                hops,
            }
        ),
        4 => (0..SOURCES, 0u8..3, 0u32..4).prop_map(|(peer, prefix, path)| Step::Withdraw {
            peer,
            prefix,
            path: if peer == 2 { 0 } else { path },
        }),
        1 => (0..PEERS).prop_map(|peer| Step::Reset { peer }),
        1 => TARGETS.prop_map(|peer| Step::Refresh { peer }),
        1 => any::<bool>().prop_map(Step::Policy),
        1 => (TARGETS, limit()).prop_map(|(peer, limit)| Step::Limit { peer, limit }),
    ]
}

/// The AS ASN that tells a source's path apart: the source and the Path
/// Identifier it sent it with. Its attributes may change; this does not.
fn identity(peer: u8, path: u32) -> u16 {
    100 + u16::from(peer) * 10 + u16::try_from(path).unwrap()
}

fn announce(
    info: &PeerInfo,
    peer: u8,
    p: Prefix,
    path: u32,
    med: Option<u32>,
    hops: u16,
) -> DecodedUpdate {
    let mut asns = vec![info.remote_as];
    asns.extend((0..hops).map(|h| Asn(1 + u32::from(h))));
    asns.push(Asn(u32::from(identity(peer, path))));
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
    let with_ids = !info.add_path_receive.is_empty();
    DecodedUpdate {
        message: UpdateMessage {
            attributes,
            nlri: vec![p],
            path_ids: with_ids.then(|| {
                Box::new(PathIds {
                    nlri: vec![PathId(path)],
                    ..PathIds::default()
                })
            }),
            ..UpdateMessage::default()
        },
        treated_as_withdraw: None,
        discarded: Vec::new(),
        disabled: Vec::new(),
    }
}

fn withdraw(info: &PeerInfo, p: Prefix, path: u32) -> DecodedUpdate {
    let with_ids = !info.add_path_receive.is_empty();
    DecodedUpdate {
        message: UpdateMessage {
            withdrawn: vec![p],
            path_ids: with_ids.then(|| {
                Box::new(PathIds {
                    withdrawn: vec![PathId(path)],
                    ..PathIds::default()
                })
            }),
            ..UpdateMessage::default()
        },
        treated_as_withdraw: None,
        discarded: Vec::new(),
        disabled: Vec::new(),
    }
}

/// What a peer has received: its table of paths by prefix and identifier,
/// from the UPDATEs it was sent.
type View = BTreeMap<(Prefix, u32), PathAttrs>;

/// Apply what the RIB asked to send to each peer to that peer's table.
fn deliver(out: Vec<Output>, infos: &[PeerInfo], views: &mut [View]) {
    for o in out {
        let Output::Send { peer, messages } = o else {
            continue;
        };
        let i = infos.iter().position(|p| p.addr == peer).unwrap();
        let with_ids = infos[i].path_limit(V4).is_some();
        let ctx = DecodeContext {
            four_octet_as: true,
            peer: infos[i].kind,
            allow_as_set: false,
            extended_next_hop: false,
            add_path: if with_ids {
                AddPathFamilies::of(&[V4])
            } else {
                AddPathFamilies::NONE
            },
        };
        for m in messages {
            assert!(m.len() <= infos[i].max_message_len());
            let d = UpdateMessage::decode(&m[HEADER_LEN..], &ctx).unwrap();
            for (_, p, id) in d.withdrawn_paths() {
                // RFC 7911 §5: withdrawing what it does not have is
                // ignored, but the RIB never sends that.
                assert!(
                    views[i].remove(&(p, id.0)).is_some(),
                    "peer {}: withdrew {p} path {id} it has not been sent",
                    infos[i].addr
                );
            }
            for (_, next_hop, prefixes, ids) in announced(&d) {
                for (k, &p) in prefixes.iter().enumerate() {
                    let id = ids.get(k).map_or(0, |i| i.0);
                    views[i].insert((p, id), PathAttrs::from_update(&d.message, next_hop));
                }
            }
        }
    }
}

/// The identity of a path: the last ASN of its AS path.
fn who(a: &PathAttrs) -> u32 {
    a.as_path
        .segments()
        .last()
        .and_then(|s| s.asns().last())
        .map_or(0, |a| a.0)
}

/// What the RIB should have sent `target` of `prefix`, worked out from the
/// candidates alone: those not from `target` itself that the policy
/// accepts, and of them all or the `n` best, repeatedly by the decision
/// process. As the attributes `rewrite` would send, and with them the
/// identities of every path export lets through, which a peer may still
/// have while the interval holds the `n` best back.
fn expected(
    rib: &Rib,
    infos: &[PeerInfo],
    policy: &Picky,
    target: &PeerInfo,
    p: Prefix,
) -> (Vec<PathAttrs>, Vec<u32>) {
    let mut open: Vec<(usize, PathAttrs)> = Vec::new();
    let candidates = rib.candidates(V4, p);
    for (k, c) in candidates.iter().enumerate() {
        if c.peer == target.addr {
            continue;
        }
        match policy.export(target, V4, p, c.attrs, c.rov) {
            Verdict::Reject => {}
            Verdict::Accept | Verdict::Restated(_) => open.push((k, (**c.attrs).clone())),
            Verdict::Modified(a) | Verdict::ModifiedRestated(a, _) => open.push((k, a)),
        }
    }
    let exportable = open.iter().map(|(_, a)| who(a)).collect();
    if let Some(PathLimit::Best(n)) = target.path_limit(V4) {
        let n = usize::try_from(n).unwrap();
        let mut picked = Vec::new();
        while picked.len() < n && !open.is_empty() {
            let at = best(open.len(), |j| {
                let c = &candidates[open[j].0];
                let info = infos.iter().find(|i| i.addr == c.peer).unwrap();
                Candidate {
                    from: Neighbor::of(info),
                    attrs: c.attrs,
                    path_id: c.path_id.map_or(0, |i| i.0),
                    demoted: false,
                }
            })
            .unwrap();
            picked.push(open.swap_remove(at));
        }
        open = picked;
    }
    let chosen = open
        .into_iter()
        .map(|(_, a)| rewrite(LOCAL_AS, V4, &a, target))
        .collect();
    (chosen, exportable)
}

/// A canonical order for a list of attribute sets.
fn sorted(mut v: Vec<PathAttrs>) -> Vec<String> {
    let mut s: Vec<String> = v.drain(..).map(|a| format!("{a:?}")).collect();
    s.sort();
    s
}

/// The checks that hold at any time, with the RIB's own record of what
/// each target was sent: ids are non-zero and unique per prefix, the wire
/// view is what the RIB has, and counts add up.
fn check_views(rib: &Rib, infos: &[PeerInfo], views: &[View]) -> Result<(), TestCaseError> {
    for i in TARGETS {
        let info = &infos[usize::from(i)];
        let sent = rib.sent_paths(info.addr, V4);
        let mut seen = BTreeSet::new();
        for (p, id, _) in &sent {
            prop_assert!(id.0 != 0, "{p}: identifier zero");
            prop_assert!(seen.insert((*p, id.0)), "{p}: identifier {id} twice");
        }
        let wire: View = sent
            .iter()
            .map(|(p, id, a)| ((*p, id.0), rewrite(LOCAL_AS, V4, a, info)))
            .collect();
        prop_assert_eq!(&views[usize::from(i)], &wire, "peer {}", info.addr);
        let advertised = rib.peer_stats(info.addr).unwrap().advertised;
        prop_assert_eq!(advertised, vec![(V4, sent.len())]);
    }
    Ok(())
}

/// A RIB, the peers it has, what each has received and the time.
struct World {
    infos: Vec<PeerInfo>,
    rib: Rib,
    policy: Picky,
    views: Vec<View>,
    now: Instant,
}

impl World {
    fn new(interval: Duration, limits: [PathLimit; 2]) -> World {
        let infos = peers(interval, limits);
        let now = Instant::now();
        let mut rib = Rib::with_policies(LOCAL_AS, Box::new(Picky(false)));
        let mut views: Vec<View> = vec![BTreeMap::new(); infos.len()];
        for (i, info) in infos.iter().enumerate() {
            let mut out = Vec::new();
            rib.peer_up(info.clone(), now, &mut out);
            views[i].clear();
            deliver(out, &infos, &mut views);
        }
        World {
            infos,
            rib,
            policy: Picky(false),
            views,
            now,
        }
    }

    /// Do one step, and what the RIB sends meanwhile; the target whose
    /// session came up afresh, if any.
    fn step(&mut self, s: &Step) -> Option<usize> {
        let (now, mut out) = (self.now, Vec::new());
        let mut fresh = None;
        match s {
            Step::Announce {
                peer,
                prefix: n,
                path,
                med,
                hops,
            } => {
                let info = &self.infos[usize::from(*peer)];
                let u = announce(info, *peer, prefix(*n), *path, *med, *hops);
                self.rib.update(info.addr, &u, now, &mut out);
            }
            Step::Withdraw {
                peer,
                prefix: n,
                path,
            } => {
                let info = &self.infos[usize::from(*peer)];
                let u = withdraw(info, prefix(*n), *path);
                self.rib.update(info.addr, &u, now, &mut out);
            }
            Step::Reset { peer } => {
                let i = usize::from(*peer);
                self.rib.peer_down(self.infos[i].addr, now, &mut out);
                self.views[i].clear();
                deliver(std::mem::take(&mut out), &self.infos, &mut self.views);
                self.views[i].clear();
                self.rib.peer_up(self.infos[i].clone(), now, &mut out);
                fresh = Some(i);
            }
            Step::Refresh { peer } => {
                let addr = self.infos[usize::from(*peer)].addr;
                self.rib.refresh(addr, V4, now, &mut out);
            }
            Step::Policy(which) => {
                self.policy = Picky(*which);
                let everyone: Vec<IpAddr> = self.infos.iter().map(|p| p.addr).collect();
                self.rib
                    .set_policies(Box::new(Picky(*which)), &everyone, now, &mut out);
            }
            Step::Limit { peer, limit } => {
                let i = usize::from(*peer);
                self.infos[i].add_path_send = vec![(V4, *limit)];
                let addr = self.infos[i].addr;
                self.rib
                    .set_add_path_limits(addr, &[(V4, *limit)], now, &mut out);
            }
        }
        self.rib.flush(now, &mut out);
        deliver(out, &self.infos, &mut self.views);
        fresh
    }

    /// The identifier of every path sent, by prefix, target and identity.
    fn identifiers(&self) -> BTreeMap<(Prefix, usize, u32), u32> {
        let mut ids = BTreeMap::new();
        for i in TARGETS {
            for (p, id, a) in self.rib.sent_paths(self.infos[usize::from(i)].addr, V4) {
                ids.insert((p, usize::from(i), who(&a)), id.0);
            }
        }
        ids
    }

    /// Paced, the paths wait but are never wrong: a path the RIB would not
    /// send at all is withdrawn at once, one it would send but for the `n`
    /// best may linger until its replacement goes.
    fn nothing_wrong(&self) -> Result<(), TestCaseError> {
        for i in TARGETS {
            let info = &self.infos[usize::from(i)];
            for n in 0..3u8 {
                let (_, exportable) =
                    expected(&self.rib, &self.infos, &self.policy, info, prefix(n));
                for (p, _, a) in self.rib.sent_paths(info.addr, V4) {
                    prop_assert!(
                        p != prefix(n) || exportable.contains(&who(&a)),
                        "peer {} prefix {} still has {}",
                        info.addr,
                        n,
                        who(&a)
                    );
                }
            }
        }
        Ok(())
    }
}

/// Every step of one run, with the checks that follow it.
fn run(
    steps: &[Step],
    limits: [PathLimit; 2],
    interval: Duration,
    pause: &[u64],
) -> Result<(), TestCaseError> {
    let mut w = World::new(interval, limits);
    let mut before = BTreeMap::new();
    for (n, s) in steps.iter().enumerate() {
        w.now += Duration::from_secs(pause.get(n).copied().unwrap_or(0));
        let fresh = w.step(s);
        // A path that was sent before and is again keeps its identifier.
        let after = w.identifiers();
        for (key @ (_, target, identity), id) in &after {
            if fresh != Some(*target)
                && let Some(old) = before.get(key)
            {
                prop_assert_eq!(old, id, "{}: identifier changed", identity);
            }
        }
        before = after;
        // What the peer has been sent is what it received, always.
        check_views(&w.rib, &w.infos, &w.views)?;
        if interval.is_zero() {
            same_as_expected(&w.rib, &w.infos, &w.policy)?;
        } else {
            w.nothing_wrong()?;
        }
    }
    if !interval.is_zero() {
        // Let every interval end: then it is what it would have been.
        w.now += Duration::from_secs(3_600);
        let mut out = Vec::new();
        w.rib.flush(w.now, &mut out);
        deliver(out, &w.infos, &mut w.views);
        check_views(&w.rib, &w.infos, &w.views)?;
        same_as_expected(&w.rib, &w.infos, &w.policy)?;
    }
    Ok(())
}

/// Every target has been sent what is expected of each prefix.
fn same_as_expected(rib: &Rib, infos: &[PeerInfo], policy: &Picky) -> Result<(), TestCaseError> {
    for i in TARGETS {
        let info = &infos[usize::from(i)];
        for n in 0..3u8 {
            let want = sorted(expected(rib, infos, policy, info, prefix(n)).0);
            let got = sorted(
                rib.sent_paths(info.addr, V4)
                    .into_iter()
                    .filter(|(p, ..)| *p == prefix(n))
                    .map(|(_, _, a)| rewrite(LOCAL_AS, V4, &a, info))
                    .collect(),
            );
            prop_assert_eq!(got, want, "peer {} prefix {}", info.addr, n);
        }
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn what_a_peer_sent_paths_has_is_what_the_rib_says_and_what_policy_and_n_allow(
        steps in proptest::collection::vec(step(), 0..30),
        limits in [limit(), limit()],
    ) {
        run(&steps, limits, Duration::ZERO, &[])?;
    }

    #[test]
    fn pacing_delays_announcements_of_paths_never_withdrawals(
        steps in proptest::collection::vec(step(), 0..30),
        limits in [limit(), limit()],
        pause in proptest::collection::vec(0u64..4, 30),
    ) {
        run(&steps, limits, Duration::from_secs(5), &pause)?;
    }
}

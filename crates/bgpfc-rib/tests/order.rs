//! Loc-RIB is a function of the Adj-RIBs-In alone: whatever order the
//! same announcements and withdrawals arrive in, the best routes and the
//! final Adj-RIBs-Out are the same (AGENTS.md §5, `bgpfc-rib` row). With
//! policy that acts on the validation state, it is a function of the
//! Adj-RIBs-In, policy and the current validation source, whatever the
//! interleaving of UPDATEs and validation changes (RFC 6811 §4). The FIB
//! changes on the way chain up to the same routes.
#![cfg(not(miri))]

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bgpfc_rib::{Output, PathAttrs, PeerInfo, Policies, Rib, RovState, Verdict};
use bgpfc_rpki::{AffectedPrefixes, InvalidAction, ValidationChange, Vrp, VrpSet};
use bgpfc_wire::as_path::AsPath;
use bgpfc_wire::attribute::{Origin, PathAttribute};
use bgpfc_wire::community::Community;
use bgpfc_wire::prefix::Prefix;
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
            receive_families: vec![V4],
            four_octet_as: true,
            extended_messages: false,
            extended_next_hop: Vec::new(),
            // Unpaced, so the Adj-RIBs-Out are final after the last step;
            // tests/pacing.rs covers the paced case.
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
        disabled: Vec::new(),
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
/// On the way, checks that the FIB changes chain: each names as previous
/// the next hop the one before gave the prefix, and together they end at
/// the routes a full reconcile gets.
fn run(steps: &[Step]) -> (Vec<(Prefix, IpAddr)>, Vec<Vec<Prefix>>) {
    let infos = peers();
    let now = Instant::now();
    let mut rib = Rib::new(LOCAL_AS);
    for info in &infos {
        outputs(|o| rib.peer_up(info.clone(), now, o));
    }
    let mut fib = BTreeMap::new();
    for s in steps {
        let info = &infos[usize::from(s.peer)];
        for o in outputs(|o| rib.update(info.addr, &update(s, info), now, o)) {
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

/// Policy that acts on the validation state, so that the Loc-RIB and the
/// Adj-RIBs-Out depend on it: import rejects Invalid routes and prefers
/// Valid ones; export tags Valid routes.
struct ByState;

impl Policies for ByState {
    fn import(
        &self,
        _: &PeerInfo,
        _: AddressFamily,
        _: Prefix,
        a: &PathAttrs,
        rov: RovState,
    ) -> Verdict {
        match rov {
            RovState::Invalid => Verdict::Reject,
            RovState::Valid => {
                let mut a = a.clone();
                a.local_pref = Some(300);
                Verdict::Modified(a)
            }
            RovState::NotFound | RovState::Disabled => Verdict::Accept,
        }
    }

    fn export(
        &self,
        _: &PeerInfo,
        _: AddressFamily,
        _: Prefix,
        a: &PathAttrs,
        rov: RovState,
    ) -> Verdict {
        if rov != RovState::Valid {
            return Verdict::Accept;
        }
        let mut a = a.clone();
        a.communities = a
            .communities
            .iter()
            .copied()
            .chain([Community::new(65_000, 1)])
            .collect();
        a.normalise();
        Verdict::Modified(a)
    }
}

/// Policy that sets the validation state too (RFC 6811 §3), from the
/// lookup and the route: an Invalid route with a MED is taken as Valid,
/// one without is rejected; a `NotFound` route from the Egp origin is
/// taken as Invalid, which export then keeps from every peer.
struct Setter;

impl Policies for Setter {
    fn import(
        &self,
        _: &PeerInfo,
        _: AddressFamily,
        _: Prefix,
        a: &PathAttrs,
        rov: RovState,
    ) -> Verdict {
        match rov {
            RovState::Invalid if a.med.is_some() => {
                let mut a = a.clone();
                a.local_pref = Some(250);
                Verdict::ModifiedRestated(a, RovState::Valid)
            }
            RovState::Invalid => Verdict::Reject,
            RovState::NotFound if a.origin == Origin::Egp => Verdict::Restated(RovState::Invalid),
            RovState::Valid => {
                let mut a = a.clone();
                a.local_pref = Some(300);
                Verdict::Modified(a)
            }
            RovState::NotFound | RovState::Disabled => Verdict::Accept,
        }
    }

    fn export(
        &self,
        peer: &PeerInfo,
        family: AddressFamily,
        prefix: Prefix,
        a: &PathAttrs,
        rov: RovState,
    ) -> Verdict {
        match rov {
            RovState::Invalid => Verdict::Reject,
            other => ByState.export(peer, family, prefix, a, other),
        }
    }
}

/// Policy that leaves Invalid routes in the decision process with a degree
/// of preference far above the others, so that whether the RIB demotes
/// them decides which route is best; export tags what is Valid.
struct FavourInvalid;

impl Policies for FavourInvalid {
    fn import(
        &self,
        _: &PeerInfo,
        _: AddressFamily,
        _: Prefix,
        a: &PathAttrs,
        rov: RovState,
    ) -> Verdict {
        if rov != RovState::Invalid {
            return Verdict::Accept;
        }
        let mut a = a.clone();
        a.local_pref = Some(500);
        Verdict::Modified(a)
    }

    fn export(
        &self,
        peer: &PeerInfo,
        family: AddressFamily,
        prefix: Prefix,
        a: &PathAttrs,
        rov: RovState,
    ) -> Verdict {
        ByState.export(peer, family, prefix, a, rov)
    }
}

/// How a test builds its RIB: its policies, and what it does with
/// Invalid routes by itself.
type Setup = (fn() -> Box<dyn Policies>, InvalidAction);

/// A VRP over the prefixes the steps use: one of them, or 192.0.0.0/16
/// (index 3) which covers all three, with a maximum length that may be
/// too short for them, for an AS the paths use.
fn vrp() -> impl Strategy<Value = Vrp> {
    (
        0u8..4,
        any::<bool>(),
        prop_oneof![1u32..5, Just(65_001), Just(65_002), Just(LOCAL_AS.0)],
    )
        .prop_map(|(i, short, asn)| {
            let (prefix, len) = if i == 3 {
                (
                    Prefix::new(IpAddr::V4(Ipv4Addr::new(192, 0, 0, 0)), 16).unwrap(),
                    16,
                )
            } else {
                (prefix(i), 24)
            };
            let max_len = if short { len } else { 24 };
            Vrp::new(prefix, max_len, Asn(asn)).unwrap()
        })
}

/// What a RIB ends with: each destination's candidates (peer, state,
/// attributes), its best route, and each peer's Adj-RIB-Out.
type Outcome = (
    Vec<Vec<(IpAddr, RovState, PathAttrs)>>,
    Vec<(Prefix, IpAddr, RovState)>,
    Vec<Vec<(Prefix, PathAttrs)>>,
);

fn outcome(rib: &Rib, infos: &[PeerInfo]) -> Outcome {
    let candidates = (0..3)
        .map(|i| {
            let mut c: Vec<_> = rib
                .candidates(V4, prefix(i))
                .iter()
                .map(|c| (c.peer, c.rov, (**c.attrs).clone()))
                .collect();
            c.sort_by_key(|c| c.0);
            c
        })
        .collect();
    let best = rib.loc_rib(V4).map(|(p, b)| (p, b.peer, b.rov)).collect();
    let outs = infos
        .iter()
        .map(|i| {
            let mut v: Vec<_> = rib
                .adj_rib_out(i.addr, V4)
                .map(|(p, a)| (p, (*a).clone()))
                .collect();
            v.sort_by_key(|e| e.0);
            v
        })
        .collect();
    (candidates, best, outs)
}

/// Apply `steps` with the validation sources `sources` given in order
/// between them: source `k` after the first `at[k]` steps. The first
/// change affects every route, as one from the null source must; each
/// later one only the prefixes its VRPs differ in from the last, and a
/// change marked in `merged` is held back and given together with the
/// next, as a consumer that fell behind would (`ValidationChange`).
fn interleaved(
    steps: &[Step],
    sources: &[VrpSet],
    at: &[usize],
    merged: &[bool],
    (policies, action): Setup,
) -> Outcome {
    let infos = peers();
    let now = Instant::now();
    let mut rib = Rib::with_policies(LOCAL_AS, policies());
    rib.set_invalid_action(action, now, &mut Vec::new());
    for info in &infos {
        outputs(|o| rib.peer_up(info.clone(), now, o));
    }
    let mut pending: Option<AffectedPrefixes> = None;
    let mut next = 0;
    let mut give = |rib: &mut Rib, k: usize| {
        let mut affected = if k == 0 {
            AffectedPrefixes::All
        } else {
            AffectedPrefixes::between(&sources[k - 1], &sources[k])
        };
        if let Some(earlier) = pending.take() {
            affected.merge(earlier);
        }
        if merged[k] && k + 1 < sources.len() {
            pending = Some(affected);
            return;
        }
        outputs(|o| {
            rib.validation_changed(
                ValidationChange {
                    source: Arc::new(sources[k].clone()),
                    affected,
                },
                now,
                o,
            );
        });
    };
    for (i, s) in steps.iter().enumerate() {
        while next < sources.len() && at[next] <= i {
            give(&mut rib, next);
            next += 1;
        }
        let info = &infos[usize::from(s.peer)];
        outputs(|o| rib.update(info.addr, &update(s, info), now, o));
    }
    while next < sources.len() {
        give(&mut rib, next);
        next += 1;
    }
    outcome(&rib, &infos)
}

/// The final validation source first, then the decisive steps.
fn source_first(steps: &[Step], source: Option<&VrpSet>, (policies, action): Setup) -> Outcome {
    let infos = peers();
    let now = Instant::now();
    let mut rib = Rib::with_policies(LOCAL_AS, policies());
    rib.set_invalid_action(action, now, &mut Vec::new());
    if let Some(source) = source {
        outputs(|o| {
            rib.validation_changed(
                ValidationChange {
                    source: Arc::new(source.clone()),
                    affected: AffectedPrefixes::All,
                },
                now,
                o,
            );
        });
    }
    for info in &infos {
        outputs(|o| rib.peer_up(info.clone(), now, o));
    }
    for s in steps {
        let info = &infos[usize::from(s.peer)];
        outputs(|o| rib.update(info.addr, &update(s, info), now, o));
    }
    outcome(&rib, &infos)
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

/// The check of `loc_rib_follows_the_validation_source_in_any_interleaving`
/// for the policies `policies` builds.
fn follows_the_source(
    steps: &[Step],
    sources: Vec<Vec<Vrp>>,
    at: &[usize],
    merged: &[bool],
    seed: u64,
    setup: Setup,
) -> Result<(), TestCaseError> {
    let sources: Vec<VrpSet> = sources
        .into_iter()
        .map(|v| v.into_iter().collect())
        .collect();
    let mut at = at[..sources.len()].to_vec();
    at.sort_unstable();
    let got = interleaved(steps, &sources, &at, merged, setup);
    if setup.1.demotes() {
        // RFC 6811 §5: an Invalid route is chosen only when no other is.
        for (i, candidates) in got.0.iter().enumerate() {
            let best = got
                .1
                .iter()
                .find(|b| b.0 == prefix(u8::try_from(i).unwrap()));
            let all_invalid = candidates.iter().all(|c| c.1 == RovState::Invalid);
            prop_assert_eq!(best.is_some(), !candidates.is_empty());
            if let Some(best) = best {
                prop_assert!(best.2 != RovState::Invalid || all_invalid, "{best:?}");
            }
        }
    }
    let mut decisive = last_words(steps);
    shuffle(&mut decisive, seed);
    let expected = source_first(&decisive, sources.last(), setup);
    prop_assert_eq!(got, expected);
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn loc_rib_follows_the_validation_source_in_any_interleaving(
        steps in proptest::collection::vec(step(), 0..12),
        sources in proptest::collection::vec(
            proptest::collection::vec(vrp(), 0..4),
            0..4,
        ),
        at in proptest::collection::vec(0usize..13, 4),
        merged in proptest::collection::vec(any::<bool>(), 4),
        seed in any::<u64>(),
    ) {
        follows_the_source(
            &steps, sources, &at, &merged, seed,
            (|| Box::new(ByState), InvalidAction::Policy),
        )?;
    }

    /// The same, with policy that sets the state of the routes it
    /// accepts: the state a route holds is a function of its lookup and
    /// policy, so the lookup is what the source's changes are compared
    /// with (RFC 6811 §3, §4).
    #[test]
    fn loc_rib_follows_the_validation_source_when_policy_sets_states(
        steps in proptest::collection::vec(step(), 0..12),
        sources in proptest::collection::vec(
            proptest::collection::vec(vrp(), 0..4),
            0..4,
        ),
        at in proptest::collection::vec(0usize..13, 4),
        merged in proptest::collection::vec(any::<bool>(), 4),
        seed in any::<u64>(),
    ) {
        follows_the_source(
            &steps, sources, &at, &merged, seed,
            (|| Box::new(Setter), InvalidAction::Policy),
        )?;
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// The same, with Invalid routes kept as candidates and the RIB
    /// demoting them (RFC 6811 §5): which route is best depends on the
    /// states, and so on the source, never on the order things happened.
    #[test]
    fn loc_rib_follows_the_validation_source_when_invalid_routes_are_demoted(
        steps in proptest::collection::vec(step(), 0..12),
        sources in proptest::collection::vec(
            proptest::collection::vec(vrp(), 0..4),
            0..4,
        ),
        at in proptest::collection::vec(0usize..13, 4),
        merged in proptest::collection::vec(any::<bool>(), 4),
        seed in any::<u64>(),
    ) {
        follows_the_source(
            &steps, sources, &at, &merged, seed,
            (|| Box::new(FavourInvalid), InvalidAction::PreferValid),
        )?;
    }
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
        shuffle(&mut shuffled, seed);
        let other = run(&shuffled);
        prop_assert_eq!(reference, other);
    }
}

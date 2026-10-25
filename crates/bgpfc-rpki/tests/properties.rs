//! Property tests: `VrpSet` against a naive model that follows the text of
//! RFC 6811 §2 and the §2.1 pseudo-code literally, one VRP at a time; and
//! `AffectedPrefixes` against the states that actually change (RFC 6811
//! §4); and a RIB-like consumer of `ValidationChange`s that validates only
//! the affected routes against one that validates everything.
#![cfg(not(miri))]

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use bgpfc_rpki::{
    AffectedPrefixes, AspaState, NullSource, PrefixSet, RouteOrigin, RovState, RpkiError,
    ValidationChange, ValidationSink, ValidationSource, Vrp, VrpSet,
};
use bgpfc_wire::as_path::{AsPath, AsPathSegment, SegmentType};
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::Asn;
use proptest::prelude::*;

/// IPv4 prefixes from a small pool, so that VRPs and routes nest often:
/// the address varies in two bits at each of three positions.
fn v4_prefix() -> impl Strategy<Value = Prefix> {
    (0u32..4, 0u32..4, 0u32..4, 0u8..=32).prop_map(|(a, b, c, len)| {
        let addr = 0xc000_0000 | a << 24 | b << 12 | c;
        Prefix::new(IpAddr::V4(Ipv4Addr::from(addr)), len).unwrap()
    })
}

/// IPv6 prefixes from a small pool, as [`v4_prefix`].
fn v6_prefix() -> impl Strategy<Value = Prefix> {
    (0u128..4, 0u128..4, 0u128..4, 0u8..=128).prop_map(|(a, b, c, len)| {
        let addr = 0x2001_0db8_u128 << 96 | a << 90 | b << 60 | c << 2;
        Prefix::new(IpAddr::V6(Ipv6Addr::from(addr)), len).unwrap()
    })
}

fn prefix() -> impl Strategy<Value = Prefix> {
    prop_oneof![v4_prefix(), v6_prefix()]
}

fn address_bits(prefix: Prefix) -> u8 {
    match prefix {
        Prefix::V4 { .. } => 32,
        Prefix::V6 { .. } => 128,
    }
}

/// A few origin ASes, and AS 0 (RFC 6483 §4).
fn asn() -> impl Strategy<Value = Asn> {
    prop_oneof![Just(Asn(0)), (64_496u32..64_499).prop_map(Asn)]
}

fn vrp() -> impl Strategy<Value = Vrp> {
    (prefix(), 0u8..=10, any::<bool>(), asn()).prop_map(|(prefix, extra, full, asn)| {
        let bits = address_bits(prefix);
        let max_len = if full {
            bits
        } else {
            prefix.prefix_len().saturating_add(extra).min(bits)
        };
        Vrp::new(prefix, max_len, asn).unwrap()
    })
}

fn origin() -> impl Strategy<Value = RouteOrigin> {
    prop_oneof![
        Just(RouteOrigin::None),
        Just(RouteOrigin::As(Asn(0))),
        (64_496u32..64_499).prop_map(|a| RouteOrigin::As(Asn(a))),
    ]
}

fn route() -> impl Strategy<Value = (Prefix, RouteOrigin)> {
    (prefix(), origin())
}

fn as_path() -> impl Strategy<Value = AsPath> {
    let segment =
        (1u8..=4, prop::collection::vec(0u32..4, 1..4)).prop_map(|(kind, asns)| AsPathSegment {
            kind: SegmentType::from_u8(kind).unwrap(),
            asns: asns.into_iter().map(|a| Asn(64_496 + a)).collect(),
        });
    prop::collection::vec(segment, 0..4).prop_map(|segments| AsPath::from_segments(&segments))
}

/// One step of a validation producer.
#[derive(Clone, Debug)]
enum Step {
    /// Announce (`true`) or withdraw VRPs, as one RTR update would.
    Delta(Vec<(bool, Vrp)>),
    /// Turn validation off.
    Disable,
}

fn step() -> impl Strategy<Value = Step> {
    prop_oneof![
        8 => prop::collection::vec((any::<bool>(), vrp()), 0..8).prop_map(Step::Delta),
        1 => Just(Step::Disable),
    ]
}

/// A producer in the manner of an RTR client: applies each step to its own
/// working set and publishes a snapshot with the routes the step affects.
fn produce(steps: &[Step], sink: &mut dyn ValidationSink) -> Result<(), RpkiError> {
    let mut working = VrpSet::new();
    let mut enabled = false;
    for step in steps {
        match step {
            Step::Disable => {
                enabled = false;
                sink.publish(ValidationChange::disabled())?;
            }
            Step::Delta(ops) => {
                let mut changed = Vec::new();
                for (announce, vrp) in ops {
                    let did = if *announce {
                        working.insert(*vrp)
                    } else {
                        working.remove(*vrp)
                    };
                    if did {
                        changed.push(*vrp);
                    }
                }
                // Coming back from Disabled every route's state changes.
                let affected = if enabled {
                    AffectedPrefixes::from_vrps(changed)
                } else {
                    AffectedPrefixes::All
                };
                enabled = true;
                sink.publish(ValidationChange {
                    source: Arc::new(working.clone()),
                    affected,
                })?;
            }
        }
    }
    Ok(())
}

/// Bit `i` of an address, most significant first.
fn bit(octets: &[u8], i: usize) -> bool {
    octets[i / 8] >> (7 - i % 8) & 1 == 1
}

/// RFC 6811 §2, "Covered", read literally.
fn covers(vrp_prefix: Prefix, route: Prefix) -> bool {
    let (vrp_bits, route_bits) = match (vrp_prefix.addr(), route.addr()) {
        (IpAddr::V4(a), IpAddr::V4(b)) => (a.octets().to_vec(), b.octets().to_vec()),
        (IpAddr::V6(a), IpAddr::V6(b)) => (a.octets().to_vec(), b.octets().to_vec()),
        _ => return false,
    };
    vrp_prefix.prefix_len() <= route.prefix_len()
        && (0..usize::from(vrp_prefix.prefix_len()))
            .all(|i| bit(&vrp_bits, i) == bit(&route_bits, i))
}

/// The RFC 6811 §2.1 pseudo-code over a plain list.
fn model(vrps: &[Vrp], route: Prefix, origin: RouteOrigin) -> RovState {
    let mut result = RovState::NotFound;
    for entry in vrps.iter().filter(|v| covers(v.prefix(), route)) {
        result = RovState::Invalid;
        if route.prefix_len() <= entry.max_len()
            && let RouteOrigin::As(origin) = origin
            && entry.asn() != Asn(0)
            && origin == entry.asn()
        {
            return RovState::Valid;
        }
    }
    result
}

/// Routes at the edges of each VRP: its own prefix, and the prefix
/// stretched to the maximum length and one past it, from its own AS.
fn edge_routes(vrps: &[Vrp]) -> Vec<(Prefix, RouteOrigin)> {
    let mut routes = Vec::new();
    for vrp in vrps {
        let origin = RouteOrigin::As(vrp.asn());
        routes.push((vrp.prefix(), origin));
        for len in [vrp.max_len(), vrp.max_len().saturating_add(1)] {
            if let Some(p) = Prefix::new(vrp.prefix().addr(), len) {
                routes.push((p, origin));
            }
        }
    }
    routes
}

proptest! {
    #[test]
    fn validate_follows_the_rfc_procedure(
        vrps in prop::collection::vec(vrp(), 0..48),
        routes in prop::collection::vec(route(), 1..48),
    ) {
        let set: VrpSet = vrps.iter().copied().collect();
        for (prefix, origin) in routes.into_iter().chain(edge_routes(&vrps)) {
            prop_assert_eq!(
                set.validate(prefix, origin),
                model(&vrps, prefix, origin),
                "{} from {}", prefix, origin
            );
        }
    }

    #[test]
    fn insert_and_remove_track_a_model(
        pool in prop::collection::vec(vrp(), 1..16),
        ops in prop::collection::vec((any::<bool>(), any::<prop::sample::Index>()), 0..96),
        routes in prop::collection::vec(route(), 1..32),
    ) {
        let mut set = VrpSet::new();
        let mut model_set = BTreeSet::new();
        for (insert, index) in ops {
            let vrp = *index.get(&pool);
            if insert {
                prop_assert_eq!(set.insert(vrp), model_set.insert(vrp));
            } else {
                prop_assert_eq!(set.remove(vrp), model_set.remove(&vrp));
            }
            prop_assert_eq!(set.len(), model_set.len());
            prop_assert_eq!(set.is_empty(), model_set.is_empty());
        }
        let mut listed: Vec<Vrp> = set.iter().collect();
        listed.sort();
        let expected: Vec<Vrp> = model_set.iter().copied().collect();
        prop_assert_eq!(&listed, &expected);
        for vrp in &pool {
            prop_assert_eq!(set.contains(*vrp), model_set.contains(vrp));
        }
        prop_assert_eq!(&set, &expected.iter().copied().collect::<VrpSet>());
        // Removals must leave no stale entries behind: the lookups agree
        // with a set built from scratch.
        for (prefix, origin) in routes.into_iter().chain(edge_routes(&pool)) {
            prop_assert_eq!(set.validate(prefix, origin), model(&expected, prefix, origin));
        }
    }

    #[test]
    fn prefix_set_covers_per_the_definition(
        prefixes in prop::collection::vec(prefix(), 0..32),
        routes in prop::collection::vec(prefix(), 1..48),
    ) {
        let set: PrefixSet = prefixes.iter().copied().collect();
        let distinct: BTreeSet<Prefix> = prefixes.iter().copied().collect();
        prop_assert_eq!(set.len(), distinct.len());
        prop_assert_eq!(set.iter().collect::<BTreeSet<_>>(), distinct);
        for route in routes.into_iter().chain(prefixes.iter().copied()) {
            prop_assert_eq!(
                set.covers(route),
                prefixes.iter().any(|p| covers(*p, route)),
                "{}", route
            );
        }
    }

    #[test]
    fn affected_prefixes_cover_every_route_that_changes_state(
        old in prop::collection::vec(vrp(), 0..32),
        keep in prop::collection::vec(any::<bool>(), 32),
        added in prop::collection::vec(vrp(), 0..16),
        routes in prop::collection::vec(prefix(), 1..48),
    ) {
        // The new set keeps some of the old VRPs and adds others, so the
        // two overlap the way consecutive RTR snapshots do.
        let old_set: VrpSet = old.iter().copied().collect();
        let new_set: VrpSet = old
            .iter()
            .zip(&keep)
            .filter(|(_, keep)| **keep)
            .map(|(vrp, _)| *vrp)
            .chain(added.iter().copied())
            .collect();
        let delta: Vec<Vrp> = old_set
            .iter()
            .filter(|vrp| !new_set.contains(*vrp))
            .chain(new_set.iter().filter(|vrp| !old_set.contains(*vrp)))
            .collect();
        let between = AffectedPrefixes::between(&old_set, &new_set);
        let from_delta = AffectedPrefixes::from_vrps(delta.iter().copied());

        // Exactly the prefixes of the VRPs that changed, from either side.
        let changed: PrefixSet = delta.iter().map(Vrp::prefix).collect();
        prop_assert_eq!(&between, &AffectedPrefixes::CoveredBy(changed.clone()));
        prop_assert_eq!(&from_delta, &AffectedPrefixes::CoveredBy(changed));
        prop_assert_eq!(&AffectedPrefixes::between(&new_set, &old_set), &between);
        prop_assert_eq!(between.is_empty(), old_set == new_set);

        // Sound: a route whose state differs, for any origin, is covered.
        let mut origins: Vec<RouteOrigin> = vec![RouteOrigin::None];
        origins.extend((64_496..64_499).map(|a| RouteOrigin::As(Asn(a))));
        let edges = edge_routes(&old).into_iter().chain(edge_routes(&added)).map(|(p, _)| p);
        for route in routes.into_iter().chain(edges) {
            let changes = origins
                .iter()
                .any(|o| old_set.validate(route, *o) != new_set.validate(route, *o));
            if changes {
                prop_assert!(between.covers(route), "{}", route);
                prop_assert!(from_delta.covers(route), "{}", route);
            }
        }
    }

    #[test]
    fn null_source_is_disabled_for_everything(
        (prefix, origin) in route(),
        path in as_path(),
        vrps in prop::collection::vec(vrp(), 0..16),
    ) {
        let null: Arc<dyn ValidationSource> = Arc::new(NullSource);
        prop_assert_eq!(null.rov(prefix, origin), RovState::Disabled);
        prop_assert_eq!(null.aspa(&path), AspaState::Disabled);
        let derived = RouteOrigin::from_as_path(&path, Asn(64_500));
        prop_assert_eq!(null.rov(prefix, derived), RovState::Disabled);
        // A VRP set never says Disabled for origins, and has no ASPA yet.
        let set: Arc<dyn ValidationSource> = Arc::new(vrps.into_iter().collect::<VrpSet>());
        prop_assert_ne!(set.rov(prefix, derived), RovState::Disabled);
        prop_assert_eq!(set.aspa(&path), AspaState::Disabled);
    }

    #[test]
    fn revalidating_affected_routes_matches_revalidating_all(
        steps in prop::collection::vec(step(), 1..12),
        routes in prop::collection::vec(route(), 1..48),
    ) {
        let mut changes = Vec::new();
        let mut sink = |change: ValidationChange| {
            changes.push(change);
            Ok(())
        };
        produce(&steps, &mut sink).unwrap();

        // A RIB-like consumer: starts with validation off, then applies
        // each change by validating only the affected routes.
        let mut source: Arc<dyn ValidationSource> = Arc::new(NullSource);
        let mut states: Vec<RovState> = routes.iter().map(|(p, o)| source.rov(*p, *o)).collect();
        let mut history = vec![states.clone()];
        for change in &changes {
            source = Arc::clone(&change.source);
            for ((prefix, origin), state) in routes.iter().zip(&mut states) {
                if change.affected.covers(*prefix) {
                    *state = source.rov(*prefix, *origin);
                }
            }
            for ((prefix, origin), state) in routes.iter().zip(&states) {
                prop_assert_eq!(*state, source.rov(*prefix, *origin), "{} from {}", prefix, origin);
            }
            history.push(states.clone());
        }

        // A consumer that fell behind after `caught_up` changes applies the
        // rest at once: the last source and the merged affected sets.
        for caught_up in 0..changes.len() {
            let mut lagging = history[caught_up].clone();
            let mut affected = AffectedPrefixes::none();
            for change in &changes[caught_up..] {
                affected.merge(change.affected.clone());
            }
            for ((prefix, origin), state) in routes.iter().zip(&mut lagging) {
                if affected.covers(*prefix) {
                    *state = source.rov(*prefix, *origin);
                }
            }
            prop_assert_eq!(&lagging, &states);
        }
    }
}

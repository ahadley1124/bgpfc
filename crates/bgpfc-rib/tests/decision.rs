//! Route selection against a model written from RFC 4271 §9.1.2 and
//! §9.1.2.2 as literally as the text allows (AGENTS.md §5, `bgpfc-rib`
//! row), with the validation step of `prefer-valid` before them (RFC 6811
//! §5, issue #47), and its independence of the order of the candidates
//! (issue #47: "deterministic (property-tested over shuffled input
//! orders)").
//!
//! The model reads the routes as the test drew them, not through the
//! crate's accessors, so that it checks those too.
#![cfg(not(miri))]

use std::net::{IpAddr, Ipv4Addr};

use bgpfc_rib::decision::{Candidate, Neighbor, best};
use bgpfc_rib::{Enforcement, PathAttrs, RovState};
use bgpfc_wire::as_path::AsPath;
use bgpfc_wire::attribute::Origin;
use bgpfc_wire::mp::NextHop;
use bgpfc_wire::types::Asn;
use bgpfc_wire::update::PeerKind;
use proptest::prelude::*;

const LOCAL_AS: Asn = Asn(65_000);

/// The neighboring ASes the routes come through: two, so that MED is
/// compared within one and not across them.
const NEIGHBORS: [u32; 2] = [65_001, 65_002];

/// One route as drawn, from the `i`th peer of a list: peers have distinct
/// addresses, as a destination holds one route per peer, but may share a
/// router ID, so that g) gets to decide.
#[derive(Clone, Debug)]
struct Drawn {
    local_pref: Option<u32>,
    /// AS numbers in its `AS_PATH`, the neighboring AS first.
    hops: usize,
    origin: Origin,
    med: Option<u32>,
    /// Index into [`NEIGHBORS`].
    neighbor: usize,
    internal: bool,
    router_id: u32,
    /// The state the lookup gave it, and the one import policy set.
    rov: RovState,
    set: Option<RovState>,
}

fn state() -> impl Strategy<Value = RovState> {
    proptest::sample::select(RovState::ALL.to_vec())
}

fn drawn() -> impl Strategy<Value = Drawn> {
    (
        (
            proptest::option::of(prop_oneof![Just(50u32), Just(100), Just(200)]),
            1usize..=3,
            0u8..3,
            proptest::option::of(0u32..3),
        ),
        (0usize..2, any::<bool>(), 1u32..=3),
        (state(), proptest::option::weighted(0.2, state())),
    )
        .prop_map(
            |((local_pref, hops, origin, med), (neighbor, internal, router_id), (rov, set))| {
                Drawn {
                    local_pref,
                    hops,
                    origin: Origin::from_u8(origin).unwrap(),
                    med,
                    neighbor,
                    internal,
                    router_id,
                    rov,
                    set,
                }
            },
        )
}

fn enforcement() -> impl Strategy<Value = Enforcement> {
    proptest::sample::select(Enforcement::ALL.to_vec())
}

/// The address of the `i`th peer.
fn addr(i: usize) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, u8::try_from(i + 1).unwrap()))
}

/// The neighbor, attributes and the state it is used with of route `d`
/// from the `i`th peer.
fn build(i: usize, d: &Drawn) -> (Neighbor, PathAttrs, RovState) {
    let neighbor = NEIGHBORS[d.neighbor];
    let from = Neighbor {
        addr: addr(i),
        kind: if d.internal {
            PeerKind::Internal
        } else {
            PeerKind::External
        },
        router_id: d.router_id,
        remote_as: if d.internal { LOCAL_AS } else { Asn(neighbor) },
    };
    let path: Vec<Asn> = [neighbor, 64_496, 64_497][..d.hops]
        .iter()
        .map(|a| Asn(*a))
        .collect();
    let attrs = PathAttrs {
        origin: d.origin,
        as_path: AsPath::sequence(&path),
        next_hop: NextHop::Ipv4(Ipv4Addr::new(10, 0, 0, 1)),
        med: d.med,
        local_pref: d.local_pref,
        atomic_aggregate: false,
        aggregator: None,
        communities: Box::default(),
        ext_communities: Box::default(),
        large_communities: Box::default(),
        unknown: Box::default(),
    };
    (from, attrs, d.set.unwrap_or(d.rov))
}

/// What `best` chooses among `routes` under `enforcement`.
fn chosen(routes: &[(Neighbor, PathAttrs, RovState)], enforcement: Enforcement) -> Option<usize> {
    best(
        routes.len(),
        |i| Candidate {
            from: routes[i].0,
            attrs: &routes[i].1,
            rov: routes[i].2,
        },
        enforcement,
    )
}

/// The route RFC 4271 chooses among `routes`, the `i`th from the `i`th
/// peer, under `enforcement`.
fn model(routes: &[Drawn], enforcement: Enforcement) -> Option<usize> {
    let mut considered: Vec<usize> = (0..routes.len()).collect();
    let keep_min = |considered: &mut Vec<usize>, key: &dyn Fn(usize) -> u64| {
        if let Some(min) = considered.iter().map(|&i| key(i)).min() {
            considered.retain(|&i| key(i) == min);
        }
    };
    // prefer-valid: Valid, then NotFound or not validated (RFC 6811 §2),
    // then Invalid, by the state policy set if it set one (RFC 6811 §3),
    // before the degree of preference (issue #47).
    if enforcement == Enforcement::PreferValid {
        keep_min(
            &mut considered,
            &|i| match routes[i].set.unwrap_or(routes[i].rov) {
                RovState::Valid => 0,
                RovState::NotFound | RovState::Disabled => 1,
                RovState::Invalid => 2,
            },
        );
    }
    // §9.1.2: "select the route that has the highest degree of
    // preference"; §9.1.1: LOCAL_PREF, which bgpfc takes as 100 where
    // nothing set it.
    keep_min(&mut considered, &|i| {
        u64::MAX - u64::from(routes[i].local_pref.unwrap_or(100))
    });
    // a) "Remove from consideration all routes that are not tied for
    // having the smallest number of AS numbers present in their AS_PATH
    // attributes."
    keep_min(&mut considered, &|i| routes[i].hops as u64);
    // b) "Remove from consideration all routes that are not tied for
    // having the lowest Origin number in their Origin attribute."
    keep_min(&mut considered, &|i| u64::from(routes[i].origin as u8));
    // c) "for m = all routes still under consideration
    //      for n = all routes still under consideration
    //        if (neighborAS(m) == neighborAS(n)) and (MED(n) < MED(m))
    //          remove route m from consideration"
    // "If route n has no MULTI_EXIT_DISC attribute, the function returns
    // the lowest possible MULTI_EXIT_DISC value (i.e., 0)."
    let med = |i: usize| routes[i].med.unwrap_or(0);
    for m in considered.clone() {
        for n in considered.clone() {
            if routes[m].neighbor == routes[n].neighbor && med(n) < med(m) {
                considered.retain(|&r| r != m);
                break;
            }
        }
    }
    // d) "If at least one of the candidate routes was received via EBGP,
    // remove from consideration all routes that were received via IBGP."
    if considered.iter().any(|&i| !routes[i].internal) {
        considered.retain(|&i| !routes[i].internal);
    }
    // e) No IGP: "consider all routes to have equal costs".
    // f) "Remove from consideration all routes other than the route that
    // was advertised by the BGP speaker with the lowest BGP Identifier
    // value."
    keep_min(&mut considered, &|i| u64::from(routes[i].router_id));
    // g) "Prefer the route received from the lowest peer address."
    considered.into_iter().min_by_key(|&i| addr(i))
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
    #![proptest_config(ProptestConfig::with_cases(1024))]

    #[test]
    fn best_follows_the_rfc_elimination(
        routes in proptest::collection::vec(drawn(), 0..=6),
        e in enforcement(),
    ) {
        let built: Vec<_> = routes.iter().enumerate().map(|(i, d)| build(i, d)).collect();
        prop_assert_eq!(chosen(&built, e), model(&routes, e));
    }

    #[test]
    fn best_is_independent_of_candidate_order(
        routes in proptest::collection::vec(drawn(), 1..=6),
        e in enforcement(),
        seed in any::<u64>(),
    ) {
        let mut built: Vec<_> = routes.iter().enumerate().map(|(i, d)| build(i, d)).collect();
        let first = built[chosen(&built, e).unwrap()].0.addr;
        shuffle(&mut built, seed);
        prop_assert_eq!(built[chosen(&built, e).unwrap()].0.addr, first);
    }
}

#[test]
fn many_candidates_are_chosen_from_like_a_few() {
    // Past 64 candidates those under consideration no longer fit one
    // word; the outcome is the model's all the same.
    let routes: Vec<Drawn> = (0..150u32)
        .map(|i| Drawn {
            local_pref: Some(100 + i % 3),
            hops: 1 + usize::try_from(i % 2).unwrap(),
            origin: Origin::Igp,
            med: Some(i % 7),
            neighbor: usize::try_from(i % 2).unwrap(),
            internal: i % 5 == 0,
            router_id: 1 + i % 4,
            rov: RovState::ALL[usize::try_from(i % 4).unwrap()],
            set: None,
        })
        .collect();
    for e in Enforcement::ALL {
        let mut built: Vec<_> = routes
            .iter()
            .enumerate()
            .map(|(i, d)| build(i, d))
            .collect();
        let expected = model(&routes, e).unwrap();
        assert_eq!(chosen(&built, e), Some(expected), "{e}");
        // Reversed, the same route is chosen.
        built.reverse();
        let reversed = built.len() - 1 - expected;
        assert_eq!(chosen(&built, e), Some(reversed), "{e}");
    }
}

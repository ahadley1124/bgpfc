//! `InvalidAction::Drop`: the RIB refuses the routes whose origin
//! validation state is Invalid, and still holds them (RFC 6811 §2 forbids
//! excluding a route from the Adj-RIB-In "as a side effect of its
//! validation state, unless explicitly configured to do so", and §4 runs
//! the decision process again when a state changes). A change of the
//! VRPs, of the policy-set state or of the action takes a held route back
//! without a ROUTE-REFRESH, and none of it changes what the Adj-RIB-In
//! keeps.

use bgpfc_rpki::{InvalidAction, RovState::*, ValidationChange};

use super::validation::{FavourInvalid, all, best_peer, delta, held, report, vrps};
use super::*;
use crate::{AcceptAll, Enforcement, PathLimit, Policies, Verdict};

/// A RIB that drops the Invalid, with sessions to two external neighbors
/// `e1` and `e2`, and to an internal `watcher` that is sent what the
/// Loc-RIB holds.
fn dropping(policies: Box<dyn Policies>) -> (Rib, PeerInfo, PeerInfo, PeerInfo) {
    let mut rib = Rib::with_policies(LOCAL_AS, policies);
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_002, 2);
    let watcher = peer("10.0.0.3", 65_000, 3);
    for info in [&e1, &e2, &watcher] {
        outputs(|o| rib.peer_up(info.clone(), now(), o));
    }
    let report = rib.set_invalid_action(InvalidAction::Drop, now(), &mut Vec::new());
    assert_eq!(report, Enforcement::default());
    (rib, e1, e2, watcher)
}

/// The Invalid route of the tests: a short path to an origin no VRP names.
fn invalid_path() -> PathAttrs {
    attrs(&[65_001, 64_496], "10.0.0.1")
}

/// The Valid one: a longer path, so that the preference of the decision
/// process would take the Invalid route if it were a candidate.
fn valid_path() -> PathAttrs {
    attrs(&[65_002, 100, 101, 64_497], "10.0.0.2")
}

#[test]
fn an_invalid_route_is_held_and_no_candidate() {
    let (mut rib, e1, e2, watcher) = dropping(Box::new(AcceptAll));
    outputs(|o| {
        rib.validation_changed(
            all(vrps(&[
                ("192.0.2.0/24", 24, 64_497),
                ("198.51.100.0/24", 24, 64_497),
            ])),
            now(),
            o,
        );
    });
    // Three routes from e1: Invalid and alone, Invalid with a Valid route
    // from e2 to the same prefix, and NotFound.
    let out = outputs(|o| {
        rib.update(
            e1.addr,
            &announce(
                &["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"],
                &invalid_path(),
            ),
            now(),
            o,
        );
    });
    // Only the NotFound route is used and passed on.
    assert_eq!(
        fib(&out).iter().map(|c| c.prefix).collect::<Vec<_>>(),
        vec![p("203.0.113.0/24")]
    );
    let m = decode_sent(sends(&out, watcher.addr)[0], &watcher);
    assert_eq!(m[0].nlri, vec![p("203.0.113.0/24")]);
    assert_eq!(sends(&out, e2.addr).len(), 1);

    let out = outputs(|o| {
        rib.update(
            e2.addr,
            &announce(&["198.51.100.0/24"], &valid_path()),
            now(),
            o,
        );
    });
    assert_eq!(best_peer(&rib, "198.51.100.0/24"), Some(e2.addr));
    assert_eq!(fib(&out).len(), 1);

    // The Invalid routes are in the Adj-RIB-In, as received, and counted,
    // but they are not candidates.
    assert_eq!(held(&rib, V4, "192.0.2.0/24"), vec![(e1.addr, Invalid)]);
    assert_eq!(
        held(&rib, V4, "198.51.100.0/24"),
        vec![(e2.addr, Valid), (e1.addr, Invalid)]
    );
    assert!(rib.candidates(V4, p("192.0.2.0/24")).is_empty());
    let c = rib.candidates(V4, p("198.51.100.0/24"));
    assert_eq!(c.len(), 1);
    assert_eq!(c[0].peer, e2.addr);
    assert_eq!(
        rib.loc_rib(V4)
            .map(|(prefix, _)| prefix)
            .collect::<Vec<_>>(),
        vec![p("198.51.100.0/24"), p("203.0.113.0/24")]
    );
    assert_eq!(
        rib.peer_stats(e1.addr).unwrap().received,
        vec![(V4, 3), (V6, 0)]
    );
    // Nothing of them is advertised.
    assert_eq!(
        rib.adj_rib_out(watcher.addr, V4)
            .map(|(prefix, _)| prefix)
            .collect::<Vec<_>>(),
        vec![p("198.51.100.0/24"), p("203.0.113.0/24")]
    );
}

#[test]
fn a_change_of_the_vrps_moves_a_route_between_held_and_used_without_an_update() {
    let (mut rib, e1, _, watcher) = dropping(Box::new(AcceptAll));
    let other_as = vrps(&[("192.0.2.0/24", 24, 64_497)]);
    outputs(|o| rib.validation_changed(all(other_as.clone()), now(), o));
    let out = outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24"], &invalid_path()),
            now(),
            o,
        );
    });
    assert_eq!(out, vec![]);

    // The ROA goes: no VRP covers the route, NotFound, and it is taken.
    let none = vrps(&[]);
    let out = outputs(|o| rib.validation_changed(delta(&other_as, none.clone()), now(), o));
    assert_eq!(report(&out).unwrap().changes, vec![(Invalid, NotFound, 1)]);
    assert_eq!(report(&out).unwrap().best_changed, 1);
    assert_eq!(
        fib(&out),
        vec![FibChange {
            family: V4,
            prefix: p("192.0.2.0/24"),
            next_hop: Some(ip("10.0.0.1")),
            previous: None,
        }]
    );
    let m = decode_sent(sends(&out, watcher.addr)[0], &watcher);
    assert_eq!(m[0].nlri, vec![p("192.0.2.0/24")]);

    // A ROA for another origin again: Invalid, held, withdrawn from the
    // FIB and from the watcher; still in the Adj-RIB-In.
    let out = outputs(|o| rib.validation_changed(delta(&none, other_as.clone()), now(), o));
    assert_eq!(report(&out).unwrap().changes, vec![(NotFound, Invalid, 1)]);
    assert_eq!(
        fib(&out),
        vec![FibChange {
            family: V4,
            prefix: p("192.0.2.0/24"),
            next_hop: None,
            previous: Some(ip("10.0.0.1")),
        }]
    );
    let m = decode_sent(sends(&out, watcher.addr)[0], &watcher);
    assert_eq!(m[0].withdrawn, vec![p("192.0.2.0/24")]);
    assert_eq!(held(&rib, V4, "192.0.2.0/24"), vec![(e1.addr, Invalid)]);
    assert_eq!(rib.loc_rib(V4).count(), 0);

    // A ROA for the route's own origin: Valid, used.
    let ours = vrps(&[("192.0.2.0/24", 24, 64_496)]);
    let out = outputs(|o| rib.validation_changed(delta(&other_as, ours), now(), o));
    assert_eq!(report(&out).unwrap().changes, vec![(Invalid, Valid, 1)]);
    assert_eq!(fib(&out).len(), 1);
    assert_eq!(best_peer(&rib, "192.0.2.0/24"), Some(e1.addr));

    // Validation off: every route is `disabled`, and none is Invalid.
    let out = outputs(|o| rib.validation_changed(ValidationChange::disabled(), now(), o));
    assert_eq!(report(&out).unwrap().changes, vec![(Valid, Disabled, 1)]);
    assert_eq!(best_peer(&rib, "192.0.2.0/24"), Some(e1.addr));
}

#[test]
fn a_newer_announcement_replaces_a_held_route_and_the_other_way_round() {
    let (mut rib, e1, _, watcher) = dropping(Box::new(AcceptAll));
    outputs(|o| rib.validation_changed(all(vrps(&[("192.0.2.0/24", 24, 64_497)])), now(), o));
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24"], &invalid_path()),
            now(),
            o,
        );
    });
    assert_eq!(rib.loc_rib(V4).count(), 0);

    // The neighbor re-announces with the origin the ROA names: taken.
    let out = outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_001, 64_497], "10.0.0.1")),
            now(),
            o,
        );
    });
    assert_eq!(fib(&out).len(), 1);
    assert_eq!(held(&rib, V4, "192.0.2.0/24"), vec![(e1.addr, Valid)]);

    // And back to an origin it does not name: the neighbor's earlier route
    // is replaced, so what the FIB and the watcher had goes. One route of
    // the neighbor is in the Adj-RIB-In throughout.
    let out = outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24"], &invalid_path()),
            now(),
            o,
        );
    });
    assert_eq!(fib(&out)[0].next_hop, None);
    let m = decode_sent(sends(&out, watcher.addr)[0], &watcher);
    assert_eq!(m[0].withdrawn, vec![p("192.0.2.0/24")]);
    assert_eq!(held(&rib, V4, "192.0.2.0/24"), vec![(e1.addr, Invalid)]);
    assert_eq!(
        rib.peer_stats(e1.addr).unwrap().received,
        vec![(V4, 1), (V6, 0)]
    );
}

#[test]
fn held_routes_go_with_a_withdrawal_and_with_the_peer() {
    let (mut rib, e1, e2, _) = dropping(Box::new(AcceptAll));
    outputs(|o| rib.validation_changed(all(vrps(&[("192.0.2.0/24", 24, 64_497)])), now(), o));
    let baseline = rib.attribute_sets();
    for (from, path) in [
        (&e1, invalid_path()),
        (&e2, attrs(&[65_002, 64_498], "10.0.0.2")),
    ] {
        outputs(|o| rib.update(from.addr, &announce(&["192.0.2.0/24"], &path), now(), o));
    }
    assert_eq!(rib.attribute_sets(), baseline + 2);
    assert_eq!(rib.loc_rib(V4).count(), 0);

    let out = outputs(|o| rib.update(e1.addr, &withdraw(&["192.0.2.0/24"]), now(), o));
    assert_eq!(out, vec![]);
    assert_eq!(held(&rib, V4, "192.0.2.0/24"), vec![(e2.addr, Invalid)]);
    assert_eq!(
        rib.peer_stats(e1.addr).unwrap().received,
        vec![(V4, 0), (V6, 0)]
    );
    assert_eq!(rib.attribute_sets(), baseline + 1);

    outputs(|o| rib.peer_down(e2.addr, now(), o));
    assert_eq!(held(&rib, V4, "192.0.2.0/24"), vec![]);
    assert_eq!(rib.attribute_sets(), baseline);
}

#[test]
fn held_routes_count_towards_the_prefix_limit() {
    // RFC 4271 §6.7: whether a route is in the Adj-RIB-In never depends on
    // the action, so a limit is crossed the same with or without it.
    let mut rib = Rib::new(LOCAL_AS);
    let mut e1 = peer("10.0.0.1", 65_001, 1);
    e1.prefix_limits = vec![(V4, 2)];
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    rib.set_invalid_action(InvalidAction::Drop, now(), &mut Vec::new());
    outputs(|o| {
        rib.validation_changed(
            all(vrps(&[
                ("192.0.2.0/24", 24, 64_497),
                ("198.51.100.0/24", 24, 64_497),
                ("203.0.113.0/24", 24, 64_497),
            ])),
            now(),
            o,
        );
    });
    let out = outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24", "198.51.100.0/24"], &invalid_path()),
            now(),
            o,
        );
    });
    assert!(
        !out.iter()
            .any(|o| matches!(o, Output::PrefixLimitExceeded { .. }))
    );
    let out = outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["203.0.113.0/24"], &invalid_path()),
            now(),
            o,
        );
    });
    assert!(
        out.iter()
            .any(|o| matches!(o, Output::PrefixLimitExceeded { limit: 2, .. }))
    );
}

/// Import policy that overrules the lookup for two prefixes (RFC 6811 §3:
/// "set the validation state"): it takes the first as Valid whatever it
/// is, and the second as Invalid.
struct Overrule;

impl Policies for Overrule {
    fn import(
        &self,
        _: &PeerInfo,
        _: AddressFamily,
        prefix: Prefix,
        _: &PathAttrs,
        _: RovState,
    ) -> Verdict {
        if prefix == p("192.0.2.0/24") {
            Verdict::Restated(Valid)
        } else if prefix == p("198.51.100.0/24") {
            Verdict::Restated(Invalid)
        } else {
            Verdict::Accept
        }
    }

    fn export(
        &self,
        _: &PeerInfo,
        _: AddressFamily,
        _: Prefix,
        _: &PathAttrs,
        _: RovState,
    ) -> Verdict {
        Verdict::Accept
    }
}

#[test]
fn the_state_import_policy_sets_decides_what_is_refused() {
    // RFC 6811 §3 and §5: policy sets the state, and the action acts on
    // the state the route holds, so an operator can overrule the lookup
    // for a route in either direction.
    let (mut rib, e1, _, _) = dropping(Box::new(Overrule));
    // 192.0.2.0/24 is Invalid by lookup, taken as Valid; 198.51.100.0/24
    // is Valid by lookup, taken as Invalid.
    outputs(|o| {
        rib.validation_changed(
            all(vrps(&[
                ("192.0.2.0/24", 24, 64_497),
                ("198.51.100.0/24", 24, 64_496),
            ])),
            now(),
            o,
        );
    });
    let out = outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24", "198.51.100.0/24"], &invalid_path()),
            now(),
            o,
        );
    });
    assert_eq!(
        fib(&out).iter().map(|c| c.prefix).collect::<Vec<_>>(),
        vec![p("192.0.2.0/24")]
    );
    assert_eq!(held(&rib, V4, "192.0.2.0/24"), vec![(e1.addr, Valid)]);
    assert_eq!(held(&rib, V4, "198.51.100.0/24"), vec![(e1.addr, Invalid)]);

    // Not dropping, both are used, with the states policy gave them.
    let mut out = Vec::new();
    rib.set_invalid_action(InvalidAction::Policy, now(), &mut out);
    assert_eq!(fib(&out).len(), 1);
    assert_eq!(held(&rib, V4, "198.51.100.0/24"), vec![(e1.addr, Invalid)]);
    assert_eq!(rib.loc_rib(V4).count(), 2);
}

#[test]
fn changing_the_action_takes_held_routes_and_holds_candidates_without_a_refresh() {
    // Invalid routes with a degree of preference far above the others, so
    // that every effect on the best route is the action's.
    let (mut rib, e1, e2, watcher) = dropping(Box::new(FavourInvalid));
    outputs(|o| {
        rib.validation_changed(
            all(vrps(&[
                ("192.0.2.0/24", 24, 64_497),
                ("198.51.100.0/24", 24, 64_497),
            ])),
            now(),
            o,
        );
    });
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24", "198.51.100.0/24"], &invalid_path()),
            now(),
            o,
        );
    });
    outputs(|o| {
        rib.update(
            e2.addr,
            &announce(&["198.51.100.0/24", "203.0.113.0/24"], &valid_path()),
            now(),
            o,
        );
    });
    // 192.0.2.0/24: nothing but the Invalid route, held. 198.51.100.0/24:
    // the Valid route. 203.0.113.0/24: a route that is not Invalid.
    assert_eq!(rib.loc_rib(V4).count(), 2);

    // Dropping becomes leaving it to policy: both Invalid routes are
    // candidates, and e1's 198.51.100.0/24 (preference 500) wins.
    let mut out = Vec::new();
    let report = rib.set_invalid_action(InvalidAction::Policy, now(), &mut out);
    assert_eq!(
        report,
        Enforcement {
            invalid: 2,
            destinations: 2,
            held: 0,
            taken: 2,
            best_changed: 2,
        }
    );
    assert_eq!(best_peer(&rib, "192.0.2.0/24"), Some(e1.addr));
    assert_eq!(best_peer(&rib, "198.51.100.0/24"), Some(e1.addr));
    let mut changes = fib(&out);
    changes.sort_by_key(|c| c.prefix);
    assert_eq!(
        changes
            .iter()
            .map(|c| (c.prefix, c.next_hop))
            .collect::<Vec<_>>(),
        vec![
            (p("192.0.2.0/24"), Some(ip("10.0.0.1"))),
            (p("198.51.100.0/24"), Some(ip("10.0.0.1"))),
        ]
    );
    assert_eq!(sends(&out, watcher.addr).len(), 1);

    // Back to dropping: held again, the Valid route is best again.
    let mut out = Vec::new();
    let report = rib.set_invalid_action(InvalidAction::Drop, now(), &mut out);
    assert_eq!(
        report,
        Enforcement {
            invalid: 2,
            destinations: 2,
            held: 2,
            taken: 0,
            best_changed: 2,
        }
    );
    assert_eq!(best_peer(&rib, "192.0.2.0/24"), None);
    assert_eq!(best_peer(&rib, "198.51.100.0/24"), Some(e2.addr));

    // Dropping becomes preferring the Valid: the held route is a candidate
    // again, and chosen only where it is alone.
    let mut out = Vec::new();
    let report = rib.set_invalid_action(InvalidAction::PreferValid, now(), &mut out);
    assert_eq!(
        report,
        Enforcement {
            invalid: 2,
            destinations: 2,
            held: 0,
            taken: 2,
            best_changed: 1,
        }
    );
    assert_eq!(best_peer(&rib, "192.0.2.0/24"), Some(e1.addr));
    assert_eq!(best_peer(&rib, "198.51.100.0/24"), Some(e2.addr));
    assert_eq!(fib(&out).len(), 1);

    // Nothing was received again: the Adj-RIB-In kept what it had.
    assert_eq!(
        rib.peer_stats(e1.addr).unwrap().received,
        vec![(V4, 2), (V6, 0)]
    );
}

#[test]
fn an_invalid_path_is_not_sent_with_add_path() {
    // RFC 7911 §5: the paths a peer is sent are among the best by the
    // decision process, and a refused route is no candidate.
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_002, 2);
    let to = PeerInfo {
        add_path_send: vec![(V4, PathLimit::All)],
        ..peer("10.0.0.9", 65_009, 9)
    };
    for info in [&e1, &e2, &to] {
        outputs(|o| rib.peer_up(info.clone(), now(), o));
    }
    rib.set_invalid_action(InvalidAction::Drop, now(), &mut Vec::new());
    outputs(|o| rib.validation_changed(all(vrps(&[("192.0.2.0/24", 24, 64_497)])), now(), o));
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24"], &invalid_path()),
            now(),
            o,
        );
    });
    outputs(|o| {
        rib.update(
            e2.addr,
            &announce(&["192.0.2.0/24"], &valid_path()),
            now(),
            o,
        );
    });
    let sent = rib.sent_paths(to.addr, V4);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].2.as_path.first_asn(), Some(Asn(65_002)));

    // The route is Valid after a ROA change, and the path follows.
    outputs(|o| {
        rib.validation_changed(
            all(vrps(&[
                ("192.0.2.0/24", 24, 64_497),
                ("192.0.2.0/24", 24, 64_496),
            ])),
            now(),
            o,
        );
    });
    assert_eq!(rib.sent_paths(to.addr, V4).len(), 2);
}

#[test]
fn the_same_action_again_changes_nothing() {
    let (mut rib, e1, _, _) = dropping(Box::new(AcceptAll));
    outputs(|o| rib.validation_changed(all(vrps(&[("192.0.2.0/24", 24, 64_497)])), now(), o));
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24"], &invalid_path()),
            now(),
            o,
        );
    });
    let mut out = Vec::new();
    assert_eq!(
        rib.set_invalid_action(InvalidAction::Drop, now(), &mut out),
        Enforcement::default()
    );
    assert_eq!(out, vec![]);
}

#[test]
fn a_destination_left_with_nothing_to_use_still_holds_its_routes() {
    // The decision process runs for a destination whose candidates all went
    // held: no best route, so the FIB and the neighbors are told, and the
    // destination stays for the routes it holds.
    let (mut rib, e1, _, watcher) = dropping(Box::new(AcceptAll));
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24"], &invalid_path()),
            now(),
            o,
        );
    });
    assert_eq!(best_peer(&rib, "192.0.2.0/24"), Some(e1.addr));
    let out = outputs(|o| {
        rib.validation_changed(all(vrps(&[("192.0.2.0/24", 24, 64_497)])), now(), o);
    });
    assert_eq!(fib(&out)[0].next_hop, None);
    let m = decode_sent(sends(&out, watcher.addr)[0], &watcher);
    assert_eq!(m[0].withdrawn, vec![p("192.0.2.0/24")]);
    assert_eq!(held(&rib, V4, "192.0.2.0/24"), vec![(e1.addr, Invalid)]);
}

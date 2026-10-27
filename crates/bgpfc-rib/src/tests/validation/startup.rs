//! The operator's startup setting (RFC 6811 §2: no route leaves the
//! decision process for its state "unless explicitly configured to do
//! so"): under `startup hold` a route not validated yet, used with state
//! `disabled`, is held in the Adj-RIB-In, counted, neither installed nor
//! advertised, until validation data gives it a state; then it is used,
//! or held, as `enforcement` says. A change of the setting judges again
//! the routes not validated yet, and only those.

use bgpfc_rpki::Enforcement::{self, DropInvalid};
use bgpfc_rpki::Startup::{self, Accept, Hold};

use super::enforcement::{counted, kept, send, sent, two_peers};
use super::*;
use crate::StartupChange;

/// The routes e1 sends, from AS 64496: Invalid, `NotFound` and Valid with
/// [`roas`].
const ROUTES: [&str; 3] = ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"];

/// A ROA for another origin over the first route, one for its own over
/// the last.
fn roas() -> VrpSet {
    vrps(&[("192.0.2.0/24", 24, 64_497), ("203.0.113.0/24", 24, 64_496)])
}

/// The one report of a change of the setting in `out`, which comes first.
fn changed(out: &[Output]) -> &StartupChange {
    let reports: Vec<&StartupChange> = out
        .iter()
        .filter_map(|o| match o {
            Output::Startup(r) => Some(r),
            _ => None,
        })
        .collect();
    assert_eq!(reports.len(), 1, "{out:?}");
    assert!(matches!(out[0], Output::Startup(_)), "{out:?}");
    reports[0]
}

/// A RIB under `enforcement` and `startup`, with e1 and e2 up.
fn rib_with(enforcement: Enforcement, startup: Startup) -> (Rib, PeerInfo, PeerInfo) {
    let mut rib = Rib::new(LOCAL_AS);
    outputs(|o| rib.set_enforcement(enforcement, now(), o));
    outputs(|o| rib.set_startup(startup, now(), o));
    let (e1, e2) = two_peers(&mut rib);
    (rib, e1, e2)
}

#[test]
fn a_rib_holds_no_route_for_startup_until_told() {
    // RFC 6811 §2: without configuration a route not validated is used.
    let mut rib = Rib::new(LOCAL_AS);
    assert_eq!(rib.startup(), Accept);
    let (e1, e2) = two_peers(&mut rib);
    let out = send(&mut rib, &e1, &ROUTES);
    assert_eq!(fib(&out).len(), 3);
    assert_eq!(sent(&out, &e2).0.len(), 3);
    assert_eq!(
        kept(&rib, ROUTES[0]),
        vec![(e1.addr, RovState::Disabled, None)]
    );
}

#[test]
fn routes_not_validated_are_held_under_startup_hold() {
    let mut rib = Rib::new(LOCAL_AS);
    let out = outputs(|o| rib.set_startup(Hold, now(), o));
    // Nothing to judge yet; the change is reported all the same.
    assert_eq!(
        out,
        vec![Output::Startup(StartupChange {
            from: Accept,
            to: Hold,
            routes: 0,
            held: 0,
            released: 0,
            best_changed: 0,
        })]
    );
    assert_eq!(rib.startup(), Hold);
    let (e1, e2) = two_peers(&mut rib);
    let out = send(&mut rib, &e1, &ROUTES);
    // Neither installed nor advertised...
    assert_eq!(fib(&out), vec![]);
    assert_eq!(sent(&out, &e2), (vec![], vec![]));
    assert_eq!(rib.loc_rib(V4).count(), 0);
    // ... but kept as received (RFC 6811 §2), counted as received and as
    // held, each held for the startup setting.
    for prefix in ROUTES {
        assert_eq!(
            kept(&rib, prefix),
            vec![(e1.addr, RovState::Disabled, Some(Held::Startup))],
            "{prefix}"
        );
        assert!(rib.candidates(V4, p(prefix)).is_empty());
    }
    let held: Vec<(Prefix, Option<Held>)> = rib.held(V4).map(|(q, r)| (q, r.held)).collect();
    assert_eq!(
        held,
        ROUTES.map(|r| (p(r), Some(Held::Startup))).to_vec(),
        "listed with the other held routes"
    );
    assert_eq!(counted(&rib, e1.addr), (3, 3));
    assert_eq!(Held::Startup.as_str(), "startup");
}

#[test]
fn the_first_full_set_releases_what_enforcement_admits() {
    // RFC 6811 §4: the first data validates every route, which is judged
    // again: under drop-invalid the Valid and NotFound routes are used,
    // the Invalid one stays held, now for enforcement; under the other
    // modes all three are used.
    for enforcement in Enforcement::ALL {
        let (mut rib, e1, e2) = rib_with(enforcement, Hold);
        send(&mut rib, &e1, &ROUTES);
        assert_eq!(counted(&rib, e1.addr), (3, 3), "{enforcement}");
        let out = outputs(|o| rib.validation_changed(all(roas()), now(), o));
        let used = if enforcement == DropInvalid { 2 } else { 3 };
        let r = report(&out).unwrap();
        assert_eq!(
            r.changes,
            vec![
                (RovState::Disabled, RovState::Valid, 1),
                (RovState::Disabled, RovState::Invalid, 1),
                (RovState::Disabled, RovState::NotFound, 1),
            ],
            "{enforcement}"
        );
        // From held for the startup to held for enforcement is no release.
        assert_eq!(
            (r.held, r.released, r.best_changed),
            (0, used, used),
            "{enforcement}"
        );
        assert_eq!(fib(&out).len(), used, "{enforcement}");
        let (nlri, withdrawn) = sent(&out, &e2);
        assert_eq!((nlri.len(), withdrawn), (used, vec![]), "{enforcement}");
        let invalid = if enforcement == DropInvalid {
            Some(Held::Enforcement)
        } else {
            None
        };
        assert_eq!(
            kept(&rib, ROUTES[0]),
            vec![(e1.addr, RovState::Invalid, invalid)],
            "{enforcement}"
        );
        assert_eq!(counted(&rib, e1.addr), (3, 3 - used), "{enforcement}");
        // A route that arrives with the data in place is validated on
        // arrival and not held for the startup.
        let out = send(&mut rib, &e1, &["198.51.100.128/25"]);
        assert_eq!(fib(&out).len(), 1, "{enforcement}");
        assert_eq!(
            rib.held(V4)
                .filter(|(_, r)| r.held == Some(Held::Startup))
                .count(),
            0
        );
    }
}

#[test]
fn set_startup_judges_again_only_the_routes_not_validated() {
    let (mut rib, e1, e2) = rib_with(DropInvalid, Accept);
    send(&mut rib, &e1, &ROUTES);
    assert_eq!(rib.loc_rib(V4).count(), 3);
    // Before any data: every route is `disabled`, and hold takes all three
    // out of use, withdrawn from the FIB and the neighbors.
    let out = outputs(|o| rib.set_startup(Hold, now(), o));
    assert_eq!(
        *changed(&out),
        StartupChange {
            from: Accept,
            to: Hold,
            routes: 3,
            held: 3,
            released: 0,
            best_changed: 3,
        }
    );
    assert!(fib(&out).iter().all(|c| c.next_hop.is_none()), "{out:?}");
    assert_eq!(fib(&out).len(), 3);
    assert_eq!(sent(&out, &e2), (vec![], ROUTES.map(p).to_vec()));
    assert_eq!(counted(&rib, e1.addr), (3, 3));
    assert_eq!(outputs(|o| rib.set_startup(Hold, now(), o)), vec![]);
    // And accept uses them again, with no UPDATE.
    let out = outputs(|o| rib.set_startup(Accept, now(), o));
    assert_eq!(
        *changed(&out),
        StartupChange {
            from: Hold,
            to: Accept,
            routes: 3,
            held: 0,
            released: 3,
            best_changed: 3,
        }
    );
    assert_eq!(sent(&out, &e2), (ROUTES.map(p).to_vec(), vec![]));
    assert_eq!(counted(&rib, e1.addr), (3, 0));
    // With data, no route is `disabled`: the setting has nothing to act
    // on, and no route is judged again.
    outputs(|o| rib.validation_changed(all(roas()), now(), o));
    assert_eq!(counted(&rib, e1.addr), (3, 1));
    for startup in [Hold, Accept] {
        let out = outputs(|o| rib.set_startup(startup, now(), o));
        let c = changed(&out);
        assert_eq!(
            (c.routes, c.held, c.released, c.best_changed),
            (0, 0, 0, 0),
            "{startup}"
        );
        assert_eq!(out.len(), 1, "{out:?}");
    }
}

#[test]
fn expired_data_leaves_nothing_held_for_the_startup() {
    // RFC 8210 §6: VRPs that expire leave an empty set, which judges every
    // route NotFound: validated, so not the startup's to hold.
    let (mut rib, e1, _) = rib_with(DropInvalid, Hold);
    send(&mut rib, &e1, &ROUTES);
    outputs(|o| rib.validation_changed(all(roas()), now(), o));
    let out = outputs(|o| rib.validation_changed(all(VrpSet::new()), now(), o));
    assert_eq!(report(&out).unwrap().released, 1);
    assert_eq!(rib.held(V4).count(), 0);
    assert_eq!(counted(&rib, e1.addr), (3, 0));
}

#[test]
fn the_owner_lets_routes_go_before_it_turns_validation_off() {
    // The null source of validation turned off judges every route
    // `disabled` too: under hold that would hold them all. The owner turns
    // the hold off first, and validation off leaves every route in use.
    let (mut rib, e1, _) = rib_with(Enforcement::Off, Hold);
    send(&mut rib, &e1, &ROUTES);
    outputs(|o| rib.validation_changed(all(roas()), now(), o));
    assert_eq!(rib.loc_rib(V4).count(), 3);
    outputs(|o| rib.set_startup(Accept, now(), o));
    let out = outputs(|o| rib.validation_changed(ValidationChange::disabled(), now(), o));
    let r = report(&out).unwrap();
    assert_eq!((r.held, r.released), (0, 0));
    assert_eq!(rib.loc_rib(V4).count(), 3);
    // In the other order, every route is held until the hold goes.
    let (mut rib, e1, _) = rib_with(Enforcement::Off, Hold);
    send(&mut rib, &e1, &ROUTES);
    outputs(|o| rib.validation_changed(all(roas()), now(), o));
    let out = outputs(|o| rib.validation_changed(ValidationChange::disabled(), now(), o));
    assert_eq!(report(&out).unwrap().held, 3);
    assert_eq!(rib.loc_rib(V4).count(), 0);
    let out = outputs(|o| rib.set_startup(Accept, now(), o));
    assert_eq!(changed(&out).released, 3);
}

#[test]
fn a_state_import_policy_sets_keeps_a_route_out_of_the_hold() {
    // RFC 6811 §3: the state import policy sets is the one the route is
    // used with, as `match rpki disabled; set rpki not-found;` sets it for
    // a trusted neighbor. Such a route is not held for the startup.
    let mut rib = Rib::with_policies(
        LOCAL_AS,
        Box::new(Override::new(RovState::Disabled, RovState::NotFound)),
    );
    outputs(|o| rib.set_startup(Hold, now(), o));
    let (e1, e2) = two_peers(&mut rib);
    let out = send(&mut rib, &e1, &ROUTES[..1]);
    assert_eq!(fib(&out).len(), 1);
    assert_eq!(sent(&out, &e2).0, vec![p(ROUTES[0])]);
    assert_eq!(
        states(&rib, ROUTES[0]),
        (
            RovState::Disabled,
            Some(RovState::NotFound),
            RovState::NotFound
        )
    );
    assert_eq!(counted(&rib, e1.addr), (1, 0));
    // A change of the setting does not judge it again either.
    let out = outputs(|o| rib.set_startup(Accept, now(), o));
    assert_eq!(changed(&out).routes, 0);
}

/// Import policy that rejects every route not validated, as `match rpki
/// disabled; action reject;` does, and takes the others.
struct RejectDisabled;

impl Policies for RejectDisabled {
    fn import(
        &self,
        _: &PeerInfo,
        _: AddressFamily,
        _: Prefix,
        _: &PathAttrs,
        rov: RovState,
    ) -> Imported {
        if rov == RovState::Disabled {
            Verdict::Reject.into()
        } else {
            Verdict::Accept.into()
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
fn a_route_import_policy_holds_stays_held_by_policy() {
    // The import-policy way of holding routes until the first data: the
    // policy decides first, and the route is held for it, whatever the
    // startup setting, which then has nothing to change.
    let mut rib = Rib::with_policies(LOCAL_AS, Box::new(RejectDisabled));
    outputs(|o| rib.set_startup(Hold, now(), o));
    let (e1, _) = two_peers(&mut rib);
    send(&mut rib, &e1, &ROUTES[..1]);
    let policy = vec![(e1.addr, RovState::Disabled, Some(Held::Policy))];
    assert_eq!(kept(&rib, ROUTES[0]), policy);
    let out = outputs(|o| rib.set_startup(Accept, now(), o));
    let c = changed(&out);
    assert_eq!((c.routes, c.held, c.released), (1, 0, 0));
    assert_eq!(kept(&rib, ROUTES[0]), policy);
    assert_eq!(counted(&rib, e1.addr), (1, 1));
    // The first data releases it, as it would under hold.
    let out = outputs(|o| rib.validation_changed(all(roas()), now(), o));
    assert_eq!(report(&out).unwrap().released, 1);
}

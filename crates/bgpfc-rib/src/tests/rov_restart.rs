//! Origin validation acted on (RFC 6811 §5, `invalid`) together with
//! Graceful Restart (RFC 4724). The routes of a session that ended are
//! stale routing information the Adj-RIB-In still holds (§4.2), so a change
//! of the VRPs or of the action judges them again like any other route
//! (RFC 6811 §4): a stale route that turns Invalid is held, leaves the
//! Loc-RIB, the FIB and what other peers were told, and stays stale; one a
//! later change admits is a candidate again, still stale. What ends stale
//! routes (the End-of-RIB, the Restart Time) ends the held ones with them,
//! and a route the peer sends again is neither stale nor judged on its old
//! state. A Restarting Speaker that defers route selection (§4.1) tells
//! nobody of a state that changes meanwhile, and the end of the deferral
//! brings out the routes as their states left them.

use bgpfc_rpki::{InvalidAction, RovState::*, ValidationChange};

use super::restart::{RESTART, gr_peer, removed, retention, secs};
use super::validation::{all, vrps};
use super::*;
use crate::{Deferral, StaleEnd};

const PREFIX: &str = "192.0.2.0/24";
const OTHER: &str = "198.51.100.0/24";

/// VRPs under which [`PREFIX`] is Valid from `asn` alone.
fn origin(asn: u32) -> ValidationChange {
    all(vrps(&[(PREFIX, 24, asn)]))
}

/// A RIB with `action` for the Invalid, and two peers: A (AS 65001), a
/// Graceful Restart peer, whose route to [`PREFIX`] is Valid, and B, which
/// is sent it. A's session has ended and its route is kept as stale.
struct Lab {
    rib: Rib,
    a: PeerInfo,
    b: PeerInfo,
    t0: Instant,
}

fn lab(action: InvalidAction) -> Lab {
    let mut rib = Rib::new(LOCAL_AS);
    let t0 = now();
    rib.set_invalid_action(action, t0, &mut Vec::new());
    outputs(|o| rib.validation_changed(origin(65_001), t0, o));
    let a = gr_peer("10.0.0.1", 65_001, 1);
    let b = peer("10.0.0.2", 65_002, 2);
    let mut out = Vec::new();
    rib.peer_up(a.clone(), t0, &mut out);
    rib.peer_up(b.clone(), t0, &mut out);
    rib.update(
        a.addr,
        &announce(&[PREFIX], &attrs(&[65_001], "10.0.0.1")),
        t0,
        &mut out,
    );
    assert_eq!(rib.peer_retain(a.addr, &retention(false), t0, &mut out), 1);
    Lab { rib, a, b, t0 }
}

/// A's route to [`PREFIX`]: its state, whether it is held, whether it is
/// stale.
fn a_route(l: &Lab) -> Vec<(RovState, bool, bool)> {
    routes(&l.rib, V4, p(PREFIX))
        .into_iter()
        .filter(|(addr, _)| *addr == l.a.addr)
        .map(|(_, r)| (r.rov, r.held, r.stale))
        .collect()
}

/// The next hops the FIB is given.
fn next_hops(out: &[Output]) -> Vec<Option<IpAddr>> {
    fib(out).iter().map(|c| c.next_hop).collect()
}

/// What `to` was sent, as (withdrawn, announced) prefixes per UPDATE.
fn sent(out: &[Output], to: &PeerInfo) -> Vec<(Vec<Prefix>, Vec<Prefix>)> {
    sends(out, to.addr)
        .into_iter()
        .flat_map(|m| decode_sent(m, to))
        .filter(|u| u.end_of_rib_family().is_none())
        .map(|u| (u.withdrawn, u.nlri))
        .collect()
}

#[test]
fn a_stale_route_is_judged_again_when_the_vrps_change_and_stays_stale() {
    let mut l = lab(InvalidAction::Drop);
    assert_eq!(a_route(&l), vec![(Valid, false, true)]);
    // RFC 6811 §4 on the stale route of a peer whose session is down: a
    // ROA for another origin makes it Invalid, and `drop` holds it. It
    // leaves the FIB and B, as RFC 4724 §4.2 has stale routes treated like
    // any other, and `drop` uses no Invalid route.
    let out = outputs(|o| l.rib.validation_changed(origin(64_496), l.t0, o));
    assert_eq!(next_hops(&out), vec![None]);
    assert_eq!(sent(&out, &l.b), vec![(vec![p(PREFIX)], vec![])]);
    assert_eq!(a_route(&l), vec![(Invalid, true, true)]);
    assert_eq!(l.rib.loc_rib(V4).count(), 0);
    // `show routes PREFIX` lists it held, and stale.
    let held = l.rib.held(V4, p(PREFIX));
    assert_eq!(held.len(), 1);
    assert!(held[0].peer == l.a.addr && held[0].stale);
    assert_eq!(l.rib.stale_routes(l.a.addr), vec![(V4, 1)]);
    // The ROA for its origin is back: a candidate again with no UPDATE from
    // A, whose session is still down, and still stale.
    let out = outputs(|o| l.rib.validation_changed(origin(65_001), l.t0, o));
    assert_eq!(next_hops(&out), vec![Some(ip("10.0.0.1"))]);
    assert_eq!(sent(&out, &l.b), vec![(vec![], vec![p(PREFIX)])]);
    assert_eq!(a_route(&l), vec![(Valid, false, true)]);
    assert_eq!(l.rib.loc_rib(V4).count(), 1);
}

#[test]
fn a_held_stale_route_goes_at_the_end_of_rib_with_nothing_to_tell() {
    let mut l = lab(InvalidAction::Drop);
    outputs(|o| l.rib.validation_changed(origin(64_496), l.t0, o));
    let t1 = l.t0 + secs(10);
    l.rib.peer_up(l.a.clone(), t1, &mut Vec::new());
    // Back, with the Forwarding State bit: held and stale until A sends it
    // again or its End-of-RIB comes.
    assert_eq!(a_route(&l), vec![(Invalid, true, true)]);
    let out = outputs(|o| l.rib.end_of_rib(l.a.addr, V4, t1, o));
    // RFC 4724 §4.2: "MUST immediately remove any routes from the peer that
    // are still marked as stale", held ones included. It was neither in the
    // FIB nor sent to B, so neither hears of it.
    assert_eq!(
        removed(&out),
        vec![(l.a.addr, Some(V4), 1, StaleEnd::EndOfRib)]
    );
    assert_eq!(next_hops(&out), vec![]);
    assert_eq!(sent(&out, &l.b), vec![]);
    assert_eq!(a_route(&l), vec![]);
    assert!(l.rib.held(V4, p(PREFIX)).is_empty());
    assert_eq!(
        l.rib.peer_stats(l.a.addr).unwrap().received,
        vec![(V4, 0), (V6, 0)]
    );
    // Gone from the Adj-RIB-In: a ROA for its origin admits nothing.
    let out = outputs(|o| l.rib.validation_changed(origin(65_001), t1, o));
    assert_eq!(next_hops(&out), vec![]);
}

#[test]
fn the_restart_time_ends_held_stale_routes_too() {
    let mut l = lab(InvalidAction::Drop);
    outputs(|o| l.rib.validation_changed(origin(64_496), l.t0, o));
    // RFC 4724 §4.2: A is not back within its Restart Time, so all its
    // stale routes go, the one held for its state among them.
    let out = outputs(|o| l.rib.flush(l.t0 + RESTART, o));
    assert_eq!(
        removed(&out),
        vec![(l.a.addr, None, 1, StaleEnd::RestartTimer)]
    );
    assert_eq!(next_hops(&out), vec![]);
    assert!(routes(&l.rib, V4, p(PREFIX)).is_empty());
    let out = outputs(|o| l.rib.validation_changed(origin(65_001), l.t0 + RESTART, o));
    assert_eq!(next_hops(&out), vec![]);
}

#[test]
fn a_stale_route_sent_again_as_invalid_is_held_and_no_longer_stale() {
    let mut l = lab(InvalidAction::Drop);
    let t1 = l.t0 + secs(10);
    l.rib.peer_up(l.a.clone(), t1, &mut Vec::new());
    // A sends the route again, from an origin the VRPs make Invalid: it
    // replaces the stale one (RFC 4724 §4.2) and is held (RFC 6811 §5).
    let out = outputs(|o| {
        l.rib.update(
            l.a.addr,
            &announce(&[PREFIX], &attrs(&[65_001, 64_496], "10.0.0.1")),
            t1,
            o,
        );
    });
    assert_eq!(next_hops(&out), vec![None]);
    assert_eq!(sent(&out, &l.b), vec![(vec![p(PREFIX)], vec![])]);
    assert_eq!(a_route(&l), vec![(Invalid, true, false)]);
    // Not stale: the End-of-RIB has nothing to remove and leaves it held.
    let out = outputs(|o| l.rib.end_of_rib(l.a.addr, V4, t1, o));
    assert_eq!(
        removed(&out),
        vec![(l.a.addr, Some(V4), 0, StaleEnd::EndOfRib)]
    );
    assert_eq!(a_route(&l), vec![(Invalid, true, false)]);
    // And a ROA for the new origin takes it, with no UPDATE.
    let out = outputs(|o| l.rib.validation_changed(origin(64_496), t1, o));
    assert_eq!(next_hops(&out), vec![Some(ip("10.0.0.1"))]);
    assert_eq!(a_route(&l), vec![(Valid, false, false)]);
}

#[test]
fn a_new_action_reaches_the_stale_routes_of_a_peer_that_is_down() {
    let mut l = lab(InvalidAction::Policy);
    // Under `policy` an Invalid route is an ordinary one: still the best,
    // still in the FIB, still stale.
    let out = outputs(|o| l.rib.validation_changed(origin(64_496), l.t0, o));
    assert_eq!(next_hops(&out), vec![]);
    assert_eq!(a_route(&l), vec![(Invalid, false, true)]);
    // RFC 6811 §5: a reload that says `invalid drop` holds it, with A's
    // session still down.
    let out = outputs(|o| {
        l.rib.set_invalid_action(InvalidAction::Drop, l.t0, o);
    });
    assert_eq!(next_hops(&out), vec![None]);
    assert_eq!(sent(&out, &l.b), vec![(vec![p(PREFIX)], vec![])]);
    assert_eq!(a_route(&l), vec![(Invalid, true, true)]);
    // `prefer-valid` makes it a candidate again, the only one, so the best.
    let out = outputs(|o| {
        l.rib
            .set_invalid_action(InvalidAction::PreferValid, l.t0, o);
    });
    assert_eq!(next_hops(&out), vec![Some(ip("10.0.0.1"))]);
    assert_eq!(a_route(&l), vec![(Invalid, false, true)]);
    // And A's End-of-RIB still ends it, as it ends any stale route.
    let t1 = l.t0 + secs(10);
    l.rib.peer_up(l.a.clone(), t1, &mut Vec::new());
    let out = outputs(|o| l.rib.end_of_rib(l.a.addr, V4, t1, o));
    assert_eq!(next_hops(&out), vec![None]);
    assert_eq!(a_route(&l), vec![]);
}

#[test]
fn a_deferred_selection_shows_nobody_a_state_that_changes_meanwhile() {
    let mut rib = Rib::new(LOCAL_AS);
    let t0 = now();
    rib.set_invalid_action(InvalidAction::Drop, t0, &mut Vec::new());
    let a = gr_peer("10.0.0.1", 65_001, 1);
    let b = peer("10.0.0.2", 65_002, 2);
    // RFC 4724 §4.1: a restarted speaker waits for A's End-of-RIB; B,
    // without the capability, is not waited for.
    rib.defer_selection(&Deferral {
        waiting: vec![(a.addr, vec![V4, V6])],
        until: t0 + RESTART,
    });
    let mut out = Vec::new();
    rib.peer_up(a.clone(), t0, &mut out);
    rib.peer_up(b.clone(), t0, &mut out);
    // A's routes come before the first VRPs: no state yet, candidates.
    rib.update(
        a.addr,
        &announce(&[PREFIX, OTHER], &attrs(&[65_001], "10.0.0.1")),
        t0,
        &mut out,
    );
    assert!(fib(&out).is_empty() && sends(&out, b.addr).is_empty());
    // The first VRPs make the route to PREFIX Invalid, and `drop` holds it.
    // Selection is deferred, so neither the FIB nor B hears of it.
    let out = outputs(|o| rib.validation_changed(all(vrps(&[(PREFIX, 24, 64_496)])), t0, o));
    assert!(fib(&out).is_empty(), "{out:?}");
    assert!(sends(&out, b.addr).is_empty(), "{out:?}");
    assert_eq!(rib.held(V4, p(PREFIX)).len(), 1);
    // A's End-of-RIB markers end the deferral: the forwarding state is
    // brought up to date from the Loc-RIB, which has the route to OTHER
    // alone, and B is sent that one only.
    let out = outputs(|o| {
        rib.end_of_rib(a.addr, V4, t0, o);
        rib.end_of_rib(a.addr, V6, t0, o);
    });
    assert!(
        out.iter()
            .any(|o| matches!(o, Output::SelectionDone { family } if *family == V4))
    );
    assert_eq!(
        rib.fib_routes_of(V4)
            .map(|(prefix, _)| prefix)
            .collect::<Vec<_>>(),
        vec![p(OTHER)]
    );
    let announced: Vec<Prefix> = sent(&out, &b)
        .into_iter()
        .flat_map(|(_, nlri)| nlri)
        .collect();
    assert_eq!(announced, vec![p(OTHER)]);
}

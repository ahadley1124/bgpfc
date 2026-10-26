//! Origin validation acted on (RFC 6811 §5, `invalid drop`) on sessions
//! with the capabilities stitched before it. A neighbor that sends several
//! paths of a prefix (RFC 7911 §5) has each held or used under its own
//! Path Identifier, and a route held from a session with a BGP Role is
//! held as the RFC 9234 §5 ingress procedure made it, while a route leak
//! is not held at all.

use bgpfc_rpki::{InvalidAction, RovState::*};
use bgpfc_wire::role::Role;
use bgpfc_wire::types::PathId;
use bgpfc_wire::update::PathIds;

use super::roles::{leaks, sent_otc};
use super::validation::{all, vrps};
use super::*;
use crate::RouteRef;

const PREFIX: &str = "192.0.2.0/24";

/// A RIB that drops the Invalid, with VRPs under which [`PREFIX`] is Valid
/// from AS 64497 alone and Invalid from any other origin.
fn dropping() -> Rib {
    let mut rib = Rib::new(LOCAL_AS);
    rib.set_invalid_action(InvalidAction::Drop, now(), &mut Vec::new());
    outputs(|o| rib.validation_changed(all(vrps(&[(PREFIX, 24, 64_497)])), now(), o));
    rib
}

/// The VRPs of [`dropping`] with one for AS 64496 too.
fn both_origins() -> bgpfc_rpki::ValidationChange {
    all(vrps(&[(PREFIX, 24, 64_497), (PREFIX, 24, 64_496)]))
}

/// [`PREFIX`] announced with `a` under Path Identifier `id`.
fn announce_path(id: u32, a: &PathAttrs) -> DecodedUpdate {
    let mut update = announce(&[PREFIX], a);
    update.message.path_ids = Some(Box::new(PathIds {
        nlri: vec![PathId(id)],
        ..PathIds::default()
    }));
    update
}

/// The withdrawal of [`PREFIX`] under Path Identifier `id`.
fn withdraw_path(id: u32) -> DecodedUpdate {
    let mut update = withdraw(&[PREFIX]);
    update.message.path_ids = Some(Box::new(PathIds {
        withdrawn: vec![PathId(id)],
        ..PathIds::default()
    }));
    update
}

/// The Path Identifiers of `routes`, in order, with their states.
fn ids(routes: &[RouteRef<'_>]) -> Vec<(Option<u32>, RovState)> {
    routes
        .iter()
        .map(|r| (r.path_id.map(|i| i.0), r.rov))
        .collect()
}

/// The next hops the FIB is given.
fn next_hops(out: &[Output]) -> Vec<Option<IpAddr>> {
    fib(out).iter().map(|c| c.next_hop).collect()
}

#[test]
fn an_invalid_path_is_held_under_its_identifier_and_taken_back_under_it() {
    // RFC 7911 §5: a route is the prefix with its Path Identifier, so one
    // path of a neighbor can be held for being Invalid (RFC 6811 §2) while
    // another of the same neighbor and prefix is used.
    let mut rib = dropping();
    let e1 = PeerInfo {
        add_path_receive: vec![V4],
        ..peer("10.0.0.1", 65_001, 1)
    };
    let watcher = peer("10.0.0.3", 65_000, 3);
    for info in [&e1, &watcher] {
        outputs(|o| rib.peer_up(info.clone(), now(), o));
    }
    // Path 1 is Invalid and the shorter of the two; path 2 is Valid.
    let short = attrs(&[65_001, 64_496], "10.0.0.1");
    let long = attrs(&[65_001, 100, 64_497], "10.0.0.11");
    let out = outputs(|o| rib.update(e1.addr, &announce_path(1, &short), now(), o));
    assert_eq!(next_hops(&out), vec![]);
    assert_eq!(sends(&out, watcher.addr).len(), 0);
    let out = outputs(|o| rib.update(e1.addr, &announce_path(2, &long), now(), o));
    assert_eq!(next_hops(&out), vec![Some(ip("10.0.0.11"))]);
    assert_eq!(ids(&rib.candidates(V4, p(PREFIX))), vec![(Some(2), Valid)]);
    assert_eq!(ids(&rib.held(V4, p(PREFIX))), vec![(Some(1), Invalid)]);
    // Both are in the Adj-RIB-In, and the RFC 4271 §6.7 limit counts both.
    assert_eq!(
        rib.peer_stats(e1.addr).unwrap().received,
        vec![(V4, 2), (V6, 0)]
    );

    // A ROA for the origin of path 1 makes it a candidate again under its
    // identifier, and the better path, with no UPDATE from e1 (§4).
    let out = outputs(|o| rib.validation_changed(both_origins(), now(), o));
    assert_eq!(next_hops(&out), vec![Some(ip("10.0.0.1"))]);
    assert_eq!(
        ids(&rib.candidates(V4, p(PREFIX))),
        vec![(Some(1), Valid), (Some(2), Valid)]
    );
    assert_eq!(ids(&rib.held(V4, p(PREFIX))), vec![]);

    // The ROA goes: path 1 is held again, and path 2 is used.
    let out = outputs(|o| rib.validation_changed(all(vrps(&[(PREFIX, 24, 64_497)])), now(), o));
    assert_eq!(next_hops(&out), vec![Some(ip("10.0.0.11"))]);
    assert_eq!(ids(&rib.held(V4, p(PREFIX))), vec![(Some(1), Invalid)]);

    // Withdrawing path 1 takes the held path alone; path 2 stays the best.
    let out = outputs(|o| rib.update(e1.addr, &withdraw_path(1), now(), o));
    assert_eq!(next_hops(&out), vec![]);
    assert_eq!(sends(&out, watcher.addr).len(), 0);
    assert_eq!(ids(&rib.held(V4, p(PREFIX))), vec![]);
    assert_eq!(ids(&rib.candidates(V4, p(PREFIX))), vec![(Some(2), Valid)]);
    assert_eq!(
        rib.peer_stats(e1.addr).unwrap().received,
        vec![(V4, 1), (V6, 0)]
    );

    // Path 2 announced again from an Invalid origin replaces the Valid one
    // and is held in its place: the destination has nothing left to use.
    let invalid = attrs(&[65_001, 64_499], "10.0.0.11");
    let out = outputs(|o| rib.update(e1.addr, &announce_path(2, &invalid), now(), o));
    assert_eq!(next_hops(&out), vec![None]);
    assert_eq!(ids(&rib.candidates(V4, p(PREFIX))), vec![]);
    assert_eq!(ids(&rib.held(V4, p(PREFIX))), vec![(Some(2), Invalid)]);
    assert_eq!(
        rib.peer_stats(e1.addr).unwrap().received,
        vec![(V4, 1), (V6, 0)]
    );
}

#[test]
fn a_route_held_from_a_provider_keeps_the_otc_its_ingress_gave_it() {
    // RFC 9234 §5: the ingress procedure runs once, on arrival, and a route
    // held for being Invalid is held as it made it. Taken back by a VRP
    // change, it has the attribute, so egress passes it to the customer
    // and keeps it from the other provider.
    let mut rib = dropping();
    let provider = PeerInfo {
        role: Some(Role::Customer),
        ..peer("10.0.0.1", 65_001, 1)
    };
    let other_provider = PeerInfo {
        role: Some(Role::Customer),
        ..peer("10.0.0.2", 65_002, 2)
    };
    let customer = PeerInfo {
        role: Some(Role::Provider),
        ..peer("10.0.0.4", 65_004, 4)
    };
    for info in [&provider, &other_provider, &customer] {
        outputs(|o| rib.peer_up(info.clone(), now(), o));
    }
    let out = outputs(|o| {
        rib.update(
            provider.addr,
            &announce(&[PREFIX], &attrs(&[65_001, 64_496], "10.0.0.1")),
            now(),
            o,
        );
    });
    assert_eq!(sends(&out, customer.addr).len(), 0);
    let held: Vec<_> = rib
        .held(V4, p(PREFIX))
        .iter()
        .map(|r| (r.rov, r.attrs.otc))
        .collect();
    assert_eq!(held, vec![(Invalid, Some(Asn(65_001)))]);

    let out = outputs(|o| rib.validation_changed(both_origins(), now(), o));
    let best: Vec<_> = rib.loc_rib(V4).map(|(_, r)| r.attrs.otc).collect();
    assert_eq!(best, vec![Some(Asn(65_001))]);
    assert_eq!(sent_otc(&out, &customer), vec![Some(Asn(65_001))]);
    assert_eq!(sends(&out, other_provider.addr).len(), 0);
}

#[test]
fn a_route_leak_is_not_held_whatever_its_validation_state() {
    // RFC 9234 §5: a leak "MUST be considered ineligible", and no state
    // makes it eligible, so the Adj-RIB-In does not hold it the way it
    // holds an Invalid route (RFC 6811 §2): a VRP change brings nothing
    // back.
    let mut rib = dropping();
    let customer = PeerInfo {
        role: Some(Role::Provider),
        ..peer("10.0.0.4", 65_004, 4)
    };
    outputs(|o| rib.peer_up(customer.clone(), now(), o));
    let route = attrs(&[65_004, 64_496], "10.0.0.4");
    outputs(|o| rib.update(customer.addr, &announce(&[PREFIX], &route), now(), o));
    assert_eq!(ids(&rib.held(V4, p(PREFIX))), vec![(None, Invalid)]);

    // The same route with the attribute is a leak, and replaces the one
    // held: nothing is held for the prefix any more.
    let leaked = PathAttrs {
        otc: Some(Asn(65_099)),
        ..route
    };
    let out = outputs(|o| rib.update(customer.addr, &announce(&[PREFIX], &leaked), now(), o));
    assert_eq!(
        leaks(&out),
        vec![(customer.addr, Asn(65_099), 1, p(PREFIX))]
    );
    assert_eq!(ids(&rib.held(V4, p(PREFIX))), vec![]);
    assert_eq!(
        rib.peer_stats(customer.addr).unwrap().received,
        vec![(V4, 0), (V6, 0)]
    );

    let out = outputs(|o| rib.validation_changed(both_origins(), now(), o));
    assert_eq!(next_hops(&out), vec![]);
    assert_eq!(ids(&rib.candidates(V4, p(PREFIX))), vec![]);
}

//! The operator's enforcement mode (issues #61, #60; RFC 6811 §5): under
//! `drop-invalid` an Invalid route is held in the Adj-RIB-In, counted,
//! neither installed nor advertised, and used again with no UPDATE once
//! its state allows (RFC 6811 §2, §4); a change of mode judges every
//! route again.

use bgpfc_rpki::Enforcement::{self, DropInvalid, Off, PreferValid};

use super::*;

/// Two external peers: e1 sends, e2 receives.
fn two_peers(rib: &mut Rib) -> (PeerInfo, PeerInfo) {
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_002, 2);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    outputs(|o| rib.peer_up(e2.clone(), now(), o));
    (e1, e2)
}

/// A ROA for 192.0.2.0/24 that makes e1's routes to it, from AS 64496,
/// Invalid; e1's route to 198.51.100.0/24 is `NotFound`.
fn other_origin() -> VrpSet {
    vrps(&[("192.0.2.0/24", 24, 64_497)])
}

/// The ROA that makes them Valid.
fn their_origin() -> VrpSet {
    vrps(&[("192.0.2.0/24", 24, 64_496)])
}

/// e1's routes to `prefixes`, from AS 64496.
fn send(rib: &mut Rib, e1: &PeerInfo, prefixes: &[&str]) -> Vec<Output> {
    let a = attrs(&[65_001, 64_496], "10.0.0.1");
    outputs(|o| rib.update(e1.addr, &announce(prefixes, &a), now(), o))
}

/// The announcements and withdrawals sent to `to`: (NLRI, withdrawn).
fn sent(out: &[Output], to: &PeerInfo) -> (Vec<Prefix>, Vec<Prefix>) {
    let mut nlri = Vec::new();
    let mut withdrawn = Vec::new();
    for messages in sends(out, to.addr) {
        for m in decode_sent(messages, to) {
            nlri.extend(m.nlri);
            withdrawn.extend(m.withdrawn);
        }
    }
    (nlri, withdrawn)
}

/// The one report of a change of mode in `out`, which comes first.
fn rejudged(out: &[Output]) -> &Rejudged {
    let reports: Vec<&Rejudged> = out
        .iter()
        .filter_map(|o| match o {
            Output::Enforcement(r) => Some(r),
            _ => None,
        })
        .collect();
    assert_eq!(reports.len(), 1, "{out:?}");
    assert!(matches!(out[0], Output::Enforcement(_)), "{out:?}");
    reports[0]
}

/// The routes the RIB holds for `prefix` of IPv4: peer, looked-up state
/// and why it is held.
fn kept(rib: &Rib, prefix: &str) -> Vec<(IpAddr, RovState, Option<Held>)> {
    rib.routes(V4, p(prefix))
        .iter()
        .map(|r| (r.peer, r.rov, r.held))
        .collect()
}

/// What `peer_stats` counts for `addr` in IPv4: received, held.
fn counted(rib: &Rib, addr: IpAddr) -> (usize, usize) {
    let s = rib.peer_stats(addr).unwrap();
    (s.received[0].1, s.held[0].1)
}

#[test]
fn a_rib_applies_no_enforcement_until_told() {
    // RFC 8481 §5: "Absent specific operator configuration, policy MUST
    // NOT be applied."
    let mut rib = Rib::new(LOCAL_AS);
    assert_eq!(rib.enforcement(), Off);
    let (e1, e2) = two_peers(&mut rib);
    outputs(|o| rib.validation_changed(all(other_origin()), now(), o));
    let out = send(&mut rib, &e1, &["192.0.2.0/24"]);
    assert_eq!(fib(&out).len(), 1);
    assert_eq!(sent(&out, &e2).0, vec![p("192.0.2.0/24")]);
    assert_eq!(
        kept(&rib, "192.0.2.0/24"),
        vec![(e1.addr, RovState::Invalid, None)]
    );
}

#[test]
fn invalid_routes_are_held_not_used_under_drop_invalid() {
    let mut rib = Rib::new(LOCAL_AS);
    let out = outputs(|o| rib.set_enforcement(DropInvalid, now(), o));
    // Nothing to judge yet; the change is reported all the same.
    assert_eq!(
        out,
        vec![Output::Enforcement(Rejudged {
            from: Off,
            to: DropInvalid,
            routes: 0,
            held: 0,
            released: 0,
            best_changed: 0,
        })]
    );
    assert_eq!(rib.enforcement(), DropInvalid);
    let (e1, e2) = two_peers(&mut rib);
    outputs(|o| rib.validation_changed(all(other_origin()), now(), o));
    let out = send(&mut rib, &e1, &["192.0.2.0/24", "198.51.100.0/24"]);
    // RFC 6811 §5, "rejecting all "invalid" routes": the Invalid route is
    // neither installed nor advertised; the NotFound one is both.
    assert_eq!(
        fib(&out),
        vec![FibChange {
            family: V4,
            prefix: p("198.51.100.0/24"),
            next_hop: Some(ip("10.0.0.1")),
            previous: None,
        }]
    );
    assert_eq!(sent(&out, &e2), (vec![p("198.51.100.0/24")], vec![]));
    // RFC 6811 §2: but the Adj-RIB-In keeps it, as received, and counts
    // it as received and as held.
    assert_eq!(
        kept(&rib, "192.0.2.0/24"),
        vec![(e1.addr, RovState::Invalid, Some(Held::Enforcement))]
    );
    assert!(rib.candidates(V4, p("192.0.2.0/24")).is_empty());
    let held: Vec<(Prefix, IpAddr, Option<Held>)> =
        rib.held(V4).map(|(p, r)| (p, r.peer, r.held)).collect();
    assert_eq!(
        held,
        vec![(p("192.0.2.0/24"), e1.addr, Some(Held::Enforcement))]
    );
    assert_eq!(rib.held(V6).count(), 0);
    let loc: Vec<Prefix> = rib.loc_rib(V4).map(|(p, _)| p).collect();
    assert_eq!(loc, vec![p("198.51.100.0/24")]);
    let stats = rib.peer_stats(e1.addr).unwrap();
    assert_eq!(stats.received, vec![(V4, 2), (V6, 0)]);
    assert_eq!(stats.held, vec![(V4, 1), (V6, 0)]);
    assert_eq!(counted(&rib, e2.addr), (0, 0));
}

#[test]
fn a_held_invalid_route_returns_when_it_becomes_valid_without_an_update() {
    // Issue #59: "A route flipping from Invalid to Valid produces an
    // advertisement", with no UPDATE (RFC 6811 §4).
    let mut rib = Rib::new(LOCAL_AS);
    outputs(|o| rib.set_enforcement(DropInvalid, now(), o));
    let (e1, e2) = two_peers(&mut rib);
    outputs(|o| rib.validation_changed(all(other_origin()), now(), o));
    send(&mut rib, &e1, &["192.0.2.0/24"]);
    assert_eq!(counted(&rib, e1.addr), (1, 1));
    let out = outputs(|o| {
        rib.validation_changed(delta(&other_origin(), their_origin()), now(), o);
    });
    assert_eq!(
        report(&out),
        Some(&one_moved(
            Revalidation {
                released: 1,
                ..revalidation(
                    1,
                    &[(RovState::Invalid, RovState::Valid, 1)],
                    &["192.0.2.0/24"],
                    1
                )
            },
            e1.addr,
            RouteStatus::Best
        ))
    );
    assert_eq!(
        fib(&out),
        vec![FibChange {
            family: V4,
            prefix: p("192.0.2.0/24"),
            next_hop: Some(ip("10.0.0.1")),
            previous: None,
        }]
    );
    assert_eq!(sent(&out, &e2), (vec![p("192.0.2.0/24")], vec![]));
    assert_eq!(
        kept(&rib, "192.0.2.0/24"),
        vec![(e1.addr, RovState::Valid, None)]
    );
    assert_eq!(counted(&rib, e1.addr), (1, 0));
}

#[test]
fn a_used_route_that_turns_invalid_is_withdrawn_from_peers_and_the_fib() {
    // Issue #59: "A route flipping to Invalid under the default policy
    // produces a withdraw toward peers."
    let mut rib = Rib::new(LOCAL_AS);
    outputs(|o| rib.set_enforcement(DropInvalid, now(), o));
    let (e1, e2) = two_peers(&mut rib);
    outputs(|o| rib.validation_changed(all(their_origin()), now(), o));
    let out = send(&mut rib, &e1, &["192.0.2.0/24"]);
    assert_eq!(sent(&out, &e2), (vec![p("192.0.2.0/24")], vec![]));
    let out = outputs(|o| {
        rib.validation_changed(delta(&their_origin(), other_origin()), now(), o);
    });
    assert_eq!(
        report(&out),
        Some(&one_moved(
            Revalidation {
                held: 1,
                ..revalidation(
                    1,
                    &[(RovState::Valid, RovState::Invalid, 1)],
                    &["192.0.2.0/24"],
                    1
                )
            },
            e1.addr,
            RouteStatus::Held(Held::Enforcement)
        ))
    );
    assert_eq!(
        fib(&out),
        vec![FibChange {
            family: V4,
            prefix: p("192.0.2.0/24"),
            next_hop: None,
            previous: Some(ip("10.0.0.1")),
        }]
    );
    assert_eq!(sent(&out, &e2), (vec![], vec![p("192.0.2.0/24")]));
    assert_eq!(
        kept(&rib, "192.0.2.0/24"),
        vec![(e1.addr, RovState::Invalid, Some(Held::Enforcement))]
    );
    assert_eq!(counted(&rib, e1.addr), (1, 1));
    assert_eq!(rib.loc_rib(V4).count(), 0);
}

#[test]
fn set_rpki_valid_overrides_drop_invalid() {
    // RFC 6811 §3: an operator's `set rpki valid` (here, on Invalid
    // routes) wins over the global drop, which acts on the state the
    // route is used with.
    let mut rib = Rib::with_policies(
        LOCAL_AS,
        Box::new(Override::new(RovState::Invalid, RovState::Valid)),
    );
    outputs(|o| rib.set_enforcement(DropInvalid, now(), o));
    let (e1, e2) = two_peers(&mut rib);
    outputs(|o| rib.validation_changed(all(other_origin()), now(), o));
    let out = send(&mut rib, &e1, &["192.0.2.0/24"]);
    assert_eq!(fib(&out).len(), 1);
    assert_eq!(sent(&out, &e2), (vec![p("192.0.2.0/24")], vec![]));
    let c = rib.candidates(V4, p("192.0.2.0/24"));
    assert_eq!(
        (c[0].rov, c[0].rov_set, c[0].held),
        (RovState::Invalid, Some(RovState::Valid), None)
    );
    assert_eq!(counted(&rib, e1.addr), (1, 0));
}

#[test]
fn set_rpki_invalid_drops_under_drop_invalid() {
    // Policy sets Invalid on NotFound routes, as an operator who trusts
    // only validated routes from a peer might: under drop-invalid the
    // route is held, not used. It is kept whatever its own state, so that
    // another mode, set by a reload with no ROUTE-REFRESH, can use it.
    let mut rib = Rib::with_policies(
        LOCAL_AS,
        Box::new(Override::new(RovState::NotFound, RovState::Invalid)),
    );
    let (e1, e2) = two_peers(&mut rib);
    outputs(|o| rib.validation_changed(all(VrpSet::new()), now(), o));
    let out = send(&mut rib, &e1, &["192.0.2.0/24"]);
    // Off: the set state is shown, and nothing acts on it.
    assert_eq!(fib(&out).len(), 1);
    let out = outputs(|o| rib.set_enforcement(DropInvalid, now(), o));
    assert_eq!(
        *rejudged(&out),
        Rejudged {
            from: Off,
            to: DropInvalid,
            routes: 1,
            held: 1,
            released: 0,
            best_changed: 1,
        }
    );
    assert_eq!(sent(&out, &e2), (vec![], vec![p("192.0.2.0/24")]));
    let r = rib.routes(V4, p("192.0.2.0/24"));
    assert_eq!(
        (r[0].rov, r[0].rov_set, r[0].held),
        (
            RovState::NotFound,
            Some(RovState::Invalid),
            Some(Held::Enforcement)
        )
    );
    assert_eq!(counted(&rib, e1.addr), (1, 1));
    // Back to off: used again.
    let out = outputs(|o| rib.set_enforcement(Off, now(), o));
    assert_eq!(
        (rejudged(&out).released, rejudged(&out).best_changed),
        (1, 1)
    );
    assert_eq!(sent(&out, &e2), (vec![p("192.0.2.0/24")], vec![]));
    assert_eq!(counted(&rib, e1.addr), (1, 0));
}

#[test]
fn set_enforcement_rejudges_every_route_and_reports_once() {
    // Every pair of modes: an Invalid, a NotFound and a Valid route, one
    // destination each, judged again under the new mode. Only a move to
    // or from drop-invalid changes what is used.
    for from in Enforcement::ALL {
        for to in Enforcement::ALL {
            let mut rib = Rib::new(LOCAL_AS);
            outputs(|o| rib.set_enforcement(from, now(), o));
            let (e1, e2) = two_peers(&mut rib);
            let set = vrps(&[("192.0.2.0/24", 24, 64_497), ("203.0.113.0/24", 24, 64_496)]);
            outputs(|o| rib.validation_changed(all(set), now(), o));
            send(
                &mut rib,
                &e1,
                &["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"],
            );
            let held_before = counted(&rib, e1.addr).1;
            let out = outputs(|o| rib.set_enforcement(to, now(), o));
            assert_eq!(rib.enforcement(), to);
            if from == to {
                assert_eq!(out, vec![], "{from} -> {to}");
                continue;
            }
            let (held, released) = match (from, to) {
                (_, DropInvalid) => (1, 0),
                (DropInvalid, _) => (0, 1),
                _ => (0, 0),
            };
            assert_eq!(
                *rejudged(&out),
                Rejudged {
                    from,
                    to,
                    routes: 3,
                    held,
                    released,
                    best_changed: held + released,
                },
                "{from} -> {to}"
            );
            let (nlri, withdrawn) = sent(&out, &e2);
            assert_eq!(nlri.len(), released, "{from} -> {to}");
            assert_eq!(withdrawn.len(), held, "{from} -> {to}");
            assert_eq!(fib(&out).len(), held + released, "{from} -> {to}");
            let held_after = counted(&rib, e1.addr).1;
            assert_eq!(held_after + released, held_before + held, "{from} -> {to}");
            let expected = if to == DropInvalid { 2 } else { 3 };
            assert_eq!(rib.loc_rib(V4).count(), expected, "{from} -> {to}");
        }
    }
}

#[test]
fn a_route_policy_rejects_by_state_is_held_by_policy_not_enforcement() {
    // Import policy rejects Invalid routes itself: the route is held for
    // policy, whatever the mode, and a change of mode does not move it.
    let mut rib = Rib::with_policies(LOCAL_AS, Box::new(RejectInvalidTagValid));
    outputs(|o| rib.set_enforcement(DropInvalid, now(), o));
    let (e1, _) = two_peers(&mut rib);
    outputs(|o| rib.validation_changed(all(other_origin()), now(), o));
    send(&mut rib, &e1, &["192.0.2.0/24"]);
    assert_eq!(
        kept(&rib, "192.0.2.0/24"),
        vec![(e1.addr, RovState::Invalid, Some(Held::Policy))]
    );
    for mode in [Off, PreferValid, DropInvalid] {
        let out = outputs(|o| rib.set_enforcement(mode, now(), o));
        let r = rejudged(&out);
        assert_eq!((r.routes, r.held, r.released), (1, 0, 0), "{mode}");
        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!(
            kept(&rib, "192.0.2.0/24"),
            vec![(e1.addr, RovState::Invalid, Some(Held::Policy))]
        );
        assert_eq!(counted(&rib, e1.addr), (1, 1));
    }
}

#[test]
fn expiry_releases_every_route_held_by_enforcement() {
    // RFC 8210 §6: VRPs past their Expire Interval are not kept, and the
    // client then publishes an empty set: every route is NotFound, and
    // every route held for being Invalid is used again (it fails open).
    let mut rib = Rib::new(LOCAL_AS);
    outputs(|o| rib.set_enforcement(DropInvalid, now(), o));
    let (e1, e2) = two_peers(&mut rib);
    let set = vrps(&[("192.0.2.0/23", 24, 64_497)]);
    outputs(|o| rib.validation_changed(all(set.clone()), now(), o));
    send(
        &mut rib,
        &e1,
        &["192.0.2.0/24", "192.0.3.0/24", "198.51.100.0/24"],
    );
    assert_eq!(counted(&rib, e1.addr), (3, 2));
    let out = outputs(|o| rib.validation_changed(all(VrpSet::new()), now(), o));
    let r = report(&out).unwrap();
    assert_eq!(r.changes, vec![(RovState::Invalid, RovState::NotFound, 2)]);
    assert_eq!((r.held, r.released, r.best_changed), (0, 2, 2));
    assert_eq!(fib(&out).len(), 2);
    assert_eq!(
        sent(&out, &e2),
        (vec![p("192.0.2.0/24"), p("192.0.3.0/24")], vec![])
    );
    assert_eq!(rib.held(V4).count(), 0);
    assert_eq!(counted(&rib, e1.addr), (3, 0));
}

#[test]
fn a_flapping_vrp_set_sends_at_most_one_announcement_and_one_withdrawal_per_interval() {
    // Issue #59, design §D5: validation-driven changes go through the RFC
    // 4271 §9.2.1.1 pacing. A ROA flapping every second moves a route in
    // and out of use; withdrawals go at once, but a re-advertisement waits
    // for the end of the interval, and one the next withdrawal overtakes
    // is not sent. So the peer hears at most one announcement and one
    // withdrawal of the destination per interval.
    let mut rib = Rib::new(LOCAL_AS);
    let t0 = now();
    outputs(|o| rib.set_enforcement(DropInvalid, t0, o));
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = paced("10.0.0.2", 65_002, 2, Duration::from_secs(30));
    outputs(|o| rib.peer_up(e1.clone(), t0, o));
    outputs(|o| rib.peer_up(e2.clone(), t0, o));
    outputs(|o| rib.validation_changed(all(their_origin()), t0, o));
    let out = outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_001, 64_496], "10.0.0.1")),
            t0,
            o,
        );
    });
    let mut heard = vec![(0, sent_for(&out, &e2, p("192.0.2.0/24")))];
    let mut valid = true;
    for s in 1..95 {
        let t = secs(t0, s);
        let (from, to) = if valid {
            (their_origin(), other_origin())
        } else {
            (other_origin(), their_origin())
        };
        valid = !valid;
        let mut out = outputs(|o| rib.flush(t, o));
        out.extend(outputs(|o| rib.validation_changed(delta(&from, to), t, o)));
        heard.push((s, sent_for(&out, &e2, p("192.0.2.0/24"))));
    }
    // Per interval of 30 s (no jitter here), one of each: the
    // advertisement held to the end of the last interval, then the next
    // withdrawal; every other move inside the interval is not sent.
    for window in 0..3u64 {
        let in_window: Vec<&Option<Vec<Asn>>> = heard
            .iter()
            .filter(|(s, _)| (window * 30..(window + 1) * 30).contains(s))
            .flat_map(|(_, v)| v)
            .collect();
        let announced = in_window.iter().filter(|m| m.is_some()).count();
        let withdrawn = in_window.iter().filter(|m| m.is_none()).count();
        assert_eq!((announced, withdrawn), (1, 1), "{window}: {heard:?}");
    }
}

#[test]
fn prefer_valid_uses_the_state_import_policy_set() {
    // RFC 6811 §3: the state import policy set is the one the route is
    // ranked with. e1's route is Invalid but used as Valid, e3's is Valid:
    // ranked as used they tie, and e1's lower router ID wins; ranked as
    // looked up, e3's would.
    let mut rib = Rib::with_policies(
        LOCAL_AS,
        Box::new(Override::new(RovState::Invalid, RovState::Valid)),
    );
    outputs(|o| rib.set_enforcement(PreferValid, now(), o));
    let (e1, _) = two_peers(&mut rib);
    let e3 = peer("10.0.0.3", 65_003, 3);
    outputs(|o| rib.peer_up(e3.clone(), now(), o));
    outputs(|o| rib.validation_changed(all(other_origin()), now(), o));
    send(&mut rib, &e1, &["192.0.2.0/24"]);
    // From AS 64497, the ROA's: Valid.
    outputs(|o| {
        rib.update(
            e3.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_003, 64_497], "10.0.0.3")),
            now(),
            o,
        );
    });
    // Both Valid as used: the router ID decides, e1's route.
    let best = rib.loc_rib(V4).next().unwrap().1;
    assert_eq!(
        (best.peer, best.rov, best.effective_rov()),
        (e1.addr, RovState::Invalid, RovState::Valid)
    );
    // Without the override, e1's route is Invalid and ranks last.
    rib.set_policies(Box::new(crate::AcceptAll), &[], now(), &mut Vec::new());
    let out = send(&mut rib, &e1, &["192.0.2.0/24"]);
    assert_eq!(rib.loc_rib(V4).next().unwrap().1.peer, e3.addr);
    assert_eq!(fib(&out)[0].next_hop, Some(ip("10.0.0.3")));
}

#[test]
fn prefer_valid_switch_redecides_without_holding_anything() {
    // Switching to prefer-valid ranks the routes again: the Valid route
    // takes over from the Invalid one with the higher LOCAL_PREF, and no
    // route is held. Back to off, LOCAL_PREF decides again.
    let mut rib = Rib::with_policies(LOCAL_AS, Box::new(RaiseFrom("10.0.0.1".parse().unwrap())));
    let (e1, e2) = two_peers(&mut rib);
    let e3 = peer("10.0.0.3", 65_003, 3);
    outputs(|o| rib.peer_up(e3.clone(), now(), o));
    outputs(|o| rib.validation_changed(all(other_origin()), now(), o));
    send(&mut rib, &e1, &["192.0.2.0/24"]);
    outputs(|o| {
        rib.update(
            e3.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_003, 64_497], "10.0.0.3")),
            now(),
            o,
        );
    });
    assert_eq!(rib.loc_rib(V4).next().unwrap().1.peer, e1.addr);
    let out = outputs(|o| rib.set_enforcement(PreferValid, now(), o));
    assert_eq!(
        *rejudged(&out),
        Rejudged {
            from: Off,
            to: PreferValid,
            routes: 2,
            held: 0,
            released: 0,
            best_changed: 1,
        }
    );
    assert_eq!(
        fib(&out),
        vec![FibChange {
            family: V4,
            prefix: p("192.0.2.0/24"),
            next_hop: Some(ip("10.0.0.3")),
            previous: Some(ip("10.0.0.1")),
        }]
    );
    assert_eq!(sent(&out, &e2).0, vec![p("192.0.2.0/24")]);
    assert_eq!(rib.held(V4).count(), 0);
    assert_eq!(rib.candidates(V4, p("192.0.2.0/24")).len(), 2);
    let out = outputs(|o| rib.set_enforcement(Off, now(), o));
    assert_eq!(rejudged(&out).best_changed, 1);
    assert_eq!(rib.loc_rib(V4).next().unwrap().1.peer, e1.addr);
}

/// Import policy that gives the routes of one peer `LOCAL_PREF` 200.
struct RaiseFrom(IpAddr);

impl Policies for RaiseFrom {
    fn import(
        &self,
        from: &PeerInfo,
        _: AddressFamily,
        _: Prefix,
        a: &PathAttrs,
        _: RovState,
    ) -> Imported {
        if from.addr != self.0 {
            return Verdict::Accept.into();
        }
        let mut a = a.clone();
        a.local_pref = Some(200);
        Verdict::Modified(a).into()
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

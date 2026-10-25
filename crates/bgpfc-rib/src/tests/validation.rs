//! Every route carries its RFC 6811 validation state (issue #56), policy
//! sees it (RFC 6811 §3), and it follows the validation source, which
//! re-runs import policy and the decision process for the routes whose
//! state changed (RFC 6811 §4).

use std::sync::Mutex;

use bgpfc_rpki::{AffectedPrefixes, PrefixSet, ValidationChange, Vrp, VrpSet};
use bgpfc_wire::update::EncodeContext;

use super::*;
use crate::{Held, Imported, Policies, Rejudged, Revalidation, RouteOrigin, RouteStatus, Verdict};

mod enforcement;

/// What a policy was asked about, and the validation state it was told.
type Seen = Arc<Mutex<Vec<(&'static str, Prefix, RovState)>>>;

/// Accepts every route and records each question it is asked.
struct Record(Seen);

impl Policies for Record {
    fn import(
        &self,
        _: &PeerInfo,
        _: AddressFamily,
        p: Prefix,
        _: &PathAttrs,
        rov: RovState,
    ) -> Imported {
        self.0.lock().unwrap().push(("import", p, rov));
        Verdict::Accept.into()
    }
    fn export(
        &self,
        _: &PeerInfo,
        _: AddressFamily,
        p: Prefix,
        _: &PathAttrs,
        rov: RovState,
    ) -> Verdict {
        self.0.lock().unwrap().push(("export", p, rov));
        Verdict::Accept
    }
}

#[test]
fn without_a_validation_source_every_route_is_disabled() {
    // Issue #56: the null source answers Disabled for everything, which is
    // not NotFound (issue #52).
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    let i1 = peer("10.0.0.2", 65_000, 2);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    outputs(|o| rib.peer_up(i1.clone(), now(), o));
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_001, 64_496], "10.0.0.1")),
            now(),
            o,
        );
    });
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["2001:db8::/32"], &attrs(&[65_001], "2001:db8::1")),
            now(),
            o,
        );
    });
    // An empty AS_PATH from an internal peer: the route originates in our
    // own AS (RFC 6811 §2).
    outputs(|o| {
        rib.update(
            i1.addr,
            &announce(
                &["192.0.2.0/24", "198.51.100.0/24"],
                &attrs(&[], "10.0.0.2"),
            ),
            now(),
            o,
        );
    });
    for (family, prefix, routes) in [
        (V4, "192.0.2.0/24", 2),
        (V4, "198.51.100.0/24", 1),
        (V6, "2001:db8::/32", 1),
    ] {
        let c = rib.candidates(family, p(prefix));
        assert_eq!(c.len(), routes, "{prefix}");
        for c in c {
            assert_eq!((c.rov, c.aspa), (RovState::Disabled, AspaState::Disabled));
        }
    }
    let best: Vec<_> = rib
        .loc_rib(V4)
        .chain(rib.loc_rib(V6))
        .map(|(_, b)| (b.rov, b.aspa))
        .collect();
    assert_eq!(best, vec![(RovState::Disabled, AspaState::Disabled); 3]);
}

#[test]
fn policy_is_told_the_validation_state() {
    let seen = Seen::default();
    let mut rib = Rib::with_policies(LOCAL_AS, Box::new(Record(Arc::clone(&seen))));
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_002, 2);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    outputs(|o| rib.peer_up(e2.clone(), now(), o));
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_001], "10.0.0.1")),
            now(),
            o,
        );
    });
    let seen = seen.lock().unwrap().clone();
    // Import once, then export to each peer (§9.2 then keeps it from the
    // peer it came from before export policy is asked).
    assert_eq!(
        seen,
        vec![
            ("import", p("192.0.2.0/24"), RovState::Disabled),
            ("export", p("192.0.2.0/24"), RovState::Disabled),
        ]
    );
}

fn vrp(prefix: &str, max_len: u8, asn: u32) -> Vrp {
    Vrp::new(p(prefix), max_len, Asn(asn)).unwrap()
}

fn vrps(list: &[(&str, u8, u32)]) -> VrpSet {
    list.iter().map(|&(p, m, a)| vrp(p, m, a)).collect()
}

/// Switch to `set`, every route affected.
fn all(set: VrpSet) -> ValidationChange {
    ValidationChange {
        source: Arc::new(set),
        affected: AffectedPrefixes::All,
    }
}

/// Go from `old` to `new`, the routes their difference covers affected.
fn delta(old: &VrpSet, new: VrpSet) -> ValidationChange {
    ValidationChange {
        affected: AffectedPrefixes::between(old, &new),
        source: Arc::new(new),
    }
}

/// Each peer's route for `prefix` in the Adj-RIB-In, with its state.
fn held(rib: &Rib, family: AddressFamily, prefix: &str) -> Vec<(IpAddr, RovState)> {
    routes(rib, family, p(prefix))
        .into_iter()
        .map(|(peer, r)| (peer, r.rov))
        .collect()
}

/// The report of the validation states that changed, if `out` has one;
/// it never has two.
fn report(out: &[Output]) -> Option<&Revalidation> {
    let mut reports = out.iter().filter_map(|o| match o {
        Output::Revalidated(r) => Some(r),
        _ => None,
    });
    let first = reports.next();
    assert!(reports.next().is_none(), "two reports in {out:?}");
    first
}

/// `routes` validated again, `changes` among them, at `destinations`.
fn revalidation(
    routes: usize,
    changes: &[(RovState, RovState, usize)],
    destinations: &[&str],
    best_changed: usize,
) -> Revalidation {
    Revalidation {
        routes,
        changes: changes.to_vec(),
        destinations: destinations.len(),
        sample: destinations.iter().map(|d| p(d)).collect(),
        best_changed,
        ..Revalidation::default()
    }
}

/// `r`, the report of a change that moved one route among the RFC 6811
/// states, with that route listed: from `peer`, originated by AS 64496 as
/// the routes here are, and `route` after the change.
fn one_moved(r: Revalidation, peer: IpAddr, route: RouteStatus) -> Revalidation {
    let (from, to, _) = r.changes[0];
    let prefix = r.sample[0];
    let family = match prefix {
        Prefix::V4 { .. } => V4,
        Prefix::V6 { .. } => V6,
    };
    Revalidation {
        transitions: vec![crate::Transition {
            family,
            prefix,
            peer,
            origin: RouteOrigin::As(Asn(64_496)),
            from,
            to,
            route,
        }],
        ..r
    }
}

/// The COMMUNITIES of a sent UPDATE.
fn communities(m: &UpdateMessage) -> Vec<Community> {
    m.attributes
        .iter()
        .find_map(|a| match a {
            PathAttribute::Communities(c) => Some(c.clone()),
            _ => None,
        })
        .unwrap_or_default()
}

/// Import policy that rejects Invalid routes; export policy that tags
/// Valid ones with community 65000:1.
struct RejectInvalidTagValid;

impl Policies for RejectInvalidTagValid {
    fn import(
        &self,
        _: &PeerInfo,
        _: AddressFamily,
        _: Prefix,
        _: &PathAttrs,
        rov: RovState,
    ) -> Imported {
        if rov == RovState::Invalid {
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

#[test]
fn states_are_set_on_arrival_from_the_source() {
    let mut rib = Rib::new(LOCAL_AS);
    // No route yet: nothing to validate again, nothing to report.
    let set = vrps(&[
        ("192.0.2.0/24", 24, 64_496),
        ("198.51.100.0/24", 24, 64_497),
        ("203.0.113.0/24", 24, LOCAL_AS.0),
        ("198.18.0.0/15", 24, 4_200_000_000),
        ("2001:db8::/32", 48, 64_496),
    ]);
    assert_eq!(
        outputs(|o| rib.validation_changed(all(set), now(), o)),
        vec![]
    );
    let e1 = peer("10.0.0.1", 65_001, 1);
    let i1 = peer("10.0.0.2", 65_000, 2);
    let mut old = peer("10.0.0.3", 65_003, 3);
    old.four_octet_as = false;
    for info in [&e1, &i1, &old] {
        outputs(|o| rib.peer_up(info.clone(), now(), o));
    }
    let send = |rib: &mut Rib, from: &PeerInfo, u: &bgpfc_wire::update::DecodedUpdate| {
        outputs(|o| rib.update(from.addr, u, now(), o))
    };
    let v4 = [
        "192.0.2.0/24",
        "192.0.2.0/25",
        "198.51.100.0/24",
        "10.0.0.0/8",
    ];
    let out = send(
        &mut rib,
        &e1,
        &announce(&v4, &attrs(&[65_001, 64_496], "10.0.0.1")),
    );
    // A route's first state is not a change.
    assert_eq!(report(&out), None);
    let v6 = ["2001:db8:1::/48", "2001:db8:1::/64"];
    send(
        &mut rib,
        &e1,
        &announce(&v6, &attrs(&[65_001, 64_496], "2001:db8::1")),
    );
    // RFC 6811 §2: an empty AS_PATH originates in our own AS.
    send(
        &mut rib,
        &i1,
        &announce(&["203.0.113.0/24"], &attrs(&[], "10.0.0.2")),
    );
    // A final AS_SET: the origin is NONE, which no VRP matches.
    let mut set_path = attrs(&[65_001], "10.0.0.1");
    set_path.as_path = AsPath::from_segments(&[
        bgpfc_wire::as_path::AsPathSegment {
            kind: bgpfc_wire::as_path::SegmentType::Sequence,
            asns: vec![Asn(65_001)],
        },
        bgpfc_wire::as_path::AsPathSegment {
            kind: bgpfc_wire::as_path::SegmentType::Set,
            asns: vec![Asn(64_496)],
        },
    ]);
    send(&mut rib, &e1, &announce(&["192.0.2.128/25"], &set_path));
    // A two-octet peer: AS_TRANS in AS_PATH, the four-octet origin in
    // AS4_PATH, merged by the decoder (RFC 6793 §4.2.3) before the lookup.
    let message = attrs(&[65_003, 4_200_000_000], "10.0.0.3")
        .to_update(V4, vec![p("198.18.0.0/24")])
        .encode(&EncodeContext {
            four_octet_as: false,
            extended_next_hop: false,
        })
        .unwrap();
    let ctx = DecodeContext {
        four_octet_as: false,
        peer: PeerKind::External,
        allow_as_set: false,
        extended_next_hop: false,
    };
    send(
        &mut rib,
        &old,
        &UpdateMessage::decode(&message, &ctx).unwrap(),
    );

    for (family, prefix, state) in [
        (V4, "192.0.2.0/24", RovState::Valid),
        // Longer than the maximum length.
        (V4, "192.0.2.0/25", RovState::Invalid),
        (V4, "192.0.2.128/25", RovState::Invalid),
        // Covered, but by another AS.
        (V4, "198.51.100.0/24", RovState::Invalid),
        (V4, "10.0.0.0/8", RovState::NotFound),
        (V4, "203.0.113.0/24", RovState::Valid),
        (V4, "198.18.0.0/24", RovState::Valid),
        (V6, "2001:db8:1::/48", RovState::Valid),
        (V6, "2001:db8:1::/64", RovState::Invalid),
    ] {
        let c = rib.candidates(family, p(prefix));
        assert_eq!(c.len(), 1, "{prefix}");
        assert_eq!(
            (c[0].rov, c[0].aspa),
            (state, AspaState::Disabled),
            "{prefix}"
        );
        let best = rib.loc_rib(family).find(|(q, _)| *q == p(prefix)).unwrap();
        assert_eq!(best.1.rov, state, "{prefix}");
        assert_eq!(held(&rib, family, prefix), vec![(c[0].peer, state)]);
    }
}

#[test]
fn only_the_affected_routes_are_validated_again_in_place() {
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    let old = vrps(&[("192.0.2.0/24", 24, 64_496)]);
    outputs(|o| rib.validation_changed(all(old.clone()), now(), o));
    let a = attrs(&[65_001, 64_496], "10.0.0.1");
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"], &a),
            now(),
            o,
        );
    });
    let before = Arc::clone(rib.candidates(V4, p("198.51.100.0/24"))[0].attrs);
    // The new source would make both NotFound routes Invalid, but the
    // change says only one of them is affected: the other is not looked
    // at again.
    let new = vrps(&[
        ("192.0.2.0/24", 24, 64_496),
        ("198.51.100.0/24", 24, 64_497),
        ("203.0.113.0/24", 24, 64_497),
    ]);
    let out = outputs(|o| {
        rib.validation_changed(
            ValidationChange {
                source: Arc::new(new.clone()),
                affected: AffectedPrefixes::from_vrps([vrp("198.51.100.0/24", 24, 64_497)]),
            },
            now(),
            o,
        );
    });
    let not_found_invalid = [(RovState::NotFound, RovState::Invalid, 1)];
    assert_eq!(
        report(&out),
        Some(&one_moved(
            revalidation(1, &not_found_invalid, &["198.51.100.0/24"], 0),
            e1.addr,
            RouteStatus::Best
        ))
    );
    assert!(matches!(out[..], [Output::Revalidated(_)]), "{out:?}");
    assert_eq!(
        held(&rib, V4, "198.51.100.0/24"),
        vec![(e1.addr, RovState::Invalid)]
    );
    assert_eq!(
        held(&rib, V4, "203.0.113.0/24"),
        vec![(e1.addr, RovState::NotFound)]
    );
    assert_eq!(
        held(&rib, V4, "192.0.2.0/24"),
        vec![(e1.addr, RovState::Valid)]
    );
    // In place: the same route, with the same attributes, and still the
    // best; only its state changed, so the FIB has nothing to do.
    let c = rib.candidates(V4, p("198.51.100.0/24"));
    assert!(Arc::ptr_eq(c[0].attrs, &before));
    assert_eq!(c[0].rov, RovState::Invalid);
    assert_eq!(fib(&out), vec![]);
    // A covering prefix affects what it covers.
    let out = outputs(|o| {
        rib.validation_changed(
            ValidationChange {
                source: Arc::new(new),
                affected: AffectedPrefixes::CoveredBy([p("203.0.0.0/16")].into_iter().collect()),
            },
            now(),
            o,
        );
    });
    assert_eq!(
        report(&out),
        Some(&one_moved(
            revalidation(1, &not_found_invalid, &["203.0.113.0/24"], 0),
            e1.addr,
            RouteStatus::Best
        ))
    );
    // Nothing affected: the source changes and no route is looked at.
    let out = outputs(|o| {
        rib.validation_changed(
            ValidationChange {
                source: Arc::new(old),
                affected: AffectedPrefixes::none(),
            },
            now(),
            o,
        );
    });
    assert_eq!(out, vec![]);
    assert_eq!(
        held(&rib, V4, "203.0.113.0/24"),
        vec![(e1.addr, RovState::Invalid)]
    );
}

#[test]
fn all_validates_every_route_again() {
    use RovState::{Disabled, Invalid, NotFound, Valid};
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_002, 2);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    outputs(|o| rib.peer_up(e2.clone(), now(), o));
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(
                &["192.0.2.0/24", "198.51.100.0/24"],
                &attrs(&[65_001, 64_496], "10.0.0.1"),
            ),
            now(),
            o,
        );
    });
    outputs(|o| {
        rib.update(
            e2.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_002, 64_497], "10.0.0.2")),
            now(),
            o,
        );
    });
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["2001:db8::/32"], &attrs(&[65_001, 64_496], "2001:db8::1")),
            now(),
            o,
        );
    });
    let set = vrps(&[("192.0.2.0/24", 24, 64_496), ("2001:db8::/32", 32, 64_496)]);
    // Turning validation on: every route leaves Disabled, both peers'
    // routes to a destination included, in prefix order.
    let out = outputs(|o| rib.validation_changed(all(set.clone()), now(), o));
    let dests = ["192.0.2.0/24", "198.51.100.0/24", "2001:db8::/32"];
    assert_eq!(
        report(&out),
        Some(&revalidation(
            4,
            &[
                (Disabled, Valid, 2),
                (Disabled, Invalid, 1),
                (Disabled, NotFound, 1)
            ],
            &dests,
            0
        ))
    );
    assert_eq!(
        held(&rib, V4, "192.0.2.0/24"),
        vec![(e1.addr, Valid), (e2.addr, Invalid)]
    );
    assert_eq!(held(&rib, V4, "198.51.100.0/24"), vec![(e1.addr, NotFound)]);
    assert_eq!(held(&rib, V6, "2001:db8::/32"), vec![(e1.addr, Valid)]);
    // The same source again: no route changes, nothing to do.
    assert_eq!(
        outputs(|o| rib.validation_changed(all(set), now(), o)),
        vec![]
    );
    // Turning it off again.
    let out = outputs(|o| rib.validation_changed(ValidationChange::disabled(), now(), o));
    assert_eq!(
        report(&out),
        Some(&revalidation(
            4,
            &[
                (Valid, Disabled, 2),
                (Invalid, Disabled, 1),
                (NotFound, Disabled, 1)
            ],
            &dests,
            0
        ))
    );
    for (family, prefix) in [
        (V4, "192.0.2.0/24"),
        (V4, "198.51.100.0/24"),
        (V6, "2001:db8::/32"),
    ] {
        assert!(
            rib.candidates(family, p(prefix))
                .iter()
                .all(|c| c.rov == RovState::Disabled)
        );
    }
}

#[test]
fn a_route_import_policy_rejected_is_kept_and_taken_once_its_state_allows() {
    let mut rib = Rib::with_policies(LOCAL_AS, Box::new(RejectInvalidTagValid));
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_002, 2);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    outputs(|o| rib.peer_up(e2.clone(), now(), o));
    let other_as = vrps(&[("192.0.2.0/24", 24, 64_497)]);
    outputs(|o| rib.validation_changed(all(other_as.clone()), now(), o));
    let out = outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_001, 64_496], "10.0.0.1")),
            now(),
            o,
        );
    });
    // Invalid, so rejected, and kept as received.
    assert_eq!(out, vec![]);
    assert!(rib.candidates(V4, p("192.0.2.0/24")).is_empty());
    assert_eq!(
        held(&rib, V4, "192.0.2.0/24"),
        vec![(e1.addr, RovState::Invalid)]
    );

    // A ROA for the route's origin: Valid, import policy takes it, the
    // decision process chooses it, and it goes to the FIB and to e2, with
    // what export policy adds to a Valid route. No ROUTE-REFRESH needed.
    let ours = vrps(&[("192.0.2.0/24", 24, 64_496)]);
    let out = outputs(|o| rib.validation_changed(delta(&other_as, ours.clone()), now(), o));
    let invalid_valid = [(RovState::Invalid, RovState::Valid, 1)];
    // Put back into use.
    assert_eq!(
        report(&out),
        Some(&one_moved(
            Revalidation {
                released: 1,
                ..revalidation(1, &invalid_valid, &["192.0.2.0/24"], 1)
            },
            e1.addr,
            RouteStatus::Best
        ))
    );
    assert!(matches!(out[0], Output::Revalidated(_)));
    assert_eq!(
        fib(&out),
        vec![FibChange {
            family: V4,
            prefix: p("192.0.2.0/24"),
            next_hop: Some(ip("10.0.0.1")),
            previous: None,
        }]
    );
    let m = decode_sent(sends(&out, e2.addr)[0], &e2);
    assert_eq!(m[0].nlri, vec![p("192.0.2.0/24")]);
    assert_eq!(communities(&m[0]), vec![Community::new(65_000, 1)]);
    let c = rib.candidates(V4, p("192.0.2.0/24"));
    assert_eq!((c.len(), c[0].rov), (1, RovState::Valid));
    assert_eq!(rib.loc_rib(V4).next().unwrap().1.rov, RovState::Valid);

    // And back: withdrawn from the FIB and from e2, still held.
    let out = outputs(|o| rib.validation_changed(delta(&ours, other_as), now(), o));
    let valid_invalid = [(RovState::Valid, RovState::Invalid, 1)];
    assert_eq!(
        report(&out),
        Some(&one_moved(
            Revalidation {
                held: 1,
                ..revalidation(1, &valid_invalid, &["192.0.2.0/24"], 1)
            },
            e1.addr,
            RouteStatus::Held(Held::Policy)
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
    let m = decode_sent(sends(&out, e2.addr)[0], &e2);
    assert_eq!(m[0].withdrawn, vec![p("192.0.2.0/24")]);
    assert_eq!(
        held(&rib, V4, "192.0.2.0/24"),
        vec![(e1.addr, RovState::Invalid)]
    );
    assert_eq!(rib.loc_rib(V4).count(), 0);
}

#[test]
fn a_new_state_of_the_best_route_alone_runs_export_policy_again() {
    let mut rib = Rib::with_policies(LOCAL_AS, Box::new(RejectInvalidTagValid));
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_002, 2);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    outputs(|o| rib.peer_up(e2.clone(), now(), o));
    outputs(|o| rib.validation_changed(all(VrpSet::new()), now(), o));
    let out = outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_001, 64_496], "10.0.0.1")),
            now(),
            o,
        );
    });
    let m = decode_sent(sends(&out, e2.addr)[0], &e2);
    assert_eq!(communities(&m[0]), vec![]);
    // NotFound to Valid: the same route stays best and the FIB stays as
    // it is, but export policy now tags it, so e2 hears it again.
    let set = vrps(&[("192.0.2.0/24", 24, 64_496)]);
    let out = outputs(|o| rib.validation_changed(delta(&VrpSet::new(), set), now(), o));
    let not_found_valid = [(RovState::NotFound, RovState::Valid, 1)];
    assert_eq!(
        report(&out),
        Some(&one_moved(
            revalidation(1, &not_found_valid, &["192.0.2.0/24"], 0),
            e1.addr,
            RouteStatus::Best
        ))
    );
    assert_eq!(fib(&out), vec![]);
    let m = decode_sent(sends(&out, e2.addr)[0], &e2);
    assert_eq!(m[0].nlri, vec![p("192.0.2.0/24")]);
    assert_eq!(communities(&m[0]), vec![Community::new(65_000, 1)]);
    // Nothing goes back to e1, the route's own peer.
    assert_eq!(sends(&out, e1.addr).len(), 0);
}

#[test]
fn validation_changes_are_paced_like_updates() {
    // RFC 4271 §9.2.1.1: a change driven by the validation source goes
    // through the same pacing as one driven by an UPDATE.
    let mut rib = Rib::with_policies(LOCAL_AS, Box::new(RejectInvalidTagValid));
    let e1 = peer("10.0.0.1", 65_001, 1);
    let mut e2 = peer("10.0.0.2", 65_002, 2);
    e2.advertisement_interval = Duration::from_secs(30);
    let t0 = now();
    outputs(|o| rib.peer_up(e1.clone(), t0, o));
    outputs(|o| rib.peer_up(e2.clone(), t0, o));
    outputs(|o| rib.validation_changed(all(VrpSet::new()), t0, o));
    let out = outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_001, 64_496], "10.0.0.1")),
            t0,
            o,
        );
    });
    assert_eq!(sends(&out, e2.addr).len(), 1);
    let set = vrps(&[("192.0.2.0/24", 24, 64_496)]);
    let t1 = t0 + Duration::from_secs(1);
    let out = outputs(|o| rib.validation_changed(delta(&VrpSet::new(), set), t1, o));
    assert_eq!(report(&out).map(Revalidation::changed), Some(1));
    assert!(sends(&out, e2.addr).is_empty(), "held by the interval");
    let due = release_at(&rib).unwrap();
    assert!(due >= t0 + Duration::from_secs(30), "{:?}", due - t0);
    assert_eq!(
        outputs(|o| rib.flush(due.checked_sub(Duration::from_secs(1)).unwrap(), o)),
        vec![]
    );
    let out = outputs(|o| rib.flush(due, o));
    let m = decode_sent(sends(&out, e2.addr)[0], &e2);
    assert_eq!(communities(&m[0]), vec![Community::new(65_000, 1)]);
}

#[test]
fn withdrawn_routes_and_those_of_a_peer_gone_are_not_validated_again() {
    let mut rib = Rib::with_policies(LOCAL_AS, Box::new(RejectInvalidTagValid));
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_002, 2);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    outputs(|o| rib.peer_up(e2.clone(), now(), o));
    let set = vrps(&[("192.0.2.0/23", 24, 64_497)]);
    outputs(|o| rib.validation_changed(all(set.clone()), now(), o));
    // Invalid, so rejected and only held.
    let a = attrs(&[65_001, 64_496], "10.0.0.1");
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24", "192.0.3.0/24"], &a),
            now(),
            o,
        );
    });
    outputs(|o| {
        rib.update(
            e2.addr,
            &announce(&["192.0.3.0/24"], &attrs(&[65_002, 64_496], "10.0.0.2")),
            now(),
            o,
        );
    });
    outputs(|o| rib.update(e1.addr, &withdraw(&["192.0.2.0/24"]), now(), o));
    outputs(|o| rib.peer_down(e2.addr, now(), o));
    assert_eq!(held(&rib, V4, "192.0.2.0/24"), vec![]);
    assert_eq!(
        held(&rib, V4, "192.0.3.0/24"),
        vec![(e1.addr, RovState::Invalid)]
    );
    let out = outputs(|o| rib.validation_changed(ValidationChange::disabled(), now(), o));
    let invalid_disabled = [(RovState::Invalid, RovState::Disabled, 1)];
    assert_eq!(
        report(&out),
        Some(&Revalidation {
            released: 1,
            ..revalidation(1, &invalid_disabled, &["192.0.3.0/24"], 1)
        })
    );
    // Taken now that it is no longer Invalid.
    assert_eq!(fib(&out).len(), 1);
}

#[test]
fn a_small_delta_against_a_large_table_finds_exactly_its_routes() {
    // Few changed prefixes against many destinations take a range query
    // each, many take one pass; either way exactly the covered routes are
    // validated again.
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    outputs(|o| rib.validation_changed(all(VrpSet::new()), now(), o));
    let prefixes: Vec<String> = (0..1024u32)
        .map(|i| format!("10.{}.{}.0/24", i >> 8, i & 0xff))
        .collect();
    let refs: Vec<&str> = prefixes.iter().map(String::as_str).collect();
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&refs, &attrs(&[65_001, 64_496], "10.0.0.1")),
            now(),
            o,
        );
    });
    let sparse = ["10.1.7.0/24", "10.2.0.0/17", "10.3.255.0/24", "10.0.0.0/23"].map(p);
    let dense = (0..200u32).map(|i| p(&format!("10.{}.{}.0/24", i % 4, (i * 7) & 0xff)));
    for changed in [sparse.into_iter().collect::<PrefixSet>(), dense.collect()] {
        // Invalid for the changed prefixes, NotFound elsewhere.
        let set: VrpSet = changed
            .iter()
            .map(|q| Vrp::new(q, 24, Asn(64_497)).unwrap())
            .collect();
        let out = outputs(|o| {
            rib.validation_changed(
                ValidationChange {
                    source: Arc::new(set),
                    affected: AffectedPrefixes::CoveredBy(changed.clone()),
                },
                now(),
                o,
            );
        });
        let expected: Vec<Prefix> = refs
            .iter()
            .map(|s| p(s))
            .filter(|q| changed.covers(*q))
            .collect();
        assert_ne!(expected.len(), 0);
        // Exactly the covered routes were looked at, and each changed.
        let n = expected.len();
        let r = report(&out).unwrap();
        assert_eq!(r.routes, n);
        assert_eq!(r.changes, vec![(RovState::NotFound, RovState::Invalid, n)]);
        assert_eq!(r.destinations, n);
        assert_eq!(r.sample, expected[..n.min(Revalidation::SAMPLE)]);
        for q in &refs {
            let state = if changed.covers(p(q)) {
                RovState::Invalid
            } else {
                RovState::NotFound
            };
            assert_eq!(held(&rib, V4, q), vec![(e1.addr, state)], "{q}");
        }
        // And back.
        let out = outputs(|o| {
            rib.validation_changed(
                ValidationChange {
                    source: Arc::new(VrpSet::new()),
                    affected: AffectedPrefixes::CoveredBy(changed),
                },
                now(),
                o,
            );
        });
        let r = report(&out).unwrap();
        assert_eq!(r.changes, vec![(RovState::Invalid, RovState::NotFound, n)]);
    }
}

#[test]
fn a_change_that_moves_every_route_is_one_report() {
    // Turning validation on or off moves every route of the table; what
    // comes out is one report with counts and a short sample, and the
    // FIB changes and UPDATEs that follow, never an entry per route.
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_002, 2);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    outputs(|o| rib.peer_up(e2.clone(), now(), o));
    let prefixes: Vec<String> = (0..600u32)
        .map(|i| format!("10.{}.{}.0/24", i >> 8, i & 0xff))
        .collect();
    let refs: Vec<&str> = prefixes.iter().map(String::as_str).collect();
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&refs, &attrs(&[65_001, 64_496], "10.0.0.1")),
            now(),
            o,
        );
    });
    outputs(|o| {
        rib.update(
            e2.addr,
            &announce(&refs, &attrs(&[65_002, 64_497], "10.0.0.2")),
            now(),
            o,
        );
    });
    // Every one of them may come from AS 64496 only.
    let set = vrps(&[("10.0.0.0/8", 24, 64_496)]);
    let out = outputs(|o| rib.validation_changed(all(set), now(), o));
    assert!(matches!(out[0], Output::Revalidated(_)));
    assert!(
        out[1..]
            .iter()
            .all(|o| !matches!(o, Output::Revalidated(_)))
    );
    let r = report(&out).unwrap();
    assert_eq!(r.routes, 1200);
    assert_eq!(
        r.changes,
        vec![
            (RovState::Disabled, RovState::Valid, 600),
            (RovState::Disabled, RovState::Invalid, 600)
        ]
    );
    assert_eq!(r.changed(), 1200);
    assert_eq!(r.destinations, 600);
    let first: Vec<Prefix> = refs[..Revalidation::SAMPLE].iter().map(|s| p(s)).collect();
    assert_eq!(r.sample, first);
    // e1's routes stay best (lower router ID): no FIB change, and no
    // UPDATE, as AcceptAll exports them as before.
    assert_eq!(r.best_changed, 0);
    assert_eq!(out.len(), 1, "{:?}", &out[1..]);
    assert_eq!(
        held(&rib, V4, "10.2.87.0/24"),
        vec![(e1.addr, RovState::Valid), (e2.addr, RovState::Invalid)]
    );
}

#[test]
fn a_held_route_no_state_can_admit_any_more_goes_when_validated_again() {
    // Between a change of policy and the ROUTE-REFRESH that follows it, a
    // route held for its state may be one the new policy rejects whatever
    // its state. Once its state changes it is put to that policy, and
    // dropped like any route it rejects: no longer held or counted.
    struct RejectAll;
    impl Policies for RejectAll {
        fn import(
            &self,
            _: &PeerInfo,
            _: AddressFamily,
            _: Prefix,
            _: &PathAttrs,
            _: RovState,
        ) -> Imported {
            Verdict::Reject.into()
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
    let mut rib = Rib::with_policies(LOCAL_AS, Box::new(RejectInvalidTagValid));
    let e1 = peer("10.0.0.1", 65_001, 1);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    outputs(|o| rib.validation_changed(all(vrps(&[("192.0.2.0/24", 24, 64_497)])), now(), o));
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_001, 64_496], "10.0.0.1")),
            now(),
            o,
        );
    });
    assert_eq!(
        held(&rib, V4, "192.0.2.0/24"),
        vec![(e1.addr, RovState::Invalid)]
    );
    assert_eq!(
        rib.peer_stats(e1.addr).unwrap().received,
        vec![(V4, 1), (V6, 0)]
    );
    rib.set_policies(Box::new(RejectAll), &[], now(), &mut Vec::new());
    let out = outputs(|o| rib.validation_changed(ValidationChange::disabled(), now(), o));
    let invalid_disabled = [(RovState::Invalid, RovState::Disabled, 1)];
    assert_eq!(
        out,
        vec![Output::Revalidated(revalidation(
            1,
            &invalid_disabled,
            &["192.0.2.0/24"],
            0
        ))]
    );
    assert_eq!(held(&rib, V4, "192.0.2.0/24"), vec![]);
    assert!(rib.tables.values().all(crate::store::PrefixMap::is_empty));
    assert_eq!(
        rib.peer_stats(e1.addr).unwrap().received,
        vec![(V4, 0), (V6, 0)]
    );
}

#[test]
fn routes_change_places_between_candidates_and_held_routes() {
    use RovState::{Invalid, Valid};
    // Two peers' routes to one destination, from different origins: the
    // VRP's AS is Valid and a candidate, the other Invalid and held. When
    // the VRP moves to the other AS the two swap, and the decision follows.
    let mut rib = Rib::with_policies(LOCAL_AS, Box::new(RejectInvalidTagValid));
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_002, 2);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    outputs(|o| rib.peer_up(e2.clone(), now(), o));
    let first = vrps(&[("192.0.2.0/24", 24, 64_496)]);
    outputs(|o| rib.validation_changed(all(first.clone()), now(), o));
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_001, 64_496], "10.0.0.1")),
            now(),
            o,
        );
    });
    outputs(|o| {
        rib.update(
            e2.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_002, 64_497], "10.0.0.2")),
            now(),
            o,
        );
    });
    let order = |rib: &Rib| -> Vec<(IpAddr, RovState, Option<Held>)> {
        routes(rib, V4, p("192.0.2.0/24"))
            .into_iter()
            .map(|(peer, r)| (peer, r.rov, r.held))
            .collect()
    };
    let policy = Some(Held::Policy);
    assert_eq!(
        order(&rib),
        vec![(e1.addr, Valid, None), (e2.addr, Invalid, policy)]
    );
    let second = vrps(&[("192.0.2.0/24", 24, 64_497)]);
    let out = outputs(|o| rib.validation_changed(delta(&first, second), now(), o));
    assert_eq!(
        order(&rib),
        vec![(e2.addr, Valid, None), (e1.addr, Invalid, policy)]
    );
    let c = rib.candidates(V4, p("192.0.2.0/24"));
    assert_eq!((c.len(), c[0].peer), (1, e2.addr));
    assert_eq!(
        fib(&out),
        vec![FibChange {
            family: V4,
            prefix: p("192.0.2.0/24"),
            next_hop: Some(ip("10.0.0.2")),
            previous: Some(ip("10.0.0.1")),
        }]
    );
    let r = report(&out).unwrap();
    assert_eq!(r.changes, vec![(Valid, Invalid, 1), (Invalid, Valid, 1)]);
    assert_eq!((r.routes, r.destinations, r.best_changed), (2, 1, 1));
    // Both still counted, each by its peer.
    for e in [&e1, &e2] {
        assert_eq!(rib.peer_stats(e.addr).unwrap().received[0], (V4, 1));
    }
}

#[test]
fn a_change_for_the_whole_table_gives_its_room_back() {
    // Turning validation on changes the state of every route at once.
    // The buffers each UPDATE reuses grow to the table for it, and must
    // not keep that room afterwards.
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    let n = 2 * crate::Scratch::KEEP;
    let prefixes: Vec<String> = (0..n)
        .map(|i| format!("10.{}.{}.0/24", i >> 8, i & 0xff))
        .collect();
    let a = attrs(&[65_001], "10.0.0.1");
    for chunk in prefixes.chunks(1000) {
        let refs: Vec<&str> = chunk.iter().map(String::as_str).collect();
        outputs(|o| rib.update(e1.addr, &announce(&refs, &a), now(), o));
    }
    let out = outputs(|o| {
        rib.validation_changed(all(vrps(&[("10.0.0.0/8", 24, 65_001)])), now(), o);
    });
    assert_eq!(report(&out).map(Revalidation::changed), Some(n));
    assert!(rib.scratch.dirty.capacity() <= crate::Scratch::KEEP);
    assert!(rib.scratch.released.capacity() <= crate::Scratch::KEEP);
}

/// Import policy that uses a route looked up as `when` with state `to`
/// instead (RFC 6811 §3, `set rpki`) and accepts every route; export
/// policy that tags the routes it is given as Valid with community
/// 65000:1. What each is told is recorded.
struct Override {
    when: RovState,
    to: RovState,
    seen: Seen,
}

impl Override {
    fn new(when: RovState, to: RovState) -> Override {
        Override {
            when,
            to,
            seen: Seen::default(),
        }
    }
}

impl Policies for Override {
    fn import(
        &self,
        _: &PeerInfo,
        _: AddressFamily,
        p: Prefix,
        _: &PathAttrs,
        rov: RovState,
    ) -> Imported {
        self.seen.lock().unwrap().push(("import", p, rov));
        Imported {
            verdict: Verdict::Accept,
            rov: (rov == self.when).then_some(self.to),
        }
    }

    fn export(
        &self,
        to: &PeerInfo,
        family: AddressFamily,
        p: Prefix,
        a: &PathAttrs,
        rov: RovState,
    ) -> Verdict {
        self.seen.lock().unwrap().push(("export", p, rov));
        RejectInvalidTagValid.export(to, family, p, a, rov)
    }
}

/// The looked-up state, the state policy set and the state used, of the
/// one candidate for `prefix`.
fn states(rib: &Rib, prefix: &str) -> (RovState, Option<RovState>, RovState) {
    let c = rib.candidates(V4, p(prefix));
    assert_eq!(c.len(), 1, "{prefix}");
    (c[0].rov, c[0].rov_set, c[0].effective_rov())
}

#[test]
fn export_policy_sees_the_effective_state() {
    use RovState::{Invalid, Valid};
    // RFC 6811 §3: import policy sets the state a route is used with. The
    // route keeps the one the lookup gave it (§2), and export policy sees
    // the one it is used with.
    let policy = Override::new(Invalid, Valid);
    let seen = Arc::clone(&policy.seen);
    let mut rib = Rib::with_policies(LOCAL_AS, Box::new(policy));
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_002, 2);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    outputs(|o| rib.peer_up(e2.clone(), now(), o));
    outputs(|o| rib.validation_changed(all(vrps(&[("192.0.2.0/24", 24, 64_497)])), now(), o));
    let out = outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_001, 64_496], "10.0.0.1")),
            now(),
            o,
        );
    });
    assert_eq!(states(&rib, "192.0.2.0/24"), (Invalid, Some(Valid), Valid));
    let best = rib.loc_rib(V4).next().unwrap().1;
    assert_eq!((best.rov, best.rov_set), (Invalid, Some(Valid)));
    assert_eq!(
        *seen.lock().unwrap(),
        vec![
            ("import", p("192.0.2.0/24"), Invalid),
            ("export", p("192.0.2.0/24"), Valid),
        ]
    );
    let m = decode_sent(sends(&out, e2.addr)[0], &e2);
    assert_eq!(communities(&m[0]), vec![Community::new(65_000, 1)]);
}

#[test]
fn a_new_override_alone_runs_export_policy_again() {
    use RovState::{Invalid, NotFound, Valid};
    // The same route, sent again after a change of import policy (as a
    // route refresh does), now used with another state: the FIB has
    // nothing to do, but export policy must run again, and the peer hears
    // what it now makes of the route.
    let mut rib = Rib::with_policies(LOCAL_AS, Box::new(Override::new(Invalid, Valid)));
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_002, 2);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    outputs(|o| rib.peer_up(e2.clone(), now(), o));
    outputs(|o| rib.validation_changed(all(VrpSet::new()), now(), o));
    let route = announce(&["192.0.2.0/24"], &attrs(&[65_001, 64_496], "10.0.0.1"));
    let out = outputs(|o| rib.update(e1.addr, &route, now(), o));
    assert_eq!(states(&rib, "192.0.2.0/24"), (NotFound, None, NotFound));
    let m = decode_sent(sends(&out, e2.addr)[0], &e2);
    assert_eq!(communities(&m[0]), vec![]);

    for (policy, set, tags) in [
        (
            Override::new(NotFound, Valid),
            Some(Valid),
            vec![Community::new(65_000, 1)],
        ),
        (Override::new(Invalid, Valid), None, vec![]),
    ] {
        rib.set_policies(Box::new(policy), &[], now(), &mut Vec::new());
        let out = outputs(|o| rib.update(e1.addr, &route, now(), o));
        assert_eq!(fib(&out), vec![]);
        assert_eq!(
            states(&rib, "192.0.2.0/24"),
            (NotFound, set, set.unwrap_or(NotFound))
        );
        let m = decode_sent(sends(&out, e2.addr)[0], &e2);
        assert_eq!(m[0].nlri, vec![p("192.0.2.0/24")]);
        assert_eq!(communities(&m[0]), tags);
    }
    // The same again: nothing changed, nothing to do.
    assert_eq!(outputs(|o| rib.update(e1.addr, &route, now(), o)), vec![]);
}

#[test]
fn a_vrp_change_runs_import_policy_again_and_the_override_follows() {
    use RovState::{Invalid, NotFound, Valid};
    // Policy sets Valid on Invalid routes only. When the ROA that made the
    // route Invalid goes, the route is looked up again (RFC 6811 §4), put
    // to import policy again, which sets nothing now, and is used as the
    // NotFound route it is; when the ROA comes back, so does the override.
    let mut rib = Rib::with_policies(LOCAL_AS, Box::new(Override::new(Invalid, Valid)));
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_002, 2);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    outputs(|o| rib.peer_up(e2.clone(), now(), o));
    let roa = vrps(&[("192.0.2.0/24", 24, 64_497)]);
    outputs(|o| rib.validation_changed(all(roa.clone()), now(), o));
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_001, 64_496], "10.0.0.1")),
            now(),
            o,
        );
    });
    assert_eq!(states(&rib, "192.0.2.0/24"), (Invalid, Some(Valid), Valid));

    let out = outputs(|o| rib.validation_changed(delta(&roa, VrpSet::new()), now(), o));
    assert_eq!(
        report(&out),
        Some(&one_moved(
            revalidation(1, &[(Invalid, NotFound, 1)], &["192.0.2.0/24"], 0),
            e1.addr,
            RouteStatus::Best
        ))
    );
    assert_eq!(states(&rib, "192.0.2.0/24"), (NotFound, None, NotFound));
    assert_eq!(fib(&out), vec![]);
    let m = decode_sent(sends(&out, e2.addr)[0], &e2);
    assert_eq!(communities(&m[0]), vec![]);

    let out = outputs(|o| rib.validation_changed(delta(&VrpSet::new(), roa), now(), o));
    assert_eq!(states(&rib, "192.0.2.0/24"), (Invalid, Some(Valid), Valid));
    let m = decode_sent(sends(&out, e2.addr)[0], &e2);
    assert_eq!(communities(&m[0]), vec![Community::new(65_000, 1)]);
}

/// The transitions of a report, as (prefix, peer, from, to, route).
fn moves(r: &Revalidation) -> Vec<(Prefix, IpAddr, RovState, RovState, RouteStatus)> {
    r.transitions
        .iter()
        .map(|t| (t.prefix, t.peer, t.from, t.to, t.route))
        .collect()
}

#[cfg(target_pointer_width = "64")]
#[test]
fn the_routes_a_report_lists_take_about_55_kb() {
    // `Revalidation::LISTED` and docs/control.md: the routes one report
    // lists, at most, take "about 55 KB", each listed route having a
    // fixed size.
    let route = std::mem::size_of::<crate::Transition>();
    assert_eq!(route, 52);
    let bytes = Revalidation::LISTED * route;
    assert!((50_000..=60_000).contains(&bytes), "{bytes}");
}

#[test]
fn transitions_list_rfc_state_moves_with_what_became_of_each_route() {
    use RouteStatus::{Best, Candidate};
    use RovState::{Invalid, NotFound, Valid};
    // Issue #59: "An operator needs to see that a prefix went Valid ->
    // Invalid". Under drop-invalid, one change of the VRPs moves a used
    // route to Invalid (held), two routes of one destination from
    // NotFound to Valid (the best and the other), and an IPv6 route from
    // Invalid to NotFound (used again). IPv6 arrived first; the list is
    // in prefix order, IPv4 first, each with its origin.
    let mut rib = Rib::new(LOCAL_AS);
    outputs(|o| rib.set_enforcement(bgpfc_rpki::Enforcement::DropInvalid, now(), o));
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_002, 2);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    outputs(|o| rib.peer_up(e2.clone(), now(), o));
    let first = vrps(&[("192.0.2.0/24", 24, 64_496), ("2001:db8::/32", 32, 64_497)]);
    outputs(|o| rib.validation_changed(all(first.clone()), now(), o));
    let from_64496 = |next_hop: &str, neighbor: u32| attrs(&[neighbor, 64_496], next_hop);
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["2001:db8::/32"], &from_64496("2001:db8::1", 65_001)),
            now(),
            o,
        );
    });
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(
                &["192.0.2.0/24", "198.51.100.0/24"],
                &from_64496("10.0.0.1", 65_001),
            ),
            now(),
            o,
        );
    });
    outputs(|o| {
        rib.update(
            e2.addr,
            &announce(&["198.51.100.0/24"], &from_64496("10.0.0.2", 65_002)),
            now(),
            o,
        );
    });
    let second = vrps(&[
        ("192.0.2.0/24", 24, 64_497),
        ("198.51.100.0/24", 24, 64_496),
    ]);
    let out = outputs(|o| rib.validation_changed(delta(&first, second), now(), o));
    let r = report(&out).unwrap();
    assert_eq!(
        moves(r),
        vec![
            (
                p("192.0.2.0/24"),
                e1.addr,
                Valid,
                Invalid,
                RouteStatus::Held(Held::Enforcement)
            ),
            (p("198.51.100.0/24"), e1.addr, NotFound, Valid, Best),
            (p("198.51.100.0/24"), e2.addr, NotFound, Valid, Candidate),
            (p("2001:db8::/32"), e1.addr, Invalid, NotFound, Best),
        ]
    );
    assert!(
        r.transitions
            .iter()
            .all(|t| t.origin == RouteOrigin::As(Asn(64_496)))
    );
    assert_eq!(
        r.transitions.iter().map(|t| t.family).collect::<Vec<_>>(),
        vec![V4, V4, V4, V6]
    );
    assert_eq!((r.unlisted, r.changed(), r.held, r.released), (0, 4, 1, 1));
    // The sample is in the same order.
    assert_eq!(
        r.sample,
        vec![p("192.0.2.0/24"), p("198.51.100.0/24"), p("2001:db8::/32")]
    );
}

#[test]
fn moves_to_and_from_disabled_are_counted_not_listed() {
    // Turning validation on or off moves every route to or from
    // `disabled`: the report counts them and lists none.
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(
                &["192.0.2.0/24", "198.51.100.0/24"],
                &attrs(&[65_001, 64_496], "10.0.0.1"),
            ),
            now(),
            o,
        );
    });
    let set = vrps(&[("192.0.2.0/24", 24, 64_496)]);
    for change in [all(set), ValidationChange::disabled()] {
        let out = outputs(|o| rib.validation_changed(change, now(), o));
        let r = report(&out).unwrap();
        assert_eq!(r.changed(), 2);
        assert_eq!((r.transitions.len(), r.unlisted), (0, 0));
    }
}

#[test]
fn a_change_lists_at_most_1024_transitions_and_counts_the_rest() {
    // One change that moves 1100 routes, NotFound to Invalid: the first
    // 1024 in prefix order are listed, the other 76 counted.
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    outputs(|o| rib.validation_changed(all(VrpSet::new()), now(), o));
    let prefixes: Vec<Prefix> = (0..1100u32)
        .map(|i| p(&format!("10.{}.{}.0/24", i >> 8, i & 0xff)))
        .collect();
    let a = attrs(&[65_001, 64_496], "10.0.0.1");
    for chunk in prefixes.chunks(500) {
        let message = a.to_update(V4, chunk.to_vec());
        let u = DecodedUpdate {
            message,
            treated_as_withdraw: None,
            discarded: Vec::new(),
            disabled: Vec::new(),
        };
        outputs(|o| rib.update(e1.addr, &u, now(), o));
    }
    let set = vrps(&[("10.0.0.0/8", 24, 64_497)]);
    let out = outputs(|o| rib.validation_changed(delta(&VrpSet::new(), set), now(), o));
    let r = report(&out).unwrap();
    assert_eq!(
        r.changes,
        vec![(RovState::NotFound, RovState::Invalid, 1100)]
    );
    assert_eq!(r.transitions.len(), Revalidation::LISTED);
    assert_eq!(r.unlisted, 1100 - Revalidation::LISTED);
    let listed: Vec<Prefix> = r.transitions.iter().map(|t| t.prefix).collect();
    assert_eq!(listed, prefixes[..Revalidation::LISTED]);
    assert!(
        r.transitions
            .iter()
            .all(|t| t.route == RouteStatus::Best && t.peer == e1.addr)
    );
}

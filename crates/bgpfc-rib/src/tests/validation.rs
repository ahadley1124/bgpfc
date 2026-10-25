//! Every route carries its RFC 6811 validation state (issue #56), policy
//! sees it (RFC 6811 §3), and it follows the validation source, which
//! re-runs import policy and the decision process for the routes whose
//! state changed (RFC 6811 §4).

use std::sync::Mutex;

use bgpfc_rpki::{AffectedPrefixes, InvalidAction, PrefixSet, ValidationChange, Vrp, VrpSet};
use bgpfc_wire::update::EncodeContext;

use super::*;
use crate::{Enforcement, Policies, Revalidation, Verdict};

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
    ) -> Verdict {
        self.0.lock().unwrap().push(("import", p, rov));
        Verdict::Accept
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
    ) -> Verdict {
        if rov == RovState::Invalid {
            Verdict::Reject
        } else {
            Verdict::Accept
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
            add_path: bgpfc_wire::update::AddPathFamilies::NONE,
        })
        .unwrap();
    let ctx = DecodeContext {
        four_octet_as: false,
        peer: PeerKind::External,
        allow_as_set: false,
        extended_next_hop: false,
        add_path: bgpfc_wire::update::AddPathFamilies::NONE,
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
        Some(&revalidation(
            1,
            &not_found_invalid,
            &["198.51.100.0/24"],
            0
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
        Some(&revalidation(1, &not_found_invalid, &["203.0.113.0/24"], 0))
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
    assert_eq!(
        report(&out),
        Some(&revalidation(1, &invalid_valid, &["192.0.2.0/24"], 1))
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
        Some(&revalidation(1, &valid_invalid, &["192.0.2.0/24"], 1))
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
        Some(&revalidation(1, &not_found_valid, &["192.0.2.0/24"], 0))
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
        Some(&revalidation(1, &invalid_disabled, &["192.0.3.0/24"], 1))
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
        ) -> Verdict {
            Verdict::Reject
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
    let order = |rib: &Rib| -> Vec<(IpAddr, RovState, bool)> {
        routes(rib, V4, p("192.0.2.0/24"))
            .into_iter()
            .map(|(peer, r)| (peer, r.rov, r.held))
            .collect()
    };
    assert_eq!(
        order(&rib),
        vec![(e1.addr, Valid, false), (e2.addr, Invalid, true)]
    );
    let second = vrps(&[("192.0.2.0/24", 24, 64_497)]);
    let out = outputs(|o| rib.validation_changed(delta(&first, second), now(), o));
    assert_eq!(
        order(&rib),
        vec![(e2.addr, Valid, false), (e1.addr, Invalid, true)]
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

/// Import policy that sets the state of the routes `from` gives to `to`
/// (RFC 6811 §3), tagging them with `tag` when it does; export policy
/// that records the state it is told and, when `export_sets`, sets one.
struct Restate {
    from: RovState,
    to: RovState,
    tag: Option<Community>,
    export_sets: bool,
    told: Seen,
}

impl Policies for Restate {
    fn import(
        &self,
        _: &PeerInfo,
        _: AddressFamily,
        p: Prefix,
        a: &PathAttrs,
        rov: RovState,
    ) -> Verdict {
        self.told.lock().unwrap().push(("import", p, rov));
        if rov != self.from {
            return Verdict::Accept;
        }
        match self.tag {
            None => Verdict::Restated(self.to),
            Some(c) => {
                let mut a = a.clone();
                a.communities = a.communities.iter().copied().chain([c]).collect();
                a.normalise();
                Verdict::ModifiedRestated(a, self.to)
            }
        }
    }
    fn export(
        &self,
        _: &PeerInfo,
        _: AddressFamily,
        p: Prefix,
        _: &PathAttrs,
        rov: RovState,
    ) -> Verdict {
        self.told.lock().unwrap().push(("export", p, rov));
        if self.export_sets {
            Verdict::Restated(RovState::Invalid)
        } else {
            Verdict::Accept
        }
    }
}

fn restating(from: RovState, to: RovState, tag: Option<Community>, told: &Seen) -> Restate {
    Restate {
        from,
        to,
        tag,
        export_sets: false,
        told: Arc::clone(told),
    }
}

#[test]
fn import_policy_sets_the_validation_state_of_a_route() {
    // RFC 6811 §3: policy can set the state. The route is held with it, the
    // decision process, export policy and the control plane see it, and the
    // lookup is what the source is compared with from then on.
    use RovState::{Invalid, NotFound, Valid};
    let told = Seen::default();
    let mut rib = Rib::with_policies(LOCAL_AS, Box::new(restating(Invalid, Valid, None, &told)));
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_002, 2);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    outputs(|o| rib.peer_up(e2.clone(), now(), o));
    let other_as = vrps(&[("192.0.2.0/24", 24, 64_497)]);
    outputs(|o| rib.validation_changed(all(other_as.clone()), now(), o));
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_001, 64_496], "10.0.0.1")),
            now(),
            o,
        );
    });
    let c = rib.candidates(V4, p("192.0.2.0/24"));
    assert_eq!((c.len(), c[0].rov), (1, Valid));
    assert_eq!(rib.loc_rib(V4).next().unwrap().1.rov, Valid);
    let stored = routes(&rib, V4, p("192.0.2.0/24"));
    assert_eq!((stored[0].1.rov, stored[0].1.lookup), (Valid, Invalid));
    // Export policy is told the state the route holds, not the lookup.
    assert_eq!(
        told.lock().unwrap().clone(),
        vec![
            ("import", p("192.0.2.0/24"), Invalid),
            ("export", p("192.0.2.0/24"), Valid),
        ]
    );

    // The same lookup again: nothing is judged again, so there is nothing
    // to report and policy is not asked.
    told.lock().unwrap().clear();
    let out = outputs(|o| rib.validation_changed(all(other_as.clone()), now(), o));
    assert_eq!(out, vec![]);
    assert!(told.lock().unwrap().is_empty());

    // The lookup moves from Invalid to NotFound: judged again, and policy
    // no longer sets a state, so the route holds the lookup's.
    let none = VrpSet::new();
    let out = outputs(|o| rib.validation_changed(delta(&other_as, none.clone()), now(), o));
    assert_eq!(
        report(&out),
        Some(&revalidation(
            1,
            &[(Invalid, NotFound, 1)],
            &["192.0.2.0/24"],
            0
        ))
    );
    let stored = routes(&rib, V4, p("192.0.2.0/24"));
    assert_eq!((stored[0].1.rov, stored[0].1.lookup), (NotFound, NotFound));
    assert_eq!(
        told.lock().unwrap().clone(),
        vec![
            ("import", p("192.0.2.0/24"), NotFound),
            // Its state changed, which export policy may look at: asked
            // about the route as it was, and as it is.
            ("export", p("192.0.2.0/24"), Valid),
            ("export", p("192.0.2.0/24"), NotFound),
        ]
    );

    // And back to Invalid: restated to Valid again, though the lookup moved
    // from NotFound to Invalid, so the report counts the lookup.
    let out = outputs(|o| rib.validation_changed(delta(&none, other_as), now(), o));
    assert_eq!(
        report(&out),
        Some(&revalidation(
            1,
            &[(NotFound, Invalid, 1)],
            &["192.0.2.0/24"],
            0
        ))
    );
    let stored = routes(&rib, V4, p("192.0.2.0/24"));
    assert_eq!((stored[0].1.rov, stored[0].1.lookup), (Valid, Invalid));
}

#[test]
fn a_route_given_the_same_state_by_two_lookups_changes_nothing_when_the_lookup_moves() {
    // The state policy sets is the same before and after the lookup moves,
    // so the route is the same to the FIB and to export policy: nothing is
    // installed or sent. The move itself is still a change of the source's
    // verdict, and counted.
    use RovState::{Invalid, NotFound, Valid};
    struct EveryUnknownIsValid;
    impl Policies for EveryUnknownIsValid {
        fn import(
            &self,
            _: &PeerInfo,
            _: AddressFamily,
            _: Prefix,
            _: &PathAttrs,
            rov: RovState,
        ) -> Verdict {
            if matches!(rov, Invalid | NotFound) {
                Verdict::Restated(Valid)
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
    let mut rib = Rib::with_policies(LOCAL_AS, Box::new(EveryUnknownIsValid));
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
    assert_eq!(fib(&out).len(), 1);
    assert_eq!(sends(&out, e2.addr).len(), 1);
    let other_as = vrps(&[("192.0.2.0/24", 24, 64_497)]);
    let out = outputs(|o| rib.validation_changed(delta(&VrpSet::new(), other_as), now(), o));
    assert_eq!(
        report(&out),
        Some(&revalidation(
            1,
            &[(NotFound, Invalid, 1)],
            &["192.0.2.0/24"],
            0
        ))
    );
    assert_eq!(fib(&out), vec![]);
    assert_eq!(sends(&out, e2.addr).len(), 0);
    assert_eq!(rib.candidates(V4, p("192.0.2.0/24"))[0].rov, Valid);
}

#[test]
fn a_route_restated_by_policy_on_arrival_is_not_a_held_one() {
    // A policy that rejects Invalid routes but sets the state of those it
    // would reject to NotFound first never rejects them: set and match are
    // in one run of the policy, so the route is a candidate.
    use RovState::{Invalid, NotFound};
    struct SetThenFilter;
    impl Policies for SetThenFilter {
        fn import(
            &self,
            _: &PeerInfo,
            _: AddressFamily,
            _: Prefix,
            _: &PathAttrs,
            rov: RovState,
        ) -> Verdict {
            // The two terms of `set rpki not-found; ...; match rpki
            // invalid; reject` seen from outside: the state after the
            // first is what the second tests.
            let after_set = if rov == Invalid { NotFound } else { rov };
            if after_set == Invalid {
                Verdict::Reject
            } else if after_set != rov {
                Verdict::Restated(after_set)
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
    let mut rib = Rib::with_policies(LOCAL_AS, Box::new(SetThenFilter));
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
    let c = rib.candidates(V4, p("192.0.2.0/24"));
    assert_eq!((c.len(), c[0].rov), (1, NotFound));
    assert_eq!(
        routes(&rib, V4, p("192.0.2.0/24"))[0].1.lookup,
        Invalid,
        "the lookup is kept beside the state policy set"
    );
}

#[test]
fn a_state_export_policy_sets_is_not_sent_or_kept() {
    // RFC 6811 §2: the state is local to the speaker. Export policy may
    // set it for its own later terms, but the route that goes out is the
    // route's own set, and the route keeps the state it had.
    let told = Seen::default();
    let mut rib = Rib::with_policies(
        LOCAL_AS,
        Box::new(Restate {
            from: RovState::Disabled,
            to: RovState::Disabled,
            tag: None,
            export_sets: true,
            told: Arc::clone(&told),
        }),
    );
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_002, 2);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    outputs(|o| rib.peer_up(e2.clone(), now(), o));
    let a = attrs(&[65_001], "10.0.0.1");
    let out = outputs(|o| rib.update(e1.addr, &announce(&["192.0.2.0/24"], &a), now(), o));
    let m = decode_sent(sends(&out, e2.addr)[0], &e2);
    assert_eq!(m[0].nlri, vec![p("192.0.2.0/24")]);
    assert_eq!(
        rib.candidates(V4, p("192.0.2.0/24"))[0].rov,
        RovState::Disabled
    );
    assert_eq!(
        rib.adj_rib_out(e2.addr, V4)
            .map(|(prefix, _)| prefix)
            .collect::<Vec<_>>(),
        vec![p("192.0.2.0/24")]
    );
}

#[test]
fn restated_attributes_are_interned_like_any_modified_ones() {
    // `ModifiedRestated` carries new attributes: they are interned and
    // shared by the routes that get the same ones, and the Adj-RIB-In
    // keeps the attributes as received for the next judgment.
    use RovState::Valid;
    let tag = Community::new(65_000, 7);
    let told = Seen::default();
    let policy = restating(RovState::Disabled, Valid, Some(tag), &told);
    let mut rib = Rib::with_policies(LOCAL_AS, Box::new(policy));
    let e1 = peer("10.0.0.1", 65_001, 1);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    let a = attrs(&[65_001], "10.0.0.1");
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24", "198.51.100.0/24"], &a),
            now(),
            o,
        );
    });
    let one = rib.candidates(V4, p("192.0.2.0/24"));
    let two = rib.candidates(V4, p("198.51.100.0/24"));
    assert_eq!((one[0].rov, two[0].rov), (Valid, Valid));
    assert_eq!(one[0].attrs.communities.as_ref(), [tag]);
    assert!(Arc::ptr_eq(one[0].attrs, two[0].attrs));
    let stored = routes(&rib, V4, p("192.0.2.0/24"));
    assert_eq!(stored[0].1.received().communities.len(), 0);
}

/// Import policy that gives Invalid routes a degree of preference of 500,
/// far above the default, so that nothing but the RIB's own treatment of
/// the Invalid can put one below another route.
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
        _: &PeerInfo,
        _: AddressFamily,
        _: Prefix,
        _: &PathAttrs,
        _: RovState,
    ) -> Verdict {
        Verdict::Accept
    }
}

/// The peer the best route to `prefix` came from.
fn best_peer(rib: &Rib, prefix: &str) -> Option<IpAddr> {
    rib.loc_rib(V4)
        .find(|(q, _)| *q == p(prefix))
        .map(|(_, b)| b.peer)
}

#[test]
fn prefer_valid_puts_an_invalid_route_below_the_others_whatever_its_preference() {
    // RFC 6811 §5: the Invalid lose in the decision process. Import policy
    // gives them a degree of preference of 500, and they still lose; and
    // their state follows the VRPs, so one that becomes Valid wins.
    let mut rib = Rib::with_policies(LOCAL_AS, Box::new(FavourInvalid));
    outputs(|o| {
        rib.set_invalid_action(InvalidAction::PreferValid, now(), o);
    });
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_002, 2);
    let watcher = peer("10.0.0.3", 65_003, 3);
    for info in [&e1, &e2, &watcher] {
        outputs(|o| rib.peer_up(info.clone(), now(), o));
    }
    let for_e2 = vrps(&[("192.0.2.0/24", 24, 64_497)]);
    outputs(|o| rib.validation_changed(all(for_e2.clone()), now(), o));

    // e1's route is Invalid, and alone it is used.
    let out = outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_001, 64_496], "10.0.0.1")),
            now(),
            o,
        );
    });
    assert_eq!(best_peer(&rib, "192.0.2.0/24"), Some(e1.addr));
    assert_eq!(fib(&out).len(), 1);
    assert_eq!(sends(&out, watcher.addr).len(), 1);

    // e2's route is Valid, with a longer path and the default preference:
    // it is chosen, and the FIB and the watcher follow.
    let out = outputs(|o| {
        rib.update(
            e2.addr,
            &announce(
                &["192.0.2.0/24"],
                &attrs(&[65_002, 100, 101, 64_497], "10.0.0.2"),
            ),
            now(),
            o,
        );
    });
    assert_eq!(best_peer(&rib, "192.0.2.0/24"), Some(e2.addr));
    assert_eq!(
        fib(&out),
        vec![FibChange {
            family: V4,
            prefix: p("192.0.2.0/24"),
            next_hop: Some(ip("10.0.0.2")),
            previous: Some(ip("10.0.0.1")),
        }]
    );
    assert_eq!(sends(&out, watcher.addr).len(), 1);
    // The Invalid route is still a candidate, in second place, with the
    // state and the preference it was given.
    let c = rib.candidates(V4, p("192.0.2.0/24"));
    assert_eq!(
        c.iter().map(|c| (c.peer, c.rov)).collect::<Vec<_>>(),
        vec![(e2.addr, RovState::Valid), (e1.addr, RovState::Invalid)]
    );
    assert_eq!(c[1].attrs.local_pref, Some(500));

    // The VRPs now name e1's origin: e1 is Valid, e2 Invalid. The choice
    // follows, with no UPDATE from either.
    let for_e1 = vrps(&[("192.0.2.0/24", 24, 64_496)]);
    let out = outputs(|o| rib.validation_changed(delta(&for_e2, for_e1.clone()), now(), o));
    assert_eq!(best_peer(&rib, "192.0.2.0/24"), Some(e1.addr));
    assert_eq!(
        fib(&out),
        vec![FibChange {
            family: V4,
            prefix: p("192.0.2.0/24"),
            next_hop: Some(ip("10.0.0.1")),
            previous: Some(ip("10.0.0.2")),
        }]
    );
    assert_eq!(report(&out).map(|r| r.best_changed), Some(1));

    // No VRPs at all: both NotFound, neither demoted, and the shorter
    // path decides.
    let out = outputs(|o| rib.validation_changed(delta(&for_e1, VrpSet::new()), now(), o));
    assert_eq!(best_peer(&rib, "192.0.2.0/24"), Some(e1.addr));
    assert_eq!(fib(&out), vec![]);
}

#[test]
fn prefer_valid_also_puts_the_invalid_below_a_route_not_found() {
    // The kinds are two: Invalid, and the rest. A policy-set NotFound (or
    // an unvalidated Disabled) route is not demoted.
    use RovState::{Invalid, NotFound, Valid};
    let told = Seen::default();
    let policy = Restate {
        from: Valid,
        to: NotFound,
        tag: None,
        export_sets: false,
        told: Arc::clone(&told),
    };
    let mut rib = Rib::with_policies(LOCAL_AS, Box::new(policy));
    outputs(|o| {
        rib.set_invalid_action(InvalidAction::PreferValid, now(), o);
    });
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_002, 2);
    for info in [&e1, &e2] {
        outputs(|o| rib.peer_up(info.clone(), now(), o));
    }
    outputs(|o| rib.validation_changed(all(vrps(&[("192.0.2.0/24", 24, 64_497)])), now(), o));
    // e1's route is Invalid and has the shorter path.
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_001], "10.0.0.1")),
            now(),
            o,
        );
    });
    outputs(|o| {
        rib.update(
            e2.addr,
            &announce(
                &["192.0.2.0/24"],
                &attrs(&[65_002, 100, 64_497], "10.0.0.2"),
            ),
            now(),
            o,
        );
    });
    let c = rib.candidates(V4, p("192.0.2.0/24"));
    assert_eq!(
        c.iter().map(|c| (c.peer, c.rov)).collect::<Vec<_>>(),
        vec![(e2.addr, NotFound), (e1.addr, Invalid)]
    );
}

#[test]
fn changing_the_action_decides_the_destinations_with_an_invalid_route_again() {
    let mut rib = Rib::with_policies(LOCAL_AS, Box::new(FavourInvalid));
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_002, 2);
    let watcher = peer("10.0.0.3", 65_003, 3);
    for info in [&e1, &e2, &watcher] {
        outputs(|o| rib.peer_up(info.clone(), now(), o));
    }
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
    // Two destinations with an Invalid route from e1 and a Valid one from
    // e2, and one with Valid routes only.
    let invalid = attrs(&[65_001, 64_496], "10.0.0.1");
    let valid = attrs(&[65_002, 100, 101, 64_497], "10.0.0.2");
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24", "198.51.100.0/24"], &invalid),
            now(),
            o,
        );
    });
    outputs(|o| {
        rib.update(
            e2.addr,
            &announce(
                &["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"],
                &valid,
            ),
            now(),
            o,
        );
    });
    // Nothing demotes them yet: the Invalid routes' preference wins.
    for prefix in ["192.0.2.0/24", "198.51.100.0/24"] {
        assert_eq!(best_peer(&rib, prefix), Some(e1.addr), "{prefix}");
    }

    let mut out = Vec::new();
    let report = rib.set_invalid_action(InvalidAction::PreferValid, now(), &mut out);
    assert_eq!(
        report,
        Enforcement {
            invalid: 2,
            destinations: 2,
            best_changed: 2,
        }
    );
    for prefix in ["192.0.2.0/24", "198.51.100.0/24"] {
        assert_eq!(best_peer(&rib, prefix), Some(e2.addr), "{prefix}");
    }
    let mut changes = fib(&out);
    changes.sort_by_key(|c| c.prefix);
    assert_eq!(
        changes
            .iter()
            .map(|c| (c.prefix, c.next_hop))
            .collect::<Vec<_>>(),
        vec![
            (p("192.0.2.0/24"), Some(ip("10.0.0.2"))),
            (p("198.51.100.0/24"), Some(ip("10.0.0.2"))),
        ]
    );
    assert_eq!(sends(&out, watcher.addr).len(), 1);

    // The same action again is no change.
    let mut out = Vec::new();
    assert_eq!(
        rib.set_invalid_action(InvalidAction::PreferValid, now(), &mut out),
        Enforcement::default()
    );
    assert_eq!(out, vec![]);

    // And back to leaving it to policy.
    let mut out = Vec::new();
    let report = rib.set_invalid_action(InvalidAction::Policy, now(), &mut out);
    assert_eq!((report.destinations, report.best_changed), (2, 2));
    for prefix in ["192.0.2.0/24", "198.51.100.0/24"] {
        assert_eq!(best_peer(&rib, prefix), Some(e1.addr), "{prefix}");
    }
    assert_eq!(fib(&out).len(), 2);
}

#[test]
fn the_n_best_paths_sent_to_a_peer_leave_out_the_demoted_ones_first() {
    // RFC 7911 §5 sends the N best by the decision process: a demoted
    // route is below every route that is not.
    use crate::PathLimit;
    let mut rib = Rib::with_policies(LOCAL_AS, Box::new(FavourInvalid));
    outputs(|o| {
        rib.set_invalid_action(InvalidAction::PreferValid, now(), o);
    });
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_002, 2);
    let e3 = peer("10.0.0.4", 65_004, 4);
    let to = PeerInfo {
        add_path_send: vec![(V4, PathLimit::Best(2))],
        ..peer("10.0.0.9", 65_009, 9)
    };
    for info in [&e1, &e2, &e3, &to] {
        outputs(|o| rib.peer_up(info.clone(), now(), o));
    }
    outputs(|o| rib.validation_changed(all(vrps(&[("192.0.2.0/24", 24, 64_497)])), now(), o));
    // e1 is Invalid (preference 500, shortest path); e2 and e3 are Valid.
    for (from, path) in [
        (&e1, vec![65_001, 64_496]),
        (&e2, vec![65_002, 100, 64_497]),
        (&e3, vec![65_004, 100, 101, 64_497]),
    ] {
        outputs(|o| {
            rib.update(
                from.addr,
                &announce(&["192.0.2.0/24"], &attrs(&path, &from.addr.to_string())),
                now(),
                o,
            );
        });
    }
    let sent: Vec<Vec<u32>> = rib
        .sent_paths(to.addr, V4)
        .iter()
        .map(|(_, _, a)| a.as_path.asns().map(|a| a.0).collect())
        .collect();
    let mut sent = sent;
    sent.sort();
    // The two Valid routes, not the Invalid one with the best preference.
    assert_eq!(
        sent,
        vec![vec![65_002, 100, 64_497], vec![65_004, 100, 101, 64_497]]
    );
}

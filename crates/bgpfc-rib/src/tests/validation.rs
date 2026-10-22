//! Every route carries its RFC 6811 validation state (issue #56), policy
//! sees it (RFC 6811 §3), and it follows the validation source, which
//! re-runs import policy and the decision process for the routes whose
//! state changed (RFC 6811 §4).

use std::sync::Mutex;

use bgpfc_rpki::{AffectedPrefixes, PrefixSet, ValidationChange, Vrp, VrpSet};
use bgpfc_wire::update::EncodeContext;

use super::*;
use crate::{Policies, RouteOrigin, Verdict};

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
    rib.peer_up(e1.clone(), now());
    rib.peer_up(i1.clone(), now());
    rib.update(
        e1.addr,
        &announce(&["192.0.2.0/24"], &attrs(&[65_001, 64_496], "10.0.0.1")),
        now(),
    );
    rib.update(
        e1.addr,
        &announce(&["2001:db8::/32"], &attrs(&[65_001], "2001:db8::1")),
        now(),
    );
    // An empty AS_PATH from an internal peer: the route originates in our
    // own AS (RFC 6811 §2).
    rib.update(
        i1.addr,
        &announce(
            &["192.0.2.0/24", "198.51.100.0/24"],
            &attrs(&[], "10.0.0.2"),
        ),
        now(),
    );
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
    rib.peer_up(e1.clone(), now());
    rib.peer_up(e2.clone(), now());
    rib.update(
        e1.addr,
        &announce(&["192.0.2.0/24"], &attrs(&[65_001], "10.0.0.1")),
        now(),
    );
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
    rib.tables
        .get(&family)
        .and_then(|t| t.get(&p(prefix)))
        .map(|d| d.received.iter().map(|r| (r.peer, r.rov)).collect())
        .unwrap_or_default()
}

type Change = (IpAddr, Prefix, RouteOrigin, RovState, RovState);

/// The validation state changes reported in `out`.
fn changes(out: &[Output]) -> Vec<Change> {
    out.iter()
        .filter_map(|o| match o {
            Output::RovStateChanged {
                peer,
                prefix,
                origin,
                from,
                to,
            } => Some((*peer, *prefix, *origin, *from, *to)),
            _ => None,
        })
        .collect()
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

fn by(asn: u32) -> RouteOrigin {
    RouteOrigin::As(Asn(asn))
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
        a.communities.push(Community::new(65_000, 1));
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
    assert_eq!(rib.validation_changed(all(set), now()), vec![]);
    let e1 = peer("10.0.0.1", 65_001, 1);
    let i1 = peer("10.0.0.2", 65_000, 2);
    let mut old = peer("10.0.0.3", 65_003, 3);
    old.four_octet_as = false;
    for info in [&e1, &i1, &old] {
        rib.peer_up(info.clone(), now());
    }
    let out = rib.update(
        e1.addr,
        &announce(
            &[
                "192.0.2.0/24",
                "192.0.2.0/25",
                "198.51.100.0/24",
                "10.0.0.0/8",
            ],
            &attrs(&[65_001, 64_496], "10.0.0.1"),
        ),
        now(),
    );
    // A route's first state is not a change.
    assert_eq!(changes(&out), vec![]);
    rib.update(
        e1.addr,
        &announce(
            &["2001:db8:1::/48", "2001:db8:1::/64"],
            &attrs(&[65_001, 64_496], "2001:db8::1"),
        ),
        now(),
    );
    // RFC 6811 §2: an empty AS_PATH originates in our own AS.
    rib.update(
        i1.addr,
        &announce(&["203.0.113.0/24"], &attrs(&[], "10.0.0.2")),
        now(),
    );
    // A final AS_SET: the origin is NONE, which no VRP matches.
    let mut set_path = attrs(&[65_001], "10.0.0.1");
    set_path
        .as_path
        .segments
        .push(bgpfc_wire::as_path::AsPathSegment {
            kind: bgpfc_wire::as_path::SegmentType::Set,
            asns: vec![Asn(64_496)],
        });
    rib.update(e1.addr, &announce(&["192.0.2.128/25"], &set_path), now());
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
    rib.update(
        old.addr,
        &UpdateMessage::decode(&message, &ctx).unwrap(),
        now(),
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
    rib.peer_up(e1.clone(), now());
    let old = vrps(&[("192.0.2.0/24", 24, 64_496)]);
    rib.validation_changed(all(old.clone()), now());
    let a = attrs(&[65_001, 64_496], "10.0.0.1");
    rib.update(
        e1.addr,
        &announce(&["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"], &a),
        now(),
    );
    let before = Arc::clone(&rib.candidates(V4, p("198.51.100.0/24"))[0].attrs);
    // The new source would make both NotFound routes Invalid, but the
    // change says only one of them is affected: the other is not looked
    // at again.
    let new = vrps(&[
        ("192.0.2.0/24", 24, 64_496),
        ("198.51.100.0/24", 24, 64_497),
        ("203.0.113.0/24", 24, 64_497),
    ]);
    let out = rib.validation_changed(
        ValidationChange {
            source: Arc::new(new.clone()),
            affected: AffectedPrefixes::from_vrps([vrp("198.51.100.0/24", 24, 64_497)]),
        },
        now(),
    );
    assert_eq!(
        changes(&out),
        vec![(
            e1.addr,
            p("198.51.100.0/24"),
            by(64_496),
            RovState::NotFound,
            RovState::Invalid
        )]
    );
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
    assert!(Arc::ptr_eq(&c[0].attrs, &before));
    assert_eq!(c[0].rov, RovState::Invalid);
    assert_eq!(fib(&out), vec![]);
    // A covering prefix affects what it covers.
    let out = rib.validation_changed(
        ValidationChange {
            source: Arc::new(new),
            affected: AffectedPrefixes::CoveredBy([p("203.0.0.0/16")].into_iter().collect()),
        },
        now(),
    );
    assert_eq!(
        changes(&out),
        vec![(
            e1.addr,
            p("203.0.113.0/24"),
            by(64_496),
            RovState::NotFound,
            RovState::Invalid
        )]
    );
    // Nothing affected: the source changes and no route is looked at.
    let out = rib.validation_changed(
        ValidationChange {
            source: Arc::new(old),
            affected: AffectedPrefixes::none(),
        },
        now(),
    );
    assert_eq!(out, vec![]);
    assert_eq!(
        held(&rib, V4, "203.0.113.0/24"),
        vec![(e1.addr, RovState::Invalid)]
    );
}

#[test]
fn all_validates_every_route_again() {
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_002, 2);
    rib.peer_up(e1.clone(), now());
    rib.peer_up(e2.clone(), now());
    rib.update(
        e1.addr,
        &announce(
            &["192.0.2.0/24", "198.51.100.0/24"],
            &attrs(&[65_001, 64_496], "10.0.0.1"),
        ),
        now(),
    );
    rib.update(
        e2.addr,
        &announce(&["192.0.2.0/24"], &attrs(&[65_002, 64_497], "10.0.0.2")),
        now(),
    );
    rib.update(
        e1.addr,
        &announce(&["2001:db8::/32"], &attrs(&[65_001, 64_496], "2001:db8::1")),
        now(),
    );
    let set = vrps(&[("192.0.2.0/24", 24, 64_496), ("2001:db8::/32", 32, 64_496)]);
    // Turning validation on: every route leaves Disabled, both peers'
    // routes to a destination included, in prefix order.
    let out = rib.validation_changed(all(set.clone()), now());
    let d = RovState::Disabled;
    assert_eq!(
        changes(&out),
        vec![
            (e1.addr, p("192.0.2.0/24"), by(64_496), d, RovState::Valid),
            (e2.addr, p("192.0.2.0/24"), by(64_497), d, RovState::Invalid),
            (
                e1.addr,
                p("198.51.100.0/24"),
                by(64_496),
                d,
                RovState::NotFound
            ),
            (e1.addr, p("2001:db8::/32"), by(64_496), d, RovState::Valid),
        ]
    );
    // The same source again: no route changes, nothing to do.
    assert_eq!(rib.validation_changed(all(set), now()), vec![]);
    // Turning it off again.
    let out = rib.validation_changed(ValidationChange::disabled(), now());
    assert_eq!(changes(&out).len(), 4);
    assert!(changes(&out).iter().all(|c| c.4 == RovState::Disabled));
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
    rib.peer_up(e1.clone(), now());
    rib.peer_up(e2.clone(), now());
    let other_as = vrps(&[("192.0.2.0/24", 24, 64_497)]);
    rib.validation_changed(all(other_as.clone()), now());
    let out = rib.update(
        e1.addr,
        &announce(&["192.0.2.0/24"], &attrs(&[65_001, 64_496], "10.0.0.1")),
        now(),
    );
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
    let out = rib.validation_changed(delta(&other_as, ours.clone()), now());
    assert_eq!(
        changes(&out),
        vec![(
            e1.addr,
            p("192.0.2.0/24"),
            by(64_496),
            RovState::Invalid,
            RovState::Valid
        )]
    );
    assert!(matches!(out[0], Output::RovStateChanged { .. }));
    assert_eq!(
        fib(&out),
        vec![FibChange {
            family: V4,
            prefix: p("192.0.2.0/24"),
            next_hop: Some(ip("10.0.0.1")),
        }]
    );
    let m = decode_sent(sends(&out, e2.addr)[0], &e2);
    assert_eq!(m[0].nlri, vec![p("192.0.2.0/24")]);
    assert_eq!(communities(&m[0]), vec![Community::new(65_000, 1)]);
    let c = rib.candidates(V4, p("192.0.2.0/24"));
    assert_eq!((c.len(), c[0].rov), (1, RovState::Valid));
    assert_eq!(rib.loc_rib(V4).next().unwrap().1.rov, RovState::Valid);

    // And back: withdrawn from the FIB and from e2, still held.
    let out = rib.validation_changed(delta(&ours, other_as), now());
    assert_eq!(changes(&out).len(), 1);
    assert_eq!(
        fib(&out),
        vec![FibChange {
            family: V4,
            prefix: p("192.0.2.0/24"),
            next_hop: None,
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
    rib.peer_up(e1.clone(), now());
    rib.peer_up(e2.clone(), now());
    rib.validation_changed(all(VrpSet::new()), now());
    let out = rib.update(
        e1.addr,
        &announce(&["192.0.2.0/24"], &attrs(&[65_001, 64_496], "10.0.0.1")),
        now(),
    );
    let m = decode_sent(sends(&out, e2.addr)[0], &e2);
    assert_eq!(communities(&m[0]), vec![]);
    // NotFound to Valid: the same route stays best and the FIB stays as
    // it is, but export policy now tags it, so e2 hears it again.
    let set = vrps(&[("192.0.2.0/24", 24, 64_496)]);
    let out = rib.validation_changed(delta(&VrpSet::new(), set), now());
    assert_eq!(changes(&out).len(), 1);
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
    rib.peer_up(e1.clone(), t0);
    rib.peer_up(e2.clone(), t0);
    rib.validation_changed(all(VrpSet::new()), t0);
    let out = rib.update(
        e1.addr,
        &announce(&["192.0.2.0/24"], &attrs(&[65_001, 64_496], "10.0.0.1")),
        t0,
    );
    assert_eq!(sends(&out, e2.addr).len(), 1);
    let set = vrps(&[("192.0.2.0/24", 24, 64_496)]);
    let t1 = t0 + Duration::from_secs(1);
    let out = rib.validation_changed(delta(&VrpSet::new(), set), t1);
    assert_eq!(changes(&out).len(), 1);
    assert!(sends(&out, e2.addr).is_empty(), "held by the interval");
    let due = rib.next_deadline().unwrap();
    assert!(due >= t0 + Duration::from_secs(30), "{:?}", due - t0);
    assert_eq!(
        rib.flush(due.checked_sub(Duration::from_secs(1)).unwrap()),
        vec![]
    );
    let out = rib.flush(due);
    let m = decode_sent(sends(&out, e2.addr)[0], &e2);
    assert_eq!(communities(&m[0]), vec![Community::new(65_000, 1)]);
}

#[test]
fn withdrawn_routes_and_those_of_a_peer_gone_are_not_validated_again() {
    let mut rib = Rib::with_policies(LOCAL_AS, Box::new(RejectInvalidTagValid));
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_002, 2);
    rib.peer_up(e1.clone(), now());
    rib.peer_up(e2.clone(), now());
    let set = vrps(&[("192.0.2.0/23", 24, 64_497)]);
    rib.validation_changed(all(set.clone()), now());
    // Invalid, so rejected and only held.
    let a = attrs(&[65_001, 64_496], "10.0.0.1");
    rib.update(
        e1.addr,
        &announce(&["192.0.2.0/24", "192.0.3.0/24"], &a),
        now(),
    );
    rib.update(
        e2.addr,
        &announce(&["192.0.3.0/24"], &attrs(&[65_002, 64_496], "10.0.0.2")),
        now(),
    );
    rib.update(e1.addr, &withdraw(&["192.0.2.0/24"]), now());
    rib.peer_down(e2.addr, now());
    assert_eq!(held(&rib, V4, "192.0.2.0/24"), vec![]);
    assert_eq!(
        held(&rib, V4, "192.0.3.0/24"),
        vec![(e1.addr, RovState::Invalid)]
    );
    let out = rib.validation_changed(ValidationChange::disabled(), now());
    assert_eq!(
        changes(&out),
        vec![(
            e1.addr,
            p("192.0.3.0/24"),
            by(64_496),
            RovState::Invalid,
            RovState::Disabled
        )]
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
    rib.peer_up(e1.clone(), now());
    rib.validation_changed(all(VrpSet::new()), now());
    let prefixes: Vec<String> = (0..1024u32)
        .map(|i| format!("10.{}.{}.0/24", i >> 8, i & 0xff))
        .collect();
    let refs: Vec<&str> = prefixes.iter().map(String::as_str).collect();
    rib.update(
        e1.addr,
        &announce(&refs, &attrs(&[65_001, 64_496], "10.0.0.1")),
        now(),
    );
    let sparse = ["10.1.7.0/24", "10.2.0.0/17", "10.3.255.0/24", "10.0.0.0/23"].map(p);
    let dense = (0..200u32).map(|i| p(&format!("10.{}.{}.0/24", i % 4, (i * 7) & 0xff)));
    for changed in [sparse.into_iter().collect::<PrefixSet>(), dense.collect()] {
        // Invalid for the changed prefixes, NotFound elsewhere.
        let set: VrpSet = changed
            .iter()
            .map(|q| Vrp::new(q, 24, Asn(64_497)).unwrap())
            .collect();
        let out = rib.validation_changed(
            ValidationChange {
                source: Arc::new(set),
                affected: AffectedPrefixes::CoveredBy(changed.clone()),
            },
            now(),
        );
        let got: Vec<Prefix> = changes(&out).iter().map(|c| c.1).collect();
        let expected: Vec<Prefix> = refs
            .iter()
            .map(|s| p(s))
            .filter(|q| changed.covers(*q))
            .collect();
        assert_ne!(expected.len(), 0);
        assert_eq!(got, expected);
        assert!(changes(&out).iter().all(|c| c.4 == RovState::Invalid));
        // And back.
        let out = rib.validation_changed(
            ValidationChange {
                source: Arc::new(VrpSet::new()),
                affected: AffectedPrefixes::CoveredBy(changed),
            },
            now(),
        );
        assert_eq!(changes(&out).len(), expected.len());
    }
}

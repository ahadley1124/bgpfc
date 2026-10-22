//! The Adj-RIBs-In hold routes as received, before import policy
//! (RFC 4271 §3.2), and the candidates are what import policy makes of
//! them (§9.1.1). A route import policy rejects is held only when its
//! validation state alone decided it (RFC 6811 §2); one rejected whatever
//! its state is dropped.

use std::sync::Mutex;

use super::*;
use crate::{AcceptAll, Policies, Verdict};

/// Import policy that rejects one prefix and gives every other route a
/// `LOCAL_PREF` of 200.
struct RejectOneRaiseRest(Prefix);

impl Policies for RejectOneRaiseRest {
    fn import(
        &self,
        _: &PeerInfo,
        _: AddressFamily,
        p: Prefix,
        a: &PathAttrs,
        _: RovState,
    ) -> Verdict {
        if p == self.0 {
            return Verdict::Reject;
        }
        let mut a = a.clone();
        a.local_pref = Some(200);
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

/// Import policy that rejects some prefixes while validation is off
/// (`disabled`) and takes them with any other state, as a policy that
/// takes only validated routes would; it takes every other prefix. What
/// it is asked is recorded.
struct RejectUnvalidated(Vec<Prefix>, Arc<Mutex<Vec<(Prefix, RovState)>>>);

impl RejectUnvalidated {
    fn new(prefixes: Vec<Prefix>) -> RejectUnvalidated {
        RejectUnvalidated(prefixes, Arc::default())
    }
}

impl Policies for RejectUnvalidated {
    fn import(
        &self,
        _: &PeerInfo,
        _: AddressFamily,
        p: Prefix,
        _: &PathAttrs,
        rov: RovState,
    ) -> Verdict {
        self.1.lock().unwrap().push((p, rov));
        if self.0.contains(&p) && rov == RovState::Disabled {
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
        _: &PathAttrs,
        _: RovState,
    ) -> Verdict {
        Verdict::Accept
    }
}

/// What the Adj-RIB-In holds for `prefix`: each peer's route as received.
fn received(rib: &Rib, family: AddressFamily, prefix: Prefix) -> Vec<(IpAddr, Arc<PathAttrs>)> {
    rib.tables
        .get(&family)
        .and_then(|t| t.get(&prefix))
        .map(|d| {
            d.received
                .iter()
                .map(|r| (r.peer, Arc::clone(&r.attrs)))
                .collect()
        })
        .unwrap_or_default()
}

/// Destinations the RIB holds in `family`, whatever is in them.
fn destinations(rib: &Rib, family: AddressFamily) -> Vec<Prefix> {
    rib.tables
        .get(&family)
        .map(|t| t.keys().copied().collect())
        .unwrap_or_default()
}

#[test]
fn accepted_routes_are_held_as_received_and_rejected_ones_are_dropped() {
    let rejected = p("198.51.100.0/24");
    let mut rib = Rib::with_policies(LOCAL_AS, Box::new(RejectOneRaiseRest(rejected)));
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_002, 2);
    rib.peer_up(e1.clone(), now());
    rib.peer_up(e2.clone(), now());
    let a = attrs(&[65_001], "10.0.0.1");
    let out = rib.update(
        e1.addr,
        &announce(&["192.0.2.0/24", "198.51.100.0/24"], &a),
        now(),
    );
    // Only the accepted route is a candidate, with what policy set.
    let f = fib(&out);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].prefix, p("192.0.2.0/24"));
    let c = rib.candidates(V4, p("192.0.2.0/24"));
    assert_eq!(c.len(), 1);
    assert_eq!(c[0].attrs.local_pref, Some(200));
    // It is held as received, for import policy to run on again.
    let held = received(&rib, V4, p("192.0.2.0/24"));
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].0, e1.addr);
    assert_eq!(*held[0].1, a);
    assert_eq!(held[0].1.local_pref, None);
    // Policy rejects the other whatever its validation state, so no
    // change of state could bring it back: it is not kept, takes no
    // memory, and is not counted.
    assert!(rib.candidates(V4, rejected).is_empty());
    assert_eq!(received(&rib, V4, rejected), vec![]);
    assert_eq!(destinations(&rib, V4), vec![p("192.0.2.0/24")]);
    assert_eq!(
        rib.peer_stats(e1.addr).unwrap().received,
        vec![(V4, 1), (V6, 0)]
    );
    // A second peer's route to the rejected destination: the same.
    rib.update(
        e2.addr,
        &announce(&["198.51.100.0/24"], &attrs(&[65_002], "10.0.0.2")),
        now(),
    );
    assert_eq!(destinations(&rib, V4), vec![p("192.0.2.0/24")]);
    assert_eq!(rib.loc_rib(V4).count(), 1);
}

#[test]
fn a_route_import_policy_rejected_is_used_once_policy_accepts_it_again() {
    // How a reload's ROUTE-REFRESH re-evaluates: the peer sends the same
    // route again, and import policy runs on it again even though nothing
    // in it changed.
    let rejected = p("198.51.100.0/24");
    let mut rib = Rib::with_policies(LOCAL_AS, Box::new(RejectOneRaiseRest(rejected)));
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_002, 2);
    rib.peer_up(e1.clone(), now());
    rib.peer_up(e2.clone(), now());
    let a = attrs(&[65_001], "10.0.0.1");
    let both = announce(&["192.0.2.0/24", "198.51.100.0/24"], &a);
    rib.update(e1.addr, &both, now());
    assert_eq!(rib.loc_rib(V4).count(), 1);
    // The same UPDATE again under the same policy: nothing to do.
    assert_eq!(rib.update(e1.addr, &both, now()), vec![]);

    rib.set_policies(Box::new(AcceptAll));
    let out = rib.update(e1.addr, &both, now());
    // The newly accepted route goes into the FIB; the other changed its
    // attributes (no LOCAL_PREF set any more) and is installed again.
    let f = fib(&out);
    assert_eq!(f.len(), 2, "{f:?}");
    assert!(f.iter().all(|c| c.next_hop == Some(ip("10.0.0.1"))));
    assert!(f.iter().any(|c| c.prefix == rejected));
    // To an external peer only the new route is news.
    let m = decode_sent(sends(&out, e2.addr)[0], &e2);
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].nlri, vec![rejected]);
    assert_eq!(
        rib.candidates(V4, p("192.0.2.0/24"))[0].attrs.local_pref,
        None
    );
    assert_eq!(
        rib.peer_stats(e1.addr).unwrap().received,
        vec![(V4, 2), (V6, 0)]
    );

    // Rejected again: withdrawn, and no longer held or counted.
    rib.set_policies(Box::new(RejectOneRaiseRest(rejected)));
    let out = rib.update(e1.addr, &both, now());
    let withdrawn: Vec<Prefix> = fib(&out)
        .iter()
        .filter(|c| c.next_hop.is_none())
        .map(|c| c.prefix)
        .collect();
    assert_eq!(withdrawn, vec![rejected]);
    assert_eq!(received(&rib, V4, rejected), vec![]);
    assert_eq!(destinations(&rib, V4), vec![p("192.0.2.0/24")]);
    assert_eq!(
        rib.peer_stats(e1.addr).unwrap().received,
        vec![(V4, 1), (V6, 0)]
    );
}

#[test]
fn a_route_rejected_for_its_validation_state_alone_is_held() {
    // RFC 6811 §2: the state must not keep a route out of the Adj-RIB-In.
    // Policy rejects the route while it is `disabled` and would take it
    // with any other state, so it is held, counted, and no candidate.
    use RovState::{Disabled, Valid};
    let held = p("198.51.100.0/24");
    let policy = RejectUnvalidated::new(vec![held]);
    let asked = Arc::clone(&policy.1);
    let mut rib = Rib::with_policies(LOCAL_AS, Box::new(policy));
    let e1 = peer("10.0.0.1", 65_001, 1);
    rib.peer_up(e1.clone(), now());
    let a = attrs(&[65_001], "10.0.0.1");
    let out = rib.update(
        e1.addr,
        &announce(&["192.0.2.0/24", "198.51.100.0/24"], &a),
        now(),
    );
    assert_eq!(fib(&out).len(), 1);
    assert!(rib.candidates(V4, held).is_empty());
    assert_eq!(received(&rib, V4, held), vec![(e1.addr, Arc::new(a))]);
    assert_eq!(destinations(&rib, V4), vec![p("192.0.2.0/24"), held]);
    assert_eq!(
        rib.peer_stats(e1.addr).unwrap().received,
        vec![(V4, 2), (V6, 0)]
    );
    // The accepted route was asked about once; the rejected one with its
    // own state, then with the others until one took it.
    assert_eq!(
        *asked.lock().unwrap(),
        vec![
            (p("192.0.2.0/24"), Disabled),
            (held, Disabled),
            (held, Valid)
        ]
    );
}

#[test]
fn withdrawals_peer_down_and_family_disable_drop_held_routes_too() {
    let held = p("198.51.100.0/24");
    let held6 = p("2001:db8:9::/48");
    let policy = RejectUnvalidated::new(vec![held, held6]);
    let mut rib = Rib::with_policies(LOCAL_AS, Box::new(policy));
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_002, 2);
    rib.peer_up(e1.clone(), now());
    rib.peer_up(e2.clone(), now());
    let a = attrs(&[65_001], "10.0.0.1");
    let v6 = attrs(&[65_001], "2001:db8::1");
    let send_all = |rib: &mut Rib| {
        rib.update(
            e1.addr,
            &announce(&["192.0.2.0/24", "198.51.100.0/24"], &a),
            now(),
        );
        rib.update(
            e1.addr,
            &announce(&["2001:db8:1::/48", "2001:db8:9::/48"], &v6),
            now(),
        );
    };
    send_all(&mut rib);
    assert_eq!(destinations(&rib, V4).len(), 2);
    assert_eq!(destinations(&rib, V6).len(), 2);

    // A withdrawal of a held route: the destination goes with it, with
    // nothing to tell anyone.
    let out = rib.update(e1.addr, &withdraw(&["198.51.100.0/24"]), now());
    assert_eq!(out, vec![]);
    assert_eq!(destinations(&rib, V4), vec![p("192.0.2.0/24")]);
    assert_eq!(
        rib.peer_stats(e1.addr).unwrap().received,
        vec![(V4, 1), (V6, 2)]
    );
    // A replacement the loop checks drop takes a held route out too.
    rib.update(e1.addr, &announce(&["198.51.100.0/24"], &a), now());
    let looped = attrs(&[65_001, LOCAL_AS.0], "10.0.0.1");
    let out = rib.update(e1.addr, &announce(&["198.51.100.0/24"], &looped), now());
    assert_eq!(out, vec![]);
    assert_eq!(destinations(&rib, V4), vec![p("192.0.2.0/24")]);

    // RFC 4760 §7: the family goes, held routes included.
    rib.update(e1.addr, &announce(&["198.51.100.0/24"], &a), now());
    let out = rib.update(e1.addr, &disabling(V6, DecodedUpdate::default()), now());
    assert_eq!(fib(&out).len(), 1);
    assert_eq!(destinations(&rib, V6), Vec::<Prefix>::new());
    assert_eq!(received(&rib, V6, held6).len(), 0);
    assert_eq!(destinations(&rib, V4).len(), 2);

    // Peer down: nothing of the peer is left.
    let out = rib.peer_down(e1.addr, now());
    assert_eq!(fib(&out).len(), 1);
    assert_eq!(destinations(&rib, V4), Vec::<Prefix>::new());
    assert_eq!(destinations(&rib, V6), Vec::<Prefix>::new());

    // A destination another peer still has a route to stays, with that
    // route alone.
    rib.peer_up(e1.clone(), now());
    send_all(&mut rib);
    rib.update(
        e2.addr,
        &announce(&["198.51.100.0/24"], &attrs(&[65_002], "10.0.0.2")),
        now(),
    );
    rib.peer_down(e1.addr, now());
    assert_eq!(destinations(&rib, V4), vec![held]);
    let peers: Vec<IpAddr> = received(&rib, V4, held).iter().map(|r| r.0).collect();
    assert_eq!(peers, vec![e2.addr]);
}

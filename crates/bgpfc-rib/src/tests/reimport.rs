//! A changed import policy is applied from the Adj-RIBs-In (RFC 4271 §3
//! (a)): every route a peer sent that the RIB kept, held ones included,
//! goes through it again at once, with no UPDATE; the peer is asked again
//! with ROUTE-REFRESH (§3 (b), RFC 2918 §4) only for the families whose
//! routes a policy dropped, which the RIB did not keep.

use crate::{Held, Imported, Policies, Reimport, Verdict};

use super::*;

/// Import policy that rejects `dropped` whatever their state, rejects
/// `held` while they are `disabled` and takes them with any other state
/// (so that they are held for policy, RFC 6811 §2), and sets `LOCAL_PREF`
/// `pref` on the others when it is given. Export takes everything.
#[derive(Clone, Default)]
struct Import {
    dropped: Vec<Prefix>,
    held: Vec<Prefix>,
    pref: Option<u32>,
}

impl Import {
    fn new(dropped: &[&str], held: &[&str], pref: Option<u32>) -> Import {
        Import {
            dropped: dropped.iter().map(|s| p(s)).collect(),
            held: held.iter().map(|s| p(s)).collect(),
            pref,
        }
    }
}

impl Policies for Import {
    fn import(
        &self,
        _: &PeerInfo,
        _: AddressFamily,
        prefix: Prefix,
        a: &PathAttrs,
        rov: RovState,
    ) -> Imported {
        if self.dropped.contains(&prefix)
            || (self.held.contains(&prefix) && rov == RovState::Disabled)
        {
            return Verdict::Reject.into();
        }
        match self.pref {
            Some(pref) => {
                let mut a = a.clone();
                a.local_pref = Some(pref);
                Verdict::Modified(a).into()
            }
            None => Verdict::Accept.into(),
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

const A: &str = "192.0.2.0/24";
const B: &str = "198.51.100.0/24";
const C: &str = "203.0.113.0/24";

/// An external peer that sends, and an internal one that is sent the
/// routes with their `LOCAL_PREF` (RFC 4271 §5.1.5).
fn sender_and_receiver(rib: &mut Rib) -> (PeerInfo, PeerInfo) {
    let e1 = peer("10.0.0.1", 65_001, 1);
    let i1 = peer("10.0.0.3", 65_000, 3);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    outputs(|o| rib.peer_up(i1.clone(), now(), o));
    (e1, i1)
}

/// e1's routes to `prefixes`, from AS 64496, as one UPDATE.
fn from_e1(rib: &mut Rib, e1: &PeerInfo, prefixes: &[&str]) -> Vec<Output> {
    let a = attrs(&[65_001, 64_496], "10.0.0.1");
    outputs(|o| rib.update(e1.addr, &announce(prefixes, &a), now(), o))
}

/// Replace the policies, exporting again to nobody, and import again the
/// routes of `peers`.
fn reload(rib: &mut Rib, policy: Import, peers: &[IpAddr]) -> Vec<Output> {
    let mut out = outputs(|o| rib.set_policies(Box::new(policy), &[], now(), o));
    assert_eq!(out, vec![], "set_policies alone judges no route again");
    rib.reimport(peers, now(), &mut out);
    out
}

/// The one report in `out`, which comes first.
fn report(out: &[Output]) -> &Reimport {
    let reports: Vec<&Reimport> = out
        .iter()
        .filter_map(|o| match o {
            Output::Reimported(r) => Some(r),
            _ => None,
        })
        .collect();
    assert_eq!(reports.len(), 1, "{out:?}");
    assert!(matches!(out[0], Output::Reimported(_)), "{out:?}");
    reports[0]
}

/// The ROUTE-REFRESH requests in `out`, which come last.
fn requests(out: &[Output]) -> Vec<(IpAddr, Vec<AddressFamily>)> {
    let asked: Vec<_> = out
        .iter()
        .filter_map(|o| match o {
            Output::RequestRoutes { peer, families } => Some((*peer, families.clone())),
            _ => None,
        })
        .collect();
    let tail = &out[out.len() - asked.len()..];
    assert!(
        tail.iter()
            .all(|o| matches!(o, Output::RequestRoutes { .. })),
        "{out:?}"
    );
    asked
}

/// The announcements, with their `LOCAL_PREF`, and the withdrawals sent to
/// `to`.
fn sent(out: &[Output], to: &PeerInfo) -> (Vec<(Prefix, Option<u32>)>, Vec<Prefix>) {
    let mut nlri = Vec::new();
    let mut withdrawn = Vec::new();
    for messages in sends(out, to.addr) {
        for m in decode_sent(messages, to) {
            let pref = m.attributes.iter().find_map(|a| match a {
                PathAttribute::LocalPref(v) => Some(*v),
                _ => None,
            });
            nlri.extend(m.nlri.iter().map(|p| (*p, pref)));
            withdrawn.extend(m.withdrawn);
        }
    }
    (nlri, withdrawn)
}

/// e1's routes the RIB keeps for `prefix`: why each is held, if it is,
/// and the `LOCAL_PREF` it is used with.
fn kept(rib: &Rib, prefix: &str) -> Vec<(Option<Held>, Option<u32>)> {
    rib.routes(V4, p(prefix))
        .iter()
        .map(|r| (r.held, r.attrs.local_pref))
        .collect()
}

/// What `peer_stats` counts for `addr` in IPv4: received, held.
fn counted(rib: &Rib, addr: IpAddr) -> (usize, usize) {
    let s = rib.peer_stats(addr).unwrap();
    (s.received[0].1, s.held[0].1)
}

#[test]
fn a_new_import_policy_applies_to_the_kept_routes_at_once() {
    let mut rib = Rib::with_policies(LOCAL_AS, Box::new(Import::default()));
    let (e1, i1) = sender_and_receiver(&mut rib);
    from_e1(&mut rib, &e1, &[A, B, C]);
    assert_eq!(rib.loc_rib(V4).count(), 3);

    // A sets LOCAL_PREF, B is rejected whatever its state, C rejected
    // while not validated: no UPDATE from e1, no ROUTE-REFRESH.
    let out = reload(&mut rib, Import::new(&[B], &[C], Some(200)), &[e1.addr]);
    let r = report(&out);
    assert_eq!(r.peers, vec![e1.addr]);
    assert_eq!(
        (r.routes, r.changed, r.held, r.released, r.dropped),
        (3, 3, 1, 0, 1)
    );
    assert_eq!(r.best_changed, 3);
    assert_eq!((r.refresh.clone(), r.missing.clone()), (vec![], vec![]));
    assert_eq!(requests(&out), vec![]);
    // The FIB keeps A, with the same next hop, and loses B and C.
    let f = fib(&out);
    assert_eq!(f.len(), 3, "{f:?}");
    assert!(
        f.iter()
            .any(|c| c.prefix == p(A) && c.next_hop == c.previous)
    );
    assert_eq!(
        f.iter().filter(|c| c.next_hop.is_none()).count(),
        2,
        "{f:?}"
    );
    // The internal peer is told A's new LOCAL_PREF and loses B and C.
    let (nlri, mut withdrawn) = sent(&out, &i1);
    withdrawn.sort();
    assert_eq!(nlri, vec![(p(A), Some(200))]);
    assert_eq!(withdrawn, vec![p(B), p(C)]);
    // B is not kept; C is held for policy, counted.
    assert_eq!(kept(&rib, A), vec![(None, Some(200))]);
    assert_eq!(kept(&rib, B), vec![]);
    assert_eq!(kept(&rib, C), vec![(Some(Held::Policy), None)]);
    assert_eq!(counted(&rib, e1.addr), (2, 1));

    // Back to the first policy: C, held, is used again at once; B, not
    // kept, only e1 can send again, so it is asked for IPv4 alone.
    let out = reload(&mut rib, Import::default(), &[e1.addr]);
    let r = report(&out);
    assert_eq!(
        (r.routes, r.changed, r.held, r.released, r.dropped),
        (2, 2, 0, 1, 0)
    );
    assert_eq!(r.refresh, vec![(e1.addr, V4)]);
    assert_eq!(requests(&out), vec![(e1.addr, vec![V4])]);
    let (nlri, withdrawn) = sent(&out, &i1);
    assert_eq!(nlri.len(), 2, "{nlri:?}");
    assert!(nlri.contains(&(p(C), Some(100))), "{nlri:?}");
    assert_eq!(withdrawn, vec![]);
    assert_eq!(kept(&rib, C), vec![(None, None)]);
    assert_eq!(rib.loc_rib(V4).count(), 2);
    // The ROUTE-REFRESH brings B back, through the policy in use.
    let out = from_e1(&mut rib, &e1, &[A, B, C]);
    assert_eq!(fib(&out).len(), 1);
    assert_eq!(sent(&out, &i1), (vec![(p(B), Some(100))], vec![]));
    assert_eq!(rib.loc_rib(V4).count(), 3);
    assert_eq!(counted(&rib, e1.addr), (3, 0));

    // The same policy again: nothing changes, nothing is asked for.
    let out = reload(&mut rib, Import::default(), &[e1.addr]);
    let r = report(&out);
    assert_eq!((r.routes, r.changed, r.best_changed), (3, 0, 0));
    assert_eq!(out.len(), 1, "{out:?}");
}

#[test]
fn a_route_dropped_again_after_the_request_is_asked_for_again() {
    // The request forgets the family; a route the policy in use drops,
    // as the peer sends it again, notes it anew.
    let mut rib = Rib::with_policies(LOCAL_AS, Box::new(Import::new(&[B], &[], None)));
    let (e1, _) = sender_and_receiver(&mut rib);
    from_e1(&mut rib, &e1, &[A, B]);
    let out = reload(&mut rib, Import::new(&[B], &[], Some(150)), &[e1.addr]);
    assert_eq!(requests(&out), vec![(e1.addr, vec![V4])]);
    // Nothing dropped since: nothing to ask.
    let out = reload(&mut rib, Import::new(&[B], &[], None), &[e1.addr]);
    assert_eq!(requests(&out), vec![]);
    // The peer answers the request; B is dropped again.
    from_e1(&mut rib, &e1, &[A, B]);
    let out = reload(&mut rib, Import::default(), &[e1.addr]);
    assert_eq!(requests(&out), vec![(e1.addr, vec![V4])]);
    // A route the walk itself drops is noted too.
    from_e1(&mut rib, &e1, &[A, B]);
    let out = reload(&mut rib, Import::new(&[A], &[], None), &[e1.addr]);
    assert_eq!(report(&out).dropped, 1);
    assert_eq!(requests(&out), vec![]);
    let out = reload(&mut rib, Import::default(), &[e1.addr]);
    assert_eq!(requests(&out), vec![(e1.addr, vec![V4])]);
}

#[test]
fn only_the_routes_of_the_named_peers_are_imported_again() {
    let mut rib = Rib::with_policies(LOCAL_AS, Box::new(Import::default()));
    let (e1, i1) = sender_and_receiver(&mut rib);
    let e2 = peer("10.0.0.2", 65_002, 2);
    outputs(|o| rib.peer_up(e2.clone(), now(), o));
    from_e1(&mut rib, &e1, &[A]);
    let a2 = attrs(&[65_002, 64_496], "10.0.0.2");
    outputs(|o| rib.update(e2.addr, &announce(&[A, B], &a2), now(), o));
    // Named twice, with a peer that is not up: e1 once, e2 not at all.
    let gone = ip("10.9.9.9");
    let out = reload(
        &mut rib,
        Import::new(&[], &[], Some(300)),
        &[e1.addr, gone, e1.addr],
    );
    let r = report(&out);
    assert_eq!(r.peers, vec![e1.addr]);
    assert_eq!((r.routes, r.changed), (1, 1));
    let prefs: Vec<(IpAddr, Option<u32>)> = rib
        .routes(V4, p(A))
        .iter()
        .map(|r| (r.peer, r.attrs.local_pref))
        .collect();
    assert!(prefs.contains(&(e1.addr, Some(300))), "{prefs:?}");
    assert!(prefs.contains(&(e2.addr, None)), "{prefs:?}");
    assert_eq!(kept(&rib, B), vec![(None, None)]);
    // e1's route wins on LOCAL_PREF now, and the internal peer hears it.
    assert_eq!(rib.loc_rib(V4).next().unwrap().1.peer, e1.addr);
    assert_eq!(sent(&out, &i1).0, vec![(p(A), Some(300))]);
    // No peer up among those named: nothing at all.
    let out = reload(&mut rib, Import::default(), &[gone]);
    assert_eq!(out, vec![]);
    let out = reload(&mut rib, Import::default(), &[]);
    assert_eq!(out, vec![]);
}

#[test]
fn a_peer_that_cannot_be_asked_is_reported_missing() {
    // RFC 2918 §4: only a peer that advertised the capability is asked,
    // and only for a family it advertised. Without either, the routes
    // stay missing, and stay noted, until the peer sends them again.
    let mut no_refresh = peer("10.0.0.1", 65_001, 1);
    no_refresh.route_refresh = false;
    let mut v4_only = peer("10.0.0.2", 65_002, 2);
    v4_only.families = vec![V4];
    let mut rib = Rib::with_policies(
        LOCAL_AS,
        Box::new(Import::new(&[B, "2001:db8::/32"], &[], None)),
    );
    for info in [&no_refresh, &v4_only] {
        outputs(|o| rib.peer_up(info.clone(), now(), o));
    }
    let a1 = attrs(&[65_001], "10.0.0.1");
    outputs(|o| rib.update(no_refresh.addr, &announce(&[A, B], &a1), now(), o));
    // v4_only sends IPv6 routes it may send (RFC 4760 §8: we advertised
    // the family), and IPv4 ones.
    let a2 = attrs(&[65_002], "10.0.0.2");
    outputs(|o| rib.update(v4_only.addr, &announce(&[B], &a2), now(), o));
    let a6 = attrs(&[65_002], "2001:db8::2");
    outputs(|o| {
        rib.update(
            v4_only.addr,
            &announce(&["2001:db8::/32", "2001:db8:1::/48"], &a6),
            now(),
            o,
        );
    });
    let both = [no_refresh.addr, v4_only.addr];
    let out = reload(&mut rib, Import::default(), &both);
    let r = report(&out);
    assert_eq!(r.refresh, vec![(v4_only.addr, V4)]);
    assert_eq!(r.missing, vec![(no_refresh.addr, V4), (v4_only.addr, V6)]);
    assert_eq!(requests(&out), vec![(v4_only.addr, vec![V4])]);
    // Still missing at the next change: they were not asked for.
    let out = reload(&mut rib, Import::default(), &both);
    let r = report(&out);
    assert_eq!(r.refresh, vec![]);
    assert_eq!(r.missing, vec![(no_refresh.addr, V4), (v4_only.addr, V6)]);
    assert_eq!(requests(&out), vec![]);
}

#[test]
fn a_disabled_family_is_neither_asked_for_nor_missing() {
    // RFC 4760 §7: the session ignores the family from then on.
    let mut rib = Rib::with_policies(LOCAL_AS, Box::new(Import::new(&[B], &[], None)));
    let (e1, _) = sender_and_receiver(&mut rib);
    from_e1(&mut rib, &e1, &[A, B]);
    let u = disabling(V4, withdraw(&["192.0.2.128/25"]));
    outputs(|o| rib.update(e1.addr, &u, now(), o));
    assert_eq!(rib.loc_rib(V4).count(), 0);
    let out = reload(&mut rib, Import::default(), &[e1.addr]);
    let r = report(&out);
    assert_eq!((r.refresh.clone(), r.missing.clone()), (vec![], vec![]));
    assert_eq!(requests(&out), vec![]);
}

#[test]
fn routes_held_for_enforcement_or_startup_meet_the_new_policy_too() {
    // RFC 6811 §2: every route kept is imported again, held or not, with
    // the state it has; what acts on the state then judges it as before.
    use bgpfc_rpki::{Enforcement, Startup};
    let mut rib = Rib::with_policies(LOCAL_AS, Box::new(Import::default()));
    outputs(|o| rib.set_enforcement(Enforcement::DropInvalid, now(), o));
    outputs(|o| rib.set_startup(Startup::Hold, now(), o));
    let (e1, _) = sender_and_receiver(&mut rib);
    from_e1(&mut rib, &e1, &[A, B]);
    assert_eq!(
        kept(&rib, A),
        vec![(Some(Held::Startup), None)],
        "held until validated"
    );
    let out = reload(&mut rib, Import::new(&[B], &[], Some(120)), &[e1.addr]);
    let r = report(&out);
    assert_eq!((r.routes, r.changed, r.dropped, r.held), (2, 1, 1, 0));
    // Still held, as received; B is gone.
    assert_eq!(kept(&rib, A), vec![(Some(Held::Startup), None)]);
    assert_eq!(kept(&rib, B), vec![]);
    assert_eq!(fib(&out), vec![]);
    assert_eq!(counted(&rib, e1.addr), (1, 1));
    // The setting released: A is used with what the new policy made of it.
    outputs(|o| rib.set_startup(Startup::Accept, now(), o));
    assert_eq!(kept(&rib, A), vec![(None, Some(120))]);
}

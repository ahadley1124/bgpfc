//! Graceful Restart (RFC 4724, RFC 8538) in the RIB: a Receiving Speaker
//! keeps the routes of a session that ended as stale ones, a Restarting
//! Speaker defers route selection, and the End-of-RIB marker ends each
//! initial update.

use super::*;
use crate::{Deferral, PeerRestart, Restart, Retention, StaleEnd};

const RESTART: Duration = Duration::from_secs(120);
const STALE: Duration = Duration::from_secs(360);

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

/// `info` with Graceful Restart on, against a peer whose capability lists
/// `families`, each with the Forwarding State bit as given.
fn gr(mut info: PeerInfo, families: &[(AddressFamily, bool)]) -> PeerInfo {
    info.restart = Some(Restart {
        peer: Some(PeerRestart {
            restarting: false,
            families: families.to_vec(),
        }),
        stale_time: STALE,
    });
    info
}

/// A Graceful Restart peer that preserved forwarding state for both
/// families.
fn gr_peer(addr: &str, remote_as: u32, router_id: u32) -> PeerInfo {
    gr(peer(addr, remote_as, router_id), &[(V4, true), (V6, true)])
}

fn retention(notification: bool) -> Retention {
    Retention {
        families: vec![V4, V6],
        restart_time: RESTART,
        notification,
    }
}

/// The families route selection waits for, with the peers each waits for.
fn deferred(rib: &Rib) -> Vec<(AddressFamily, usize)> {
    rib.deferred().into_iter().map(|(f, n, _)| (f, n)).collect()
}

fn stale_flags(rib: &Rib, prefix: &str) -> Vec<(IpAddr, bool)> {
    routes(rib, V4, p(prefix))
        .into_iter()
        .map(|(a, r)| (a, r.stale))
        .collect()
}

fn removed(out: &[Output]) -> Vec<(IpAddr, Option<AddressFamily>, usize, StaleEnd)> {
    out.iter()
        .filter_map(|o| match o {
            Output::StaleRemoved {
                peer,
                family,
                routes,
                why,
            } => Some((*peer, *family, *routes, *why)),
            _ => None,
        })
        .collect()
}

/// The families of the End-of-RIB markers among what was sent to `to`.
fn markers(out: &[Output], to: &PeerInfo) -> Vec<AddressFamily> {
    sends(out, to.addr)
        .into_iter()
        .flat_map(|m| decode_sent(m, to))
        .filter_map(|m| m.end_of_rib_family())
        .collect()
}

/// Two peers up: A (65001), a Graceful Restart peer, sends `prefixes`;
/// B (65002) takes them.
struct Lab {
    rib: Rib,
    a: PeerInfo,
    b: PeerInfo,
    t0: Instant,
}

fn lab(prefixes: &[&str]) -> Lab {
    let mut rib = Rib::new(LOCAL_AS);
    let a = gr_peer("10.0.0.1", 65_001, 1);
    let b = peer("10.0.0.2", 65_002, 2);
    let t0 = now();
    let mut out = Vec::new();
    rib.peer_up(a.clone(), t0, &mut out);
    rib.peer_up(b.clone(), t0, &mut out);
    let v4: Vec<&str> = prefixes
        .iter()
        .copied()
        .filter(|s| !s.contains(':'))
        .collect();
    let v6: Vec<&str> = prefixes
        .iter()
        .copied()
        .filter(|s| s.contains(':'))
        .collect();
    for (set, nh) in [(v4, "10.0.0.1"), (v6, "2001:db8::1")] {
        if !set.is_empty() {
            rib.update(a.addr, &announce(&set, &attrs(&[65_001], nh)), t0, &mut out);
        }
    }
    Lab { rib, a, b, t0 }
}

#[test]
fn a_retained_peers_routes_stay_stale_in_the_tables_and_the_fib() {
    let mut l = lab(&["192.0.2.0/24", "198.51.100.0/24", "2001:db8:1::/48"]);
    let out = outputs(|o| assert_eq!(l.rib.peer_retain(l.a.addr, &retention(false), l.t0, o), 3));
    // RFC 4724 §4.2: kept, and "MUST NOT differentiate between stale and
    // other routing information during forwarding": nothing for the FIB
    // and nothing for the other peers.
    assert!(out.is_empty(), "{out:?}");
    assert_eq!(stale_flags(&l.rib, "192.0.2.0/24"), vec![(l.a.addr, true)]);
    assert_eq!(l.rib.loc_rib(V4).count(), 2);
    assert_eq!(l.rib.loc_rib(V6).count(), 1);
    assert_eq!(l.rib.fib_routes().count(), 3);
    // The session is down: the peer is not among those up, takes no input
    // and is sent nothing.
    assert!(l.rib.peers().all(|i| i.addr != l.a.addr));
    assert!(l.rib.peer(l.a.addr).is_none());
    let out = outputs(|o| {
        l.rib
            .update(l.a.addr, &withdraw(&["192.0.2.0/24"]), l.t0, o);
    });
    assert!(out.is_empty(), "{out:?}");
    assert_eq!(l.rib.loc_rib(V4).count(), 2);
    let status = l.rib.stale_peers(l.t0 + secs(20));
    assert_eq!(status.len(), 1);
    assert!(status[0].down && status[0].pending == vec![V4, V6]);
    assert_eq!(status[0].restart_in, Some(secs(100)));
    assert_eq!(status[0].stale_in, None);
    assert_eq!(l.rib.stale_routes(l.a.addr), vec![(V4, 2), (V6, 1)]);
    // The other peer still hears of changes meanwhile: a route of its own
    // for a stale prefix wins or loses as any other.
    let out = outputs(|o| {
        l.rib.update(
            l.b.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_002], "10.0.0.2")),
            l.t0,
            o,
        );
    });
    // Equal paths: the older one stays best (A's, with the lower router
    // id), so the FIB and B hear nothing.
    assert!(fib(&out).is_empty(), "{out:?}");
    assert!(sends(&out, l.b.addr).is_empty(), "{out:?}");
}

#[test]
fn stale_families_are_listed_in_order_whichever_table_was_made_first() {
    // The control plane shows them as the RIB lists them: IPv4 first,
    // though the IPv6 table is the older one here.
    let mut rib = Rib::new(LOCAL_AS);
    let a = gr_peer("10.0.0.1", 65_001, 1);
    let t0 = now();
    let mut out = Vec::new();
    rib.peer_up(a.clone(), t0, &mut out);
    rib.update(
        a.addr,
        &announce(&["2001:db8:1::/48"], &attrs(&[65_001], "2001:db8::1")),
        t0,
        &mut out,
    );
    rib.update(
        a.addr,
        &announce(&["192.0.2.0/24"], &attrs(&[65_001], "10.0.0.1")),
        t0,
        &mut out,
    );
    rib.peer_retain(a.addr, &retention(false), t0, &mut out);
    assert_eq!(rib.stale_peers(t0)[0].pending, vec![V4, V6]);
    assert_eq!(rib.stale_routes(a.addr), vec![(V4, 1), (V6, 1)]);
}

#[test]
fn nothing_is_kept_for_a_peer_that_sent_nothing() {
    let mut l = lab(&[]);
    let out = outputs(|o| assert_eq!(l.rib.peer_retain(l.a.addr, &retention(false), l.t0, o), 0));
    assert!(out.is_empty(), "{out:?}");
    assert_eq!(l.rib.stale_peers(l.t0).len(), 0);
    assert!(l.rib.peer_stats(l.a.addr).is_none());
}

#[test]
fn routes_of_families_the_peer_did_not_list_are_deleted() {
    let mut l = lab(&["192.0.2.0/24", "2001:db8:1::/48"]);
    let only_v4 = Retention {
        families: vec![V4],
        ..retention(false)
    };
    let out = outputs(|o| assert_eq!(l.rib.peer_retain(l.a.addr, &only_v4, l.t0, o), 1));
    // RFC 4724 §4.2 keeps "the address families that were previously
    // received in the Graceful Restart Capability".
    assert_eq!(fib(&out).len(), 1);
    assert_eq!(fib(&out)[0].prefix, p("2001:db8:1::/48"));
    assert_eq!(l.rib.loc_rib(V6).count(), 0);
    assert_eq!(l.rib.loc_rib(V4).count(), 1);
}

#[test]
fn a_returning_peer_replaces_stale_routes_and_its_end_of_rib_removes_the_rest() {
    let mut l = lab(&["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"]);
    l.rib
        .peer_retain(l.a.addr, &retention(false), l.t0, &mut Vec::new());
    let t1 = l.t0 + secs(30);
    // RFC 4724 §4.2: the session is back, with the Forwarding State bit.
    let out = outputs(|o| l.rib.peer_up(l.a.clone(), t1, o));
    assert_eq!(fib(&out).len(), 0);
    assert_eq!(removed(&out).len(), 0);
    // Our table goes to it, then a marker per family (§4).
    assert_eq!(markers(&out, &l.a), vec![V4, V6]);
    assert_eq!(l.rib.stale_peers(t1)[0].stale_in, Some(STALE));
    // It sends two of its three routes again: the same routes, so the FIB
    // and the other peer hear nothing, and the routes are not stale any
    // more.
    let out = outputs(|o| {
        l.rib.update(
            l.a.addr,
            &announce(
                &["192.0.2.0/24", "198.51.100.0/24"],
                &attrs(&[65_001], "10.0.0.1"),
            ),
            t1,
            o,
        );
    });
    assert!(out.is_empty(), "{out:?}");
    assert_eq!(stale_flags(&l.rib, "192.0.2.0/24"), vec![(l.a.addr, false)]);
    assert_eq!(
        stale_flags(&l.rib, "203.0.113.0/24"),
        vec![(l.a.addr, true)]
    );
    // Its End-of-RIB for IPv4: the third goes, to the FIB and to B.
    let out = outputs(|o| l.rib.end_of_rib(l.a.addr, V4, t1, o));
    assert_eq!(
        removed(&out),
        vec![(l.a.addr, Some(V4), 1, StaleEnd::EndOfRib)]
    );
    let changes = fib(&out);
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].prefix, p("203.0.113.0/24"));
    assert_eq!(changes[0].next_hop, None);
    let to_b = sends(&out, l.b.addr);
    assert_eq!(to_b.len(), 1);
    assert_eq!(
        decode_sent(to_b[0], &l.b)[0].withdrawn,
        vec![p("203.0.113.0/24")]
    );
    assert_eq!(stale_flags(&l.rib, "203.0.113.0/24").len(), 0);
    // Nothing is stale in IPv6 either: its marker has nothing to remove.
    assert_eq!(l.rib.stale_peers(t1).len(), 0);
    assert_eq!(outputs(|o| l.rib.end_of_rib(l.a.addr, V6, t1, o)).len(), 0);
    // The routes it holds count as before.
    assert_eq!(
        l.rib.peer_stats(l.a.addr).unwrap().received,
        vec![(V4, 2), (V6, 0)]
    );
}

#[test]
fn a_session_without_the_forwarding_state_bit_deletes_the_family_at_once() {
    let mut l = lab(&["192.0.2.0/24", "2001:db8:1::/48"]);
    l.rib
        .peer_retain(l.a.addr, &retention(false), l.t0, &mut Vec::new());
    // RFC 4724 §4.2: IPv4 without the bit, IPv6 with it.
    let back = gr(peer("10.0.0.1", 65_001, 1), &[(V4, false), (V6, true)]);
    let out = outputs(|o| l.rib.peer_up(back, l.t0 + secs(5), o));
    assert_eq!(
        removed(&out),
        vec![(l.a.addr, Some(V4), 1, StaleEnd::NoForwardingState)]
    );
    assert_eq!(fib(&out).len(), 1);
    assert_eq!(l.rib.loc_rib(V4).count(), 0);
    assert_eq!(l.rib.loc_rib(V6).count(), 1);
    assert_eq!(l.rib.stale_peers(l.t0)[0].pending, vec![V6]);
}

#[test]
fn a_session_that_lists_no_family_or_no_capability_deletes_everything_at_once() {
    for (label, back) in [
        (
            "family not listed",
            gr(peer("10.0.0.1", 65_001, 1), &[(V6, true)]),
        ),
        ("no capability", {
            let mut i = peer("10.0.0.1", 65_001, 1);
            i.restart = Some(Restart {
                peer: None,
                stale_time: STALE,
            });
            i
        }),
        ("our side off", peer("10.0.0.1", 65_001, 1)),
    ] {
        let mut l = lab(&["192.0.2.0/24"]);
        l.rib
            .peer_retain(l.a.addr, &retention(false), l.t0, &mut Vec::new());
        let out = outputs(|o| l.rib.peer_up(back, l.t0 + secs(5), o));
        assert_eq!(fib(&out).len(), 1, "{label}");
        assert_eq!(l.rib.loc_rib(V4).count(), 0, "{label}");
        assert!(l.rib.stale_peers(l.t0).is_empty(), "{label}");
    }
}

#[test]
fn the_restart_timer_deletes_the_routes_of_a_peer_that_does_not_come_back() {
    let mut l = lab(&["192.0.2.0/24", "2001:db8:1::/48"]);
    l.rib
        .peer_retain(l.a.addr, &retention(false), l.t0, &mut Vec::new());
    assert_eq!(l.rib.next_deadline(), Some(l.t0 + RESTART));
    // RFC 4724 §4.2: "If the session does not get re-established within the
    // "Restart Time" that the peer advertised previously".
    let out = outputs(|o| l.rib.flush(l.t0 + secs(119), o));
    assert!(out.is_empty(), "{out:?}");
    let out = outputs(|o| l.rib.flush(l.t0 + RESTART, o));
    assert_eq!(
        removed(&out),
        vec![(l.a.addr, None, 2, StaleEnd::RestartTimer)]
    );
    assert_eq!(fib(&out).len(), 2);
    assert_eq!(l.rib.loc_rib(V4).count() + l.rib.loc_rib(V6).count(), 0);
    assert_eq!(l.rib.stale_peers(l.t0 + RESTART).len(), 0);
    assert_eq!(l.rib.next_deadline(), None);
    // And the peer can come up as a new one.
    let out = outputs(|o| l.rib.peer_up(l.a.clone(), l.t0 + RESTART, o));
    assert_eq!(markers(&out, &l.a), vec![V4, V6]);
}

#[test]
fn the_restart_timer_does_not_fire_once_the_session_is_back() {
    let mut l = lab(&["192.0.2.0/24"]);
    l.rib
        .peer_retain(l.a.addr, &retention(false), l.t0, &mut Vec::new());
    l.rib.peer_up(l.a.clone(), l.t0 + secs(10), &mut Vec::new());
    let out = outputs(|o| l.rib.flush(l.t0 + RESTART, o));
    assert!(removed(&out).is_empty(), "{out:?}");
    assert_eq!(l.rib.loc_rib(V4).count(), 1);
}

#[test]
fn the_stale_timer_ends_the_wait_for_an_end_of_rib() {
    let mut l = lab(&["192.0.2.0/24", "198.51.100.0/24"]);
    l.rib
        .peer_retain(l.a.addr, &retention(false), l.t0, &mut Vec::new());
    let t1 = l.t0 + secs(10);
    l.rib.peer_up(l.a.clone(), t1, &mut Vec::new());
    l.rib.update(
        l.a.addr,
        &announce(&["192.0.2.0/24"], &attrs(&[65_001], "10.0.0.1")),
        t1,
        &mut Vec::new(),
    );
    assert_eq!(l.rib.next_deadline(), Some(t1 + STALE));
    // RFC 8538 §4.1: "an upper bound on the amount of time a router
    // retains the stale routes". The route sent again stays.
    let out = outputs(|o| l.rib.flush(t1 + STALE, o));
    assert_eq!(
        removed(&out),
        vec![(l.a.addr, Some(V4), 1, StaleEnd::StaleTimer)]
    );
    assert_eq!(fib(&out).len(), 1);
    assert_eq!(l.rib.loc_rib(V4).count(), 1);
    assert_eq!(l.rib.stale_peers(t1 + STALE).len(), 0);
}

#[test]
fn an_end_of_rib_for_every_family_cancels_the_stale_timer() {
    let mut l = lab(&["192.0.2.0/24"]);
    l.rib
        .peer_retain(l.a.addr, &retention(false), l.t0, &mut Vec::new());
    let t1 = l.t0 + secs(10);
    l.rib.peer_up(l.a.clone(), t1, &mut Vec::new());
    l.rib.end_of_rib(l.a.addr, V4, t1, &mut Vec::new());
    l.rib.end_of_rib(l.a.addr, V6, t1, &mut Vec::new());
    let out = outputs(|o| l.rib.flush(t1 + STALE, o));
    assert!(out.is_empty(), "{out:?}");
    assert_eq!(l.rib.next_deadline(), None);
}

#[test]
fn a_second_session_end_without_the_n_bit_deletes_what_is_still_stale() {
    // RFC 4724 §4.2: "To deal with possible consecutive restarts, a route
    // (from the peer) previously marked as stale MUST be deleted."
    let mut l = lab(&["192.0.2.0/24", "198.51.100.0/24"]);
    l.rib
        .peer_retain(l.a.addr, &retention(false), l.t0, &mut Vec::new());
    let t1 = l.t0 + secs(10);
    l.rib.peer_up(l.a.clone(), t1, &mut Vec::new());
    l.rib.update(
        l.a.addr,
        &announce(&["192.0.2.0/24"], &attrs(&[65_001], "10.0.0.1")),
        t1,
        &mut Vec::new(),
    );
    let out = outputs(|o| assert_eq!(l.rib.peer_retain(l.a.addr, &retention(false), t1, o), 1));
    assert_eq!(
        removed(&out),
        vec![(l.a.addr, Some(V4), 1, StaleEnd::Superseded)]
    );
    assert_eq!(l.rib.loc_rib(V4).count(), 1);
    assert_eq!(stale_flags(&l.rib, "192.0.2.0/24"), vec![(l.a.addr, true)]);
}

#[test]
fn a_second_session_end_with_the_n_bit_keeps_them_all_stale() {
    // RFC 8538 §4.1: with the N bit exchanged that sentence "only applies"
    // when it has not been, so what was not sent again stays.
    let mut l = lab(&["192.0.2.0/24", "198.51.100.0/24"]);
    l.rib
        .peer_retain(l.a.addr, &retention(true), l.t0, &mut Vec::new());
    let t1 = l.t0 + secs(10);
    l.rib.peer_up(l.a.clone(), t1, &mut Vec::new());
    l.rib.update(
        l.a.addr,
        &announce(&["192.0.2.0/24"], &attrs(&[65_001], "10.0.0.1")),
        t1,
        &mut Vec::new(),
    );
    let out = outputs(|o| assert_eq!(l.rib.peer_retain(l.a.addr, &retention(true), t1, o), 2));
    assert!(out.is_empty(), "{out:?}");
    assert_eq!(
        stale_flags(&l.rib, "198.51.100.0/24"),
        vec![(l.a.addr, true)]
    );
    assert_eq!(l.rib.loc_rib(V4).count(), 2);
}

#[test]
fn repeated_resets_do_not_restart_the_stale_timer() {
    // RFC 8538 §9: the stale timer is mandatory so that "repeated session
    // resets" cannot keep stale routes for ever.
    let mut l = lab(&["192.0.2.0/24"]);
    let mut all = Vec::new();
    l.rib
        .peer_retain(l.a.addr, &retention(true), l.t0, &mut all);
    let t1 = l.t0 + secs(10);
    l.rib.peer_up(l.a.clone(), t1, &mut all);
    assert_eq!(l.rib.stale_peers(t1)[0].stale_in, Some(STALE));
    l.rib
        .peer_retain(l.a.addr, &retention(true), t1 + secs(100), &mut all);
    let t2 = t1 + secs(200);
    l.rib.peer_up(l.a.clone(), t2, &mut all);
    // 360 s from the first return, 160 s from now.
    assert_eq!(l.rib.stale_peers(t2)[0].stale_in, Some(secs(160)));
    let out = outputs(|o| l.rib.flush(t1 + STALE, o));
    assert_eq!(
        removed(&out)[0],
        (l.a.addr, Some(V4), 1, StaleEnd::StaleTimer)
    );
    assert_eq!(l.rib.loc_rib(V4).count(), 0);
}

#[test]
fn the_stale_timer_running_while_the_session_is_down_removes_the_peer() {
    let mut l = lab(&["192.0.2.0/24"]);
    let mut all = Vec::new();
    let long = Retention {
        restart_time: secs(1000),
        ..retention(true)
    };
    l.rib.peer_retain(l.a.addr, &long, l.t0, &mut all);
    let t1 = l.t0 + secs(10);
    l.rib.peer_up(l.a.clone(), t1, &mut all);
    l.rib.peer_retain(l.a.addr, &long, t1 + secs(5), &mut all);
    let out = outputs(|o| l.rib.flush(t1 + STALE, o));
    assert_eq!(
        removed(&out),
        vec![(l.a.addr, None, 1, StaleEnd::StaleTimer)]
    );
    assert_eq!(l.rib.loc_rib(V4).count(), 0);
    assert_eq!(l.rib.stale_peers(t1 + STALE).len(), 0);
}

#[test]
fn peer_down_deletes_a_retained_peers_routes_at_once() {
    let mut l = lab(&["192.0.2.0/24"]);
    l.rib
        .peer_retain(l.a.addr, &retention(false), l.t0, &mut Vec::new());
    // RFC 8538 §3.2: a Hard Reset, or any other end the peer thread does
    // not keep the routes for.
    let out = outputs(|o| l.rib.peer_down(l.a.addr, l.t0, o));
    assert_eq!(fib(&out).len(), 1);
    assert_eq!(l.rib.loc_rib(V4).count(), 0);
    assert_eq!(l.rib.stale_peers(l.t0).len(), 0);
    assert_eq!(outputs(|o| l.rib.flush(l.t0 + RESTART, o)).len(), 0);
}

#[test]
fn the_prefix_limit_counts_stale_routes_as_held_and_replaced_ones_once() {
    let mut l = lab(&[]);
    let mut limited = l.a.clone();
    limited.prefix_limits = vec![(V4, 3)];
    let mut all = Vec::new();
    l.rib.peer_down(l.a.addr, l.t0, &mut all);
    l.rib.peer_up(limited.clone(), l.t0, &mut all);
    let three = ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"];
    l.rib.update(
        limited.addr,
        &announce(&three, &attrs(&[65_001], "10.0.0.1")),
        l.t0,
        &mut all,
    );
    l.rib
        .peer_retain(limited.addr, &retention(false), l.t0, &mut all);
    l.rib.peer_up(limited.clone(), l.t0, &mut all);
    // The same three again: three routes, not six, and no limit hit.
    let out = outputs(|o| {
        l.rib.update(
            limited.addr,
            &announce(&three, &attrs(&[65_001], "10.0.0.1")),
            l.t0,
            o,
        );
    });
    assert!(
        !out.iter()
            .any(|o| matches!(o, Output::PrefixLimitExceeded { .. })),
        "{out:?}"
    );
    assert_eq!(l.rib.peer_stats(limited.addr).unwrap().received[0], (V4, 3));
    // A fourth prefix is over the limit as it would be without a restart.
    let out = outputs(|o| {
        l.rib.update(
            limited.addr,
            &announce(&["192.0.2.128/25"], &attrs(&[65_001], "10.0.0.1")),
            l.t0,
            o,
        );
    });
    assert!(
        out.iter()
            .any(|o| matches!(o, Output::PrefixLimitExceeded { .. }))
    );
}

#[test]
fn stale_routes_are_replaced_whatever_their_attributes() {
    let mut l = lab(&["192.0.2.0/24"]);
    l.rib
        .peer_retain(l.a.addr, &retention(false), l.t0, &mut Vec::new());
    l.rib.peer_up(l.a.clone(), l.t0, &mut Vec::new());
    let out = outputs(|o| {
        l.rib.update(
            l.a.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_001, 7], "10.0.0.1")),
            l.t0,
            o,
        );
    });
    // Another path: a change of the best route, as for any route, which
    // the FIB sees with the same next hop, and B hears of with the path;
    // and the route is no longer stale.
    let changes = fib(&out);
    assert_eq!(changes.len(), 1, "{out:?}");
    assert_eq!(changes[0].next_hop, changes[0].previous);
    assert_eq!(stale_flags(&l.rib, "192.0.2.0/24"), vec![(l.a.addr, false)]);
    assert_eq!(sends(&out, l.b.addr).len(), 1);
}

// --------------------------------------------------------------- End-of-RIB

#[test]
fn every_family_of_a_session_with_graceful_restart_ends_with_a_marker() {
    // RFC 4724 §4: "(including the case when there is no update to send)".
    let mut rib = Rib::new(LOCAL_AS);
    let a = gr_peer("10.0.0.1", 65_001, 1);
    let out = outputs(|o| rib.peer_up(a.clone(), now(), o));
    assert_eq!(markers(&out, &a), vec![V4, V6]);
    // With a table, the marker follows it.
    let b = gr_peer("10.0.0.2", 65_002, 2);
    rib.update(
        a.addr,
        &announce(&["192.0.2.0/24"], &attrs(&[65_001], "10.0.0.1")),
        now(),
        &mut Vec::new(),
    );
    let out = outputs(|o| rib.peer_up(b.clone(), now(), o));
    let all: Vec<UpdateMessage> = sends(&out, b.addr)
        .into_iter()
        .flat_map(|m| decode_sent(m, &b))
        .collect();
    assert_eq!(all.len(), 3, "{all:?}");
    assert_eq!(all[0].nlri, vec![p("192.0.2.0/24")]);
    assert_eq!(all[1].end_of_rib_family(), Some(V4));
    assert_eq!(all[2].end_of_rib_family(), Some(V6));
}

#[test]
fn a_session_without_graceful_restart_gets_no_marker() {
    let mut rib = Rib::new(LOCAL_AS);
    let a = peer("10.0.0.1", 65_001, 1);
    let out = outputs(|o| rib.peer_up(a.clone(), now(), o));
    assert_eq!(sends(&out, a.addr).len(), 0);
}

#[test]
fn a_family_that_was_not_negotiated_gets_no_marker() {
    let mut rib = Rib::new(LOCAL_AS);
    let mut a = gr_peer("10.0.0.1", 65_001, 1);
    a.families = vec![V6];
    let out = outputs(|o| rib.peer_up(a.clone(), now(), o));
    assert_eq!(markers(&out, &a), vec![V6]);
}

#[test]
fn a_refresh_is_not_an_initial_update_and_has_no_marker() {
    let mut rib = Rib::new(LOCAL_AS);
    let a = gr_peer("10.0.0.1", 65_001, 1);
    rib.peer_up(a.clone(), now(), &mut Vec::new());
    let out = outputs(|o| rib.refresh(a.addr, V4, now(), o));
    assert_eq!(markers(&out, &a).len(), 0);
}

// ------------------------------------------------------ selection deferral

fn waiting(peers: &[&PeerInfo], t0: Instant) -> Deferral {
    Deferral {
        waiting: peers.iter().map(|p| (p.addr, vec![V4, V6])).collect(),
        until: t0 + RESTART,
    }
}

#[test]
fn route_selection_waits_for_every_end_of_rib() {
    let mut rib = Rib::new(LOCAL_AS);
    let a = gr_peer("10.0.0.1", 65_001, 1);
    let b = gr_peer("10.0.0.2", 65_002, 2);
    let t0 = now();
    rib.defer_selection(&waiting(&[&a, &b], t0));
    assert_eq!(deferred(&rib), vec![(V4, 2), (V6, 2)]);
    assert_eq!(rib.next_deadline(), Some(t0 + RESTART));
    let mut out = Vec::new();
    rib.peer_up(a.clone(), t0, &mut out);
    rib.peer_up(b.clone(), t0, &mut out);
    // RFC 4724 §4.1: "prior to route selection, the speaker has no routes
    // to advertise to its peers and no routes to update the forwarding
    // state": a new session gets neither a table nor a marker.
    assert!(out.is_empty(), "{out:?}");
    let out = outputs(|o| {
        rib.update(
            a.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_001], "10.0.0.1")),
            t0,
            o,
        );
        rib.update(
            b.addr,
            &announce(&["198.51.100.0/24"], &attrs(&[65_002], "10.0.0.2")),
            t0,
            o,
        );
    });
    assert!(out.is_empty(), "{out:?}");
    // The tables hold the routes meanwhile.
    assert_eq!(rib.fib_routes_of(V4).count(), 2);
    // A's markers, and B's for IPv6: IPv6 has all it waits for, IPv4 still
    // waits for B's.
    let out = outputs(|o| {
        rib.end_of_rib(a.addr, V4, t0, o);
        rib.end_of_rib(a.addr, V6, t0, o);
        rib.end_of_rib(b.addr, V6, t0, o);
    });
    assert_eq!(deferred(&rib), vec![(V4, 1)]);
    // IPv6 is done: nothing to bring to the FIB, a table of nothing and its
    // marker for each peer.
    assert!(
        out.iter()
            .any(|o| matches!(o, Output::SelectionDone { family } if *family == V6))
    );
    assert_eq!(markers(&out, &a), vec![V6]);
    assert_eq!(markers(&out, &b), vec![V6]);
    assert_eq!(fib(&out).len(), 0);
    let out = outputs(|o| rib.end_of_rib(b.addr, V4, t0, o));
    assert_eq!(deferred(&rib).len(), 0);
    assert!(
        out.iter()
            .any(|o| matches!(o, Output::SelectionDone { family } if *family == V4))
    );
    // Each peer is sent the other's route, then the marker.
    for (to, route) in [(&a, "198.51.100.0/24"), (&b, "192.0.2.0/24")] {
        let msgs: Vec<UpdateMessage> = sends(&out, to.addr)
            .into_iter()
            .flat_map(|m| decode_sent(m, to))
            .collect();
        assert_eq!(msgs.len(), 2, "{msgs:?}");
        assert_eq!(msgs[0].nlri, vec![p(route)]);
        assert_eq!(msgs[1].end_of_rib_family(), Some(V4));
    }
    // The FIB is the caller's to bring up to date from the Loc-RIB.
    assert_eq!(fib(&out).len(), 0);
    // And from now on changes flow as usual.
    let out = outputs(|o| {
        rib.update(
            a.addr,
            &announce(&["203.0.113.0/24"], &attrs(&[65_001], "10.0.0.1")),
            t0,
            o,
        );
    });
    assert_eq!(fib(&out).len(), 1);
    assert_eq!(sends(&out, b.addr).len(), 1);
}

#[test]
fn route_selection_does_not_wait_for_peers_that_will_not_send_a_marker() {
    // RFC 4724 §4.1: "excluding the ones with the "Restart State" bit set
    // in the received capability and excluding the ones that do not
    // advertise the graceful restart capability".
    let t0 = now();
    let a = gr_peer("10.0.0.1", 65_001, 1);
    let restarting = {
        let mut i = gr_peer("10.0.0.2", 65_002, 2);
        if let Some(Restart { peer: Some(p), .. }) = &mut i.restart {
            p.restarting = true;
        }
        i
    };
    let silent = {
        let mut i = peer("10.0.0.3", 65_003, 3);
        i.restart = Some(Restart {
            peer: None,
            stale_time: STALE,
        });
        i
    };
    let unlisted = gr(peer("10.0.0.4", 65_004, 4), &[(V6, true)]);
    for (label, other) in [
        ("restarting", restarting),
        ("no capability", silent),
        ("family not listed", unlisted),
    ] {
        let mut rib = Rib::new(LOCAL_AS);
        rib.defer_selection(&Deferral {
            waiting: vec![(a.addr, vec![V4]), (other.addr, vec![V4])],
            until: t0 + RESTART,
        });
        rib.peer_up(a.clone(), t0, &mut Vec::new());
        assert_eq!(deferred(&rib), vec![(V4, 2)], "{label}");
        rib.peer_up(other.clone(), t0, &mut Vec::new());
        assert_eq!(deferred(&rib), vec![(V4, 1)], "{label}");
        let out = outputs(|o| rib.end_of_rib(a.addr, V4, t0, o));
        assert!(deferred(&rib).is_empty(), "{label}");
        assert!(
            out.iter()
                .any(|o| matches!(o, Output::SelectionDone { .. })),
            "{label}"
        );
    }
}

#[test]
fn the_deferral_timer_ends_the_wait() {
    let mut rib = Rib::new(LOCAL_AS);
    let a = gr_peer("10.0.0.1", 65_001, 1);
    let t0 = now();
    rib.defer_selection(&waiting(&[&a], t0));
    rib.peer_up(a.clone(), t0, &mut Vec::new());
    rib.update(
        a.addr,
        &announce(&["192.0.2.0/24"], &attrs(&[65_001], "10.0.0.1")),
        t0,
        &mut Vec::new(),
    );
    assert_eq!(outputs(|o| rib.flush(t0 + secs(119), o)).len(), 0);
    let out = outputs(|o| rib.flush(t0 + RESTART, o));
    let done: Vec<_> = out
        .iter()
        .filter_map(|o| match o {
            Output::SelectionDone { family } => Some(*family),
            _ => None,
        })
        .collect();
    assert_eq!(done, vec![V4, V6]);
    assert_eq!(deferred(&rib).len(), 0);
    // A is sent its table (nothing of its own back) and the markers.
    assert_eq!(markers(&out, &a), vec![V4, V6]);
    assert_eq!(rib.next_deadline(), None);
}

#[test]
fn a_peer_that_is_gone_is_not_waited_for() {
    let mut rib = Rib::new(LOCAL_AS);
    let a = gr_peer("10.0.0.1", 65_001, 1);
    let b = gr_peer("10.0.0.2", 65_002, 2);
    let t0 = now();
    rib.defer_selection(&waiting(&[&a, &b], t0));
    rib.peer_up(a.clone(), t0, &mut Vec::new());
    rib.end_of_rib(a.addr, V4, t0, &mut Vec::new());
    rib.end_of_rib(a.addr, V6, t0, &mut Vec::new());
    assert_eq!(deferred(&rib), vec![(V4, 1), (V6, 1)]);
    // B's session is not one that comes back: it was removed.
    let out = outputs(|o| rib.peer_down(b.addr, t0, o));
    assert_eq!(deferred(&rib).len(), 0);
    assert_eq!(
        out.iter()
            .filter(|o| matches!(o, Output::SelectionDone { .. }))
            .count(),
        2
    );
}

#[test]
fn a_family_nobody_waits_for_is_not_deferred() {
    let mut rib = Rib::new(LOCAL_AS);
    let a = gr_peer("10.0.0.1", 65_001, 1);
    rib.defer_selection(&Deferral {
        waiting: vec![(a.addr, vec![V4])],
        until: now() + RESTART,
    });
    assert_eq!(deferred(&rib), vec![(V4, 1)]);
    // IPv6 goes ahead as usual: a table and its marker.
    let out = outputs(|o| rib.peer_up(a.clone(), now(), o));
    assert_eq!(markers(&out, &a), vec![V6]);
}

#[test]
fn a_refresh_request_waits_for_the_deferral_too() {
    let mut rib = Rib::new(LOCAL_AS);
    let a = gr_peer("10.0.0.1", 65_001, 1);
    let t0 = now();
    rib.defer_selection(&waiting(&[&a], t0));
    rib.peer_up(a.clone(), t0, &mut Vec::new());
    assert_eq!(outputs(|o| rib.refresh(a.addr, V4, t0, o)).len(), 0);
}

// ---------------------------------------------------------------- ADD-PATH

use super::add_path::{add_path_peer, announce_paths, withdraw_paths};

#[test]
fn every_path_of_a_prefix_is_kept_and_replaced_on_its_own() {
    // RFC 7911 §5 with RFC 4724 §4.2: the Adj-RIB-In holds a route per
    // prefix and Path Identifier, and so does a peer's stale set.
    let mut rib = Rib::new(LOCAL_AS);
    let mut a = gr(
        add_path_peer("10.0.0.1", 65_001, 1),
        &[(V4, true), (V6, true)],
    );
    a.add_path_receive = vec![V4];
    let t0 = now();
    rib.peer_up(a.clone(), t0, &mut Vec::new());
    let mut near = attrs(&[65_001], "10.0.0.1");
    near.local_pref = Some(200);
    let far = attrs(&[65_001, 7], "10.0.0.1");
    rib.update(
        a.addr,
        &announce_paths(&[("192.0.2.0/24", 1)], &near),
        t0,
        &mut Vec::new(),
    );
    rib.update(
        a.addr,
        &announce_paths(&[("192.0.2.0/24", 2), ("192.0.2.0/24", 3)], &far),
        t0,
        &mut Vec::new(),
    );
    assert_eq!(routes(&rib, V4, p("192.0.2.0/24")).len(), 3);
    assert_eq!(rib.peer_stats(a.addr).unwrap().received[0], (V4, 3));
    assert_eq!(
        rib.peer_retain(a.addr, &retention(false), t0, &mut Vec::new()),
        3
    );
    assert!(
        routes(&rib, V4, p("192.0.2.0/24"))
            .iter()
            .all(|(_, r)| r.stale)
    );
    // The session returns, and the peer sends two of the three paths
    // again, one of them with other attributes.
    let t1 = t0 + secs(5);
    rib.peer_up(a.clone(), t1, &mut Vec::new());
    rib.update(
        a.addr,
        &announce_paths(&[("192.0.2.0/24", 1)], &near),
        t1,
        &mut Vec::new(),
    );
    let mut other = far.clone();
    other.med = Some(5);
    rib.update(
        a.addr,
        &announce_paths(&[("192.0.2.0/24", 2)], &other),
        t1,
        &mut Vec::new(),
    );
    let live: Vec<bool> = routes(&rib, V4, p("192.0.2.0/24"))
        .iter()
        .map(|(_, r)| r.stale)
        .collect();
    assert_eq!(live.iter().filter(|s| **s).count(), 1, "{live:?}");
    // The marker removes only the path not sent again, and the best path
    // is untouched: no FIB change.
    let out = outputs(|o| rib.end_of_rib(a.addr, V4, t1, o));
    assert_eq!(
        removed(&out),
        vec![(a.addr, Some(V4), 1, StaleEnd::EndOfRib)]
    );
    assert!(fib(&out).is_empty(), "{out:?}");
    assert_eq!(routes(&rib, V4, p("192.0.2.0/24")).len(), 2);
    assert_eq!(rib.peer_stats(a.addr).unwrap().received[0], (V4, 2));
    assert!(
        routes(&rib, V4, p("192.0.2.0/24"))
            .iter()
            .all(|(_, r)| !r.stale)
    );
}

#[test]
fn paths_kept_from_a_session_with_identifiers_go_if_the_next_has_none() {
    // The new session sends the prefix with no Path Identifier, which is a
    // route of its own beside the stale ones; the marker removes them.
    let mut rib = Rib::new(LOCAL_AS);
    let mut a = gr(
        add_path_peer("10.0.0.1", 65_001, 1),
        &[(V4, true), (V6, true)],
    );
    a.add_path_receive = vec![V4];
    let t0 = now();
    rib.peer_up(a.clone(), t0, &mut Vec::new());
    let attrs1 = attrs(&[65_001], "10.0.0.1");
    rib.update(
        a.addr,
        &announce_paths(&[("192.0.2.0/24", 4), ("192.0.2.0/24", 5)], &attrs1),
        t0,
        &mut Vec::new(),
    );
    rib.peer_retain(a.addr, &retention(false), t0, &mut Vec::new());
    let mut plain = a.clone();
    plain.add_path_receive = Vec::new();
    rib.peer_up(plain, t0, &mut Vec::new());
    rib.update(
        a.addr,
        &announce(&["192.0.2.0/24"], &attrs1),
        t0,
        &mut Vec::new(),
    );
    assert_eq!(routes(&rib, V4, p("192.0.2.0/24")).len(), 3);
    let out = outputs(|o| rib.end_of_rib(a.addr, V4, t0, o));
    assert_eq!(
        removed(&out),
        vec![(a.addr, Some(V4), 2, StaleEnd::EndOfRib)]
    );
    assert_eq!(routes(&rib, V4, p("192.0.2.0/24")).len(), 1);
    // A withdrawal of a path names it, stale or not.
    let mut rib = Rib::new(LOCAL_AS);
    rib.peer_up(a.clone(), t0, &mut Vec::new());
    rib.update(
        a.addr,
        &announce_paths(&[("192.0.2.0/24", 4), ("192.0.2.0/24", 5)], &attrs1),
        t0,
        &mut Vec::new(),
    );
    rib.peer_retain(a.addr, &retention(false), t0, &mut Vec::new());
    rib.peer_up(a.clone(), t0, &mut Vec::new());
    rib.update(
        a.addr,
        &withdraw_paths(&[("192.0.2.0/24", 4)]),
        t0,
        &mut Vec::new(),
    );
    assert_eq!(routes(&rib, V4, p("192.0.2.0/24")).len(), 1);
}

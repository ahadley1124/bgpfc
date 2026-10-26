//! Enhanced Route Refresh (RFC 7313) in the RIB: the routes a peer's route
//! refresh leaves behind are removed at its `EoRR`, or when the time
//! allowed for it runs out; a route refresh we make is bracketed by `BoRR`
//! and `EoRR`.

use bgpfc_wire::header::MessageType;
use bgpfc_wire::notification::max_data_len;
use bgpfc_wire::route_refresh::{RefreshSubtype, RouteRefreshMessage};

use super::add_path::{add_path_peer, announce_paths, withdraw_paths};
use super::restart::{gr_peer, removed, retention, secs};
use super::*;
use crate::{EnhancedRefresh, RefreshIgnored, StaleEnd};

const STALE: Duration = Duration::from_secs(360);

/// `info` with Enhanced Route Refresh negotiated, against a peer that has
/// advertised Graceful Restart or not.
fn err(mut info: PeerInfo, peer_graceful_restart: bool) -> PeerInfo {
    info.enhanced_refresh = Some(EnhancedRefresh {
        stale_time: STALE,
        peer_graceful_restart,
    });
    info
}

/// Two peers up: A (65001) with Enhanced Route Refresh sends `prefixes`;
/// B (65002) takes them.
struct Lab {
    rib: Rib,
    a: PeerInfo,
    b: PeerInfo,
    t0: Instant,
}

fn lab_with(a: PeerInfo, prefixes: &[&str]) -> Lab {
    let mut rib = Rib::new(LOCAL_AS);
    let b = peer("10.0.0.2", 65_002, 2);
    let t0 = now();
    let mut out = Vec::new();
    rib.peer_up(a.clone(), t0, &mut out);
    rib.peer_up(b.clone(), t0, &mut out);
    for (set, nh) in [
        (
            prefixes
                .iter()
                .copied()
                .filter(|s| !s.contains(':'))
                .collect::<Vec<_>>(),
            "10.0.0.1",
        ),
        (
            prefixes
                .iter()
                .copied()
                .filter(|s| s.contains(':'))
                .collect::<Vec<_>>(),
            "2001:db8::1",
        ),
    ] {
        if !set.is_empty() {
            rib.update(a.addr, &announce(&set, &attrs(&[65_001], nh)), t0, &mut out);
        }
    }
    Lab { rib, a, b, t0 }
}

fn lab(prefixes: &[&str]) -> Lab {
    lab_with(err(peer("10.0.0.1", 65_001, 1), false), prefixes)
}

/// The stale flag of each route to `prefix`.
fn stale_flags(rib: &Rib, family: AddressFamily, prefix: &str) -> Vec<(IpAddr, bool)> {
    routes(rib, family, p(prefix))
        .into_iter()
        .map(|(a, r)| (a, r.stale))
        .collect()
}

fn ignored(out: &[Output]) -> Vec<(IpAddr, AddressFamily, RefreshIgnored)> {
    out.iter()
        .filter_map(|o| match o {
            Output::RefreshIgnored { peer, family, why } => Some((*peer, *family, *why)),
            _ => None,
        })
        .collect()
}

/// What was sent to `to`, in order: a ROUTE-REFRESH by its subtype and
/// family, an UPDATE as a plain `Update` with the prefixes it announces and
/// withdraws.
#[derive(Debug, PartialEq, Eq)]
enum Sent {
    Refresh(RefreshSubtype, AddressFamily),
    Update { announced: usize, withdrawn: usize },
}

fn sent(out: &[Output], to: &PeerInfo) -> Vec<Sent> {
    // The UPDATEs of a peer sent several paths carry Path Identifiers.
    let ctx = DecodeContext {
        four_octet_as: to.four_octet_as,
        peer: to.kind,
        allow_as_set: false,
        extended_next_hop: false,
        add_path: bgpfc_wire::update::AddPathFamilies::of(
            &to.add_path_send.iter().map(|(f, _)| *f).collect::<Vec<_>>(),
        ),
    };
    let mut all = Vec::new();
    for messages in sends(out, to.addr) {
        for m in messages {
            if m[18] == MessageType::RouteRefresh as u8 {
                assert_eq!(m.len(), 23, "a ROUTE-REFRESH is 23 octets");
                let r = RouteRefreshMessage::decode(&m[HEADER_LEN..], Some(max_data_len(false)))
                    .unwrap();
                all.push(Sent::Refresh(r.subtype, r.family));
            } else {
                let u = UpdateMessage::decode(&m[HEADER_LEN..], &ctx)
                    .unwrap()
                    .message;
                let announced = u.nlri.len() + u.mp_reach.as_ref().map_or(0, |r| r.nlri.len());
                let withdrawn =
                    u.withdrawn.len() + u.mp_unreach.as_ref().map_or(0, |r| r.withdrawn.len());
                all.push(Sent::Update {
                    announced,
                    withdrawn,
                });
            }
        }
    }
    all
}

const BORR: RefreshSubtype = RefreshSubtype::BeginOfRefresh;
const EORR: RefreshSubtype = RefreshSubtype::EndOfRefresh;

#[test]
fn a_borr_marks_the_routes_stale_and_changes_nothing_else() {
    let mut l = lab(&["192.0.2.0/24", "198.51.100.0/24", "2001:db8:1::/48"]);
    let out = outputs(|o| assert_eq!(l.rib.refresh_begin(l.a.addr, V4, l.t0, o), 2));
    // RFC 7313 §4: "it MUST mark all the routes with the given AFI and SAFI
    // from that peer as stale", which changes no best path: the FIB and the
    // other peer hear nothing.
    assert!(out.is_empty(), "{out:?}");
    assert_eq!(stale_flags(&l.rib, V4, "192.0.2.0/24"), [(l.a.addr, true)]);
    assert_eq!(
        stale_flags(&l.rib, V4, "198.51.100.0/24"),
        [(l.a.addr, true)]
    );
    // Of that family alone.
    assert_eq!(
        stale_flags(&l.rib, V6, "2001:db8:1::/48"),
        [(l.a.addr, false)]
    );
    assert_eq!(l.rib.loc_rib(V4).count(), 2);
    assert_eq!(l.rib.fib_routes().count(), 3);
    // The session is up: the peer is still one, and it is what the control
    // plane lists as refreshing, not as a peer whose session is down.
    assert!(l.rib.peer(l.a.addr).is_some());
    assert_eq!(l.rib.stale_peers(l.t0).len(), 0);
    assert_eq!(
        l.rib.refreshes(l.t0 + secs(10)),
        [crate::RefreshReport {
            addr: l.a.addr,
            family: V4,
            stale_in: Some(secs(350)),
        }]
    );
    assert_eq!(l.rib.stale_routes(l.a.addr), [(V4, 2)]);
}

#[test]
fn routes_sent_again_replace_their_stale_ones_and_the_eorr_removes_the_rest() {
    let mut l = lab(&["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"]);
    outputs(|o| {
        l.rib.refresh_begin(l.a.addr, V4, l.t0, o);
    });
    // RFC 7313 §4: "As it receives routes from its peer's subsequent
    // Adj-RIB-Out re-advertisement, these replace any corresponding stale
    // routes." The same routes: nothing changes for the FIB or B.
    let out = outputs(|o| {
        l.rib.update(
            l.a.addr,
            &announce(
                &["192.0.2.0/24", "198.51.100.0/24"],
                &attrs(&[65_001], "10.0.0.1"),
            ),
            l.t0,
            o,
        );
    });
    assert!(out.is_empty(), "{out:?}");
    assert_eq!(stale_flags(&l.rib, V4, "192.0.2.0/24"), [(l.a.addr, false)]);
    assert_eq!(
        stale_flags(&l.rib, V4, "203.0.113.0/24"),
        [(l.a.addr, true)]
    );
    // "When a BGP speaker receives an EoRR message from a peer, it MUST
    // immediately remove any routes from the peer that are still marked as
    // stale for that <AFI, SAFI>": the third, from the FIB and from B.
    let out = outputs(|o| l.rib.refresh_end(l.a.addr, V4, l.t0 + secs(5), o));
    assert_eq!(
        removed(&out),
        [(l.a.addr, Some(V4), 1, StaleEnd::EndOfRefresh)]
    );
    let changes = fib(&out);
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].prefix, p("203.0.113.0/24"));
    assert_eq!(changes[0].next_hop, None);
    let to_b = sends(&out, l.b.addr);
    assert_eq!(to_b.len(), 1);
    assert_eq!(
        decode_sent(to_b[0], &l.b)[0].withdrawn,
        [p("203.0.113.0/24")]
    );
    assert_eq!(l.rib.loc_rib(V4).count(), 2);
    // Nothing waits any more: no refresh, no wake-up, the count follows.
    assert_eq!(l.rib.refreshes(l.t0).len(), 0);
    assert_eq!(l.rib.next_deadline(), None);
    assert_eq!(
        l.rib.peer_stats(l.a.addr).unwrap().received,
        [(V4, 2), (V6, 0)]
    );
    // And the routes it sent again are those of an ordinary session: a
    // later withdrawal takes one away, a later refresh begins afresh.
    let out = outputs(|o| {
        l.rib
            .update(l.a.addr, &withdraw(&["192.0.2.0/24"]), l.t0, o);
    });
    assert_eq!(fib(&out).len(), 1);
}

#[test]
fn a_route_that_changed_is_replaced_and_announced_as_any_update() {
    let mut l = lab(&["192.0.2.0/24"]);
    outputs(|o| {
        l.rib.refresh_begin(l.a.addr, V4, l.t0, o);
    });
    // The peer sends the route again with another next hop: it is a change
    // like any other, and no longer stale.
    let out = outputs(|o| {
        l.rib.update(
            l.a.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_001, 7], "10.0.0.9")),
            l.t0,
            o,
        );
    });
    let changes = fib(&out);
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].next_hop, Some(ip("10.0.0.9")));
    assert_eq!(stale_flags(&l.rib, V4, "192.0.2.0/24"), [(l.a.addr, false)]);
    let out = outputs(|o| l.rib.refresh_end(l.a.addr, V4, l.t0, o));
    assert!(fib(&out).is_empty(), "{out:?}");
    assert_eq!(l.rib.loc_rib(V4).count(), 1);
}

#[test]
fn a_withdrawal_during_a_refresh_removes_the_route_at_once() {
    let mut l = lab(&["192.0.2.0/24", "198.51.100.0/24"]);
    outputs(|o| {
        l.rib.refresh_begin(l.a.addr, V4, l.t0, o);
    });
    let out = outputs(|o| {
        l.rib
            .update(l.a.addr, &withdraw(&["192.0.2.0/24"]), l.t0, o);
    });
    assert_eq!(fib(&out).len(), 1);
    // The EoRR removes the one left, and only that.
    let out = outputs(|o| l.rib.refresh_end(l.a.addr, V4, l.t0, o));
    assert_eq!(
        removed(&out),
        [(l.a.addr, Some(V4), 1, StaleEnd::EndOfRefresh)]
    );
    assert_eq!(l.rib.loc_rib(V4).count(), 0);
}

#[test]
fn a_refresh_of_one_family_leaves_the_other_alone() {
    let mut l = lab(&["192.0.2.0/24", "2001:db8:1::/48"]);
    outputs(|o| {
        l.rib.refresh_begin(l.a.addr, V6, l.t0, o);
    });
    let out = outputs(|o| l.rib.refresh_end(l.a.addr, V6, l.t0, o));
    assert_eq!(
        removed(&out),
        [(l.a.addr, Some(V6), 1, StaleEnd::EndOfRefresh)]
    );
    assert_eq!(fib(&out).len(), 1);
    assert_eq!(l.rib.loc_rib(V4).count(), 1);
    assert_eq!(l.rib.loc_rib(V6).count(), 0);
    // Both under way at once, each ended by its own EoRR.
    let mut l = lab(&["192.0.2.0/24", "2001:db8:1::/48"]);
    outputs(|o| {
        l.rib.refresh_begin(l.a.addr, V4, l.t0, o);
        l.rib.refresh_begin(l.a.addr, V6, l.t0, o);
    });
    assert_eq!(l.rib.refreshes(l.t0).len(), 2);
    outputs(|o| l.rib.refresh_end(l.a.addr, V4, l.t0, o));
    assert_eq!(l.rib.refreshes(l.t0).len(), 1);
    assert_eq!(l.rib.loc_rib(V6).count(), 1);
}

#[test]
fn a_borr_for_a_family_with_no_routes_marks_nothing_and_waits_for_nothing() {
    let mut l = lab(&["192.0.2.0/24"]);
    let out = outputs(|o| assert_eq!(l.rib.refresh_begin(l.a.addr, V6, l.t0, o), 0));
    assert!(out.is_empty(), "{out:?}");
    // No timer for nothing; the refresh is still begun, so its EoRR is not
    // one without a BoRR.
    assert_eq!(l.rib.next_deadline(), None);
    assert_eq!(l.rib.refreshes(l.t0).len(), 1);
    let out = outputs(|o| l.rib.refresh_end(l.a.addr, V6, l.t0, o));
    assert!(out.is_empty(), "{out:?}");
    assert_eq!(l.rib.refreshes(l.t0).len(), 0);
}

#[test]
fn a_family_disabled_during_a_refresh_leaves_no_time_to_wait_for() {
    let mut l = lab(&["192.0.2.0/24", "2001:db8:1::/48", "2001:db8:2::/48"]);
    outputs(|o| {
        l.rib.refresh_begin(l.a.addr, V6, l.t0, o);
        l.rib.refresh_begin(l.a.addr, V4, l.t0, o);
    });
    assert!(l.rib.next_deadline().is_some());
    // RFC 4760 §7: the IPv6 routes of the peer go with the family.
    let more = announce(&["198.51.100.0/24"], &attrs(&[65_001], "10.0.0.1"));
    outputs(|o| l.rib.update(l.a.addr, &disabling(V6, more), l.t0, o));
    assert_eq!(l.rib.loc_rib(V6).count(), 0);
    // The IPv4 refresh keeps its time, the IPv6 one has none: nothing is
    // left to remove, so its timer does not stay in the queue.
    let report = l.rib.refreshes(l.t0);
    assert_eq!(report.len(), 2);
    assert_eq!(
        report
            .iter()
            .map(|r| (r.family, r.stale_in.is_some()))
            .collect::<Vec<_>>(),
        [(V4, true), (V6, false)]
    );
    // Only the IPv4 refresh is left to expire: the route the peer did not
    // send again goes, and the one it announced meanwhile stays.
    let out = outputs(|o| l.rib.flush(l.t0 + STALE, o));
    assert_eq!(
        removed(&out),
        [(l.a.addr, Some(V4), 1, StaleEnd::RefreshTimer)],
        "{out:?}"
    );
    assert_eq!(l.rib.loc_rib(V4).count(), 1);
    assert_eq!(l.rib.next_deadline(), None);
    // The EoRR of the disabled family's refresh still matches its BoRR.
    let out = outputs(|o| l.rib.refresh_end(l.a.addr, V6, l.t0 + STALE, o));
    assert!(out.is_empty(), "{out:?}");
    assert_eq!(l.rib.refreshes(l.t0 + STALE).len(), 0);
}

#[test]
fn an_eorr_without_a_borr_is_ignored_and_reported() {
    let mut l = lab(&["192.0.2.0/24"]);
    // RFC 7313 §4: "A BGP speaker MAY ignore any EoRR message received
    // without a prior receipt of an associated BoRR message."
    let out = outputs(|o| l.rib.refresh_end(l.a.addr, V4, l.t0, o));
    assert_eq!(ignored(&out), [(l.a.addr, V4, RefreshIgnored::NoBegin)]);
    assert_eq!(out.len(), 1);
    assert_eq!(l.rib.loc_rib(V4).count(), 1);
    assert_eq!(stale_flags(&l.rib, V4, "192.0.2.0/24"), [(l.a.addr, false)]);
    // Nor does one for another family's refresh count.
    outputs(|o| {
        l.rib.refresh_begin(l.a.addr, V4, l.t0, o);
    });
    let out = outputs(|o| l.rib.refresh_end(l.a.addr, V6, l.t0, o));
    assert_eq!(ignored(&out), [(l.a.addr, V6, RefreshIgnored::NoBegin)]);
    assert_eq!(l.rib.refreshes(l.t0).len(), 1);
    // Twice is once too many: the first EoRR ended it.
    outputs(|o| l.rib.refresh_end(l.a.addr, V4, l.t0, o));
    let out = outputs(|o| l.rib.refresh_end(l.a.addr, V4, l.t0, o));
    assert_eq!(ignored(&out), [(l.a.addr, V4, RefreshIgnored::NoBegin)]);
}

#[test]
fn the_stale_time_removes_what_is_left_without_an_eorr() {
    let mut l = lab(&["192.0.2.0/24", "198.51.100.0/24"]);
    outputs(|o| {
        l.rib.refresh_begin(l.a.addr, V4, l.t0, o);
    });
    // RFC 7313 §4: "An implementation MAY impose a locally configurable upper
    // bound on how long it would retain any stale routes."
    assert_eq!(l.rib.next_deadline(), Some(l.t0 + STALE));
    outputs(|o| {
        l.rib.update(
            l.a.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_001], "10.0.0.1")),
            l.t0 + secs(100),
            o,
        );
    });
    let out = outputs(|o| l.rib.flush(l.t0 + secs(359), o));
    assert!(out.is_empty(), "{out:?}");
    let out = outputs(|o| l.rib.flush(l.t0 + STALE, o));
    assert_eq!(
        removed(&out),
        [(l.a.addr, Some(V4), 1, StaleEnd::RefreshTimer)]
    );
    assert_eq!(fib(&out).len(), 1);
    assert_eq!(l.rib.loc_rib(V4).count(), 1);
    assert_eq!(l.rib.refreshes(l.t0 + STALE).len(), 0);
    assert_eq!(l.rib.next_deadline(), None);
    // The refresh is over, so an EoRR after the time is one without a BoRR.
    let out = outputs(|o| l.rib.refresh_end(l.a.addr, V4, l.t0 + STALE, o));
    assert_eq!(ignored(&out), [(l.a.addr, V4, RefreshIgnored::NoBegin)]);
}

#[test]
fn the_eorr_cancels_the_stale_time_and_a_new_borr_starts_it_afresh() {
    let mut l = lab(&["192.0.2.0/24"]);
    outputs(|o| {
        l.rib.refresh_begin(l.a.addr, V4, l.t0, o);
        // The peer sends it again, so it survives the EoRR.
        l.rib.update(
            l.a.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_001], "10.0.0.1")),
            l.t0,
            o,
        );
    });
    outputs(|o| l.rib.refresh_end(l.a.addr, V4, l.t0 + secs(5), o));
    // No wake-up is left behind by a refresh that ended.
    assert_eq!(l.rib.next_deadline(), None);
    // A refresh begun twice counts from the second BoRR, with the one
    // timer.
    let t1 = l.t0 + secs(100);
    outputs(|o| {
        l.rib.refresh_begin(l.a.addr, V4, l.t0 + secs(10), o);
    });
    outputs(|o| {
        l.rib.refresh_begin(l.a.addr, V4, t1, o);
    });
    assert_eq!(l.rib.next_deadline(), Some(t1 + STALE));
    assert_eq!(l.rib.refreshes(t1).len(), 1);
    let out = outputs(|o| l.rib.flush(l.t0 + secs(10) + STALE, o));
    assert!(removed(&out).is_empty(), "{out:?}");
    let out = outputs(|o| l.rib.flush(t1 + STALE, o));
    assert_eq!(removed(&out).len(), 1);
}

#[test]
fn a_second_borr_marks_again_the_routes_the_first_refresh_replaced() {
    let mut l = lab(&["192.0.2.0/24", "198.51.100.0/24"]);
    outputs(|o| {
        l.rib.refresh_begin(l.a.addr, V4, l.t0, o);
    });
    outputs(|o| {
        l.rib.update(
            l.a.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_001], "10.0.0.1")),
            l.t0,
            o,
        );
    });
    // RFC 7313 §4: on a BoRR it "MUST mark all the routes", the replaced
    // included, so the peer has to send the table again.
    assert_eq!(
        outputs(|o| assert_eq!(l.rib.refresh_begin(l.a.addr, V4, l.t0, o), 2)).len(),
        0
    );
    assert_eq!(stale_flags(&l.rib, V4, "192.0.2.0/24"), [(l.a.addr, true)]);
    let out = outputs(|o| l.rib.refresh_end(l.a.addr, V4, l.t0, o));
    assert_eq!(
        removed(&out),
        [(l.a.addr, Some(V4), 2, StaleEnd::EndOfRefresh)]
    );
    assert_eq!(l.rib.loc_rib(V4).count(), 0);
}

#[test]
fn without_the_capability_nothing_is_marked_or_removed() {
    // RFC 7313 §4: "The following procedures are applicable only if a BGP
    // speaker has received the Enhanced Route Refresh Capability from a
    // peer."
    let mut l = lab_with(peer("10.0.0.1", 65_001, 1), &["192.0.2.0/24"]);
    let out = outputs(|o| {
        assert_eq!(l.rib.refresh_begin(l.a.addr, V4, l.t0, o), 0);
        l.rib.refresh_end(l.a.addr, V4, l.t0, o);
    });
    assert!(out.is_empty(), "{out:?}");
    assert_eq!(stale_flags(&l.rib, V4, "192.0.2.0/24"), [(l.a.addr, false)]);
    assert_eq!(l.rib.loc_rib(V4).count(), 1);
    // And an unknown peer, or a family we do not take, is not a refresh.
    let out = outputs(|o| {
        assert_eq!(l.rib.refresh_begin(ip("10.9.9.9"), V4, l.t0, o), 0);
        l.rib.refresh_end(ip("10.9.9.9"), V4, l.t0, o);
    });
    assert!(out.is_empty(), "{out:?}");
    let mut v4_only = err(peer("10.0.0.1", 65_001, 1), false);
    v4_only.families = vec![V4];
    v4_only.receive_families = vec![V4];
    let mut l = lab_with(v4_only, &["192.0.2.0/24"]);
    assert_eq!(
        outputs(|o| assert_eq!(l.rib.refresh_begin(l.a.addr, V6, l.t0, o), 0)).len(),
        0
    );
    assert_eq!(l.rib.refreshes(l.t0).len(), 0);
}

#[test]
fn held_routes_are_marked_and_removed_with_the_rest() {
    use crate::{Policies, Verdict};
    // A policy that rejects Valid and accepts the rest keeps a route its
    // state alone would make a candidate (RFC 6811 §2); here the RIB has no
    // validation source, so every route is `disabled` and is accepted. A
    // held route needs the drop action: Invalid routes are held.
    struct InvalidOnly;
    impl Policies for InvalidOnly {
        fn import(
            &self,
            _: &PeerInfo,
            _: AddressFamily,
            _: Prefix,
            _: &PathAttrs,
            _: RovState,
        ) -> Verdict {
            Verdict::Restated(RovState::Invalid)
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
    let mut rib = Rib::with_policies(LOCAL_AS, Box::new(InvalidOnly));
    rib.set_invalid_action(bgpfc_rpki::InvalidAction::Drop, now(), &mut Vec::new());
    let a = err(peer("10.0.0.1", 65_001, 1), false);
    let t0 = now();
    outputs(|o| rib.peer_up(a.clone(), t0, o));
    outputs(|o| {
        rib.update(
            a.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_001], "10.0.0.1")),
            t0,
            o,
        );
    });
    // Held: in the Adj-RIB-In, no candidate, not in the Loc-RIB.
    assert_eq!(rib.loc_rib(V4).count(), 0);
    assert_eq!(rib.peer_stats(a.addr).unwrap().received[0], (V4, 1));
    assert_eq!(rib.refresh_begin(a.addr, V4, t0, &mut Vec::new()), 1);
    let out = outputs(|o| rib.refresh_end(a.addr, V4, t0, o));
    assert_eq!(
        removed(&out),
        [(a.addr, Some(V4), 1, StaleEnd::EndOfRefresh)]
    );
    assert_eq!(rib.peer_stats(a.addr).unwrap().received[0], (V4, 0));
}

// --- ADD-PATH (RFC 7911) ------------------------------------------------

#[test]
fn each_path_is_replaced_under_its_identifier_and_the_unsent_ones_go() {
    let a = err(add_path_peer("10.0.0.1", 65_001, 1), false);
    let mut l = lab_with(a, &[]);
    // Three paths to one prefix, and one to another.
    for (path, id) in [
        (&[65_001, 5, 6][..], 1),
        (&[65_001, 5][..], 2),
        (&[65_001][..], 3),
    ] {
        outputs(|o| {
            l.rib.update(
                l.a.addr,
                &announce_paths(&[("192.0.2.0/24", id)], &attrs(path, "10.0.0.1")),
                l.t0,
                o,
            );
        });
    }
    outputs(|o| {
        l.rib.update(
            l.a.addr,
            &announce_paths(&[("198.51.100.0/24", 9)], &attrs(&[65_001], "10.0.0.1")),
            l.t0,
            o,
        );
    });
    assert_eq!(l.rib.refresh_begin(l.a.addr, V4, l.t0, &mut Vec::new()), 4);
    // The peer sends path 2 of the first prefix again, and path 9 of the
    // other under a new identifier, which is another path (RFC 7911 §2).
    outputs(|o| {
        l.rib.update(
            l.a.addr,
            &announce_paths(&[("192.0.2.0/24", 2)], &attrs(&[65_001, 5], "10.0.0.1")),
            l.t0,
            o,
        );
        l.rib.update(
            l.a.addr,
            &announce_paths(&[("198.51.100.0/24", 10)], &attrs(&[65_001], "10.0.0.1")),
            l.t0,
            o,
        );
    });
    let out = outputs(|o| l.rib.refresh_end(l.a.addr, V4, l.t0, o));
    // Paths 1 and 3 and path 9 are stale; path 2 and path 10 are not.
    assert_eq!(
        removed(&out),
        [(l.a.addr, Some(V4), 3, StaleEnd::EndOfRefresh)]
    );
    let ids = |prefix: &str| -> Vec<Option<u32>> {
        l.rib
            .candidates(V4, p(prefix))
            .iter()
            .map(|c| c.path_id.map(|i| i.0))
            .collect()
    };
    assert_eq!(ids("192.0.2.0/24"), [Some(2)]);
    assert_eq!(ids("198.51.100.0/24"), [Some(10)]);
    assert_eq!(
        l.rib.peer_stats(l.a.addr).unwrap().received,
        [(V4, 2), (V6, 0)]
    );
    // A withdrawal of a path that went is ignored (RFC 7911 §5).
    let out = outputs(|o| {
        l.rib
            .update(l.a.addr, &withdraw_paths(&[("192.0.2.0/24", 1)]), l.t0, o);
    });
    assert!(out.is_empty(), "{out:?}");
}

// --- Graceful Restart (RFC 4724) and RFC 7313 §4 ------------------------

/// A Graceful Restart peer that also has Enhanced Route Refresh.
fn gr_err(addr: &str, remote_as: u32, router_id: u32) -> PeerInfo {
    err(gr_peer(addr, remote_as, router_id), true)
}

#[test]
fn a_borr_before_the_end_of_rib_of_a_graceful_restart_peer_is_ignored() {
    let mut l = lab_with(gr_err("10.0.0.1", 65_001, 1), &["192.0.2.0/24"]);
    // RFC 7313 §4: "A BGP speaker that has received the Graceful Restart
    // Capability from its neighbor MUST ignore any BoRRs for an
    // <AFI, SAFI> from the neighbor before the speaker receives the EoR for
    // the given <AFI, SAFI> from the neighbor. The BGP speaker SHOULD log an
    // error of the condition for further analysis."
    let out = outputs(|o| assert_eq!(l.rib.refresh_begin(l.a.addr, V4, l.t0, o), 0));
    assert_eq!(
        ignored(&out),
        [(l.a.addr, V4, RefreshIgnored::BeforeEndOfRib)]
    );
    assert_eq!(stale_flags(&l.rib, V4, "192.0.2.0/24"), [(l.a.addr, false)]);
    assert_eq!(l.rib.refreshes(l.t0).len(), 0);
    // Its EoRR is then one without a BoRR, and removes nothing.
    let out = outputs(|o| l.rib.refresh_end(l.a.addr, V4, l.t0, o));
    assert_eq!(ignored(&out), [(l.a.addr, V4, RefreshIgnored::NoBegin)]);
    assert_eq!(l.rib.loc_rib(V4).count(), 1);
    // The IPv6 End-of-RIB does not release IPv4, but the IPv4 one does.
    outputs(|o| l.rib.end_of_rib(l.a.addr, V6, l.t0, o));
    let out = outputs(|o| assert_eq!(l.rib.refresh_begin(l.a.addr, V4, l.t0, o), 0));
    assert_eq!(ignored(&out).len(), 1);
    outputs(|o| l.rib.end_of_rib(l.a.addr, V4, l.t0, o));
    let out = outputs(|o| assert_eq!(l.rib.refresh_begin(l.a.addr, V4, l.t0, o), 1));
    assert!(out.is_empty(), "{out:?}");
    let out = outputs(|o| l.rib.refresh_end(l.a.addr, V4, l.t0, o));
    assert_eq!(removed(&out).len(), 1);
}

#[test]
fn a_peer_without_graceful_restart_is_not_waited_for() {
    // The rule is for the speaker "that has received the Graceful Restart
    // Capability from its neighbor".
    let mut l = lab(&["192.0.2.0/24"]);
    assert_eq!(l.rib.refresh_begin(l.a.addr, V4, l.t0, &mut Vec::new()), 1);
}

#[test]
fn routes_stale_from_a_restart_are_not_marked_again_by_a_borr() {
    let mut l = lab_with(gr_err("10.0.0.1", 65_001, 1), &["192.0.2.0/24"]);
    l.rib
        .peer_retain(l.a.addr, &retention(false), l.t0, &mut Vec::new());
    // The session is back, its End-of-RIB not yet in: the routes are stale
    // from the restart, which a refresh must not mix with its own marks.
    let t1 = l.t0 + secs(10);
    outputs(|o| l.rib.peer_up(gr_err("10.0.0.1", 65_001, 1), t1, o));
    let out = outputs(|o| assert_eq!(l.rib.refresh_begin(l.a.addr, V4, t1, o), 0));
    assert_eq!(
        ignored(&out),
        [(l.a.addr, V4, RefreshIgnored::BeforeEndOfRib)]
    );
    // The End-of-RIB ends Graceful Restart's stale routes, then a refresh
    // may begin.
    let out = outputs(|o| l.rib.end_of_rib(l.a.addr, V4, t1, o));
    assert_eq!(removed(&out).len(), 1);
    assert_eq!(l.rib.refresh_begin(l.a.addr, V4, t1, &mut Vec::new()), 0);
}

#[test]
fn a_session_that_ends_during_a_refresh_keeps_the_routes_as_a_restart_does() {
    let mut l = lab_with(
        gr_err("10.0.0.1", 65_001, 1),
        &["192.0.2.0/24", "198.51.100.0/24"],
    );
    outputs(|o| l.rib.end_of_rib(l.a.addr, V4, l.t0, o));
    outputs(|o| {
        l.rib.refresh_begin(l.a.addr, V4, l.t0, o);
        l.rib.update(
            l.a.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_001], "10.0.0.1")),
            l.t0,
            o,
        );
    });
    assert_eq!(l.rib.next_deadline(), Some(l.t0 + STALE));
    // RFC 4724 §4.2: the session fails and its routes are kept, both the
    // one sent again and the one not; the refresh is over with the session,
    // and its timer is gone for the Restart Time's.
    let out = outputs(|o| assert_eq!(l.rib.peer_retain(l.a.addr, &retention(false), l.t0, o), 2));
    assert!(out.is_empty(), "{out:?}");
    assert_eq!(l.rib.refreshes(l.t0).len(), 0);
    assert_eq!(l.rib.next_deadline(), Some(l.t0 + secs(120)));
    assert_eq!(l.rib.stale_routes(l.a.addr), [(V4, 2)]);
    // No refresh wake-up outlives it.
    let out = outputs(|o| l.rib.flush(l.t0 + STALE, o));
    assert_eq!(removed(&out).len(), 1);
    assert_eq!(removed(&out)[0].3, StaleEnd::RestartTimer);
}

#[test]
fn a_session_that_ends_for_good_during_a_refresh_leaves_no_state_or_timer() {
    let mut l = lab(&["192.0.2.0/24"]);
    outputs(|o| {
        l.rib.refresh_begin(l.a.addr, V4, l.t0, o);
    });
    outputs(|o| l.rib.peer_down(l.a.addr, l.t0, o));
    assert_eq!(l.rib.next_deadline(), None);
    assert_eq!(l.rib.refreshes(l.t0).len(), 0);
    // The slot goes to another peer, which finds no refresh of A's.
    let c = err(peer("10.0.0.3", 65_003, 3), false);
    outputs(|o| l.rib.peer_up(c.clone(), l.t0, o));
    assert_eq!(l.rib.refreshes(l.t0).len(), 0);
    let out = outputs(|o| l.rib.flush(l.t0 + STALE, o));
    assert!(out.is_empty(), "{out:?}");
}

// --- Sending a refresh --------------------------------------------------

#[test]
fn a_refresh_to_a_peer_with_the_capability_is_a_borr_the_table_and_an_eorr() {
    let mut l = lab_with(
        peer("10.0.0.1", 65_001, 1),
        &["192.0.2.0/24", "198.51.100.0/24", "2001:db8:1::/48"],
    );
    let b = err(l.b.clone(), false);
    outputs(|o| l.rib.peer_down(b.addr, l.t0, o));
    outputs(|o| l.rib.peer_up(b.clone(), l.t0, o));
    // RFC 7313 §4: no BoRR before the initial update; it is no route
    // refresh.
    let out = outputs(|o| {
        l.rib
            .peer_up(err(peer("10.0.0.7", 65_007, 7), false), l.t0, o);
    });
    assert!(
        sent(&out, &err(peer("10.0.0.7", 65_007, 7), false))
            .iter()
            .all(|s| matches!(s, Sent::Update { .. })),
        "{out:?}"
    );
    let out = outputs(|o| l.rib.refresh(b.addr, V4, l.t0, o));
    assert_eq!(
        sent(&out, &b),
        [
            Sent::Refresh(BORR, V4),
            Sent::Update {
                announced: 2,
                withdrawn: 0
            },
            Sent::Refresh(EORR, V4),
        ]
    );
    let out = outputs(|o| l.rib.refresh(b.addr, V6, l.t0, o));
    assert_eq!(
        sent(&out, &b),
        [
            Sent::Refresh(BORR, V6),
            Sent::Update {
                announced: 1,
                withdrawn: 0
            },
            Sent::Refresh(EORR, V6),
        ]
    );
}

#[test]
fn an_empty_adj_rib_out_is_a_borr_and_an_eorr() {
    // RFC 7313 §4: the entire Adj-RIB-Out, which may be nothing, and then
    // the peer purges what it has of ours.
    let mut l = lab(&[]);
    let b = err(l.b.clone(), false);
    outputs(|o| l.rib.peer_down(b.addr, l.t0, o));
    outputs(|o| l.rib.peer_up(b.clone(), l.t0, o));
    let out = outputs(|o| l.rib.refresh(b.addr, V4, l.t0, o));
    assert_eq!(
        sent(&out, &b),
        [Sent::Refresh(BORR, V4), Sent::Refresh(EORR, V4)]
    );
}

#[test]
fn a_refresh_to_a_peer_without_the_capability_is_the_table_alone() {
    let mut l = lab(&["192.0.2.0/24"]);
    let out = outputs(|o| l.rib.refresh(l.b.addr, V4, l.t0, o));
    assert_eq!(
        sent(&out, &l.b),
        [Sent::Update {
            announced: 1,
            withdrawn: 0
        }]
    );
}

#[test]
fn a_refresh_that_sends_nothing_has_no_brackets() {
    let mut l = lab(&["192.0.2.0/24"]);
    // A family that was not negotiated.
    let mut v4_only = err(peer("10.0.0.3", 65_003, 3), false);
    v4_only.families = vec![V4];
    outputs(|o| l.rib.peer_up(v4_only.clone(), l.t0, o));
    let out = outputs(|o| l.rib.refresh(v4_only.addr, V6, l.t0, o));
    assert!(out.is_empty(), "{out:?}");
    // A peer that is not up.
    let out = outputs(|o| l.rib.refresh(ip("10.9.9.9"), V4, l.t0, o));
    assert!(out.is_empty(), "{out:?}");
}

#[test]
fn no_borr_goes_before_our_end_of_rib() {
    // RFC 7313 §4: "For a BGP speaker that supports the BGP Graceful
    // Restart, it MUST NOT send a BoRR for an <AFI, SAFI> to a neighbor
    // before it sends the EoR for the <AFI, SAFI> to the neighbor." While
    // route selection is deferred (RFC 4724 §4.1) no table and no EoR go,
    // and so no BoRR.
    let mut rib = Rib::new(LOCAL_AS);
    let b = err(gr_peer("10.0.0.2", 65_002, 2), true);
    let t0 = now();
    rib.defer_selection(&crate::Deferral {
        waiting: vec![(ip("10.0.0.1"), vec![V4])],
        until: t0 + secs(120),
    });
    let out = outputs(|o| rib.peer_up(b.clone(), t0, o));
    assert!(
        sent(&out, &b)
            .iter()
            .all(|s| !matches!(s, Sent::Refresh(..)))
    );
    let out = outputs(|o| rib.refresh(b.addr, V4, t0, o));
    assert!(sent(&out, &b).is_empty(), "{out:?}");
    // The IPv6 family is not deferred, and gets its refresh.
    let out = outputs(|o| rib.refresh(b.addr, V6, t0, o));
    assert_eq!(
        sent(&out, &b),
        [Sent::Refresh(BORR, V6), Sent::Refresh(EORR, V6)]
    );
}

#[test]
fn the_brackets_come_with_the_paths_of_an_add_path_peer() {
    let mut l = lab(&["192.0.2.0/24"]);
    let b = err(
        PeerInfo {
            add_path_send: vec![(V4, crate::PathLimit::All)],
            ..peer("10.0.0.3", 65_003, 3)
        },
        false,
    );
    outputs(|o| l.rib.peer_up(b.clone(), l.t0, o));
    let out = outputs(|o| l.rib.refresh(b.addr, V4, l.t0, o));
    let s = sent(&out, &b);
    assert_eq!(s.first(), Some(&Sent::Refresh(BORR, V4)));
    assert_eq!(s.last(), Some(&Sent::Refresh(EORR, V4)));
    assert_eq!(s.len(), 3, "{s:?}");
}

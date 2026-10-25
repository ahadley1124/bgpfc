//! Several paths of a prefix from one peer (RFC 7911 §3, §5): the
//! Adj-RIB-In keeps each under its Path Identifier, every one takes part
//! in the decision process, and the FIB still gets the one best path.

use bgpfc_wire::types::PathId;
use bgpfc_wire::update::PathIds;

use super::*;
use crate::{AcceptAll, Policies, Verdict};

/// A peer that sends us paths with identifiers for both families.
fn add_path_peer(addr: &str, remote_as: u32, router_id: u32) -> PeerInfo {
    PeerInfo {
        add_path_receive: vec![V4, V6],
        ..peer(addr, remote_as, router_id)
    }
}

/// `a` announced for each of `paths` (prefix, Path Identifier), in the NLRI
/// field of IPv4 or in `MP_REACH_NLRI` for any other family, as the encoder
/// puts them.
fn announce_paths(paths: &[(&str, u32)], a: &PathAttrs) -> DecodedUpdate {
    let family = if paths[0].0.contains(':') { V6 } else { V4 };
    let prefixes = paths.iter().map(|(s, _)| p(s)).collect();
    let mut message = a.to_update(family, prefixes);
    let ids = paths.iter().map(|(_, id)| PathId(*id)).collect();
    let mut path_ids = PathIds::default();
    if message.mp_reach.is_some() {
        path_ids.mp_reach = ids;
    } else {
        path_ids.nlri = ids;
    }
    message.path_ids = Some(Box::new(path_ids));
    DecodedUpdate {
        message,
        treated_as_withdraw: None,
        discarded: Vec::new(),
        disabled: Vec::new(),
    }
}

/// A withdrawal of each of `paths`.
fn withdraw_paths(paths: &[(&str, u32)]) -> DecodedUpdate {
    let mut message = UpdateMessage::default();
    let ids = paths.iter().map(|(_, id)| PathId(*id)).collect();
    let prefixes = paths.iter().map(|(s, _)| p(s)).collect();
    let mut path_ids = PathIds::default();
    if paths[0].0.contains(':') {
        message.mp_unreach = Some(bgpfc_wire::mp::MpUnreach {
            family: V6,
            withdrawn: prefixes,
        });
        path_ids.mp_unreach = ids;
    } else {
        message.withdrawn = prefixes;
        path_ids.withdrawn = ids;
    }
    message.path_ids = Some(Box::new(path_ids));
    DecodedUpdate {
        message,
        treated_as_withdraw: None,
        discarded: Vec::new(),
        disabled: Vec::new(),
    }
}

/// The path identifiers of the candidates to `prefix`, best first, with the
/// peers they came from.
fn candidates(rib: &Rib, family: AddressFamily, prefix: &str) -> Vec<(IpAddr, Option<u32>)> {
    rib.candidates(family, p(prefix))
        .iter()
        .map(|c| (c.peer, c.path_id.map(|i| i.0)))
        .collect()
}

#[test]
fn several_paths_of_a_prefix_are_kept_apart_and_all_take_part_in_the_decision() {
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = add_path_peer("10.0.0.1", 65_001, 1);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    // Three paths to one prefix in one UPDATE would share attributes;
    // send them in turn, with a different AS path each.
    let paths: [(&[u32], u32); 3] = [
        (&[65_001, 5, 6], 1),
        (&[65_001, 5], 2),
        (&[65_001, 7, 8], 3),
    ];
    for (path, id) in paths {
        let out = outputs(|o| {
            rib.update(
                e1.addr,
                &announce_paths(&[("192.0.2.0/24", id)], &attrs(path, "10.0.0.1")),
                now(),
                o,
            );
        });
        // RFC 4271 §9.1: all candidates compete, the shortest path wins.
        let _ = out;
    }
    assert_eq!(
        candidates(&rib, V4, "192.0.2.0/24"),
        vec![(e1.addr, Some(2)), (e1.addr, Some(1)), (e1.addr, Some(3))]
    );
    let best: Vec<_> = rib.loc_rib(V4).collect();
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].1.path_id, Some(PathId(2)));
    assert_eq!(best[0].1.attrs.as_path.hop_count(), 2);
    // Three routes in the Adj-RIB-In, counted as such (RFC 4271 §6.7 counts
    // the routes held).
    assert_eq!(
        rib.peer_stats(e1.addr).unwrap().received,
        vec![(V4, 3), (V6, 0)]
    );
    // The FIB has the one best path.
    let fib: Vec<_> = rib.fib_routes().collect();
    assert_eq!(fib, vec![(p("192.0.2.0/24"), ip("10.0.0.1"))]);
}

#[test]
fn a_withdrawal_names_one_path_and_an_unknown_one_is_ignored() {
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = add_path_peer("10.0.0.1", 65_001, 1);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    let short = attrs(&[65_001], "10.0.0.1");
    let long = attrs(&[65_001, 5], "10.0.0.1");
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce_paths(&[("192.0.2.0/24", 7)], &short),
            now(),
            o,
        );
    });
    let out = outputs(|o| {
        rib.update(
            e1.addr,
            &announce_paths(&[("192.0.2.0/24", 9)], &long),
            now(),
            o,
        );
    });
    // A worse path changes nothing the FIB follows.
    assert_eq!(fib(&out), vec![]);
    // RFC 7911 §5: "a Path Identifier not seen before" is silently ignored.
    for unknown in [0, 8, 10] {
        let out = outputs(|o| {
            rib.update(
                e1.addr,
                &withdraw_paths(&[("192.0.2.0/24", unknown)]),
                now(),
                o,
            );
        });
        assert_eq!(out, vec![], "path {unknown}");
        assert_eq!(rib.candidates(V4, p("192.0.2.0/24")).len(), 2);
    }
    // Nor does a plain withdrawal, which is for path zero, take them.
    let out = outputs(|o| rib.update(e1.addr, &withdraw(&["192.0.2.0/24"]), now(), o));
    assert_eq!(out, vec![]);
    // Withdrawing the best: the other takes over, and the FIB is told only
    // if its next hop differs, which it does not here.
    outputs(|o| rib.update(e1.addr, &withdraw_paths(&[("192.0.2.0/24", 7)]), now(), o));
    assert_eq!(
        candidates(&rib, V4, "192.0.2.0/24"),
        vec![(e1.addr, Some(9))]
    );
    assert_eq!(rib.peer_stats(e1.addr).unwrap().received[0], (V4, 1));
    // The last one takes the destination away.
    let out = outputs(|o| rib.update(e1.addr, &withdraw_paths(&[("192.0.2.0/24", 9)]), now(), o));
    assert_eq!(fib(&out).len(), 1);
    assert!(rib.candidates(V4, p("192.0.2.0/24")).is_empty());
    assert_eq!(rib.loc_rib(V4).count(), 0);
}

#[test]
fn a_newer_advertisement_of_a_prefix_and_path_replaces_the_older() {
    // RFC 7911 §5.
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = add_path_peer("10.0.0.1", 65_001, 1);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    let first = attrs(&[65_001, 5, 6], "10.0.0.1");
    let second = attrs(&[65_001], "10.0.0.1");
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce_paths(&[("192.0.2.0/24", 4)], &first),
            now(),
            o,
        );
    });
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce_paths(&[("192.0.2.0/24", 5)], &first),
            now(),
            o,
        );
    });
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce_paths(&[("192.0.2.0/24", 4)], &second),
            now(),
            o,
        );
    });
    let routes = rib.candidates(V4, p("192.0.2.0/24"));
    assert_eq!(routes.len(), 2);
    assert_eq!(routes[0].path_id, Some(PathId(4)));
    assert_eq!(routes[0].attrs.as_path.hop_count(), 1);
    // Announcing the same again changes nothing.
    let out = outputs(|o| {
        rib.update(
            e1.addr,
            &announce_paths(&[("192.0.2.0/24", 4)], &second),
            now(),
            o,
        );
    });
    assert_eq!(out, vec![]);
    assert_eq!(rib.peer_stats(e1.addr).unwrap().received[0], (V4, 2));
}

#[test]
fn the_lowest_path_identifier_breaks_the_last_tie_whatever_the_arrival_order() {
    // RFC 4271 §9.1.2.2 ends at the peer address, which two paths of one
    // peer share.
    let e1 = add_path_peer("10.0.0.1", 65_001, 1);
    let a = attrs(&[65_001], "10.0.0.1");
    let mut b = a.clone();
    b.next_hop = NextHop::Ipv4(Ipv4Addr::new(10, 0, 0, 9));
    for order in [[3, 1, 2], [1, 2, 3], [2, 3, 1]] {
        let mut rib = Rib::new(LOCAL_AS);
        outputs(|o| rib.peer_up(e1.clone(), now(), o));
        for id in order {
            let x = if id == 1 { &b } else { &a };
            outputs(|o| {
                rib.update(
                    e1.addr,
                    &announce_paths(&[("192.0.2.0/24", id)], x),
                    now(),
                    o,
                );
            });
        }
        let best: Vec<_> = rib.loc_rib(V4).collect();
        assert_eq!(best[0].1.path_id, Some(PathId(1)), "{order:?}");
        // Path 1 has the other next hop, and so the FIB's.
        assert_eq!(
            rib.fib_routes().collect::<Vec<_>>(),
            vec![(p("192.0.2.0/24"), ip("10.0.0.9"))]
        );
    }
}

#[test]
fn paths_of_two_peers_compete_and_a_plain_peer_has_no_identifier() {
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = add_path_peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_002, 2);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    outputs(|o| rib.peer_up(e2.clone(), now(), o));
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce_paths(&[("192.0.2.0/24", 11)], &attrs(&[65_001, 5], "10.0.0.1")),
            now(),
            o,
        );
    });
    outputs(|o| {
        rib.update(
            e2.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_002], "10.0.0.2")),
            now(),
            o,
        );
    });
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce_paths(
                &[("192.0.2.0/24", 12)],
                &attrs(&[65_001, 6, 7, 8], "10.0.0.1"),
            ),
            now(),
            o,
        );
    });
    // Identifiers are shown where the peer sends them, and only there.
    assert_eq!(
        candidates(&rib, V4, "192.0.2.0/24"),
        vec![(e2.addr, None), (e1.addr, Some(11)), (e1.addr, Some(12))]
    );
    // A withdrawal from the plain peer is for path zero, and leaves the
    // other peer's paths; the other peer's path zero would be its own.
    outputs(|o| rib.update(e2.addr, &withdraw(&["192.0.2.0/24"]), now(), o));
    assert_eq!(
        candidates(&rib, V4, "192.0.2.0/24"),
        vec![(e1.addr, Some(11)), (e1.addr, Some(12))]
    );
    // Identifier zero from a peer with ADD-PATH is an identifier like any.
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce_paths(&[("192.0.2.0/24", 0)], &attrs(&[65_001], "10.0.0.1")),
            now(),
            o,
        );
    });
    assert_eq!(candidates(&rib, V4, "192.0.2.0/24")[0], (e1.addr, Some(0)));
    assert_eq!(rib.candidates(V4, p("192.0.2.0/24")).len(), 3);
    outputs(|o| rib.update(e1.addr, &withdraw_paths(&[("192.0.2.0/24", 0)]), now(), o));
    assert_eq!(rib.candidates(V4, p("192.0.2.0/24")).len(), 2);
}

#[test]
fn one_update_may_carry_several_paths_of_a_prefix() {
    // RFC 7911 §3: paths with equal attributes can share an UPDATE, one
    // tuple each; the destination changes once for all of them.
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = add_path_peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_002, 2);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    outputs(|o| rib.peer_up(e2.clone(), now(), o));
    let a = attrs(&[65_001], "10.0.0.1");
    let out = outputs(|o| {
        rib.update(
            e1.addr,
            &announce_paths(
                &[
                    ("192.0.2.0/24", 1),
                    ("192.0.2.0/24", 2),
                    ("198.51.100.0/24", 1),
                ],
                &a,
            ),
            now(),
            o,
        );
    });
    assert_eq!(rib.candidates(V4, p("192.0.2.0/24")).len(), 2);
    // The FIB hears of each destination once, and e2 (which takes the one
    // best path) of each once.
    assert_eq!(fib(&out).len(), 2);
    let sent = sends(&out, e2.addr);
    assert_eq!(sent.len(), 1);
    let updates = decode_sent(sent[0], &e2);
    let announced: usize = updates.iter().map(|u| u.nlri.len()).sum();
    assert_eq!(announced, 2);
    // Withdrawing a path and announcing another of the same prefix in one
    // UPDATE leaves the destination as the last word has it, with one
    // change in the Loc-RIB.
    let mut d = withdraw_paths(&[("192.0.2.0/24", 1)]);
    let b = attrs(&[65_001, 9, 9], "10.0.0.1");
    let announced = announce_paths(&[("192.0.2.0/24", 3)], &b);
    d.message.nlri = announced.message.nlri;
    d.message.attributes = announced.message.attributes;
    d.message.path_ids = Some(Box::new(PathIds {
        withdrawn: vec![PathId(1)],
        nlri: vec![PathId(3)],
        ..PathIds::default()
    }));
    outputs(|o| rib.update(e1.addr, &d, now(), o));
    assert_eq!(
        candidates(&rib, V4, "192.0.2.0/24"),
        vec![(e1.addr, Some(2)), (e1.addr, Some(3))]
    );
}

#[test]
fn a_route_treated_as_withdrawn_is_withdrawn_by_its_path_identifier() {
    // RFC 7606 §2 with RFC 7911 §3.
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = add_path_peer("10.0.0.1", 65_001, 1);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    let a = attrs(&[65_001], "10.0.0.1");
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce_paths(&[("192.0.2.0/24", 1), ("192.0.2.0/24", 2)], &a),
            now(),
            o,
        );
    });
    let mut d = announce_paths(&[("192.0.2.0/24", 2)], &a);
    d.treated_as_withdraw = Some(bgpfc_wire::error::DecodeError::update(
        bgpfc_wire::error::UpdateSubcode::InvalidOrigin,
        vec![],
    ));
    outputs(|o| rib.update(e1.addr, &d, now(), o));
    assert_eq!(
        candidates(&rib, V4, "192.0.2.0/24"),
        vec![(e1.addr, Some(1))]
    );
}

#[test]
fn losing_the_peer_removes_every_path_and_gives_back_the_attributes() {
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = add_path_peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_002, 2);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    outputs(|o| rib.peer_up(e2.clone(), now(), o));
    outputs(|o| {
        rib.update(
            e2.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_002, 4, 5, 6], "10.0.0.2")),
            now(),
            o,
        );
    });
    for (path, id) in [
        (&[65_001, 5][..], 1),
        (&[65_001, 6][..], 2),
        (&[65_001, 7][..], 3),
    ] {
        outputs(|o| {
            rib.update(
                e1.addr,
                &announce_paths(
                    &[("192.0.2.0/24", id), ("198.51.100.0/24", id)],
                    &attrs(path, "10.0.0.1"),
                ),
                now(),
                o,
            );
        });
    }
    assert_eq!(rib.peer_stats(e1.addr).unwrap().received[0], (V4, 6));
    assert!(rib.attribute_sets() >= 4);
    let out = outputs(|o| rib.peer_down(e1.addr, now(), o));
    // The destination e1 alone had goes, the other falls back to e2's.
    let f = fib(&out);
    assert_eq!(f.len(), 2);
    assert!(
        f.iter()
            .any(|c| c.prefix == p("198.51.100.0/24") && c.next_hop.is_none())
    );
    assert!(
        f.iter()
            .any(|c| c.prefix == p("192.0.2.0/24") && c.next_hop == Some(ip("10.0.0.2")))
    );
    assert_eq!(rib.candidates(V4, p("192.0.2.0/24")).len(), 1);
    assert!(rib.candidates(V4, p("198.51.100.0/24")).is_empty());
    // Only e2's attribute set is left.
    assert_eq!(rib.attribute_sets(), 1);
}

#[test]
fn the_prefix_limit_counts_each_path() {
    // RFC 4271 §6.7: the routes the Adj-RIB-In holds, and with ADD-PATH
    // that is a route for each path.
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = limited(add_path_peer("10.0.0.1", 65_001, 1), V4, 3);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    let a = attrs(&[65_001], "10.0.0.1");
    let out = outputs(|o| {
        rib.update(
            e1.addr,
            &announce_paths(
                &[
                    ("192.0.2.0/24", 1),
                    ("192.0.2.0/24", 2),
                    ("192.0.2.0/24", 3),
                ],
                &a,
            ),
            now(),
            o,
        );
    });
    assert_eq!(limit_hits(&out), vec![]);
    // A replacement is no new route.
    let out = outputs(|o| {
        rib.update(
            e1.addr,
            &announce_paths(&[("192.0.2.0/24", 3)], &attrs(&[65_001, 2], "10.0.0.1")),
            now(),
            o,
        );
    });
    assert_eq!(limit_hits(&out), vec![]);
    let out = outputs(|o| {
        rib.update(
            e1.addr,
            &announce_paths(&[("192.0.2.0/24", 4)], &a),
            now(),
            o,
        );
    });
    assert_eq!(limit_hits(&out), vec![(e1.addr, V4, 3)]);
    assert!(rib.candidates(V4, p("192.0.2.0/24")).is_empty());
    assert_eq!(rib.attribute_sets(), 0);
}

#[test]
fn import_policy_judges_each_path() {
    /// Rejects the paths through AS 65009.
    struct NoNine;
    impl Policies for NoNine {
        fn import(
            &self,
            _: &PeerInfo,
            _: AddressFamily,
            _: Prefix,
            a: &PathAttrs,
            _: RovState,
        ) -> Verdict {
            if a.as_path.contains(Asn(65_009)) {
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
    let _ = AcceptAll;
    let mut rib = Rib::with_policies(LOCAL_AS, Box::new(NoNine));
    let e1 = add_path_peer("10.0.0.1", 65_001, 1);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce_paths(&[("192.0.2.0/24", 1)], &attrs(&[65_001], "10.0.0.1")),
            now(),
            o,
        );
    });
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce_paths(
                &[("192.0.2.0/24", 2)],
                &attrs(&[65_001, 65_009], "10.0.0.1"),
            ),
            now(),
            o,
        );
    });
    assert_eq!(
        candidates(&rib, V4, "192.0.2.0/24"),
        vec![(e1.addr, Some(1))]
    );
    // A path replaced by one policy rejects goes, the other stays.
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce_paths(
                &[("192.0.2.0/24", 1)],
                &attrs(&[65_001, 65_009], "10.0.0.1"),
            ),
            now(),
            o,
        );
    });
    assert_eq!(candidates(&rib, V4, "192.0.2.0/24"), vec![]);
}

#[test]
fn ipv6_paths_in_mp_reach_are_kept_apart_too() {
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = add_path_peer("2001:db8::1", 65_001, 1);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
    let a = attrs(&[65_001], "2001:db8::1");
    let b = attrs(&[65_001, 6], "2001:db8::1");
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce_paths(&[("2001:db8:1::/48", 5)], &a),
            now(),
            o,
        );
    });
    outputs(|o| {
        rib.update(
            e1.addr,
            &announce_paths(&[("2001:db8:1::/48", 6)], &b),
            now(),
            o,
        );
    });
    assert_eq!(
        candidates(&rib, V6, "2001:db8:1::/48"),
        vec![(e1.addr, Some(5)), (e1.addr, Some(6))]
    );
    outputs(|o| {
        rib.update(
            e1.addr,
            &withdraw_paths(&[("2001:db8:1::/48", 5)]),
            now(),
            o,
        );
    });
    assert_eq!(
        candidates(&rib, V6, "2001:db8:1::/48"),
        vec![(e1.addr, Some(6))]
    );
}

#[test]
fn a_family_without_add_path_ignores_path_identifiers_in_the_rib() {
    // The decoder gives no identifiers for such a family; the RIB treats
    // what it is given as the plain encoding says, one route per peer.
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    outputs(|o| rib.peer_up(e1.clone(), now(), o));
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
            e1.addr,
            &announce(&["192.0.2.0/24"], &attrs(&[65_001, 2], "10.0.0.1")),
            now(),
            o,
        );
    });
    assert_eq!(candidates(&rib, V4, "192.0.2.0/24"), vec![(e1.addr, None)]);
}

// --- Sending several paths (RFC 7911 §5) ---------------------------------

use crate::PathLimit;

/// A peer that is sent paths with identifiers, `limit` of them, for both
/// families.
fn path_sender(addr: &str, remote_as: u32, router_id: u32, limit: PathLimit) -> PeerInfo {
    PeerInfo {
        add_path_send: vec![(V4, limit), (V6, limit)],
        ..peer(addr, remote_as, router_id)
    }
}

/// What one UPDATE did to a peer's paths.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Wire {
    Announce(Prefix, u32, Vec<u32>),
    Withdraw(Prefix, u32),
}

fn as_numbers(a: &PathAttrs) -> Vec<u32> {
    a.as_path
        .segments()
        .flat_map(bgpfc_wire::Segment::asns)
        .map(|a| a.0)
        .collect()
}

/// The paths the RIB sent `to` in `out`, in the order of the messages,
/// decoded with the extended NLRI encoding; the AS path is without our own
/// AS, which the session rewrite prepends.
fn wire(out: &[Output], to: &PeerInfo) -> Vec<Wire> {
    let ctx = DecodeContext {
        four_octet_as: true,
        peer: to.kind,
        allow_as_set: false,
        extended_next_hop: false,
        add_path: bgpfc_wire::update::AddPathFamilies::of(
            &to.add_path_send.iter().map(|(f, _)| *f).collect::<Vec<_>>(),
        ),
    };
    let mut v = Vec::new();
    for messages in sends(out, to.addr) {
        for m in messages {
            assert!(m.len() <= to.max_message_len());
            let d = UpdateMessage::decode(&m[HEADER_LEN..], &ctx).unwrap();
            for (_, prefix, id) in d.withdrawn_paths() {
                v.push(Wire::Withdraw(prefix, id.0));
            }
            for (_, next_hop, prefixes, ids) in announced(&d) {
                let a = PathAttrs::from_update(&d.message, next_hop);
                for (k, &prefix) in prefixes.iter().enumerate() {
                    let numbers = as_numbers(&a)[1..].to_vec();
                    v.push(Wire::Announce(prefix, ids[k].0, numbers));
                }
            }
        }
    }
    v
}

/// The sources: three plain external peers whose paths to a prefix are of
/// length 1, 2 and 3, so that the first is the best and the last the worst.
fn three_sources(rib: &mut Rib) -> [PeerInfo; 3] {
    three_sources_at(rib, now())
}

/// As [`three_sources`], up at `at`, which is where the RIB's pacing clock
/// starts.
fn three_sources_at(rib: &mut Rib, at: Instant) -> [PeerInfo; 3] {
    let e = [
        peer("10.0.0.1", 65_001, 1),
        peer("10.0.0.2", 65_002, 2),
        peer("10.0.0.3", 65_003, 3),
    ];
    for i in &e {
        outputs(|o| rib.peer_up(i.clone(), at, o));
    }
    e
}

fn source_path(rib: &mut Rib, from: &PeerInfo, prefix: &str, longer: u32) -> Vec<Output> {
    let mut path = vec![from.remote_as.0];
    path.extend((0..longer).map(|n| 100 + n));
    outputs(|o| {
        rib.update(
            from.addr,
            &announce(&[prefix], &attrs(&path, &from.addr.to_string())),
            now(),
            o,
        );
    })
}

#[test]
fn a_peer_sent_all_paths_gets_each_with_an_identifier_of_ours() {
    let mut rib = Rib::new(LOCAL_AS);
    let e = three_sources(&mut rib);
    for (i, from) in e.iter().enumerate() {
        source_path(&mut rib, from, "192.0.2.0/24", u32::try_from(i).unwrap());
    }
    // A peer coming up is sent every path of every prefix, no pacing.
    let to = path_sender("10.0.0.9", 65_009, 9, PathLimit::All);
    let out = outputs(|o| rib.peer_up(to.clone(), now(), o));
    let sent = wire(&out, &to);
    assert_eq!(sent.len(), 3, "{sent:?}");
    let dst = p("192.0.2.0/24");
    let mut ids: Vec<u32> = sent
        .iter()
        .map(|w| match w {
            Wire::Announce(prefix, id, _) => {
                assert_eq!(*prefix, dst);
                *id
            }
            Wire::Withdraw(..) => panic!("{sent:?}"),
        })
        .collect();
    // RFC 7911 §2: our own identifiers, the first free from 1 up.
    ids.sort_unstable();
    assert_eq!(ids, vec![1, 2, 3]);
    let mut paths: Vec<Vec<u32>> = sent
        .iter()
        .map(|w| match w {
            Wire::Announce(_, _, p) => p.clone(),
            Wire::Withdraw(..) => unreachable!(),
        })
        .collect();
    paths.sort();
    assert_eq!(
        paths,
        vec![vec![65_001], vec![65_002, 100], vec![65_003, 100, 101]]
    );
    // Counted as the paths they are.
    assert_eq!(
        rib.peer_stats(to.addr).unwrap().advertised,
        vec![(V4, 3), (V6, 0)]
    );
    assert_eq!(rib.sent_paths(to.addr, V4).len(), 3);
    assert_eq!(rib.adj_rib_out(to.addr, V4).count(), 3);
}

#[test]
fn the_n_best_by_the_decision_process_are_sent() {
    let mut rib = Rib::new(LOCAL_AS);
    let e = three_sources(&mut rib);
    let to = path_sender("10.0.0.9", 65_009, 9, PathLimit::Best(2));
    outputs(|o| rib.peer_up(to.clone(), now(), o));
    let dst = p("192.0.2.0/24");
    // The worst arrives first and is sent: it is all there is.
    let out = source_path(&mut rib, &e[2], "192.0.2.0/24", 2);
    assert_eq!(
        wire(&out, &to),
        vec![Wire::Announce(dst, 1, vec![65_003, 100, 101])]
    );
    // The best arrives: now the two best are sent, the new one under a new
    // identifier.
    let out = source_path(&mut rib, &e[0], "192.0.2.0/24", 0);
    assert_eq!(wire(&out, &to), vec![Wire::Announce(dst, 2, vec![65_001])]);
    // The middle one displaces the worst: the worst goes, under its
    // identifier, and the new one comes, under the freed one's successor.
    let out = source_path(&mut rib, &e[1], "192.0.2.0/24", 1);
    assert_eq!(
        wire(&out, &to),
        vec![
            Wire::Withdraw(dst, 1),
            Wire::Announce(dst, 3, vec![65_002, 100])
        ]
    );
    // The best goes: the worst, withdrawn before, is the third and is sent
    // again, with an identifier no path has.
    let out = outputs(|o| rib.update(e[0].addr, &withdraw(&["192.0.2.0/24"]), now(), o));
    assert_eq!(
        wire(&out, &to),
        vec![
            Wire::Withdraw(dst, 2),
            Wire::Announce(dst, 1, vec![65_003, 100, 101])
        ]
    );
    // The paths kept their identifiers all along: the middle one is 3.
    let sent = rib.sent_paths(to.addr, V4);
    assert_eq!(
        sent.iter().map(|(_, id, _)| id.0).collect::<Vec<_>>(),
        vec![1, 3]
    );
}

#[test]
fn a_path_keeps_its_identifier_through_changes_and_its_withdrawal_names_it() {
    let mut rib = Rib::new(LOCAL_AS);
    let e = three_sources(&mut rib);
    let to = path_sender("10.0.0.9", 65_009, 9, PathLimit::All);
    outputs(|o| rib.peer_up(to.clone(), now(), o));
    let dst = p("192.0.2.0/24");
    source_path(&mut rib, &e[0], "192.0.2.0/24", 0);
    source_path(&mut rib, &e[1], "192.0.2.0/24", 1);
    // e1's path changes attributes: the same identifier, a newer
    // advertisement replacing the older (RFC 7911 §5), and nothing about
    // the other path.
    let out = source_path(&mut rib, &e[0], "192.0.2.0/24", 3);
    assert_eq!(
        wire(&out, &to),
        vec![Wire::Announce(dst, 1, vec![65_001, 100, 101, 102])]
    );
    // A change to a path that is not the best is sent too: this is the
    // point of ADD-PATH, and a peer without it would hear nothing.
    let out = source_path(&mut rib, &e[1], "192.0.2.0/24", 2);
    assert_eq!(
        wire(&out, &to),
        vec![Wire::Announce(dst, 2, vec![65_002, 100, 101])]
    );
    // A withdrawal names the identifier.
    let out = outputs(|o| rib.update(e[1].addr, &withdraw(&["192.0.2.0/24"]), now(), o));
    assert_eq!(wire(&out, &to), vec![Wire::Withdraw(dst, 2)]);
    // And the last one takes the prefix away.
    let out = outputs(|o| rib.update(e[0].addr, &withdraw(&["192.0.2.0/24"]), now(), o));
    assert_eq!(wire(&out, &to), vec![Wire::Withdraw(dst, 1)]);
    assert_eq!(rib.sent_paths(to.addr, V4), vec![]);
    assert_eq!(
        rib.peer_stats(to.addr).unwrap().advertised,
        vec![(V4, 0), (V6, 0)]
    );
    // An identifier freed is the first free again.
    let out = source_path(&mut rib, &e[2], "192.0.2.0/24", 0);
    assert_eq!(wire(&out, &to), vec![Wire::Announce(dst, 1, vec![65_003])]);
}

#[test]
fn a_peers_own_paths_are_not_sent_back_to_it() {
    // RFC 7911 §5: "unless it is a path received from that neighbor".
    let mut rib = Rib::new(LOCAL_AS);
    let e = three_sources(&mut rib);
    let to = path_sender("10.0.0.9", 65_009, 9, PathLimit::Best(1));
    let sender_peer = PeerInfo {
        add_path_receive: vec![V4],
        ..to.clone()
    };
    outputs(|o| rib.peer_up(sender_peer.clone(), now(), o));
    let dst = p("192.0.2.0/24");
    // The sender's own path is the best; the sender is sent the best of
    // the others, not its own.
    outputs(|o| {
        rib.update(
            sender_peer.addr,
            &announce_paths(&[("192.0.2.0/24", 4)], &attrs(&[65_009], "10.0.0.9")),
            now(),
            o,
        );
    });
    let out = source_path(&mut rib, &e[1], "192.0.2.0/24", 1);
    assert_eq!(
        wire(&out, &sender_peer),
        vec![Wire::Announce(dst, 1, vec![65_002, 100])]
    );
    let out = source_path(&mut rib, &e[0], "192.0.2.0/24", 0);
    assert_eq!(
        wire(&out, &sender_peer),
        vec![Wire::Withdraw(dst, 1), Wire::Announce(dst, 2, vec![65_001])]
    );
}

#[test]
fn export_policy_filters_before_n_counts() {
    // The `n` best of the paths policy accepts, so a rejected best does
    // not use up a place.
    struct NoOne;
    impl Policies for NoOne {
        fn import(
            &self,
            _: &PeerInfo,
            _: AddressFamily,
            _: Prefix,
            _: &PathAttrs,
            _: RovState,
        ) -> Verdict {
            Verdict::Accept
        }
        fn export(
            &self,
            _: &PeerInfo,
            _: AddressFamily,
            _: Prefix,
            a: &PathAttrs,
            _: RovState,
        ) -> Verdict {
            if a.as_path.contains(Asn(65_001)) {
                Verdict::Reject
            } else {
                Verdict::Accept
            }
        }
    }
    let mut rib = Rib::with_policies(LOCAL_AS, Box::new(NoOne));
    let e = three_sources(&mut rib);
    let to = path_sender("10.0.0.9", 65_009, 9, PathLimit::Best(1));
    outputs(|o| rib.peer_up(to.clone(), now(), o));
    let dst = p("192.0.2.0/24");
    source_path(&mut rib, &e[0], "192.0.2.0/24", 0);
    let out = source_path(&mut rib, &e[2], "192.0.2.0/24", 1);
    assert_eq!(
        wire(&out, &to),
        vec![Wire::Announce(dst, 1, vec![65_003, 100])]
    );
    let out = source_path(&mut rib, &e[1], "192.0.2.0/24", 0);
    assert_eq!(
        wire(&out, &to),
        vec![Wire::Withdraw(dst, 1), Wire::Announce(dst, 2, vec![65_002])]
    );
}

#[test]
fn a_refresh_sends_everything_again_under_the_same_identifiers() {
    let mut rib = Rib::new(LOCAL_AS);
    let e = three_sources(&mut rib);
    let to = path_sender("10.0.0.9", 65_009, 9, PathLimit::All);
    outputs(|o| rib.peer_up(to.clone(), now(), o));
    for (i, from) in e.iter().enumerate() {
        source_path(&mut rib, from, "192.0.2.0/24", u32::try_from(i).unwrap());
        source_path(&mut rib, from, "198.51.100.0/24", 0);
    }
    let before = rib.sent_paths(to.addr, V4);
    assert_eq!(before.len(), 6);
    let out = outputs(|o| rib.refresh(to.addr, V4, now(), o));
    let sent = wire(&out, &to);
    assert_eq!(sent.len(), 6);
    assert!(sent.iter().all(|w| matches!(w, Wire::Announce(..))));
    // RFC 2918 §4 re-advertises; the identifiers are the ones the paths
    // have.
    assert_eq!(rib.sent_paths(to.addr, V4), before);
    // Another family's refresh is not this one's business.
    let out = outputs(|o| rib.refresh(to.addr, V6, now(), o));
    assert_eq!(wire(&out, &to), vec![]);
}

#[test]
fn a_policy_change_sends_only_the_difference_between_what_was_sent_and_what_is() {
    struct DropOne(bool);
    impl Policies for DropOne {
        fn import(
            &self,
            _: &PeerInfo,
            _: AddressFamily,
            _: Prefix,
            _: &PathAttrs,
            _: RovState,
        ) -> Verdict {
            Verdict::Accept
        }
        fn export(
            &self,
            _: &PeerInfo,
            _: AddressFamily,
            _: Prefix,
            a: &PathAttrs,
            _: RovState,
        ) -> Verdict {
            if self.0 && a.as_path.contains(Asn(65_002)) {
                Verdict::Reject
            } else {
                Verdict::Accept
            }
        }
    }
    let mut rib = Rib::with_policies(LOCAL_AS, Box::new(DropOne(false)));
    let e = three_sources(&mut rib);
    let to = path_sender("10.0.0.9", 65_009, 9, PathLimit::All);
    outputs(|o| rib.peer_up(to.clone(), now(), o));
    let dst = p("192.0.2.0/24");
    for (i, from) in e.iter().enumerate() {
        source_path(&mut rib, from, "192.0.2.0/24", u32::try_from(i).unwrap());
    }
    let out = outputs(|o| rib.set_policies(Box::new(DropOne(true)), &[to.addr], now(), o));
    assert_eq!(wire(&out, &to), vec![Wire::Withdraw(dst, 2)]);
    let out = outputs(|o| rib.set_policies(Box::new(DropOne(false)), &[to.addr], now(), o));
    assert_eq!(
        wire(&out, &to),
        vec![Wire::Announce(dst, 2, vec![65_002, 100])]
    );
    // Unchanged policy for the peer: nothing.
    let out = outputs(|o| rib.set_policies(Box::new(DropOne(false)), &[to.addr], now(), o));
    assert_eq!(wire(&out, &to), vec![]);
}

#[test]
fn a_reload_of_how_many_paths_applies_to_the_running_session() {
    let mut rib = Rib::new(LOCAL_AS);
    let e = three_sources(&mut rib);
    let to = path_sender("10.0.0.9", 65_009, 9, PathLimit::Best(1));
    outputs(|o| rib.peer_up(to.clone(), now(), o));
    let dst = p("192.0.2.0/24");
    for (i, from) in e.iter().enumerate() {
        source_path(&mut rib, from, "192.0.2.0/24", u32::try_from(i).unwrap());
    }
    assert_eq!(rib.sent_paths(to.addr, V4).len(), 1);
    // More: the rest are announced.
    let out = outputs(|o| rib.set_add_path_limits(to.addr, &[(V4, PathLimit::Best(2))], now(), o));
    assert_eq!(wire(&out, &to).len(), 1);
    let out = outputs(|o| rib.set_add_path_limits(to.addr, &[(V4, PathLimit::All)], now(), o));
    assert_eq!(wire(&out, &to).len(), 1);
    assert_eq!(rib.sent_paths(to.addr, V4).len(), 3);
    assert_eq!(
        rib.peer(to.addr).unwrap().path_limit(V4),
        Some(PathLimit::All)
    );
    // Fewer: the worst go, withdrawn by identifier; the best stays.
    let out = outputs(|o| rib.set_add_path_limits(to.addr, &[(V4, PathLimit::Best(1))], now(), o));
    let sent = wire(&out, &to);
    assert_eq!(sent.len(), 2);
    assert!(sent.iter().all(|w| matches!(w, Wire::Withdraw(..))));
    let left = rib.sent_paths(to.addr, V4);
    assert_eq!(left.len(), 1);
    assert_eq!(as_numbers(&left[0].2), vec![65_001]);
    assert_eq!(left[0].0, dst);
    // The same number, a family not sent paths of, a peer not up: nothing.
    for (limits, addr) in [
        (vec![(V4, PathLimit::Best(1))], to.addr),
        (vec![(AddressFamily::IPV6_UNICAST, PathLimit::All)], to.addr),
        (vec![(V4, PathLimit::All)], ip("10.9.9.9")),
    ] {
        let out = outputs(|o| rib.set_add_path_limits(addr, &limits, now(), o));
        assert_eq!(out, vec![], "{limits:?} {addr}");
    }
}

#[test]
fn a_peer_without_add_path_is_still_sent_the_one_best_route() {
    let mut rib = Rib::new(LOCAL_AS);
    let e = three_sources(&mut rib);
    let to = path_sender("10.0.0.9", 65_009, 9, PathLimit::All);
    let plain = peer("10.0.0.8", 65_008, 8);
    outputs(|o| rib.peer_up(to.clone(), now(), o));
    outputs(|o| rib.peer_up(plain.clone(), now(), o));
    source_path(&mut rib, &e[1], "192.0.2.0/24", 1);
    let out = source_path(&mut rib, &e[0], "192.0.2.0/24", 0);
    // The plain peer is told the new best, the other peer the new path.
    let m = decode_sent(sends(&out, plain.addr)[0], &plain);
    assert_eq!(m[0].nlri, vec![p("192.0.2.0/24")]);
    assert_eq!(m[0].path_ids, None);
    assert_eq!(
        wire(&out, &to),
        vec![Wire::Announce(p("192.0.2.0/24"), 2, vec![65_001])]
    );
    // A worse path changes nothing for the plain peer.
    let out = source_path(&mut rib, &e[2], "192.0.2.0/24", 1);
    assert_eq!(sends(&out, plain.addr).len(), 0);
    assert_eq!(wire(&out, &to).len(), 1);
    assert_eq!(rib.adj_rib_out(plain.addr, V4).count(), 1);
}

#[test]
fn ipv6_paths_are_sent_in_mp_reach_with_identifiers() {
    let mut rib = Rib::new(LOCAL_AS);
    let e = [
        peer("2001:db8::1", 65_001, 1),
        peer("2001:db8::2", 65_002, 2),
    ];
    let to = path_sender("2001:db8::9", 65_009, 9, PathLimit::All);
    for i in e.iter().chain([&to]) {
        outputs(|o| rib.peer_up(i.clone(), now(), o));
    }
    for (i, from) in e.iter().enumerate() {
        let path = [from.remote_as.0, 100 + u32::try_from(i).unwrap()];
        outputs(|o| {
            rib.update(
                from.addr,
                &announce(&["2001:db8:1::/48"], &attrs(&path, &from.addr.to_string())),
                now(),
                o,
            );
        });
    }
    let sent = rib.sent_paths(to.addr, V6);
    assert_eq!(sent.len(), 2);
    assert_eq!(
        sent.iter().map(|(_, id, _)| id.0).collect::<Vec<_>>(),
        vec![1, 2]
    );
    let out = outputs(|o| rib.update(e[0].addr, &withdraw(&["2001:db8:1::/48"]), now(), o));
    assert_eq!(
        wire(&out, &to),
        vec![Wire::Withdraw(p("2001:db8:1::/48"), 1)]
    );
}

#[test]
fn many_paths_are_packed_to_the_message_size_with_their_identifiers() {
    let mut rib = Rib::new(LOCAL_AS);
    let e = three_sources(&mut rib);
    let to = path_sender("10.0.0.9", 65_009, 9, PathLimit::All);
    // A thousand prefixes of /24, two paths each, to a peer coming up.
    for (i, from) in e.iter().take(2).enumerate() {
        let prefixes: Vec<String> = (0..1000u32)
            .map(|n| format!("10.{}.{}.0/24", n / 256, n % 256))
            .collect();
        let refs: Vec<&str> = prefixes.iter().map(String::as_str).collect();
        let path = [from.remote_as.0, 100 + u32::try_from(i).unwrap()];
        outputs(|o| {
            rib.update(
                from.addr,
                &announce(&refs, &attrs(&path, &from.addr.to_string())),
                now(),
                o,
            );
        });
    }
    let out = outputs(|o| rib.peer_up(to.clone(), now(), o));
    let sent = wire(&out, &to);
    assert_eq!(sent.len(), 2000);
    // Four octets more per prefix, over several messages, each within the
    // limit (checked in `wire`).
    let messages: usize = sends(&out, to.addr).iter().map(|m| m.len()).sum();
    assert!(messages >= 2000 * 8 / 4096, "{messages}");
    let mut ids: Vec<u32> = sent
        .iter()
        .filter_map(|w| match w {
            Wire::Announce(prefix, id, _) if *prefix == p("10.0.0.0/24") => Some(*id),
            _ => None,
        })
        .collect();
    ids.sort_unstable();
    assert_eq!(ids, vec![1, 2]);
}

#[test]
fn losing_a_peer_sent_paths_gives_back_what_it_held() {
    let mut rib = Rib::new(LOCAL_AS);
    let e = three_sources(&mut rib);
    let to = path_sender("10.0.0.9", 65_009, 9, PathLimit::All);
    outputs(|o| rib.peer_up(to.clone(), now(), o));
    for (i, from) in e.iter().enumerate() {
        source_path(&mut rib, from, "192.0.2.0/24", u32::try_from(i).unwrap());
    }
    assert_eq!(rib.attribute_sets(), 3);
    // The sources go: the destination is empty and so are the paths sent.
    for from in &e {
        outputs(|o| rib.peer_down(from.addr, now(), o));
    }
    assert_eq!(rib.sent_paths(to.addr, V4), vec![]);
    // The sets the peer was sent are given back with it.
    outputs(|o| rib.peer_down(to.addr, now(), o));
    assert_eq!(rib.attribute_sets(), 0);
    // And a peer that goes with paths sent gives them back too.
    let to = path_sender("10.0.0.9", 65_009, 9, PathLimit::All);
    outputs(|o| rib.peer_up(to.clone(), now(), o));
    source_path(&mut rib, &e[0], "192.0.2.0/24", 0);
    outputs(|o| rib.peer_up(e[0].clone(), now(), o));
    source_path(&mut rib, &e[0], "192.0.2.0/24", 0);
    outputs(|o| rib.peer_down(to.addr, now(), o));
    outputs(|o| rib.peer_down(e[0].addr, now(), o));
    assert_eq!(rib.attribute_sets(), 0);
}

#[test]
fn pacing_holds_the_announcements_of_a_destination_and_the_paths_it_displaces() {
    // RFC 4271 §9.2.1.1 on the paths of one destination together.
    let t0 = Instant::now();
    let mut rib = Rib::new(LOCAL_AS);
    let e = three_sources_at(&mut rib, t0);
    let to = PeerInfo {
        advertisement_interval: Duration::from_secs(30),
        ..path_sender("10.0.0.9", 65_009, 9, PathLimit::Best(1))
    };
    outputs(|o| rib.peer_up(to.clone(), t0, o));
    let dst = p("192.0.2.0/24");
    let update = |rib: &mut Rib, from: &PeerInfo, longer: u32, at: u64| {
        let mut path = vec![from.remote_as.0];
        path.extend((0..longer).map(|n| 100 + n));
        outputs(|o| {
            rib.update(
                from.addr,
                &announce(&["192.0.2.0/24"], &attrs(&path, &from.addr.to_string())),
                secs(t0, at),
                o,
            );
        })
    };
    // The first advertisement of a destination is not held.
    let out = update(&mut rib, &e[1], 1, 0);
    assert_eq!(
        wire(&out, &to),
        vec![Wire::Announce(dst, 1, vec![65_002, 100])]
    );
    // A better path inside the interval displaces it: the peer keeps what
    // it has, a valid route, until the interval ends, and then has the
    // latest.
    let out = update(&mut rib, &e[2], 5, 3);
    assert_eq!(wire(&out, &to), vec![]);
    let out = update(&mut rib, &e[0], 0, 5);
    assert_eq!(wire(&out, &to), vec![]);
    assert_eq!(release_at(&rib), Some(secs(t0, 30)));
    assert_eq!(rib.sent_paths(to.addr, V4).len(), 1);
    let out = outputs(|o| rib.flush(secs(t0, 30), o));
    assert_eq!(
        wire(&out, &to),
        vec![Wire::Withdraw(dst, 1), Wire::Announce(dst, 2, vec![65_001])]
    );
    assert_eq!(release_at(&rib), None);
    // A path that is gone altogether is withdrawn at once, held
    // destination or not.
    let out = update(&mut rib, &e[1], 0, 31);
    assert_eq!(wire(&out, &to), vec![]);
    let out = outputs(|o| rib.update(e[0].addr, &withdraw(&["192.0.2.0/24"]), secs(t0, 32), o));
    assert_eq!(wire(&out, &to), vec![Wire::Withdraw(dst, 2)]);
    // The held destination's announcement still goes at the interval's end.
    let out = outputs(|o| rib.flush(secs(t0, 60), o));
    assert_eq!(wire(&out, &to), vec![Wire::Announce(dst, 1, vec![65_002])]);
}

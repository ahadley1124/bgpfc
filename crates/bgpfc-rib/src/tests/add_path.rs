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

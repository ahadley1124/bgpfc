//! The Only to Customer procedures end to end (RFC 9234 §5): routes
//! received and sent over sessions with BGP Roles, in the RIB.

use bgpfc_wire::role::Role;

use super::*;

const NEIGHBOR_AS: u32 = 65_001;

/// A session whose neighbor is in `remote_as`, with our `role` on it.
fn with_role(addr: &str, remote_as: u32, router_id: u32, role: Option<Role>) -> PeerInfo {
    let mut p = peer(addr, remote_as, router_id);
    p.role = role;
    p
}

/// An announcement of `prefix` as a neighbor in `remote_as` sends it, with
/// `otc` as the Only to Customer attribute.
fn route(prefix: &str, remote_as: u32, otc: Option<u32>) -> DecodedUpdate {
    let mut a = attrs(&[remote_as], "10.0.0.1");
    a.otc = otc.map(Asn);
    announce(&[prefix], &a)
}

/// The Only to Customer attribute of the UPDATEs sent to `to`, one entry
/// per announcement.
fn sent_otc(out: &[Output], to: &PeerInfo) -> Vec<Option<Asn>> {
    sends(out, to.addr)
        .into_iter()
        .flat_map(|m| decode_sent(m, to))
        .filter(|u| !u.nlri.is_empty())
        .map(|u| match u.attribute(35) {
            Some(PathAttribute::OnlyToCustomer(a)) => Some(*a),
            _ => None,
        })
        .collect()
}

fn withdrawn_to(out: &[Output], to: &PeerInfo) -> Vec<Prefix> {
    sends(out, to.addr)
        .into_iter()
        .flat_map(|m| decode_sent(m, to))
        .flat_map(|u| u.withdrawn)
        .collect()
}

fn leaks(out: &[Output]) -> Vec<(IpAddr, Asn, usize, Prefix)> {
    out.iter()
        .filter_map(|o| match o {
            Output::RouteLeak {
                peer,
                otc,
                routes,
                first,
                ..
            } => Some((*peer, *otc, *routes, *first)),
            _ => None,
        })
        .collect()
}

/// The Only to Customer attribute of the Loc-RIB's best route to `prefix`:
/// one entry, or none if there is no route.
fn best_otc(rib: &Rib, prefix: &str) -> Vec<Option<Asn>> {
    rib.loc_rib(V4)
        .filter(|(p0, _)| *p0 == p(prefix))
        .map(|(_, r)| r.attrs.otc)
        .collect()
}

#[test]
fn a_route_with_otc_from_a_customer_or_rs_client_is_a_leak() {
    // RFC 9234 §5 ingress 1: we are the Provider, or the RS.
    for role in [Role::Provider, Role::RouteServer] {
        let from = with_role("10.0.0.1", NEIGHBOR_AS, 1, Some(role));
        let other = peer("10.0.0.2", 65_002, 2);
        let mut rib = Rib::new(LOCAL_AS);
        outputs(|o| rib.peer_up(from.clone(), now(), o));
        outputs(|o| rib.peer_up(other.clone(), now(), o));
        // The OTC value does not matter: any is a leak from a customer.
        for otc in [NEIGHBOR_AS, 65_099, LOCAL_AS.0] {
            let out = outputs(|o| {
                rib.update(
                    from.addr,
                    &route("192.0.2.0/24", NEIGHBOR_AS, Some(otc)),
                    now(),
                    o,
                );
            });
            // Ineligible: not in the Loc-RIB, not for the FIB, not passed on.
            assert_eq!(best_otc(&rib, "192.0.2.0/24"), vec![], "{role}");
            assert_eq!(fib(&out), vec![], "{role}");
            assert_eq!(sends(&out, other.addr).len(), 0, "{role}");
            assert_eq!(
                leaks(&out),
                vec![(from.addr, Asn(otc), 1, p("192.0.2.0/24"))],
                "{role}"
            );
            assert_eq!(rib.peer_stats(from.addr).unwrap().received[0], (V4, 0));
        }
        // One without the attribute is a customer's route as usual.
        let out = outputs(|o| {
            rib.update(
                from.addr,
                &route("192.0.2.0/24", NEIGHBOR_AS, None),
                now(),
                o,
            );
        });
        assert_eq!(leaks(&out), vec![]);
        assert_eq!(fib(&out).len(), 1);
        assert_eq!(best_otc(&rib, "192.0.2.0/24"), vec![None]);
        // Nothing is added on the way in from a customer.
        assert_eq!(sent_otc(&out, &other), vec![None]);
    }
}

#[test]
fn a_leak_replaces_the_route_the_peer_sent_before() {
    // RFC 9234 §5: the new announcement of the prefix is the one that is
    // ineligible; the peer's old route is not kept alive under it (the
    // announcement replaces it, RFC 4271 §3.1).
    let from = with_role("10.0.0.1", NEIGHBOR_AS, 1, Some(Role::Provider));
    let other = peer("10.0.0.2", 65_002, 2);
    let mut rib = Rib::new(LOCAL_AS);
    outputs(|o| rib.peer_up(from.clone(), now(), o));
    outputs(|o| rib.peer_up(other.clone(), now(), o));
    outputs(|o| {
        rib.update(
            from.addr,
            &route("192.0.2.0/24", NEIGHBOR_AS, None),
            now(),
            o,
        );
    });
    let out = outputs(|o| {
        rib.update(
            from.addr,
            &route("192.0.2.0/24", NEIGHBOR_AS, Some(NEIGHBOR_AS)),
            now(),
            o,
        );
    });
    assert_eq!(best_otc(&rib, "192.0.2.0/24"), vec![]);
    assert_eq!(
        fib(&out),
        vec![FibChange {
            family: V4,
            prefix: p("192.0.2.0/24"),
            next_hop: None,
            previous: Some(ip("10.0.0.1")),
        }]
    );
    assert_eq!(withdrawn_to(&out, &other), vec![p("192.0.2.0/24")]);
    // The leak is reported before what it changed.
    assert!(matches!(out[0], Output::RouteLeak { .. }));
}

#[test]
fn a_peer_may_send_otc_with_its_own_as_only() {
    // RFC 9234 §5 ingress 2.
    let from = with_role("10.0.0.1", NEIGHBOR_AS, 1, Some(Role::Peer));
    let mut rib = Rib::new(LOCAL_AS);
    outputs(|o| rib.peer_up(from.clone(), now(), o));
    let out = outputs(|o| {
        rib.update(
            from.addr,
            &route("192.0.2.0/24", NEIGHBOR_AS, Some(NEIGHBOR_AS)),
            now(),
            o,
        );
    });
    assert_eq!(leaks(&out), vec![]);
    assert_eq!(best_otc(&rib, "192.0.2.0/24"), vec![Some(Asn(NEIGHBOR_AS))]);
    // Another AS, ours included: a leak.
    for otc in [65_099, LOCAL_AS.0] {
        let out = outputs(|o| {
            rib.update(
                from.addr,
                &route("198.51.100.0/24", NEIGHBOR_AS, Some(otc)),
                now(),
                o,
            );
        });
        assert_eq!(
            leaks(&out),
            vec![(from.addr, Asn(otc), 1, p("198.51.100.0/24"))]
        );
        assert_eq!(best_otc(&rib, "198.51.100.0/24"), vec![]);
    }
}

#[test]
fn routes_from_a_provider_peer_or_rs_get_otc_with_the_neighbors_as() {
    // RFC 9234 §5 ingress 3: we are the Customer, the Peer, or the
    // RS-Client; the attribute is added when missing and kept when there.
    for role in [Role::Customer, Role::Peer, Role::RouteServerClient] {
        let from = with_role("10.0.0.1", NEIGHBOR_AS, 1, Some(role));
        let mut rib = Rib::new(LOCAL_AS);
        outputs(|o| rib.peer_up(from.clone(), now(), o));
        let out = outputs(|o| {
            rib.update(
                from.addr,
                &route("192.0.2.0/24", NEIGHBOR_AS, None),
                now(),
                o,
            );
        });
        assert_eq!(leaks(&out), vec![]);
        assert_eq!(
            best_otc(&rib, "192.0.2.0/24"),
            vec![Some(Asn(NEIGHBOR_AS))],
            "{role}"
        );
        // One that has it keeps its value (a provider's customers may have
        // set another AS; a peer's is its own).
        let out = outputs(|o| {
            rib.update(
                from.addr,
                &route("198.51.100.0/24", NEIGHBOR_AS, Some(NEIGHBOR_AS)),
                now(),
                o,
            );
        });
        assert_eq!(leaks(&out), vec![]);
        assert_eq!(
            best_otc(&rib, "198.51.100.0/24"),
            vec![Some(Asn(NEIGHBOR_AS))]
        );
        if role != Role::Peer {
            outputs(|o| {
                rib.update(
                    from.addr,
                    &route("203.0.113.0/24", NEIGHBOR_AS, Some(65_099)),
                    now(),
                    o,
                );
            });
            assert_eq!(best_otc(&rib, "203.0.113.0/24"), vec![Some(Asn(65_099))]);
        }
    }
}

#[test]
fn a_session_without_a_role_leaves_the_attribute_alone() {
    // RFC 9234 §4: the procedures are for sessions with a Role.
    let from = peer("10.0.0.1", NEIGHBOR_AS, 1);
    let mut rib = Rib::new(LOCAL_AS);
    outputs(|o| rib.peer_up(from.clone(), now(), o));
    let out = outputs(|o| {
        rib.update(
            from.addr,
            &route("192.0.2.0/24", NEIGHBOR_AS, Some(65_099)),
            now(),
            o,
        );
        rib.update(
            from.addr,
            &route("198.51.100.0/24", NEIGHBOR_AS, None),
            now(),
            o,
        );
    });
    assert_eq!(leaks(&out), vec![]);
    assert_eq!(best_otc(&rib, "192.0.2.0/24"), vec![Some(Asn(65_099))]);
    assert_eq!(best_otc(&rib, "198.51.100.0/24"), vec![None]);
}

/// Our Role on each session of a router with a provider (our Customer
/// role), a peer, a customer and an RS-client, and the sessions.
fn gao_rexford() -> (Rib, [PeerInfo; 4]) {
    let sessions = [
        with_role("10.0.0.1", 65_001, 1, Some(Role::Customer)),
        with_role("10.0.0.2", 65_002, 2, Some(Role::Peer)),
        with_role("10.0.0.3", 65_003, 3, Some(Role::Provider)),
        with_role("10.0.0.4", 65_004, 4, Some(Role::RouteServer)),
    ];
    let mut rib = Rib::new(LOCAL_AS);
    for s in &sessions {
        outputs(|o| rib.peer_up(s.clone(), now(), o));
    }
    (rib, sessions)
}

#[test]
fn routes_learned_from_a_provider_go_to_customers_only() {
    // RFC 9234 §3.1 and §5: Provider → Customer is the one way a route
    // from a provider may go.
    let (mut rib, [provider, lateral, customer, rs_client]) = gao_rexford();
    let out = outputs(|o| {
        rib.update(
            provider.addr,
            &route("192.0.2.0/24", 65_001, None),
            now(),
            o,
        );
    });
    // To the customer and to the RS-client (we are their RS: ours Provider
    // and RS): the attribute is there already, with the provider's AS.
    assert_eq!(sent_otc(&out, &customer), [Some(Asn(65_001))]);
    assert_eq!(sent_otc(&out, &rs_client), [Some(Asn(65_001))]);
    // Not to the peer: the attribute is there (RFC 9234 §5 egress 2).
    assert_eq!(sent_otc(&out, &lateral), []);
    assert_eq!(sends(&out, lateral.addr).len(), 0);
}

#[test]
fn routes_learned_from_a_customer_go_everywhere_and_the_marks_follow_the_role() {
    let (mut rib, [provider, lateral, customer, rs_client]) = gao_rexford();
    let out = outputs(|o| {
        rib.update(
            customer.addr,
            &route("192.0.2.0/24", 65_003, None),
            now(),
            o,
        );
    });
    // RFC 9234 §5 egress 1: ours Provider, Peer, RS add our AS...
    assert_eq!(sent_otc(&out, &lateral), [Some(LOCAL_AS)]);
    assert_eq!(sent_otc(&out, &rs_client), [Some(LOCAL_AS)]);
    // ...and ours Customer adds nothing for the provider.
    assert_eq!(sent_otc(&out, &provider), [None]);
}

#[test]
fn routes_learned_from_a_peer_go_to_customers_with_the_peers_as() {
    let (mut rib, [provider, lateral, customer, rs_client]) = gao_rexford();
    let out = outputs(|o| {
        rib.update(lateral.addr, &route("192.0.2.0/24", 65_002, None), now(), o);
    });
    assert_eq!(sent_otc(&out, &customer), [Some(Asn(65_002))]);
    assert_eq!(sent_otc(&out, &rs_client), [Some(Asn(65_002))]);
    assert_eq!(sends(&out, provider.addr).len(), 0);
}

#[test]
fn a_route_gaining_otc_is_withdrawn_from_those_it_may_no_longer_reach() {
    // RFC 9234 §5 egress 2 applies to every change of the best route: a
    // route sent to a provider, then re-announced with the attribute, is
    // withdrawn from it, and sent again when it loses it.
    let provider = with_role("10.0.0.1", 65_001, 1, Some(Role::Customer));
    let origin = peer("10.0.0.2", 65_002, 2);
    let mut rib = Rib::new(LOCAL_AS);
    outputs(|o| rib.peer_up(provider.clone(), now(), o));
    outputs(|o| rib.peer_up(origin.clone(), now(), o));
    let out = outputs(|o| {
        rib.update(origin.addr, &route("192.0.2.0/24", 65_002, None), now(), o);
    });
    assert_eq!(sent_otc(&out, &provider), [None]);
    let out = outputs(|o| {
        rib.update(
            origin.addr,
            &route("192.0.2.0/24", 65_002, Some(65_002)),
            now(),
            o,
        );
    });
    assert_eq!(withdrawn_to(&out, &provider), vec![p("192.0.2.0/24")]);
    assert_eq!(
        rib.peer_stats(provider.addr).unwrap().advertised,
        vec![(V4, 0), (V6, 0)]
    );
    let out = outputs(|o| {
        rib.update(origin.addr, &route("192.0.2.0/24", 65_002, None), now(), o);
    });
    assert_eq!(sent_otc(&out, &provider), [None]);
    assert_eq!(
        rib.peer_stats(provider.addr).unwrap().advertised,
        vec![(V4, 1), (V6, 0)]
    );
}

#[test]
fn a_new_session_is_sent_what_its_role_allows() {
    // RFC 9234 §5 egress on the initial Adj-RIB-Out and on route refresh
    // (RFC 2918 §4): the same rules as for a change.
    let (mut rib, [provider, lateral, customer, _]) = gao_rexford();
    outputs(|o| {
        rib.update(
            provider.addr,
            &route("192.0.2.0/24", 65_001, None),
            now(),
            o,
        );
        rib.update(
            customer.addr,
            &route("198.51.100.0/24", 65_003, None),
            now(),
            o,
        );
    });
    outputs(|o| rib.peer_down(lateral.addr, now(), o));
    let mut out = Vec::new();
    rib.peer_up(lateral.clone(), now(), &mut out);
    // Only the customer's route, marked with our AS; the provider's carries
    // the attribute.
    assert_eq!(sent_otc(&out, &lateral), [Some(LOCAL_AS)]);
    let mut out = Vec::new();
    rib.refresh(lateral.addr, V4, now(), &mut out);
    assert_eq!(sent_otc(&out, &lateral), [Some(LOCAL_AS)]);
}

#[test]
fn internal_sessions_pass_the_attribute_on_unchanged() {
    // RFC 9234 §5: "Once the OTC Attribute has been set, it MUST be
    // preserved unchanged" (also across an AS), and the procedures are for
    // eBGP: an internal session has no Role.
    let provider = with_role("10.0.0.1", 65_001, 1, Some(Role::Customer));
    let internal = peer("10.0.0.2", LOCAL_AS.0, 2);
    let mut rib = Rib::new(LOCAL_AS);
    outputs(|o| rib.peer_up(provider.clone(), now(), o));
    outputs(|o| rib.peer_up(internal.clone(), now(), o));
    let out = outputs(|o| {
        rib.update(
            provider.addr,
            &route("192.0.2.0/24", 65_001, None),
            now(),
            o,
        );
    });
    assert_eq!(sent_otc(&out, &internal), [Some(Asn(65_001))]);
}

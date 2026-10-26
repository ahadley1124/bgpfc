//! The Only to Customer procedures (RFC 9234 §5) on sessions that carry
//! several paths of a prefix (RFC 7911): a leak is one path, and every
//! path sent goes through the egress procedure on its own.

use bgpfc_wire::role::Role;
use bgpfc_wire::types::PathId;
use bgpfc_wire::update::{AddPathFamilies, PathIds};

use super::*;
use crate::PathLimit;

/// A session with our `role` on it whose neighbor sends us paths with
/// identifiers for IPv4 unicast.
fn path_receiver(addr: &str, remote_as: u32, router_id: u32, role: Role) -> PeerInfo {
    PeerInfo {
        add_path_receive: vec![V4],
        role: Some(role),
        ..peer(addr, remote_as, router_id)
    }
}

/// A session with our `role` on it, if any, that is sent every path of an
/// IPv4 unicast prefix.
fn path_sender(addr: &str, remote_as: u32, router_id: u32, role: Option<Role>) -> PeerInfo {
    PeerInfo {
        add_path_send: vec![(V4, PathLimit::All)],
        role,
        ..peer(addr, remote_as, router_id)
    }
}

/// `prefix` announced under Path Identifier `id` with the AS path `path`
/// and `otc` as the Only to Customer attribute.
fn announce_path(prefix: &str, id: u32, path: &[u32], otc: Option<u32>) -> DecodedUpdate {
    let mut a = attrs(path, "10.0.0.1");
    a.otc = otc.map(Asn);
    let mut message = a.to_update(V4, vec![p(prefix)]);
    message.path_ids = Some(Box::new(PathIds {
        nlri: vec![PathId(id)],
        ..PathIds::default()
    }));
    DecodedUpdate {
        message,
        treated_as_withdraw: None,
        discarded: Vec::new(),
        disabled: Vec::new(),
    }
}

/// `prefix` announced, without a Path Identifier, by the neighbor in
/// `remote_as`, with `otc` as the Only to Customer attribute.
fn announce_route(prefix: &str, remote_as: u32, otc: Option<u32>) -> DecodedUpdate {
    let mut a = attrs(&[remote_as], "10.0.0.1");
    a.otc = otc.map(Asn);
    announce(&[prefix], &a)
}

/// What one UPDATE did to a path of a peer sent several.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Sent {
    /// Our Path Identifier, the first AS after ours, and the Only to
    /// Customer attribute.
    Announce(u32, u32, Option<Asn>),
    /// Our Path Identifier.
    Withdraw(u32),
}

/// The paths sent `to` in `out`, decoded with the extended NLRI encoding,
/// sorted.
fn sent(out: &[Output], to: &PeerInfo) -> Vec<Sent> {
    let ctx = DecodeContext {
        four_octet_as: true,
        peer: to.kind,
        allow_as_set: false,
        extended_next_hop: false,
        add_path: AddPathFamilies::of(&[V4]),
    };
    let mut v = Vec::new();
    for messages in sends(out, to.addr) {
        for m in messages {
            let d = UpdateMessage::decode(&m[HEADER_LEN..], &ctx).unwrap();
            for (_, _, id) in d.withdrawn_paths() {
                v.push(Sent::Withdraw(id.0));
            }
            for (_, next_hop, prefixes, ids) in announced(&d) {
                let a = PathAttrs::from_update(&d.message, next_hop);
                // invariant: the session rewrite prepends our AS to a
                // path the neighbor's AS starts.
                let from = a.as_path.asns().nth(1).unwrap().0;
                for id in ids.iter().take(prefixes.len()) {
                    v.push(Sent::Announce(id.0, from, a.otc));
                }
            }
        }
    }
    v.sort();
    v
}

fn candidates(rib: &Rib, prefix: &str) -> Vec<Option<u32>> {
    rib.candidates(V4, p(prefix))
        .iter()
        .map(|c| c.path_id.map(|i| i.0))
        .collect()
}

#[test]
fn a_leak_replaces_only_the_path_it_was_sent_under() {
    // RFC 9234 §5 ingress 1: from a customer, a route with the attribute is
    // a leak. RFC 7911 §5: a route is the prefix with its Path Identifier,
    // so the leak replaces that one path of the prefix and no other.
    let from = path_receiver("10.0.0.1", 65_001, 1, Role::Provider);
    let mut rib = Rib::new(LOCAL_AS);
    outputs(|o| rib.peer_up(from.clone(), now(), o));
    for (id, path) in [(1, &[65_001][..]), (2, &[65_001, 5][..])] {
        outputs(|o| {
            rib.update(
                from.addr,
                &announce_path("192.0.2.0/24", id, path, None),
                now(),
                o,
            );
        });
    }
    assert_eq!(candidates(&rib, "192.0.2.0/24"), vec![Some(1), Some(2)]);
    // The best path comes again with the attribute: it goes, the other
    // takes over.
    let out = outputs(|o| {
        rib.update(
            from.addr,
            &announce_path("192.0.2.0/24", 1, &[65_001], Some(65_099)),
            now(),
            o,
        );
    });
    let leaks: Vec<_> = out
        .iter()
        .filter(|o| matches!(o, Output::RouteLeak { .. }))
        .collect();
    assert_eq!(
        leaks,
        vec![&Output::RouteLeak {
            peer: from.addr,
            family: V4,
            otc: Asn(65_099),
            routes: 1,
            first: p("192.0.2.0/24"),
        }]
    );
    assert_eq!(candidates(&rib, "192.0.2.0/24"), vec![Some(2)]);
    assert_eq!(rib.peer_stats(from.addr).unwrap().received[0], (V4, 1));
    // A leak under an identifier the peer has not used takes nothing.
    outputs(|o| {
        rib.update(
            from.addr,
            &announce_path("192.0.2.0/24", 7, &[65_001], Some(65_001)),
            now(),
            o,
        );
    });
    assert_eq!(candidates(&rib, "192.0.2.0/24"), vec![Some(2)]);
}

#[test]
fn each_path_sent_goes_through_the_egress_procedure() {
    // RFC 9234 §5 egress: a route with the attribute is not sent to a
    // provider (2.), and one without it is sent to a customer with our AS
    // (1.). With ADD-PATH that is asked of every path (RFC 7911 §5).
    let mut rib = Rib::new(LOCAL_AS);
    // Our provider: its route gets its AS on the way in (ingress 3.).
    let provider = PeerInfo {
        role: Some(Role::Customer),
        ..peer("10.0.0.1", 65_001, 1)
    };
    // Our customer: its route has no attribute.
    let customer = PeerInfo {
        role: Some(Role::Provider),
        ..peer("10.0.0.2", 65_002, 2)
    };
    for from in [&provider, &customer] {
        outputs(|o| rib.peer_up(from.clone(), now(), o));
        outputs(|o| {
            rib.update(
                from.addr,
                &announce_route("192.0.2.0/24", from.remote_as.0, None),
                now(),
                o,
            );
        });
    }
    let to_provider = path_sender("10.0.0.8", 65_008, 8, Some(Role::Customer));
    let to_customer = path_sender("10.0.0.9", 65_009, 9, Some(Role::Provider));
    let out = outputs(|o| rib.peer_up(to_provider.clone(), now(), o));
    assert_eq!(
        sent(&out, &to_provider),
        vec![Sent::Announce(1, 65_002, None)]
    );
    let out = outputs(|o| rib.peer_up(to_customer.clone(), now(), o));
    let mut paths = sent(&out, &to_customer);
    // The identifiers are ours and say nothing here; the rest does.
    for s in &mut paths {
        if let Sent::Announce(id, ..) = s {
            *id = 0;
        }
    }
    paths.sort();
    assert_eq!(
        paths,
        vec![
            // "Once the OTC Attribute has been set, it MUST be preserved
            // unchanged."
            Sent::Announce(0, 65_001, Some(Asn(65_001))),
            Sent::Announce(0, 65_002, Some(LOCAL_AS)),
        ]
    );
    // The provider's route goes: the customer loses that one path, and the
    // provider, which never had it, hears nothing.
    let (_, tx, _) = rib
        .sent_paths(to_customer.addr, V4)
        .into_iter()
        .find(|(_, _, a)| a.as_path.first_asn() == Some(provider.remote_as))
        .unwrap();
    let out = outputs(|o| rib.update(provider.addr, &withdraw(&["192.0.2.0/24"]), now(), o));
    assert_eq!(sent(&out, &to_customer), vec![Sent::Withdraw(tx.0)]);
    assert_eq!(sent(&out, &to_provider), vec![]);
}

#[test]
fn a_path_is_sent_again_when_the_attribute_it_goes_out_with_changes() {
    // A path sent several is compared with what was sent before it, after
    // the session rewrite (RFC 7911 §5: a new advertisement under the same
    // identifier replaces the old); the egress procedure is part of that
    // rewrite (RFC 9234 §5), so a change of the attribute that goes out is
    // a change of the path, and one that does not is none.
    let mut rib = Rib::new(LOCAL_AS);
    let from = peer("10.0.0.1", 65_001, 1);
    let to = path_sender("10.0.0.9", 65_009, 9, Some(Role::Provider));
    outputs(|o| rib.peer_up(from.clone(), now(), o));
    outputs(|o| rib.peer_up(to.clone(), now(), o));
    let update = |rib: &mut Rib, otc: Option<u32>| {
        outputs(|o| {
            rib.update(
                from.addr,
                &announce_route("192.0.2.0/24", 65_001, otc),
                now(),
                o,
            );
        })
    };
    // Without the attribute, our AS goes with it to a customer.
    let out = update(&mut rib, None);
    assert_eq!(
        sent(&out, &to),
        vec![Sent::Announce(1, 65_001, Some(LOCAL_AS))]
    );
    // With the neighbor's, that one, under the same identifier.
    let out = update(&mut rib, Some(65_001));
    assert_eq!(
        sent(&out, &to),
        vec![Sent::Announce(1, 65_001, Some(Asn(65_001)))]
    );
    // With ours, the same as the egress procedure would add: the path that
    // goes out changes back.
    let out = update(&mut rib, Some(LOCAL_AS.0));
    assert_eq!(
        sent(&out, &to),
        vec![Sent::Announce(1, 65_001, Some(LOCAL_AS))]
    );
    // Without it again: the attribute the route has changed, but not the
    // one it goes out with, so nothing is sent.
    let out = update(&mut rib, None);
    assert_eq!(sent(&out, &to), vec![]);
}

//! Term evaluation: match clauses, set actions, actions and the
//! per-neighbor engine.

use std::net::IpAddr;

use bgpfc_rib::{PathAttrs, PeerInfo, Policies, RovState, Verdict};
use bgpfc_wire::as_path::AsPath;
use bgpfc_wire::attribute::Origin;
use bgpfc_wire::community::{Community, LargeCommunity};
use bgpfc_wire::mp::NextHop;
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::{AddressFamily, Asn, RouterId};
use bgpfc_wire::update::PeerKind;

use crate::{Engine, PolicySet, Route};

const V4: AddressFamily = AddressFamily::IPV4_UNICAST;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn attrs(path: &[u32]) -> PathAttrs {
    PathAttrs {
        origin: Origin::Igp,
        as_path: AsPath::sequence(&path.iter().map(|a| Asn(*a)).collect::<Vec<_>>()),
        next_hop: NextHop::Ipv4("10.0.0.1".parse().unwrap()),
        med: None,
        local_pref: None,
        atomic_aggregate: false,
        aggregator: None,
        communities: vec![Community::new(65_001, 1)].into(),
        ext_communities: Box::default(),
        large_communities: Box::default(),
        unknown: Box::default(),
        otc: None,
    }
}

fn set(text: &str) -> PolicySet {
    let cfg = bgpfc_config::parse_str(
        "t",
        &format!(
            "router-id 192.0.2.1; local-as 65000;
             prefix-list BOGONS {{ 10.0.0.0/8 le 32; 192.168.0.0/16 le 32; }}
             {text}"
        ),
    )
    .unwrap();
    PolicySet::compile(&cfg).unwrap()
}

fn route<'a>(prefix: &str, a: &'a PathAttrs) -> Route<'a> {
    Route {
        prefix: prefix.parse().unwrap(),
        family: V4,
        attrs: a,
        neighbor: ip("10.0.0.1"),
        local_addr: ip("10.0.0.254"),
        extended_next_hop: false,
        rov: RovState::Disabled,
    }
}

/// [`route`] for a route with validation state `rov`.
fn validated<'a>(prefix: &str, a: &'a PathAttrs, rov: RovState) -> Route<'a> {
    Route {
        rov,
        ..route(prefix, a)
    }
}

#[test]
fn terms_run_in_order_and_undecided_rejects() {
    let s = set("policy P {
        term bogons { match prefix-list BOGONS; action reject; }
        term exact { match prefix 203.0.113.0/24; action accept; }
        term wide { match prefix 198.51.100.0/24 le 32; set med 7; action next; }
        term rest { match origin egp; action accept; }
    }");
    let a = attrs(&[65_001]);
    assert_eq!(s.evaluate("P", &route("10.1.0.0/16", &a)), Verdict::Reject);
    assert_eq!(
        s.evaluate("P", &route("203.0.113.0/24", &a)),
        Verdict::Accept
    );
    // `next` keeps the modification, then no term decides: rejected.
    assert_eq!(
        s.evaluate("P", &route("198.51.100.128/25", &a)),
        Verdict::Reject
    );
    // Unknown policy.
    assert_eq!(
        s.evaluate("NOPE", &route("203.0.113.0/24", &a)),
        Verdict::Reject
    );
    assert!(s.has("P"));
    assert!(!s.has("NOPE"));
    // Empty policy: nothing decides.
    let e = set("policy E { }");
    assert_eq!(
        e.evaluate("E", &route("203.0.113.0/24", &a)),
        Verdict::Reject
    );
}

#[test]
fn every_match_clause_kind() {
    let s = set("policy P {
        term a { match as-path \"^65001 .* 7$\"; match community 65001:1; action accept; }
        term b { match origin incomplete; action accept; }
        term c { match neighbor 10.0.0.9; action accept; }
        term d { match large-community 1:2:3; action accept; }
        term e { match ext-community as2:2:1:1; action accept; }
        term f { action reject; }
    }");
    let mut a = attrs(&[65_001, 5, 7]);
    assert_eq!(
        s.evaluate("P", &route("203.0.113.0/24", &a)),
        Verdict::Accept
    );
    a.as_path = AsPath::sequence(&[Asn(65_001), Asn(8)]);
    assert_eq!(
        s.evaluate("P", &route("203.0.113.0/24", &a)),
        Verdict::Reject
    );
    a.origin = Origin::Incomplete;
    assert_eq!(
        s.evaluate("P", &route("203.0.113.0/24", &a)),
        Verdict::Accept
    );
    a.origin = Origin::Igp;
    let mut r = route("203.0.113.0/24", &a);
    r.neighbor = ip("10.0.0.9");
    assert_eq!(s.evaluate("P", &r), Verdict::Accept);
    a.large_communities = vec![LargeCommunity {
        global: 1,
        local1: 2,
        local2: 3,
    }]
    .into();
    assert_eq!(
        s.evaluate("P", &route("203.0.113.0/24", &a)),
        Verdict::Accept
    );
    a.large_communities = Box::default();
    a.ext_communities = vec![bgpfc_wire::community::ExtendedCommunity::two_octet_as(
        2, true, 1, 1,
    )]
    .into();
    assert_eq!(
        s.evaluate("P", &route("203.0.113.0/24", &a)),
        Verdict::Accept
    );
}

#[test]
fn set_actions_modify_a_copy() {
    let s = set("policy P {
        term t {
            set local-pref 200; set med 10;
            set community add 65000:5 no-export;
            set community remove 65001:1;
            set large-community replace 9:9:9;
            set as-path prepend 65000 65000;
            set next-hop self;
            action accept;
        }
    }");
    let a = attrs(&[65_001]);
    let Verdict::Modified(m) = s.evaluate("P", &route("203.0.113.0/24", &a)) else {
        panic!("expected a modification");
    };
    assert_eq!(m.local_pref, Some(200));
    assert_eq!(m.med, Some(10));
    assert_eq!(
        *m.communities,
        [Community::new(65_000, 5), Community::NO_EXPORT]
    );
    assert_eq!(m.large_communities.len(), 1);
    assert_eq!(
        m.as_path.asns().collect::<Vec<_>>(),
        vec![Asn(65_000), Asn(65_000), Asn(65_001)]
    );
    assert_eq!(m.next_hop, NextHop::Ipv4("10.0.0.254".parse().unwrap()));
    // The original is untouched.
    assert_eq!(a.local_pref, None);
    // next-hop self with no address of the family keeps the next hop.
    let mut r6 = route("203.0.113.0/24", &a);
    r6.local_addr = ip("2001:db8::1");
    let Verdict::Modified(m) = s.evaluate("P", &r6) else {
        panic!("expected a modification");
    };
    assert_eq!(m.next_hop, a.next_hop);
    // RFC 8950 §5: with the capability negotiated, our IPv6 address on the
    // session is a next hop the IPv4 route may carry.
    r6.extended_next_hop = true;
    let Verdict::Modified(m) = s.evaluate("P", &r6) else {
        panic!("expected a modification");
    };
    assert_eq!(
        m.next_hop,
        NextHop::Ipv6 {
            global: "2001:db8::1".parse().unwrap(),
            link_local: None
        }
    );
    // Modifications accumulate across `next` terms, and the later term
    // sees them.
    let s = set("policy Q {
        term one { set community add 65000:1; action next; }
        term two { match community 65000:1; set med 3; action accept; }
    }");
    let Verdict::Modified(m) = s.evaluate("Q", &route("203.0.113.0/24", &a)) else {
        panic!("expected a modification");
    };
    assert_eq!(m.med, Some(3));
    assert!(m.has_community(Community::new(65_000, 1)));
}

#[test]
fn regex_errors_point_at_the_term() {
    let cfg = bgpfc_config::parse_str(
        "t",
        "router-id 192.0.2.1; local-as 65000;
         policy P {
             term ok { action accept; }
             term bad { match as-path \"(1\"; action accept; }
         }",
    )
    .unwrap();
    let errs = PolicySet::compile(&cfg).unwrap_err();
    assert_eq!(errs.len(), 1);
    assert_eq!(errs[0].pos.line, 4);
    assert!(errs[0].message.contains("term `bad`"), "{}", errs[0]);
    assert!(errs[0].to_string().starts_with("4:"));
}

#[test]
fn engine_applies_each_neighbors_policies() {
    let cfg = bgpfc_config::parse_str(
        "t",
        "router-id 192.0.2.1; local-as 65000;
         policy IN { term t { set local-pref 50; action accept; } }
         policy OUT { term t { match prefix 203.0.113.0/24; action accept; } }
         neighbor 10.0.0.1 { remote-as 65001; import IN; export OUT; }",
    )
    .unwrap();
    let engine = Engine::new(&cfg).unwrap();
    assert!(engine.policies().has("IN"));
    let peer = PeerInfo {
        addr: ip("10.0.0.1"),
        local_addr: ip("10.0.0.254"),
        remote_as: Asn(65_001),
        router_id: RouterId::new(1).unwrap(),
        kind: PeerKind::External,
        families: vec![V4],
        receive_families: vec![V4],
        four_octet_as: true,
        extended_messages: false,
        extended_next_hop: Vec::new(),
        advertisement_interval: std::time::Duration::ZERO,
        prefix_limits: Vec::new(),
        add_path_receive: Vec::new(),
        add_path_send: Vec::new(),
        role: None,
        restart: None,
        enhanced_refresh: None,
    };
    let a = attrs(&[65_001]);
    let p: Prefix = "203.0.113.0/24".parse().unwrap();
    let Verdict::Modified(m) = engine.import(&peer, V4, p, &a, RovState::Disabled) else {
        panic!("import should set local-pref");
    };
    assert_eq!(m.local_pref, Some(50));
    assert_eq!(
        engine.export(&peer, V4, p, &a, RovState::Disabled),
        Verdict::Accept
    );
    let other: Prefix = "198.51.100.0/24".parse().unwrap();
    assert_eq!(
        engine.export(&peer, V4, other, &a, RovState::Disabled),
        Verdict::Reject
    );
    // An unconfigured peer gets nothing.
    let mut stranger = peer.clone();
    stranger.addr = ip("10.0.0.2");
    assert_eq!(
        engine.import(&stranger, V4, p, &a, RovState::Disabled),
        Verdict::Reject
    );
    assert_eq!(
        engine.export(&stranger, V4, p, &a, RovState::Disabled),
        Verdict::Reject
    );
    // The engine is given each route's RFC 6811 validation state, and no
    // clause matches on it: every state gets the same verdicts.
    for rov in RovState::ALL {
        for prefix in [p, other] {
            assert_eq!(
                engine.import(&peer, V4, prefix, &a, rov),
                engine.import(&peer, V4, prefix, &a, RovState::Disabled),
                "{rov} {prefix}"
            );
            assert_eq!(
                engine.export(&peer, V4, prefix, &a, rov),
                engine.export(&peer, V4, prefix, &a, RovState::Disabled),
                "{rov} {prefix}"
            );
        }
    }
}

#[test]
fn engine_tells_next_hop_self_what_the_session_negotiated() {
    // RFC 8950 §5 through the Engine: the peer's negotiated families
    // decide whether an IPv4 route may take our IPv6 session address.
    let cfg = bgpfc_config::parse_str(
        "t",
        "router-id 192.0.2.1; local-as 65000;
         policy SELF { term t { set next-hop self; action accept; } }
         neighbor 2001:db8::2 { remote-as 65000; import SELF; export SELF; }",
    )
    .unwrap();
    let engine = Engine::new(&cfg).unwrap();
    let mut peer = PeerInfo {
        addr: ip("2001:db8::2"),
        local_addr: ip("2001:db8::1"),
        remote_as: Asn(65_000),
        router_id: RouterId::new(2).unwrap(),
        kind: PeerKind::Internal,
        families: vec![V4],
        receive_families: vec![V4],
        four_octet_as: true,
        extended_messages: false,
        extended_next_hop: Vec::new(),
        advertisement_interval: std::time::Duration::ZERO,
        prefix_limits: Vec::new(),
        add_path_receive: Vec::new(),
        add_path_send: Vec::new(),
        role: None,
        restart: None,
        enhanced_refresh: None,
    };
    let a = attrs(&[65_001]);
    let p: Prefix = "203.0.113.0/24".parse().unwrap();
    let Verdict::Modified(m) = engine.export(&peer, V4, p, &a, RovState::Disabled) else {
        panic!("next-hop self modifies");
    };
    assert_eq!(m.next_hop, a.next_hop);
    peer.extended_next_hop = vec![V4];
    let Verdict::Modified(m) = engine.export(&peer, V4, p, &a, RovState::Disabled) else {
        panic!("next-hop self modifies");
    };
    assert_eq!(
        m.next_hop,
        NextHop::Ipv6 {
            global: "2001:db8::1".parse().unwrap(),
            link_local: None
        }
    );
}

#[test]
fn engine_keeps_each_neighbors_policies_apart() {
    let cfg = bgpfc_config::parse_str(
        "t",
        "router-id 192.0.2.1; local-as 65000;
         policy LOW { term t { set local-pref 50; action accept; } }
         policy HIGH { term t { set local-pref 200; action accept; } }
         policy NONE { term t { action reject; } }
         neighbor 10.0.0.1 { remote-as 65001; import LOW; export NONE; }
         neighbor 10.0.0.2 { remote-as 65002; import HIGH; export NONE; }",
    )
    .unwrap();
    let engine = Engine::new(&cfg).unwrap();
    let peer = |addr: &str| PeerInfo {
        addr: ip(addr),
        local_addr: ip("10.0.0.254"),
        remote_as: Asn(65_001),
        router_id: RouterId::new(1).unwrap(),
        kind: PeerKind::External,
        families: vec![V4],
        receive_families: vec![V4],
        four_octet_as: true,
        extended_messages: false,
        extended_next_hop: Vec::new(),
        advertisement_interval: std::time::Duration::ZERO,
        prefix_limits: Vec::new(),
        add_path_receive: Vec::new(),
        add_path_send: Vec::new(),
        role: None,
        restart: None,
        enhanced_refresh: None,
    };
    let local_pref = |v: Verdict| match v {
        Verdict::Modified(m) => m.local_pref,
        other => panic!("{other:?}"),
    };
    let a = attrs(&[65_001]);
    let p: Prefix = "203.0.113.0/24".parse().unwrap();
    // Alternate, and go through an unknown peer in between: each
    // neighbor's own policy every time.
    for _ in 0..2 {
        assert_eq!(
            local_pref(engine.import(&peer("10.0.0.1"), V4, p, &a, RovState::Disabled)),
            Some(50)
        );
        assert_eq!(
            local_pref(engine.import(&peer("10.0.0.1"), V4, p, &a, RovState::Disabled)),
            Some(50)
        );
        assert_eq!(
            engine.import(&peer("10.0.0.9"), V4, p, &a, RovState::Disabled),
            Verdict::Reject
        );
        assert_eq!(
            local_pref(engine.import(&peer("10.0.0.2"), V4, p, &a, RovState::Disabled)),
            Some(200)
        );
        assert_eq!(
            engine.export(&peer("10.0.0.2"), V4, p, &a, RovState::Disabled),
            Verdict::Reject
        );
    }
}

#[test]
fn match_rpki_compares_the_validation_state() {
    // RFC 6811 §3: policy can match the state, and so filter by it or
    // adjust the preference by it (RFC 6811 §5).
    let s = set("policy P {
        term bad { match rpki invalid; action reject; }
        term good { match rpki valid; set local-pref 200; action accept; }
        term unknown { match rpki not-found; set local-pref 90; action accept; }
        term unchecked { match rpki disabled; set local-pref 95; action accept; }
    }");
    let a = attrs(&[65_001]);
    let verdict = |rov| s.evaluate("P", &validated("203.0.113.0/24", &a, rov));
    let local_pref = |v: Verdict| match v {
        Verdict::Modified(m) => m.local_pref,
        other => panic!("{other:?}"),
    };
    assert_eq!(verdict(RovState::Invalid), Verdict::Reject);
    assert_eq!(local_pref(verdict(RovState::Valid)), Some(200));
    assert_eq!(local_pref(verdict(RovState::NotFound)), Some(90));
    assert_eq!(local_pref(verdict(RovState::Disabled)), Some(95));
}

#[test]
fn match_rpki_combines_with_the_other_clauses() {
    let s = set("policy P {
        term t { match rpki invalid; match prefix-list BOGONS; action accept; }
        term u { match rpki not-found; match origin egp; action accept; }
    }");
    let a = attrs(&[65_001]);
    let mut egp = attrs(&[65_001]);
    egp.origin = Origin::Egp;
    let at = |prefix: &str, a: &PathAttrs, rov| s.evaluate("P", &validated(prefix, a, rov));
    assert_eq!(at("10.1.0.0/16", &a, RovState::Invalid), Verdict::Accept);
    // Both clauses must hold.
    assert_eq!(at("203.0.113.0/24", &a, RovState::Invalid), Verdict::Reject);
    assert_eq!(at("10.1.0.0/16", &a, RovState::Valid), Verdict::Reject);
    assert_eq!(
        at("203.0.113.0/24", &egp, RovState::NotFound),
        Verdict::Accept
    );
    assert_eq!(
        at("203.0.113.0/24", &a, RovState::NotFound),
        Verdict::Reject
    );
}

#[test]
fn set_rpki_changes_what_the_terms_after_it_match() {
    // RFC 6811 §3: the state a policy sets is the one the next terms see
    // and the one the route has once the policy accepts it (§5: an iBGP
    // neighbor's verdict, carried in a community, set on the receiving
    // side).
    let s = set("policy P {
        term told { match community 65001:1; set rpki invalid; action next; }
        term bad { match rpki invalid; set med 666; action accept; }
        term good { match rpki valid; action accept; }
        term rest { action reject; }
    }");
    let a = attrs(&[65_001]);
    // The community is on the route: Valid when it came, Invalid after the
    // first term, accepted by the second with a MED, and the verdict says
    // both.
    let Verdict::ModifiedRestated(m, state) =
        s.evaluate("P", &validated("203.0.113.0/24", &a, RovState::Valid))
    else {
        panic!("set med and set rpki");
    };
    assert_eq!((m.med, state), (Some(666), RovState::Invalid));
    // Without the community the state is the lookup's, and no verdict
    // restates it.
    let mut other = a.clone();
    other.communities = Box::default();
    assert_eq!(
        s.evaluate("P", &validated("203.0.113.0/24", &other, RovState::Valid)),
        Verdict::Accept
    );
    assert_eq!(
        s.evaluate(
            "P",
            &validated("203.0.113.0/24", &other, RovState::NotFound)
        ),
        Verdict::Reject
    );
}

#[test]
fn a_term_that_only_sets_the_state_changes_no_attribute() {
    // Nothing is copied or normalised for it: the verdict is `Restated`,
    // and a state set to the one the route has is no change at all.
    let s = set("policy P {
        term a { match prefix 203.0.113.0/24; set rpki valid; action accept; }
        term b { match prefix 198.51.100.0/24; set rpki not-found; action accept; }
        term c { match prefix 192.0.2.0/24; set rpki invalid; set local-pref 5; action accept; }
    }");
    let a = attrs(&[65_001]);
    let at = |prefix: &str, rov| s.evaluate("P", &validated(prefix, &a, rov));
    assert_eq!(
        at("203.0.113.0/24", RovState::Invalid),
        Verdict::Restated(RovState::Valid)
    );
    assert_eq!(at("203.0.113.0/24", RovState::Valid), Verdict::Accept);
    assert_eq!(at("198.51.100.0/24", RovState::NotFound), Verdict::Accept);
    let Verdict::ModifiedRestated(m, RovState::Invalid) = at("192.0.2.0/24", RovState::Valid)
    else {
        panic!("attributes and state");
    };
    assert_eq!(m.local_pref, Some(5));
    // A state set and then set back is no change either.
    let s = set("policy Q {
        term a { set rpki invalid; action next; }
        term b { set rpki valid; action accept; }
    }");
    assert_eq!(
        s.evaluate("Q", &validated("203.0.113.0/24", &a, RovState::Valid)),
        Verdict::Accept
    );
}

#[test]
fn a_state_set_by_a_term_that_does_not_decide_is_kept_or_lost_with_the_route() {
    // `next` keeps the sets, like the attribute sets; and a policy no term
    // of which decides rejects, so its sets mean nothing.
    let s = set("policy P { term a { set rpki invalid; action next; } }");
    let a = attrs(&[65_001]);
    assert_eq!(
        s.evaluate("P", &validated("203.0.113.0/24", &a, RovState::Valid)),
        Verdict::Reject
    );
}

#[test]
fn the_engine_tells_import_and_export_policy_the_state() {
    let cfg = bgpfc_config::parse_str(
        "t",
        "router-id 192.0.2.1; local-as 65000;
         policy IN {
             term bad { match rpki invalid; action reject; }
             term good { match rpki valid; set local-pref 300; action accept; }
             term rest { action accept; }
         }
         policy OUT {
             term bad { match rpki invalid; action reject; }
             term rest { set rpki valid; action accept; }
         }
         neighbor 10.0.0.1 { remote-as 65001; import IN; export OUT; }",
    )
    .unwrap();
    let engine = Engine::new(&cfg).unwrap();
    let peer = PeerInfo {
        addr: ip("10.0.0.1"),
        local_addr: ip("10.0.0.254"),
        remote_as: Asn(65_001),
        router_id: RouterId::new(1).unwrap(),
        kind: PeerKind::External,
        families: vec![V4],
        receive_families: vec![V4],
        four_octet_as: true,
        extended_messages: false,
        extended_next_hop: Vec::new(),
        advertisement_interval: std::time::Duration::ZERO,
        prefix_limits: Vec::new(),
        add_path_receive: Vec::new(),
        add_path_send: Vec::new(),
        role: None,
        restart: None,
        enhanced_refresh: None,
    };
    let a = attrs(&[65_001]);
    let p: Prefix = "203.0.113.0/24".parse().unwrap();
    assert_eq!(
        engine.import(&peer, V4, p, &a, RovState::Invalid),
        Verdict::Reject
    );
    assert!(matches!(
        engine.import(&peer, V4, p, &a, RovState::Valid),
        Verdict::Modified(m) if m.local_pref == Some(300)
    ));
    assert_eq!(
        engine.import(&peer, V4, p, &a, RovState::NotFound),
        Verdict::Accept
    );
    assert_eq!(
        engine.export(&peer, V4, p, &a, RovState::Invalid),
        Verdict::Reject
    );
    // What an export policy sets is its own business; the RIB sends the
    // route as it is.
    assert_eq!(
        engine.export(&peer, V4, p, &a, RovState::NotFound),
        Verdict::Restated(RovState::Valid)
    );
}

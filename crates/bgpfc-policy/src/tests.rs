//! Term evaluation: match clauses, set actions, actions and the
//! per-neighbor engine.

use std::net::IpAddr;

use bgpfc_rib::{Imported, PathAttrs, PeerInfo, Policies, RovState, Verdict};
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
fn match_rpki_sees_each_state_and_not_found_holds_for_disabled() {
    // RFC 6811 §3: policy matches the validation state. Each term marks
    // the route with a MED of its own.
    let s = set("policy P {
        term d { match rpki disabled; set med 4; action accept; }
        term v { match rpki valid; set med 1; action accept; }
        term i { match rpki invalid; set med 2; action accept; }
        term n { match rpki not-found; set med 3; action accept; }
    }");
    let a = attrs(&[65_001]);
    let med = |rov: RovState| {
        let mut r = route("203.0.113.0/24", &a);
        r.rov = rov;
        match s.run("P", &r) {
            Imported {
                verdict: Verdict::Modified(m),
                rov: None,
            } => m.med,
            other => panic!("{rov}: {other:?}"),
        }
    };
    assert_eq!(med(RovState::Valid), Some(1));
    assert_eq!(med(RovState::Invalid), Some(2));
    assert_eq!(med(RovState::NotFound), Some(3));
    // `disabled` is told apart where asked for first...
    assert_eq!(med(RovState::Disabled), Some(4));
    // ...and otherwise reads as NotFound (RFC 6811 §2).
    let s = set("policy Q {
        term n { match rpki not-found; action accept; }
        term rest { action reject; }
    }");
    for rov in RovState::ALL {
        let mut r = route("203.0.113.0/24", &a);
        r.rov = rov;
        let accepted = matches!(rov, RovState::NotFound | RovState::Disabled);
        assert_eq!(
            s.evaluate("Q", &r),
            if accepted {
                Verdict::Accept
            } else {
                Verdict::Reject
            },
            "{rov}"
        );
    }
}

#[test]
fn set_rpki_is_seen_by_later_terms_and_returned() {
    let s = set("policy P {
        term allow { match prefix 198.51.100.0/24; match rpki invalid; set rpki valid; action next; }
        term mark { match community 65000:666; set rpki invalid; action next; }
        term v { match rpki valid; set local-pref 200; action accept; }
        term i { match rpki invalid; action reject; }
        term rest { action accept; }
    }");
    let a = attrs(&[65_001]);
    let run = |prefix: &str, a: &PathAttrs, rov: RovState| {
        let mut r = route(prefix, a);
        r.rov = rov;
        s.run("P", &r)
    };
    let local_pref = |i: &Imported| match &i.verdict {
        Verdict::Modified(m) => m.local_pref,
        _ => None,
    };
    // The later term sees the state the earlier one set, and it is
    // returned with the verdict.
    let i = run("198.51.100.0/24", &a, RovState::Invalid);
    assert_eq!((local_pref(&i), i.rov), (Some(200), Some(RovState::Valid)));
    // Elsewhere the looked-up state stands, and none is returned.
    let i = run("192.0.2.0/24", &a, RovState::Valid);
    assert_eq!((local_pref(&i), i.rov), (Some(200), None));
    assert_eq!(
        run("192.0.2.0/24", &a, RovState::Invalid),
        Verdict::Reject.into()
    );
    assert_eq!(
        run("192.0.2.0/24", &a, RovState::NotFound),
        Verdict::Accept.into()
    );
    // A later `set rpki` replaces an earlier one; a rejected route has no
    // state set.
    let mut marked = a.clone();
    marked.communities = vec![Community::new(65_000, 666)].into();
    assert_eq!(
        run("198.51.100.0/24", &marked, RovState::Invalid),
        Verdict::Reject.into()
    );
    // Within a term the clauses are tested first, so `set rpki` is seen
    // by later terms only, and the last one in a term wins.
    let s = set("policy Q {
        term t { match rpki valid; set rpki invalid; set rpki not-found; action next; }
        term u { match rpki valid; action reject; }
        term rest { action accept; }
    }");
    let mut r = route("192.0.2.0/24", &a);
    r.rov = RovState::Valid;
    assert_eq!(
        s.run("Q", &r),
        Imported {
            verdict: Verdict::Accept,
            rov: Some(RovState::NotFound)
        }
    );
}

#[test]
fn a_term_that_only_sets_the_state_keeps_the_attributes() {
    let s = set("policy P {
        term t { set rpki valid; action accept; }
    }");
    let a = attrs(&[65_001]);
    let mut r = route("203.0.113.0/24", &a);
    r.rov = RovState::Invalid;
    // No copy of the attributes, so the RIB keeps the received set.
    assert_eq!(
        s.run("P", &r),
        Imported {
            verdict: Verdict::Accept,
            rov: Some(RovState::Valid)
        }
    );
    // With an attribute change too, both.
    let both = set("policy P {
        term t { set rpki valid; set med 5; action accept; }
    }");
    let imported = both.run("P", &r);
    assert_eq!(imported.rov, Some(RovState::Valid));
    let Verdict::Modified(modified) = imported.verdict else {
        panic!("{imported:?}");
    };
    assert_eq!(modified.med, Some(5));
    // `evaluate` is the verdict alone.
    assert_eq!(both.evaluate("P", &r), Verdict::Modified(modified));
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
        route_refresh: true,
        extended_next_hop: Vec::new(),
        advertisement_interval: std::time::Duration::ZERO,
        prefix_limits: Vec::new(),
    };
    let a = attrs(&[65_001]);
    let p: Prefix = "203.0.113.0/24".parse().unwrap();
    let Verdict::Modified(m) = engine.import(&peer, V4, p, &a, RovState::Disabled).verdict else {
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
        engine
            .import(&stranger, V4, p, &a, RovState::Disabled)
            .verdict,
        Verdict::Reject
    );
    assert_eq!(
        engine.export(&stranger, V4, p, &a, RovState::Disabled),
        Verdict::Reject
    );
    // The engine is given each route's RFC 6811 validation state, and no
    // clause of these policies matches on it: every state gets the same
    // verdicts.
    for rov in RovState::ALL {
        for prefix in [p, other] {
            assert_eq!(
                engine.import(&peer, V4, prefix, &a, rov).verdict,
                engine
                    .import(&peer, V4, prefix, &a, RovState::Disabled)
                    .verdict,
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

fn peer_at(addr: &str) -> PeerInfo {
    PeerInfo {
        addr: ip(addr),
        local_addr: ip("10.0.0.254"),
        remote_as: Asn(65_001),
        router_id: RouterId::new(1).unwrap(),
        kind: PeerKind::External,
        families: vec![V4],
        receive_families: vec![V4],
        four_octet_as: true,
        extended_messages: false,
        route_refresh: true,
        extended_next_hop: Vec::new(),
        advertisement_interval: std::time::Duration::ZERO,
        prefix_limits: Vec::new(),
    }
}

#[test]
fn engine_import_matches_the_looked_up_state_and_returns_the_set_one() {
    let cfg = bgpfc_config::parse_str(
        "t",
        "router-id 192.0.2.1; local-as 65000;
         policy IN {
             term allow { match prefix 198.51.100.0/24; match rpki invalid; set rpki valid; action accept; }
             term i { match rpki invalid; action reject; }
             term rest { action accept; }
         }
         policy OUT { term t { action accept; } }
         neighbor 10.0.0.1 { remote-as 65001; import IN; export OUT; }",
    )
    .unwrap();
    let engine = Engine::new(&cfg).unwrap();
    let peer = peer_at("10.0.0.1");
    let a = attrs(&[65_001]);
    let p = |s: &str| -> Prefix { s.parse().unwrap() };
    assert_eq!(
        engine.import(&peer, V4, p("198.51.100.0/24"), &a, RovState::Invalid),
        Imported {
            verdict: Verdict::Accept,
            rov: Some(RovState::Valid)
        }
    );
    assert_eq!(
        engine.import(&peer, V4, p("192.0.2.0/24"), &a, RovState::Invalid),
        Verdict::Reject.into()
    );
    for rov in [RovState::Valid, RovState::NotFound, RovState::Disabled] {
        assert_eq!(
            engine.import(&peer, V4, p("192.0.2.0/24"), &a, rov),
            Verdict::Accept.into(),
            "{rov}"
        );
    }
}

#[test]
fn engine_reads_rov_only_with_a_match_rpki_clause() {
    let cfg = bgpfc_config::parse_str(
        "t",
        "router-id 192.0.2.1; local-as 65000;
         policy PLAIN { term t { match prefix 192.0.2.0/24; action reject; } term r { action accept; } }
         policy SETS { term t { match prefix 192.0.2.0/24; set rpki valid; action accept; } }
         policy READS { term t { action next; } term u { match rpki invalid; action reject; } }
         policy OUT { term t { match rpki invalid; action reject; } }
         neighbor 10.0.0.1 { remote-as 65001; import PLAIN; export OUT; }
         neighbor 10.0.0.2 { remote-as 65001; import SETS; export OUT; }
         neighbor 10.0.0.3 { remote-as 65001; import READS; export PLAIN; }",
    )
    .unwrap();
    let engine = Engine::new(&cfg).unwrap();
    let set = engine.policies();
    assert!(!set.reads_rov("PLAIN"));
    // Setting the state is no reading of it.
    assert!(!set.reads_rov("SETS"));
    assert!(set.reads_rov("READS"));
    assert!(set.reads_rov("OUT"));
    assert!(!set.reads_rov("NOPE"));
    // Per neighbor, its import policy's; an unknown peer is rejected
    // whatever the state.
    let reads = |addr: &str| engine.import_reads_rov(&peer_at(addr));
    assert!(!reads("10.0.0.1"));
    assert!(!reads("10.0.0.2"));
    assert!(reads("10.0.0.3"));
    assert!(!reads("10.0.0.9"));
    // And it holds: where the flag is false, every state gets the same
    // answer.
    let a = attrs(&[65_001]);
    for addr in ["10.0.0.1", "10.0.0.2", "10.0.0.9"] {
        for prefix in ["192.0.2.0/24", "203.0.113.0/24"] {
            let prefix: Prefix = prefix.parse().unwrap();
            let answers: Vec<Imported> = RovState::ALL
                .into_iter()
                .map(|rov| engine.import(&peer_at(addr), V4, prefix, &a, rov))
                .collect();
            assert!(answers.iter().all(|i| *i == answers[0]), "{addr} {prefix}");
        }
    }
}

#[test]
fn export_sees_the_state_it_is_given() {
    // The RIB passes the state the route is used with; export policy
    // matches it and returns a verdict alone.
    let cfg = bgpfc_config::parse_str(
        "t",
        "router-id 192.0.2.1; local-as 65000;
         policy IN { term t { action accept; } }
         policy OUT {
             term i { match rpki invalid; action reject; }
             term n { match rpki not-found; set med 7; action accept; }
             term rest { action accept; }
         }
         neighbor 10.0.0.1 { remote-as 65001; import IN; export OUT; }",
    )
    .unwrap();
    let engine = Engine::new(&cfg).unwrap();
    let peer = peer_at("10.0.0.1");
    let a = attrs(&[65_001]);
    let p: Prefix = "203.0.113.0/24".parse().unwrap();
    assert_eq!(
        engine.export(&peer, V4, p, &a, RovState::Invalid),
        Verdict::Reject
    );
    assert_eq!(
        engine.export(&peer, V4, p, &a, RovState::Valid),
        Verdict::Accept
    );
    for rov in [RovState::NotFound, RovState::Disabled] {
        let Verdict::Modified(m) = engine.export(&peer, V4, p, &a, rov) else {
            panic!("{rov}");
        };
        assert_eq!(m.med, Some(7), "{rov}");
    }
}

#[test]
fn rejecting_not_found_without_validation_holds_every_route() {
    // docs/config.md, `match rpki`: without an `rpki` block every route
    // is `disabled`, which `match rpki not-found` matches (RFC 6811 §2:
    // "SHOULD initialize the validation state of such a route to
    // "NotFound""). A policy that rejects it there and accepts another
    // state holds the route for policy, whatever the `enforcement`, so
    // nothing is used; `match rpki disabled` placed first takes
    // unvalidated routes apart.
    use std::time::Instant;

    use bgpfc_rib::{Held, Output, Rib};
    use bgpfc_wire::attribute::PathAttribute;
    use bgpfc_wire::update::{DecodedUpdate, UpdateMessage};

    let prefix: Prefix = "192.0.2.0/24".parse().unwrap();
    let update = DecodedUpdate {
        message: UpdateMessage {
            nlri: vec![prefix],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::sequence(&[Asn(65_001)])),
                PathAttribute::NextHop("10.0.0.1".parse().unwrap()),
            ],
            ..UpdateMessage::default()
        },
        ..DecodedUpdate::default()
    };
    // The state and hold of the route the RIB keeps, and the Loc-RIB's
    // size, with `terms` as the import policy.
    let run = |terms: &str| -> (Vec<(RovState, Option<Held>)>, usize) {
        let cfg = bgpfc_config::parse_str(
            "t",
            &format!(
                "router-id 192.0.2.1; local-as 65000;
                 policy IN {{ {terms} }}
                 policy OUT {{ term t {{ action accept; }} }}
                 neighbor 10.0.0.1 {{ remote-as 65001; import IN; export OUT; }}"
            ),
        )
        .unwrap();
        let mut rib = Rib::with_policies(Asn(65_000), Box::new(Engine::new(&cfg).unwrap()));
        let mut out: Vec<Output> = Vec::new();
        let now = Instant::now();
        // As bgpfcd starts it: the block's `enforcement`, here the
        // default.
        rib.set_enforcement(cfg.rpki.enforcement, now, &mut out);
        let peer = peer_at("10.0.0.1");
        rib.peer_up(peer.clone(), now, &mut out);
        rib.update(peer.addr, &update, now, &mut out);
        let kept = rib
            .routes(V4, prefix)
            .iter()
            .map(|r| (r.rov, r.held))
            .collect();
        (kept, rib.loc_rib(V4).count())
    };
    assert_eq!(
        run("term nf { match rpki not-found; action reject; } term rest { action accept; }"),
        (vec![(RovState::Disabled, Some(Held::Policy))], 0)
    );
    assert_eq!(
        run("term off { match rpki disabled; action accept; }
             term nf { match rpki not-found; action reject; }
             term rest { action accept; }"),
        (vec![(RovState::Disabled, None)], 1)
    );
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
        route_refresh: true,
        extended_next_hop: Vec::new(),
        advertisement_interval: std::time::Duration::ZERO,
        prefix_limits: Vec::new(),
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
        route_refresh: true,
        extended_next_hop: Vec::new(),
        advertisement_interval: std::time::Duration::ZERO,
        prefix_limits: Vec::new(),
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
            local_pref(
                engine
                    .import(&peer("10.0.0.1"), V4, p, &a, RovState::Disabled)
                    .verdict
            ),
            Some(50)
        );
        assert_eq!(
            local_pref(
                engine
                    .import(&peer("10.0.0.1"), V4, p, &a, RovState::Disabled)
                    .verdict
            ),
            Some(50)
        );
        assert_eq!(
            engine
                .import(&peer("10.0.0.9"), V4, p, &a, RovState::Disabled)
                .verdict,
            Verdict::Reject
        );
        assert_eq!(
            local_pref(
                engine
                    .import(&peer("10.0.0.2"), V4, p, &a, RovState::Disabled)
                    .verdict
            ),
            Some(200)
        );
        assert_eq!(
            engine.export(&peer("10.0.0.2"), V4, p, &a, RovState::Disabled),
            Verdict::Reject
        );
    }
}

//! Term evaluation: match clauses, set actions, actions and the
//! per-neighbor engine.

use std::net::IpAddr;

use bgpfc_rib::{PathAttrs, PeerInfo, Policies, Verdict};
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
        communities: vec![Community::new(65_001, 1)],
        ext_communities: Vec::new(),
        large_communities: Vec::new(),
        unknown: Vec::new(),
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
    }];
    assert_eq!(
        s.evaluate("P", &route("203.0.113.0/24", &a)),
        Verdict::Accept
    );
    a.large_communities.clear();
    a.ext_communities = vec![bgpfc_wire::community::ExtendedCommunity::two_octet_as(
        2, true, 1, 1,
    )];
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
        m.communities,
        vec![Community::new(65_000, 5), Community::NO_EXPORT]
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
        four_octet_as: true,
        extended_messages: false,
    };
    let a = attrs(&[65_001]);
    let p: Prefix = "203.0.113.0/24".parse().unwrap();
    let Verdict::Modified(m) = engine.import(&peer, V4, p, &a) else {
        panic!("import should set local-pref");
    };
    assert_eq!(m.local_pref, Some(50));
    assert_eq!(engine.export(&peer, V4, p, &a), Verdict::Accept);
    let other: Prefix = "198.51.100.0/24".parse().unwrap();
    assert_eq!(engine.export(&peer, V4, other, &a), Verdict::Reject);
    // An unconfigured peer gets nothing.
    let mut stranger = peer.clone();
    stranger.addr = ip("10.0.0.2");
    assert_eq!(engine.import(&stranger, V4, p, &a), Verdict::Reject);
    assert_eq!(engine.export(&stranger, V4, p, &a), Verdict::Reject);
}

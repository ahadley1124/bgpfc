//! Policy evaluation per route (AGENTS.md §5, benches row): a policy with
//! prefix-list, as-path regex and community clauses, against routes that
//! fall through to the last term.

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};

use bgpfc_policy::{PolicySet, Route};
use bgpfc_rib::PathAttrs;
use bgpfc_wire::as_path::AsPath;
use bgpfc_wire::attribute::Origin;
use bgpfc_wire::community::Community;
use bgpfc_wire::mp::NextHop;
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::{AddressFamily, Asn};
use criterion::Criterion;

const CONFIG: &str = "router-id 192.0.2.1; local-as 65000;
prefix-list BOGONS { 10.0.0.0/8 le 32; 172.16.0.0/12 le 32; 192.168.0.0/16 le 32; 100.64.0.0/10 le 32; }
prefix-list CUSTOMERS { 203.0.113.0/24 le 28; 198.51.100.0/24 le 28; }
policy IN {
    term bogons { match prefix-list BOGONS; action reject; }
    term long { match as-path \"^.* .* .* .* .* .* .* .* .*$\"; action reject; }
    term blackhole { match community 65535:666; action reject; }
    term customers { match prefix-list CUSTOMERS; set local-pref 200; action accept; }
    term transit { match as-path \"^65001_\"; set local-pref 80; set community add 65000:1; action accept; }
    term rest { action accept; }
}";

fn attrs() -> PathAttrs {
    PathAttrs {
        origin: Origin::Igp,
        as_path: AsPath::sequence(&[Asn(65_001), Asn(3356), Asn(174), Asn(7018)]),
        next_hop: NextHop::Ipv4(Ipv4Addr::new(10, 0, 0, 1)),
        med: None,
        local_pref: None,
        atomic_aggregate: false,
        aggregator: None,
        communities: vec![Community::new(3356, 3), Community::new(3356, 22)],
        ext_communities: Vec::new(),
        large_communities: Vec::new(),
        unknown: Vec::new(),
    }
}

fn bench(c: &mut Criterion) {
    let cfg = bgpfc_config::parse_str("bench", CONFIG).unwrap();
    let set = PolicySet::compile(&cfg).unwrap();
    let a = attrs();
    let route = Route {
        prefix: Prefix::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 0)), 24).unwrap(),
        family: AddressFamily::IPV4_UNICAST,
        attrs: &a,
        neighbor: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        local_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 254)),
    };
    c.bench_function("policy_evaluate_six_terms", |b| {
        b.iter(|| set.evaluate("IN", black_box(&route)));
    });
}

/// Entry point without `criterion_main!`, whose generated items lack docs.
fn main() {
    let mut c = Criterion::default().configure_from_args();
    bench(&mut c);
    c.final_summary();
}

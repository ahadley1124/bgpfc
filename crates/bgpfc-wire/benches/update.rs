//! UPDATE decode and encode (AGENTS.md §5, benches row).

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};

use bgpfc_wire::as_path::AsPath;
use bgpfc_wire::attribute::{Origin, PathAttribute};
use bgpfc_wire::community::{Community, LargeCommunity};
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::Asn;
use bgpfc_wire::update::{DecodeContext, EncodeContext, PeerKind, UpdateMessage};
use criterion::Criterion;

/// A typical full-table UPDATE: a handful of attributes and many prefixes.
fn message(prefixes: u32) -> UpdateMessage {
    UpdateMessage {
        withdrawn: Vec::new(),
        nlri: (0..prefixes)
            .map(|i| Prefix::new(IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + (i << 8))), 24).unwrap())
            .collect(),
        mp_reach: None,
        mp_unreach: None,
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::sequence(&[
                Asn(65_001),
                Asn(3356),
                Asn(174),
                Asn(7018),
            ])),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 1)),
            PathAttribute::MultiExitDisc(0),
            PathAttribute::Communities(vec![Community::new(3356, 3), Community::new(3356, 22)]),
            PathAttribute::LargeCommunities(vec![LargeCommunity {
                global: 65_001,
                local1: 1,
                local2: 2,
            }]),
        ],
    }
}

fn bench(c: &mut Criterion) {
    let ctx = DecodeContext {
        four_octet_as: true,
        peer: PeerKind::External,
        allow_as_set: false,
    };
    let ectx = EncodeContext {
        four_octet_as: true,
    };
    let mut group = c.benchmark_group("update");
    for prefixes in [1u32, 50, 500] {
        let m = message(prefixes);
        let body = m.encode(&ectx).unwrap();
        group.bench_function(
            format!("decode_{prefixes}_prefixes_{}_bytes", body.len()),
            |b| {
                b.iter(|| UpdateMessage::decode(black_box(&body), &ctx).unwrap());
            },
        );
        group.bench_function(format!("encode_{prefixes}_prefixes"), |b| {
            b.iter(|| black_box(&m).encode(&ectx).unwrap());
        });
    }
    group.finish();
}

/// Entry point without `criterion_main!`, whose generated items lack docs.
fn main() {
    let mut c = Criterion::default().configure_from_args();
    bench(&mut c);
    c.final_summary();
}

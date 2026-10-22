//! RIB insert and withdraw at scale (AGENTS.md §5, benches row). The
//! default sizes are a fraction of a full table so the bench finishes
//! quickly; set `BGPFC_BENCH_ROUTES` to 1250000 for the full-table figure.

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bgpfc_rib::{PeerInfo, Rib};
use bgpfc_wire::as_path::AsPath;
use bgpfc_wire::attribute::{Origin, PathAttribute};
use bgpfc_wire::mp::{MpReach, NextHop};
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::{AddressFamily, Asn, RouterId};
use bgpfc_wire::update::{DecodedUpdate, PeerKind, UpdateMessage};
use criterion::Criterion;

fn peer(i: u8) -> PeerInfo {
    PeerInfo {
        addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, i)),
        local_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 254)),
        remote_as: Asn(65_000 + u32::from(i)),
        router_id: RouterId::new(u32::from(i)).unwrap(),
        kind: PeerKind::External,
        families: vec![AddressFamily::IPV4_UNICAST, AddressFamily::IPV6_UNICAST],
        four_octet_as: true,
        extended_messages: false,
    }
}

/// `n` routes in UPDATEs of 200 prefixes, with a different `AS_PATH` every
/// 50 messages so attribute sets are shared but not identical.
fn updates(n: u32, v6: bool, peer_as: u32) -> Vec<DecodedUpdate> {
    let mut out = Vec::new();
    let mut i = 0u32;
    while i < n {
        let mut message = UpdateMessage::default();
        let path = AsPath::sequence(&[Asn(peer_as), Asn(1 + (i / 10_000) % 500), Asn(7)]);
        message.attributes = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(path),
        ];
        let nlri: Vec<Prefix> = (i..(i + 200).min(n))
            .map(|k| {
                if v6 {
                    let [_, _, hi, lo] = k.to_be_bytes();
                    Prefix::new(
                        IpAddr::V6(Ipv6Addr::new(
                            0x2001,
                            0xdb8,
                            u16::from(hi),
                            u16::from(lo),
                            0,
                            0,
                            0,
                            0,
                        )),
                        48,
                    )
                    .unwrap()
                } else {
                    Prefix::new(IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + (k << 8))), 24).unwrap()
                }
            })
            .collect();
        if v6 {
            message.mp_reach = Some(MpReach {
                family: AddressFamily::IPV6_UNICAST,
                next_hop: NextHop::Ipv6 {
                    global: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                    link_local: None,
                },
                nlri,
            });
        } else {
            message
                .attributes
                .push(PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 1)));
            message.nlri = nlri;
        }
        out.push(DecodedUpdate {
            message,
            treated_as_withdraw: None,
            discarded: Vec::new(),
        });
        i += 200;
    }
    out
}

fn bench(c: &mut Criterion) {
    let routes: u32 = std::env::var("BGPFC_BENCH_ROUTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100_000);
    let v4 = updates(routes * 4 / 5, false, 65_001);
    let v6 = updates(routes / 5, true, 65_001);
    let mut group = c.benchmark_group("rib");
    group.sample_size(10);
    group.bench_function(format!("insert_{routes}_from_one_peer_to_one_peer"), |b| {
        b.iter(|| {
            let mut rib = Rib::new(Asn(65_000));
            rib.peer_up(peer(1));
            rib.peer_up(peer(2));
            for u in v4.iter().chain(&v6) {
                black_box(rib.update(peer(1).addr, u));
            }
            rib
        });
    });
    group.bench_function(format!("withdraw_{routes}_on_peer_down"), |b| {
        b.iter_batched(
            || {
                let mut rib = Rib::new(Asn(65_000));
                rib.peer_up(peer(1));
                rib.peer_up(peer(2));
                for u in v4.iter().chain(&v6) {
                    rib.update(peer(1).addr, u);
                }
                rib
            },
            |mut rib| black_box(rib.peer_down(peer(1).addr)),
            criterion::BatchSize::LargeInput,
        );
    });
    group.finish();
}

/// Entry point; `criterion_main!` is not used because its generated items
/// lack docs and the workspace warns on that.
fn main() {
    let mut c = Criterion::default().configure_from_args();
    bench(&mut c);
    c.final_summary();
}

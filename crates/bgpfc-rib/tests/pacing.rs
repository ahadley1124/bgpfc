//! RFC 4271 §9.2.1.1 pacing against an unpaced reference: whatever the
//! sequence of changes and however time passes, a paced peer
//!
//! - never receives two advertisements of a destination closer together
//!   than its interval (three quarters of it with RFC 4271 §10 jitter);
//! - never keeps a route the unpaced peer no longer has, because
//!   withdrawals are not held back;
//! - ends up, once the intervals have run out, with exactly what the
//!   unpaced peer has: the latest state wins.
#![cfg(not(miri))]

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use bgpfc_rib::{Output, PathAttrs, PeerInfo, Rib};
use bgpfc_wire::as_path::AsPath;
use bgpfc_wire::attribute::{Origin, PathAttribute};
use bgpfc_wire::header::HEADER_LEN;
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::{AddressFamily, Asn, RouterId};
use bgpfc_wire::update::{DecodeContext, DecodedUpdate, PeerKind, UpdateMessage};
use proptest::prelude::*;

/// Run one RIB input and collect what it produced.
fn outputs(input: impl FnOnce(&mut Vec<Output>)) -> Vec<Output> {
    let mut out = Vec::new();
    input(&mut out);
    out
}

const LOCAL_AS: Asn = Asn(65_000);
const V4: AddressFamily = AddressFamily::IPV4_UNICAST;

/// Two external sources, then the receivers: an external peer with the
/// RFC 4271 §10 default of 30 s, an internal one with 5 s, and an
/// external one with 7 s.
fn peers(paced: bool) -> Vec<PeerInfo> {
    let intervals = [30, 30, 30, 5, 7];
    (0..5u8)
        .map(|i| {
            let internal = i == 3;
            PeerInfo {
                addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, i + 1)),
                local_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 254)),
                remote_as: if internal {
                    LOCAL_AS
                } else {
                    Asn(65_001 + u32::from(i))
                },
                router_id: RouterId::new(u32::from(i) + 1).unwrap(),
                kind: if internal {
                    PeerKind::Internal
                } else {
                    PeerKind::External
                },
                families: vec![V4],
                receive_families: vec![V4],
                four_octet_as: true,
                extended_messages: false,
                extended_next_hop: Vec::new(),
                advertisement_interval: if paced {
                    Duration::from_secs(intervals[usize::from(i)])
                } else {
                    Duration::ZERO
                },
                prefix_limits: Vec::new(),
            }
        })
        .collect()
}

#[derive(Clone, Debug)]
struct Step {
    /// Seconds since the previous step.
    after: u8,
    /// Milliseconds on top, so that steps fall between whole seconds.
    millis: u16,
    /// Which source (0 or 1).
    peer: u8,
    prefix: u8,
    /// AS path tail, or `None` to withdraw.
    route: Option<Vec<u16>>,
}

fn prefix(i: u8) -> Prefix {
    Prefix::new(IpAddr::V4(Ipv4Addr::new(192, 0, i, 0)), 24).unwrap()
}

fn update(step: &Step, info: &PeerInfo) -> DecodedUpdate {
    let mut message = UpdateMessage::default();
    match &step.route {
        None => message.withdrawn = vec![prefix(step.prefix)],
        Some(tail) => {
            message.nlri = vec![prefix(step.prefix)];
            let mut path = vec![info.remote_as];
            path.extend(tail.iter().map(|a| Asn(u32::from(*a))));
            message.attributes = vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::sequence(&path)),
                PathAttribute::NextHop(match info.addr {
                    IpAddr::V4(a) => a,
                    IpAddr::V6(_) => unreachable!(),
                }),
            ];
        }
    }
    DecodedUpdate {
        message,
        treated_as_withdraw: None,
        discarded: Vec::new(),
        disabled: Vec::new(),
    }
}

fn step() -> impl Strategy<Value = Step> {
    (
        0u8..12,
        0u16..1000,
        0u8..2,
        0u8..3,
        proptest::option::weighted(0.75, proptest::collection::vec(1u16..4, 0..3)),
    )
        .prop_map(|(after, millis, peer, prefix, route)| Step {
            after,
            millis,
            peer,
            prefix,
            route,
        })
}

/// Advertisement times per (receiver, prefix), from what the RIB sent.
type Log = HashMap<(IpAddr, Prefix), Vec<Instant>>;

fn note(log: &mut Log, out: &[Output], infos: &[PeerInfo], at: Instant) {
    for o in out {
        let Output::Send { peer, messages } = o else {
            continue;
        };
        let info = infos.iter().find(|i| i.addr == *peer).unwrap();
        let ctx = DecodeContext {
            four_octet_as: info.four_octet_as,
            peer: info.kind,
            allow_as_set: false,
            extended_next_hop: false,
            add_path: bgpfc_wire::update::AddPathFamilies::NONE,
        };
        for m in messages {
            assert!(m.len() <= info.max_message_len());
            let u = UpdateMessage::decode(&m[HEADER_LEN..], &ctx)
                .unwrap()
                .message;
            for p in u.nlri {
                log.entry((*peer, p)).or_default().push(at);
            }
        }
    }
}

fn adj_out(rib: &Rib, addr: IpAddr) -> BTreeMap<Prefix, PathAttrs> {
    rib.adj_rib_out(addr, V4)
        .map(|(p, a)| (p, (*a).clone()))
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn pacing_only_delays_announcements(
        steps in proptest::collection::vec(step(), 0..40),
        jitter in prop_oneof![Just(0u64), any::<u64>()],
    ) {
        let t0 = Instant::now();
        let paced_infos = peers(true);
        let plain_infos = peers(false);
        let mut paced = Rib::new(LOCAL_AS);
        paced.set_jitter_seed(jitter);
        let mut plain = Rib::new(LOCAL_AS);
        let mut log = Log::new();
        for (p, q) in paced_infos.iter().zip(&plain_infos) {
            let out = outputs(|o| paced.peer_up(p.clone(), t0, o));
            note(&mut log, &out, &paced_infos, t0);
            outputs(|o| plain.peer_up(q.clone(), t0, o));
        }
        let mut t = t0;
        for s in &steps {
            t += Duration::from_secs(u64::from(s.after)) + Duration::from_millis(u64::from(s.millis));
            // The daemon's RIB thread flushes at every deadline.
            while let Some(d) = paced.next_deadline() && d <= t {
                let out = outputs(|o| paced.flush(d, o));
                note(&mut log, &out, &paced_infos, d);
            }
            let info = &paced_infos[usize::from(s.peer)];
            let mut out = outputs(|o| paced.update(info.addr, &update(s, info), t, o));
            out.extend(outputs(|o| paced.flush(t, o)));
            note(&mut log, &out, &paced_infos, t);
            outputs(|o| plain.update(info.addr, &update(s, info), t, o));
            // Withdrawals are never held: the paced peer has nothing the
            // unpaced one lacks.
            for i in &paced_infos {
                let ours = adj_out(&paced, i.addr);
                let theirs = adj_out(&plain, i.addr);
                for p in ours.keys() {
                    prop_assert!(theirs.contains_key(p), "{} kept {p}", i.addr);
                }
            }
        }
        // Two advertisements of a destination are an interval apart.
        for ((addr, p), times) in &log {
            let info = paced_infos.iter().find(|i| i.addr == *addr).unwrap();
            let min = if jitter == 0 {
                info.advertisement_interval
            } else {
                info.advertisement_interval * 3 / 4
            };
            for w in times.windows(2) {
                prop_assert!(w[1] - w[0] >= min, "{addr} {p}: {times:?}");
            }
        }
        // Once every interval has run out, the latest state is what the
        // peers have.
        let end = t + Duration::from_secs(60);
        outputs(|o| paced.flush(end, o));
        prop_assert_eq!(paced.next_deadline().filter(|d| *d <= end), None);
        for i in &paced_infos {
            prop_assert_eq!(adj_out(&paced, i.addr), adj_out(&plain, i.addr));
        }
    }
}

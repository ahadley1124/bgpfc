//! Graceful Restart against a naive model (RFC 4724 §4.2, RFC 8538 §4.1):
//! whatever a peer had before its session ended, whatever the other peers
//! did while it was down, and however the stale routes ended (the peer's
//! End-of-RIB, or the stale timer), the RIB, the FIB and the other peers'
//! Adj-RIB-Out end up where they would have if the peer's old routes had
//! been deleted when its session ended and its new session had sent what it
//! sent: stale routes only change when things happen, never what is true
//! in the end. And the End-of-RIB marker follows every family's initial
//! update, whatever it holds.
#![cfg(not(miri))]

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use bgpfc_rib::{Output, PathAttrs, PeerInfo, PeerRestart, Restart, Retention, Rib, Sink};
use bgpfc_wire::as_path::AsPath;
use bgpfc_wire::attribute::Origin;
use bgpfc_wire::mp::NextHop;
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::{AddressFamily, Asn, RouterId};
use bgpfc_wire::update::{DecodedUpdate, PeerKind, UpdateMessage};
use proptest::prelude::*;

const LOCAL_AS: Asn = Asn(65_000);
const V4: AddressFamily = AddressFamily::IPV4_UNICAST;
const RESTART: Duration = Duration::from_secs(120);
const STALE: Duration = Duration::from_secs(360);

fn addr(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
}

fn prefix(i: u8) -> Prefix {
    Prefix::new(IpAddr::V4(Ipv4Addr::new(192, 0, i, 0)), 24).unwrap()
}

fn info(last: u8, restart: Option<Restart>) -> PeerInfo {
    PeerInfo {
        addr: addr(last),
        local_addr: addr(254),
        remote_as: Asn(65_000 + u32::from(last)),
        router_id: RouterId::new(u32::from(last)).unwrap(),
        kind: PeerKind::External,
        families: vec![V4],
        receive_families: vec![V4],
        four_octet_as: true,
        extended_messages: false,
        extended_next_hop: Vec::new(),
        advertisement_interval: Duration::ZERO,
        prefix_limits: Vec::new(),
        add_path_receive: Vec::new(),
        add_path_send: Vec::new(),
        role: None,
        restart,
    }
}

/// Graceful Restart on, against a peer that lists IPv4 unicast with the
/// Forwarding State bit `forwarding`.
fn gr(last: u8, forwarding: bool) -> PeerInfo {
    info(
        last,
        Some(Restart {
            peer: Some(PeerRestart {
                restarting: false,
                families: vec![(V4, forwarding)],
            }),
            stale_time: STALE,
        }),
    )
}

/// An UPDATE from peer `last` announcing `prefixes`, each of its own AS path
/// of `extra` more hops than the peer itself.
fn announce(last: u8, prefixes: &BTreeMap<u8, u8>) -> Vec<DecodedUpdate> {
    // One UPDATE per path length: the attributes are shared by an UPDATE.
    let mut by_len: BTreeMap<u8, Vec<Prefix>> = BTreeMap::new();
    for (&p, &extra) in prefixes {
        by_len.entry(extra).or_default().push(prefix(p));
    }
    by_len
        .into_iter()
        .map(|(extra, nlri)| {
            let mut path = vec![Asn(65_000 + u32::from(last))];
            path.extend((0..extra).map(|i| Asn(64_000 + u32::from(i))));
            let attrs = PathAttrs {
                origin: Origin::Igp,
                as_path: AsPath::sequence(&path),
                next_hop: NextHop::Ipv4(Ipv4Addr::new(10, 0, 0, last)),
                med: None,
                local_pref: None,
                atomic_aggregate: false,
                aggregator: None,
                communities: Box::default(),
                ext_communities: Box::default(),
                large_communities: Box::default(),
                unknown: Box::default(),
                otc: None,
            };
            DecodedUpdate {
                message: attrs.to_update(V4, nlri),
                treated_as_withdraw: None,
                discarded: Vec::new(),
                disabled: Vec::new(),
            }
        })
        .collect()
}

fn withdraw(prefixes: &[u8]) -> DecodedUpdate {
    DecodedUpdate {
        message: UpdateMessage {
            withdrawn: prefixes.iter().map(|i| prefix(*i)).collect(),
            ..UpdateMessage::default()
        },
        treated_as_withdraw: None,
        discarded: Vec::new(),
        disabled: Vec::new(),
    }
}

/// What a test sees of the outputs: the FIB as they leave it.
#[derive(Default)]
struct Watch {
    fib: BTreeMap<Prefix, IpAddr>,
    markers: usize,
}

impl Sink for Watch {
    fn put(&mut self, output: Output) {
        match output {
            Output::Fib(c) => {
                match c.next_hop {
                    Some(nh) => self.fib.insert(c.prefix, nh),
                    None => self.fib.remove(&c.prefix),
                };
            }
            Output::Send { messages, .. } => {
                // Every message of a RIB with one family is a table's
                // UPDATE or a marker; count the markers (23 octets).
                self.markers += messages.iter().filter(|m| m.len() == 23).count();
            }
            _ => {}
        }
    }
}

type Table = BTreeMap<Prefix, (IpAddr, Vec<u32>)>;

/// The Loc-RIB: for each destination, the peer its best route came from
/// and the AS path.
fn loc_rib(rib: &Rib) -> Table {
    rib.loc_rib(V4)
        .map(|(p, r)| {
            let path = r
                .attrs
                .as_path
                .segments()
                .flat_map(bgpfc_wire::Segment::asns)
                .map(|a| a.0)
                .collect();
            (p, (r.peer, path))
        })
        .collect()
}

fn adj_rib_out(rib: &Rib, to: IpAddr) -> BTreeMap<Prefix, Vec<u32>> {
    rib.adj_rib_out(to, V4)
        .map(|(p, a)| {
            (
                p,
                a.as_path
                    .segments()
                    .flat_map(bgpfc_wire::Segment::asns)
                    .map(|a| a.0)
                    .collect(),
            )
        })
        .collect()
}

/// What ends the stale routes.
#[derive(Clone, Copy, Debug)]
enum Ending {
    /// The peer's End-of-RIB.
    EndOfRib,
    /// The stale timer.
    StaleTimer,
}

#[derive(Clone, Debug)]
struct Scenario {
    /// A's routes before: prefix → extra AS path hops.
    before: BTreeMap<u8, u8>,
    /// C's routes, fixed.
    other: BTreeMap<u8, u8>,
    /// Prefixes C withdraws while A is down.
    withdrawn_while_down: Vec<u8>,
    /// A's routes after, from the new session.
    after: BTreeMap<u8, u8>,
    /// The Graceful Notification bit was exchanged.
    notification: bool,
    /// The new session has the Forwarding State bit.
    forwarding: bool,
    /// How the stale routes end.
    ending: Ending,
    /// A's session ended twice before it came back for good.
    flapped: bool,
}

fn routes() -> impl Strategy<Value = BTreeMap<u8, u8>> {
    proptest::collection::btree_map(0u8..8, 0u8..3, 0..8)
}

fn scenario() -> impl Strategy<Value = Scenario> {
    (
        routes(),
        routes(),
        proptest::collection::vec(0u8..8, 0..3),
        routes(),
        any::<bool>(),
        any::<bool>(),
        prop_oneof![Just(Ending::EndOfRib), Just(Ending::StaleTimer)],
        any::<bool>(),
    )
        .prop_map(
            |(
                before,
                other,
                withdrawn_while_down,
                after,
                notification,
                forwarding,
                ending,
                flapped,
            )| Scenario {
                before,
                other,
                withdrawn_while_down,
                after,
                notification,
                forwarding,
                ending,
                flapped,
            },
        )
}

/// Run `s`. With `graceful` A's first session ends with its routes kept;
/// without, they are deleted when it ends, which is what the model says
/// the end result is.
fn run(
    s: &Scenario,
    graceful: bool,
) -> (Table, BTreeMap<Prefix, IpAddr>, BTreeMap<Prefix, Vec<u32>>) {
    let t0 = Instant::now();
    let mut rib = Rib::new(LOCAL_AS);
    let mut watch = Watch::default();
    // B observes; C competes.
    rib.peer_up(info(2, None), t0, &mut watch);
    rib.peer_up(info(3, None), t0, &mut watch);
    rib.peer_up(gr(1, true), t0, &mut watch);
    for u in announce(3, &s.other) {
        rib.update(addr(3), &u, t0, &mut watch);
    }
    for u in announce(1, &s.before) {
        rib.update(addr(1), &u, t0, &mut watch);
    }
    let retention = Retention {
        families: vec![V4],
        restart_time: RESTART,
        notification: s.notification,
    };
    let down = |rib: &mut Rib, watch: &mut Watch, at: Instant| {
        if graceful {
            rib.peer_retain(addr(1), &retention, at, watch);
        } else {
            rib.peer_down(addr(1), at, watch);
        }
    };
    down(&mut rib, &mut watch, t0);
    if s.flapped {
        // It comes back and goes again before it sends anything.
        rib.peer_up(gr(1, true), t0 + Duration::from_secs(5), &mut watch);
        down(&mut rib, &mut watch, t0 + Duration::from_secs(6));
    }
    let t1 = t0 + Duration::from_secs(10);
    rib.update(addr(3), &withdraw(&s.withdrawn_while_down), t1, &mut watch);
    rib.peer_up(gr(1, s.forwarding), t1, &mut watch);
    for u in announce(1, &s.after) {
        rib.update(addr(1), &u, t1, &mut watch);
    }
    match s.ending {
        Ending::EndOfRib => rib.end_of_rib(addr(1), V4, t1, &mut watch),
        Ending::StaleTimer => rib.flush(t1 + STALE, &mut watch),
    }
    // Whatever ended them, nothing is stale any more and no timer is left.
    assert_eq!(rib.stale_peers(t1 + STALE).len(), 0);
    assert_eq!(rib.next_deadline(), None);
    (loc_rib(&rib), watch.fib, adj_rib_out(&rib, addr(2)))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn stale_routes_end_as_if_deleted_and_learned_again(s in scenario()) {
        // Without the Forwarding State bit the routes were never kept in
        // the new session, with the same end result.
        let (loc, fib, out) = run(&s, true);
        let (model_loc, model_fib, model_out) = run(&s, false);
        prop_assert_eq!(&loc, &model_loc);
        prop_assert_eq!(&fib, &model_fib);
        prop_assert_eq!(&out, &model_out);
        // The FIB the outputs left is the Loc-RIB's, next hops and all.
        let want: BTreeMap<Prefix, IpAddr> =
            loc.iter().map(|(p, (peer, _))| (*p, *peer)).collect();
        prop_assert_eq!(fib, want);
    }

    #[test]
    fn a_marker_ends_the_initial_update_of_each_family_whatever_it_holds(
        routes in routes(),
    ) {
        let t0 = Instant::now();
        let mut rib = Rib::new(LOCAL_AS);
        rib.peer_up(info(3, None), t0, &mut Watch::default());
        for u in announce(3, &routes) {
            rib.update(addr(3), &u, t0, &mut Watch::default());
        }
        let mut watch = Watch::default();
        rib.peer_up(gr(1, true), t0, &mut watch);
        prop_assert_eq!(watch.markers, 1);
        let mut watch = Watch::default();
        rib.peer_up(info(2, None), t0, &mut watch);
        prop_assert_eq!(watch.markers, 0);
    }
}

//! Enhanced Route Refresh against a naive model (RFC 7313 §4): whatever a
//! peer announces and withdraws, and however it begins, ends or abandons
//! route refreshes, the routes the RIB holds for it are those the model
//! says: a `BoRR` marks all of them stale, a route sent again clears its
//! mark, and the `EoRR` (or the time allowed for it) removes those still
//! marked. The FIB and the other peers' Adj-RIB-Out follow, and no timer is
//! left when no refresh is. With and without ADD-PATH (RFC 7911), where a
//! route is a prefix with its Path Identifier.
#![cfg(not(miri))]

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use bgpfc_rib::{EnhancedRefresh, Output, PathAttrs, PeerInfo, Rib, Sink};
use bgpfc_wire::as_path::AsPath;
use bgpfc_wire::attribute::Origin;
use bgpfc_wire::mp::NextHop;
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::{AddressFamily, Asn, PathId, RouterId};
use bgpfc_wire::update::{DecodedUpdate, PathIds, PeerKind, UpdateMessage};
use proptest::prelude::*;

const LOCAL_AS: Asn = Asn(65_000);
const V4: AddressFamily = AddressFamily::IPV4_UNICAST;
const STALE: Duration = Duration::from_secs(360);
const A: u8 = 1;
const B: u8 = 2;

fn addr(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
}

fn prefix(i: u8) -> Prefix {
    Prefix::new(IpAddr::V4(Ipv4Addr::new(192, 0, i, 0)), 24).unwrap()
}

fn info(last: u8, paths: bool, refresh: bool) -> PeerInfo {
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
        add_path_receive: if paths { vec![V4] } else { Vec::new() },
        add_path_send: Vec::new(),
        role: None,
        restart: None,
        enhanced_refresh: refresh.then_some(EnhancedRefresh {
            stale_time: STALE,
            peer_graceful_restart: false,
        }),
    }
}

/// The attributes of A's route with `extra` more hops than A.
fn attrs(extra: u8) -> PathAttrs {
    let mut path = vec![Asn(65_000 + u32::from(A))];
    path.extend((0..extra).map(|i| Asn(64_000 + u32::from(i))));
    PathAttrs {
        origin: Origin::Igp,
        as_path: AsPath::sequence(&path),
        next_hop: NextHop::Ipv4(Ipv4Addr::new(10, 0, 0, A)),
        med: None,
        local_pref: None,
        atomic_aggregate: false,
        aggregator: None,
        communities: Box::default(),
        ext_communities: Box::default(),
        large_communities: Box::default(),
        unknown: Box::default(),
        otc: None,
    }
}

fn announce(prefix_i: u8, path: u8, extra: u8, paths: bool) -> DecodedUpdate {
    let mut message = attrs(extra).to_update(V4, vec![prefix(prefix_i)]);
    if paths {
        message.path_ids = Some(Box::new(PathIds {
            nlri: vec![PathId(u32::from(path))],
            ..PathIds::default()
        }));
    }
    DecodedUpdate {
        message,
        treated_as_withdraw: None,
        discarded: Vec::new(),
        disabled: Vec::new(),
    }
}

fn withdraw(prefix_i: u8, path: u8, paths: bool) -> DecodedUpdate {
    let mut message = UpdateMessage {
        withdrawn: vec![prefix(prefix_i)],
        ..UpdateMessage::default()
    };
    if paths {
        message.path_ids = Some(Box::new(PathIds {
            withdrawn: vec![PathId(u32::from(path))],
            ..PathIds::default()
        }));
    }
    DecodedUpdate {
        message,
        treated_as_withdraw: None,
        discarded: Vec::new(),
        disabled: Vec::new(),
    }
}

/// The FIB as the outputs leave it.
#[derive(Default)]
struct Watch {
    fib: BTreeMap<Prefix, IpAddr>,
}

impl Sink for Watch {
    fn put(&mut self, output: Output) {
        if let Output::Fib(c) = output {
            match c.next_hop {
                Some(nh) => self.fib.insert(c.prefix, nh),
                None => self.fib.remove(&c.prefix),
            };
        }
    }
}

#[derive(Clone, Debug)]
enum Op {
    Announce {
        prefix: u8,
        path: u8,
        extra: u8,
    },
    Withdraw {
        prefix: u8,
        path: u8,
    },
    Begin,
    End,
    /// Time passes, in seconds.
    Wait(u16),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        4 => (0u8..6, 0u8..3, 0u8..3).prop_map(|(prefix, path, extra)| Op::Announce { prefix, path, extra }),
        2 => (0u8..6, 0u8..3).prop_map(|(prefix, path)| Op::Withdraw { prefix, path }),
        2 => Just(Op::Begin),
        2 => Just(Op::End),
        2 => prop_oneof![1u16..100, 100u16..400].prop_map(Op::Wait),
    ]
}

/// A refresh under way: none; one that marked nothing, so waits for
/// nothing; or one whose stale routes go at the time given.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Refresh {
    #[default]
    None,
    Idle,
    Until(Duration),
}

/// What the RIB should hold for A: (prefix, path) → (extra hops, stale),
/// and the refresh under way.
#[derive(Default)]
struct Model {
    routes: BTreeMap<(u8, u8), (u8, bool)>,
    refresh: Refresh,
    now: Duration,
}

impl Model {
    fn apply(&mut self, op: &Op, paths: bool) {
        match *op {
            Op::Announce {
                prefix,
                path,
                extra,
            } => {
                let path = if paths { path } else { 0 };
                self.routes.insert((prefix, path), (extra, false));
            }
            Op::Withdraw { prefix, path } => {
                let path = if paths { path } else { 0 };
                self.routes.remove(&(prefix, path));
            }
            Op::Begin => {
                for r in self.routes.values_mut() {
                    r.1 = true;
                }
                self.refresh = if self.routes.is_empty() {
                    Refresh::Idle
                } else {
                    Refresh::Until(self.now + STALE)
                };
            }
            Op::End => {
                if std::mem::take(&mut self.refresh) != Refresh::None {
                    self.routes.retain(|_, r| !r.1);
                }
            }
            Op::Wait(secs) => {
                self.now += Duration::from_secs(u64::from(secs));
                if let Refresh::Until(at) = self.refresh
                    && at <= self.now
                {
                    self.refresh = Refresh::None;
                    self.routes.retain(|_, r| !r.1);
                }
            }
        }
    }

    fn deadline(&self) -> Option<Duration> {
        match self.refresh {
            Refresh::Until(at) => Some(at),
            Refresh::None | Refresh::Idle => None,
        }
    }
}

/// A's routes as the RIB holds them, in the model's form.
fn held(rib: &Rib) -> BTreeMap<(u8, u8), (u8, bool)> {
    let mut all = BTreeMap::new();
    for i in 0..6 {
        for c in rib.candidates(V4, prefix(i)) {
            assert_eq!(c.peer, addr(A));
            let hops = c.attrs.as_path.hop_count();
            let extra = u8::try_from(hops - 1).unwrap();
            let path = c.path_id.map_or(0, |p| u8::try_from(p.0).unwrap());
            assert!(all.insert((i, path), (extra, c.stale)).is_none());
        }
    }
    all
}

fn run(ops: &[Op], paths: bool) {
    let t0 = Instant::now();
    let mut rib = Rib::new(LOCAL_AS);
    let mut watch = Watch::default();
    rib.peer_up(info(B, false, false), t0, &mut watch);
    rib.peer_up(info(A, paths, true), t0, &mut watch);
    let mut model = Model::default();
    for op in ops {
        let at = t0 + model.now;
        match *op {
            Op::Announce {
                prefix,
                path,
                extra,
            } => rib.update(
                addr(A),
                &announce(prefix, path, extra, paths),
                at,
                &mut watch,
            ),
            Op::Withdraw { prefix, path } => {
                rib.update(addr(A), &withdraw(prefix, path, paths), at, &mut watch);
            }
            Op::Begin => {
                rib.refresh_begin(addr(A), V4, at, &mut watch);
            }
            Op::End => rib.refresh_end(addr(A), V4, at, &mut watch),
            Op::Wait(secs) => {
                let later = at + Duration::from_secs(u64::from(secs));
                rib.flush(later, &mut watch);
            }
        }
        model.apply(op, paths);
        // The routes and their marks.
        assert_eq!(held(&rib), model.routes, "after {op:?}");
        assert_eq!(
            rib.peer_stats(addr(A)).unwrap().received,
            vec![(V4, model.routes.len())]
        );
        // What follows from them: the destinations, in the FIB and in what
        // B has been sent; marking itself changes neither.
        let prefixes: Vec<Prefix> = model.routes.keys().map(|(p, _)| prefix(*p)).collect();
        let mut want: Vec<Prefix> = prefixes;
        want.dedup();
        assert_eq!(watch.fib.keys().copied().collect::<Vec<_>>(), want, "fib");
        assert_eq!(
            rib.adj_rib_out(addr(B), V4)
                .map(|(p, _)| p)
                .collect::<Vec<_>>(),
            want,
            "adj-rib-out"
        );
        // One wake-up while a refresh holds stale routes, none otherwise.
        assert_eq!(
            rib.next_deadline(),
            model.deadline().map(|d| t0 + d),
            "timer after {op:?}"
        );
        assert_eq!(
            rib.refreshes(t0 + model.now)
                .iter()
                .filter(|r| r.stale_in.is_some())
                .count(),
            usize::from(model.deadline().is_some())
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn the_rib_holds_what_the_model_says(ops in proptest::collection::vec(op(), 0..40)) {
        run(&ops, false);
    }

    #[test]
    fn the_rib_holds_what_the_model_says_with_add_path(ops in proptest::collection::vec(op(), 0..40)) {
        run(&ops, true);
    }

    /// RFC 7313 §4: a complete refresh, whatever the peer had before, ends
    /// where a session that sent only that would: the stale routes only
    /// change when things happen, never what is true in the end.
    #[test]
    fn a_complete_refresh_leaves_what_it_sent(
        before in proptest::collection::btree_map(0u8..6, 0u8..3, 0..6),
        sent in proptest::collection::btree_map(0u8..6, 0u8..3, 0..6),
        paths in any::<bool>(),
    ) {
        let t0 = Instant::now();
        let table = |rib: &Rib| -> BTreeMap<(u8, u8), (u8, bool)> { held(rib) };
        // One RIB had `before` and refreshed with `sent`; the other had
        // only `sent`.
        let mut refreshed = Rib::new(LOCAL_AS);
        let mut fresh = Rib::new(LOCAL_AS);
        let (mut w1, mut w2) = (Watch::default(), Watch::default());
        for (rib, w) in [(&mut refreshed, &mut w1), (&mut fresh, &mut w2)] {
            rib.peer_up(info(B, false, false), t0, w);
            rib.peer_up(info(A, paths, true), t0, w);
        }
        for (&p, &extra) in &before {
            refreshed.update(addr(A), &announce(p, 0, extra, paths), t0, &mut w1);
        }
        refreshed.refresh_begin(addr(A), V4, t0, &mut w1);
        for (&p, &extra) in &sent {
            refreshed.update(addr(A), &announce(p, 0, extra, paths), t0, &mut w1);
            fresh.update(addr(A), &announce(p, 0, extra, paths), t0, &mut w2);
        }
        refreshed.refresh_end(addr(A), V4, t0, &mut w1);
        prop_assert_eq!(table(&refreshed), table(&fresh));
        prop_assert_eq!(&w1.fib, &w2.fib);
        prop_assert_eq!(refreshed.next_deadline(), None);
        let out = |rib: &Rib| -> Vec<Prefix> {
            rib.adj_rib_out(addr(B), V4).map(|(p, _)| p).collect()
        };
        prop_assert_eq!(out(&refreshed), out(&fresh));
    }
}

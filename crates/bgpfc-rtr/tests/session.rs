//! Property tests for the RTR client session against a simulated cache
//! that keeps to RFC 8210: whatever the cache's updates, restarts,
//! outages and No Data periods, and however the transport drops and time
//! jumps,
//!
//! - every commit is a whole VRP set the cache held at some serial, or
//!   the empty set when the data expired; never part of a reply
//!   (issue #58);
//! - the routes a commit marks as affected include every prefix whose
//!   VRPs changed (issue #59), and the first commit affects every route;
//! - the client never sends an Error Report to a cache that keeps to the
//!   protocol, never downgrades from version 1 and never panics;
//! - once the cache is reachable and has data, the client ends up in sync
//!   with it.
//!
//! Not run under Miri: proptest's case counts would take hours, and the
//! unit tests cover the same code paths there.
#![cfg(not(miri))]

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use bgpfc_rpki::{AffectedPrefixes, Vrp, VrpSet};
use bgpfc_rtr::session::{Action, Commit, Config, Event, State};
use bgpfc_rtr::{ErrorCode, ErrorReport, Intervals, Pdu, Received, Session, Version};
use bgpfc_wire::types::Asn;
use proptest::collection::vec;
use proptest::prelude::*;

/// The VRPs the cache picks from: both families, nested and overlapping
/// prefixes, and the same prefix with different ASNs and maximum lengths.
fn universe() -> Vec<Vrp> {
    [
        ("192.0.2.0/24", 24, 64_496),
        ("192.0.2.0/24", 24, 64_497),
        ("192.0.2.0/24", 26, 64_496),
        ("192.0.2.128/25", 25, 64_498),
        ("198.51.100.0/22", 24, 64_499),
        ("2001:db8::/32", 48, 64_496),
        ("2001:db8:1::/48", 48, 64_500),
        ("2001:db8::/32", 32, 0),
    ]
    .iter()
    .map(|&(p, max_len, asn)| Vrp::new(p.parse().unwrap(), max_len, Asn(asn)).unwrap())
    .collect()
}

/// Short timers, so that a few jumps of time reach every one of them;
/// still within RFC 8210 §6.
const INTERVALS: Intervals = Intervals {
    refresh: 60,
    retry: 10,
    expire: 600,
};

/// A cache that keeps to RFC 8210.
struct Cache {
    universe: Vec<Vrp>,
    session_id: u16,
    /// The set at each serial of each session, oldest first.
    history: HashMap<u16, Vec<VrpSet>>,
    /// Refusing connections.
    down: bool,
    /// Answering every query with No Data Available (§8.4).
    no_data: bool,
}

impl Cache {
    fn new() -> Cache {
        Cache {
            universe: universe(),
            session_id: 100,
            history: HashMap::from([(100, vec![VrpSet::new()])]),
            down: false,
            no_data: false,
        }
    }

    fn serials(&self) -> &Vec<VrpSet> {
        &self.history[&self.session_id]
    }

    fn serial(&self) -> u32 {
        u32::try_from(self.serials().len() - 1).unwrap()
    }

    fn current(&self) -> &VrpSet {
        self.serials().last().unwrap()
    }

    fn set_at(&self, session_id: u16, serial: u32) -> &VrpSet {
        &self.history[&session_id][usize::try_from(serial).unwrap()]
    }

    /// Toggle the VRPs at `picks`; a new serial if anything changed.
    fn update(&mut self, picks: &[usize]) -> bool {
        let mut set = self.current().clone();
        for &i in picks {
            let vrp = self.universe[i % self.universe.len()];
            if !set.remove(vrp) {
                set.insert(vrp);
            }
        }
        if set == *self.current() {
            return false;
        }
        self.history.get_mut(&self.session_id).unwrap().push(set);
        true
    }

    /// A new cache instance: a new Session ID, serials from 0, the same
    /// data (RFC 8210 §5.1).
    fn restart(&mut self) {
        let current = self.current().clone();
        self.session_id += 1;
        self.history.insert(self.session_id, vec![current]);
    }

    /// The reply to a query (RFC 8210 §8.1–§8.4).
    fn answer(&self, query: &Pdu) -> Vec<Pdu> {
        let v = Version::V1;
        if self.no_data {
            return vec![Pdu::ErrorReport(ErrorReport::new(
                v,
                ErrorCode::NoDataAvailable,
                &query.encode(),
                "",
            ))];
        }
        let sid = self.session_id;
        let mut out = vec![Pdu::CacheResponse {
            version: v,
            session_id: sid,
        }];
        match *query {
            Pdu::ResetQuery { .. } => {
                // §5.5: the whole set, all announcements.
                out.extend(self.current().iter().map(|vrp| Pdu::Prefix {
                    version: v,
                    announce: true,
                    vrp,
                }));
            }
            Pdu::SerialQuery {
                session_id, serial, ..
            } => {
                let known = session_id == sid && serial <= self.serial();
                if !known {
                    // §5.9: no incremental update from that serial.
                    return vec![Pdu::CacheReset { version: v }];
                }
                // §5.3: the minimum set of changes.
                let old = self.set_at(sid, serial);
                let new = self.current();
                out.extend(
                    old.iter()
                        .filter(|x| !new.contains(*x))
                        .map(|vrp| Pdu::Prefix {
                            version: v,
                            announce: false,
                            vrp,
                        }),
                );
                out.extend(
                    new.iter()
                        .filter(|x| !old.contains(*x))
                        .map(|vrp| Pdu::Prefix {
                            version: v,
                            announce: true,
                            vrp,
                        }),
                );
            }
            ref other => panic!("the router sent {other:?}"),
        }
        out.push(Pdu::EndOfData {
            session_id: sid,
            serial: self.serial(),
            intervals: Some(INTERVALS),
        });
        out
    }
}

/// What the PDU being handed over may commit.
#[derive(Clone, Copy, Debug)]
enum Expect {
    /// Nothing: no commit may happen.
    Nothing,
    /// An End of Data: the cache's set at that serial.
    Snapshot(u16, u32),
    /// Time passed: only the empty set, when the data expires.
    Expiry,
}

/// The session, the cache, the transport between them, and what the RIB
/// holds.
struct Sim {
    session: Session,
    now: Instant,
    cache: Cache,
    /// PDUs the cache has written and the router not yet read.
    in_flight: VecDeque<Pdu>,
    connected: bool,
    rib: Option<VrpSet>,
    commits: usize,
}

#[derive(Clone, Debug)]
enum Op {
    /// The cache's data changes; with a Serial Notify if connected.
    Update(Vec<usize>, bool),
    /// Up to this many PDUs reach the router.
    Deliver(usize),
    /// Time passes.
    Wait(u64),
    /// The transport fails.
    Drop,
    /// The cache restarts, and the transport with it.
    Restart,
    /// The cache stops or starts accepting connections.
    Down(bool),
    /// The cache loses or regains its data.
    NoData(bool),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => (vec(0usize..8, 1..4), any::<bool>()).prop_map(|(p, n)| Op::Update(p, n)),
        6 => (1usize..12).prop_map(Op::Deliver),
        3 => prop_oneof![0u64..20, 50u64..70, 590u64..700].prop_map(Op::Wait),
        1 => Just(Op::Drop),
        1 => Just(Op::Restart),
        1 => any::<bool>().prop_map(Op::Down),
        1 => any::<bool>().prop_map(Op::NoData),
    ]
}

impl Sim {
    fn new() -> Sim {
        let now = Instant::now();
        Sim {
            session: Session::new(Config::default(), now),
            now,
            cache: Cache::new(),
            in_flight: VecDeque::new(),
            connected: false,
            rib: None,
            commits: 0,
        }
    }

    fn step(&mut self, event: Event<'_>, expect: Expect) {
        let actions = self.session.step(event, self.now);
        self.carry_out(actions, expect);
        // The session's own view matches what it committed.
        assert_eq!(
            self.session.vrps().map(|v| (**v).clone()),
            self.rib,
            "session and RIB disagree"
        );
    }

    fn carry_out(&mut self, actions: Vec<Action>, expect: Expect) {
        for action in actions {
            match action {
                Action::Connect => {
                    self.in_flight.clear();
                    let event = if self.cache.down {
                        Event::Disconnected
                    } else {
                        self.connected = true;
                        Event::Connected
                    };
                    let more = self.session.step(event, self.now);
                    self.carry_out(more, Expect::Nothing);
                }
                Action::Send(Pdu::ErrorReport(r)) => {
                    panic!("error report to a correct cache: {r:?}")
                }
                Action::Send(query) => {
                    assert!(self.connected, "sent on a closed connection");
                    let reply = self.cache.answer(&query);
                    self.in_flight.extend(reply);
                }
                Action::Close => {
                    self.connected = false;
                    self.in_flight.clear();
                }
                Action::Commit(commit) => self.check_commit(&commit, expect),
                Action::Negotiated(v) => assert_eq!(v, Version::V1),
                Action::Downgrade(v) => panic!("downgrade to {v} from a version 1 cache"),
                Action::Log(_) => {}
            }
        }
    }

    fn check_commit(&mut self, commit: &Commit, expect: Expect) {
        let new = &*commit.vrps;
        match expect {
            Expect::Snapshot(sid, serial) => {
                assert_eq!(new, self.cache.set_at(sid, serial), "not a whole snapshot");
            }
            Expect::Expiry => assert!(new.is_empty(), "only an expiry commits on a tick"),
            Expect::Nothing => panic!("unexpected commit of {} VRPs", new.len()),
        }
        match &self.rib {
            None => assert_eq!(commit.affected, AffectedPrefixes::All),
            Some(old) => {
                let changed = old
                    .iter()
                    .filter(|v| !new.contains(*v))
                    .chain(new.iter().filter(|v| !old.contains(*v)));
                for vrp in changed {
                    assert!(
                        commit.affected.covers(vrp.prefix()),
                        "{vrp} changed but is not covered"
                    );
                }
            }
        }
        self.rib = Some(new.clone());
        self.commits += 1;
    }

    fn deliver(&mut self, n: usize) {
        for _ in 0..n {
            let Some(pdu) = self.in_flight.pop_front() else {
                return;
            };
            let expect = match pdu {
                Pdu::EndOfData {
                    session_id, serial, ..
                } => Expect::Snapshot(session_id, serial),
                _ => Expect::Nothing,
            };
            let octets = pdu.encode();
            self.step(
                Event::Pdu(Received {
                    pdu,
                    octets: &octets,
                }),
                expect,
            );
        }
    }

    fn drop_transport(&mut self) {
        if self.connected {
            self.connected = false;
            self.in_flight.clear();
            self.step(Event::Disconnected, Expect::Nothing);
        }
    }

    fn apply(&mut self, op: &Op) {
        match op {
            Op::Update(picks, notify) => {
                if self.cache.update(picks) && *notify && self.connected {
                    // RFC 8210 §5.2, written after whatever is in flight.
                    self.in_flight.push_back(Pdu::SerialNotify {
                        version: Version::V1,
                        session_id: self.cache.session_id,
                        serial: self.cache.serial(),
                    });
                }
            }
            Op::Deliver(n) => self.deliver(*n),
            Op::Wait(secs) => {
                self.now += Duration::from_secs(*secs);
                self.step(Event::Tick, Expect::Expiry);
            }
            Op::Drop => self.drop_transport(),
            Op::Restart => {
                self.cache.restart();
                self.drop_transport();
            }
            Op::Down(down) => self.cache.down = *down,
            Op::NoData(no_data) => self.cache.no_data = *no_data,
        }
    }

    /// Let the cache be reachable and have data, and run until the client
    /// is in sync with it.
    fn settle(&mut self) {
        self.cache.down = false;
        self.cache.no_data = false;
        for _ in 0..1_000 {
            if !self.in_flight.is_empty() {
                self.deliver(self.in_flight.len());
                continue;
            }
            if self.session.state() == State::Idle
                && self.session.session_id() == Some(self.cache.session_id)
                && self.session.serial() == Some(self.cache.serial())
            {
                return;
            }
            let next = self.session.next_deadline().expect("a timer runs");
            self.now = self.now.max(next);
            self.step(Event::Tick, Expect::Expiry);
        }
        panic!("never in sync: {:?}", self.session.state());
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn commits_are_whole_snapshots_and_the_client_converges(ops in vec(op(), 0..80)) {
        let mut sim = Sim::new();
        sim.step(Event::Tick, Expect::Nothing);
        for op in &ops {
            sim.apply(op);
        }
        sim.settle();
        prop_assert_eq!(sim.rib.as_ref(), Some(sim.cache.current()));
        prop_assert!(sim.commits >= 1);
    }
}

#[test]
fn a_quiet_run_syncs_once() {
    let mut sim = Sim::new();
    sim.apply(&Op::Update(vec![0, 5], false));
    sim.step(Event::Tick, Expect::Nothing);
    sim.settle();
    assert_eq!(sim.rib.as_ref(), Some(sim.cache.current()));
    assert_eq!(sim.commits, 1);
    // A refresh that finds nothing new commits nothing.
    sim.apply(&Op::Wait(60));
    sim.settle();
    assert_eq!(sim.commits, 1);
    // A change arrives as a delta.
    sim.apply(&Op::Update(vec![1], true));
    sim.settle();
    assert_eq!(sim.commits, 2);
    assert_eq!(sim.rib.as_ref(), Some(sim.cache.current()));
}

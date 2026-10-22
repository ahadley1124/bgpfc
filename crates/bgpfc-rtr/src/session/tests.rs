//! The RTR client with injected time (AGENTS.md §5): a table of every PDU
//! type and every transport and timer event in every state, then the
//! sequences of RFC 8210 §8, the error paths (§5.1, §5.11, §12), version
//! negotiation (§7), the timers (§6) and stale data (issue #57).

use std::time::{Duration, Instant};

use bgpfc_rpki::{AffectedPrefixes, RouteOrigin, RovState, ValidationChange, Vrp, VrpSet};
use bgpfc_wire::types::Asn;

use super::*;
use crate::pdu::RouterKey;

const V0: Version = Version::V0;
const V1: Version = Version::V1;
const SID: u16 = 7;

fn vrp(prefix: &str, max_len: u8, asn: u32) -> Vrp {
    Vrp::new(prefix.parse().unwrap(), max_len, Asn(asn)).unwrap()
}

fn a() -> Vrp {
    vrp("192.0.2.0/24", 24, 64_496)
}

fn b() -> Vrp {
    vrp("2001:db8::/32", 48, 64_497)
}

fn c() -> Vrp {
    vrp("198.51.100.0/24", 24, 64_498)
}

fn set(vrps: &[Vrp]) -> VrpSet {
    vrps.iter().copied().collect()
}

// -------------------------------------------------------------- PDUs

fn notify(version: Version, session_id: u16, serial: u32) -> Pdu {
    Pdu::SerialNotify {
        version,
        session_id,
        serial,
    }
}

fn response(version: Version, session_id: u16) -> Pdu {
    Pdu::CacheResponse {
        version,
        session_id,
    }
}

fn announce(version: Version, vrp: Vrp) -> Pdu {
    Pdu::Prefix {
        version,
        announce: true,
        vrp,
    }
}

fn withdraw(version: Version, vrp: Vrp) -> Pdu {
    Pdu::Prefix {
        version,
        announce: false,
        vrp,
    }
}

/// A version 1 End of Data with the RFC 8210 §6 default intervals.
fn eod(session_id: u16, serial: u32) -> Pdu {
    eod_with(session_id, serial, Intervals::DEFAULT)
}

fn eod_with(session_id: u16, serial: u32, intervals: Intervals) -> Pdu {
    Pdu::EndOfData {
        session_id,
        serial,
        intervals: Some(intervals),
    }
}

/// A version 0 End of Data.
fn eod0(session_id: u16, serial: u32) -> Pdu {
    Pdu::EndOfData {
        session_id,
        serial,
        intervals: None,
    }
}

fn report(version: Version, code: ErrorCode) -> Pdu {
    Pdu::ErrorReport(ErrorReport::new(version, code, &[], "from the cache"))
}

fn router_key() -> Pdu {
    Pdu::RouterKey(RouterKey::new(true, [3; 20], Asn(64_496), vec![0x30; 91]).unwrap())
}

// ----------------------------------------------------------- harness

/// A session and a clock.
struct H {
    s: Session,
    now: Instant,
}

impl H {
    fn new() -> H {
        H::with(Config::default())
    }

    fn with(config: Config) -> H {
        let now = Instant::now();
        H {
            s: Session::new(config, now),
            now,
        }
    }

    fn step(&mut self, event: Event) -> Vec<Action> {
        self.s.step(event, self.now)
    }

    fn pdu(&mut self, pdu: Pdu) -> Vec<Action> {
        self.step(Event::Pdu(pdu))
    }

    /// Hand over several PDUs; all their actions.
    fn pdus(&mut self, pdus: &[Pdu]) -> Vec<Action> {
        pdus.iter().flat_map(|p| self.pdu(p.clone())).collect()
    }

    /// Let `secs` pass, then tick.
    fn wait(&mut self, secs: u64) -> Vec<Action> {
        self.now += Duration::from_secs(secs);
        self.step(Event::Tick)
    }

    /// `secs` from now.
    fn secs(&self, secs: u64) -> Instant {
        self.now + Duration::from_secs(secs)
    }

    /// The committed set; empty before the first commit.
    fn vrps(&self) -> VrpSet {
        self.s.vrps().map(|v| (**v).clone()).unwrap_or_default()
    }
}

/// The actions in a compact form for the tables; log lines are left out.
fn tags(actions: &[Action]) -> Vec<String> {
    actions
        .iter()
        .filter_map(|a| {
            Some(match a {
                Action::Connect => "connect".to_owned(),
                Action::Close => "close".to_owned(),
                Action::Send(Pdu::ResetQuery { version }) => format!("reset-query v{version}"),
                Action::Send(Pdu::SerialQuery {
                    version,
                    session_id,
                    serial,
                }) => format!("serial-query v{version} {session_id}/{serial}"),
                Action::Send(Pdu::ErrorReport(r)) => {
                    format!("report v{} code {}", r.version(), r.code().to_u16())
                }
                Action::Send(other) => format!("send {}", other.pdu_type()),
                Action::Negotiated(v) => format!("negotiated v{v}"),
                Action::Downgrade(v) => format!("downgrade v{v}"),
                Action::Commit(c) => match &c.affected {
                    AffectedPrefixes::All => format!("commit {} all", c.vrps.len()),
                    AffectedPrefixes::CoveredBy(p) => {
                        format!("commit {} ~{}", c.vrps.len(), p.len())
                    }
                },
                Action::Log(_) => return None,
            })
        })
        .collect()
}

fn commits(actions: &[Action]) -> Vec<&Commit> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::Commit(c) => Some(c),
            _ => None,
        })
        .collect()
}

fn reports(actions: &[Action]) -> Vec<&ErrorReport> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::Send(Pdu::ErrorReport(r)) => Some(r),
            _ => None,
        })
        .collect()
}

fn logs(actions: &[Action]) -> Vec<&LogLine> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::Log(l) => Some(l),
            _ => None,
        })
        .collect()
}

fn field_of<'a>(line: &'a LogLine, key: &str) -> Option<&'a str> {
    line.fields
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v.as_str())
}

// ------------------------------------------------------------ setups

/// Fresh, after the first tick: connecting.
fn connecting() -> H {
    let mut h = H::new();
    assert_eq!(h.s.state(), State::Disconnected);
    assert_eq!(h.s.next_deadline(), Some(h.now), "connects at once");
    assert_eq!(tags(&h.wait(0)), ["connect"]);
    h
}

/// Connected for the first time: a Reset Query is out, the version not
/// yet settled.
fn querying_cold() -> H {
    let mut h = connecting();
    assert_eq!(tags(&h.step(Event::Connected)), ["reset-query v1"]);
    assert_eq!(h.s.negotiated(), None);
    h
}

/// Receiving the reply to the first Reset Query.
fn receiving_reset() -> H {
    let mut h = querying_cold();
    assert_eq!(tags(&h.pdu(response(V1, SID))), ["negotiated v1"]);
    h
}

/// In sync at Session ID 7, serial 5, with {a, b}.
fn idle() -> H {
    let mut h = receiving_reset();
    let actions = h.pdus(&[announce(V1, a()), announce(V1, b()), eod(SID, 5)]);
    assert_eq!(tags(&actions), ["commit 2 all"]);
    assert_eq!(h.s.state(), State::Idle);
    h
}

/// In sync, then the connection was lost.
fn disconnected() -> H {
    let mut h = idle();
    assert_eq!(tags(&h.step(Event::Disconnected)), NONE);
    h
}

/// In sync; the Refresh Interval ran out and a Serial Query is out.
fn querying_serial() -> H {
    let mut h = idle();
    assert_eq!(tags(&h.wait(3_600)), ["serial-query v1 7/5"]);
    h
}

/// Receiving the reply to a Serial Query.
fn receiving_serial() -> H {
    let mut h = querying_serial();
    assert_eq!(tags(&h.pdu(response(V1, SID))), NONE);
    h
}

/// The cache answered the first Reset Query with No Data Available.
fn no_data() -> H {
    let mut h = querying_cold();
    assert_eq!(
        tags(&h.pdu(report(V1, ErrorCode::NoDataAvailable))),
        ["negotiated v1"]
    );
    h
}

// ------------------------------------------------------------- table

/// Every event: the timer tick, the transport events, a decoding error,
/// and every PDU type of RFC 8210 §5 (version 1), with Error Reports of a
/// non-fatal and a fatal code (§12).
fn every_event() -> Vec<(&'static str, Event)> {
    vec![
        ("tick", Event::Tick),
        ("connected", Event::Connected),
        ("disconnected", Event::Disconnected),
        (
            "decode-error",
            Event::DecodeError {
                error: RtrError::TooShort {
                    pdu_type: 4,
                    length: 12,
                    min: 20,
                },
                erroneous_pdu: vec![1, 4, 0, 0, 0, 0, 0, 12],
            },
        ),
        ("serial-notify", Event::Pdu(notify(V1, SID, 6))),
        (
            "serial-query",
            Event::Pdu(Pdu::SerialQuery {
                version: V1,
                session_id: SID,
                serial: 5,
            }),
        ),
        ("reset-query", Event::Pdu(Pdu::ResetQuery { version: V1 })),
        ("cache-response", Event::Pdu(response(V1, SID))),
        ("ipv4-prefix", Event::Pdu(announce(V1, c()))),
        ("ipv6-prefix", Event::Pdu(withdraw(V1, b()))),
        ("end-of-data", Event::Pdu(eod(SID, 6))),
        ("cache-reset", Event::Pdu(Pdu::CacheReset { version: V1 })),
        ("router-key", Event::Pdu(router_key())),
        (
            "no-data",
            Event::Pdu(report(V1, ErrorCode::NoDataAvailable)),
        ),
        (
            "error-report",
            Event::Pdu(report(V1, ErrorCode::InternalError)),
        ),
    ]
}

type Row = (&'static str, State, &'static [&'static str]);

/// Run every event against a fresh session from `setup` and compare with
/// the table, which must name every event. Every Error Report sent
/// carries the octets of the PDU in error (RFC 8210 §5.11).
fn check_table(name: &str, setup: fn() -> H, table: &[Row]) {
    let events = every_event();
    assert_eq!(table.len(), events.len(), "{name}: one row per event");
    for (label, event) in events {
        let Some(&(_, state, expected)) = table.iter().find(|r| r.0 == label) else {
            panic!("{name}: no row for {label}");
        };
        let mut h = setup();
        let actions = h.step(event.clone());
        assert_eq!(tags(&actions), expected, "{name} + {label}: actions");
        assert_eq!(h.s.state(), state, "{name} + {label}: state");
        for r in reports(&actions) {
            let octets = match &event {
                Event::Pdu(pdu) => pdu.encode(),
                Event::DecodeError { erroneous_pdu, .. } => erroneous_pdu.clone(),
                other => panic!("{name} + {label}: report on {other:?}"),
            };
            assert_eq!(r.erroneous_pdu(), octets, "{name} + {label}");
            assert!(!r.text().is_empty(), "{name} + {label}");
        }
    }
}

/// Corrupt Data, then the session is dropped (RFC 8210 §12).
const ERR: &[&str] = &["report v1 code 0", "close"];
const NONE: &[&str] = &[];
const NO_ACTIONS: Vec<Action> = Vec::new();
const NO_COMMITS: Vec<&Commit> = Vec::new();

#[test]
fn table_disconnected() {
    // Nothing is connected: PDUs and decoding errors are left over from a
    // connection that is gone, and the Retry Interval has not run out.
    use State::Disconnected as D;
    check_table(
        "disconnected",
        disconnected,
        &[
            ("tick", D, NONE),
            // RFC 8210 §8.1: unexpired data from a broken session.
            ("connected", State::Querying, &["serial-query v1 7/5"]),
            ("disconnected", D, NONE),
            ("decode-error", D, NONE),
            ("serial-notify", D, NONE),
            ("serial-query", D, NONE),
            ("reset-query", D, NONE),
            ("cache-response", D, NONE),
            ("ipv4-prefix", D, NONE),
            ("ipv6-prefix", D, NONE),
            ("end-of-data", D, NONE),
            ("cache-reset", D, NONE),
            ("router-key", D, NONE),
            ("no-data", D, NONE),
            ("error-report", D, NONE),
        ],
    );
}

#[test]
fn table_connecting() {
    use State::Connecting as C;
    check_table(
        "connecting",
        connecting,
        &[
            ("tick", C, NONE),
            ("connected", State::Querying, &["reset-query v1"]),
            ("disconnected", State::Disconnected, NONE),
            ("decode-error", C, NONE),
            ("serial-notify", C, NONE),
            ("serial-query", C, NONE),
            ("reset-query", C, NONE),
            ("cache-response", C, NONE),
            ("ipv4-prefix", C, NONE),
            ("ipv6-prefix", C, NONE),
            ("end-of-data", C, NONE),
            ("cache-reset", C, NONE),
            ("router-key", C, NONE),
            ("no-data", C, NONE),
            ("error-report", C, NONE),
        ],
    );
}

#[test]
fn table_querying_cold() {
    // Before the version is settled: a Serial Notify is ignored (RFC 8210
    // §7), any other version 1 PDU settles it, and anything but a Cache
    // Response or an Error Report is out of sequence (§8.1).
    use State::{Disconnected as D, Querying as Q};
    const NEG_ERR: &[&str] = &["negotiated v1", "report v1 code 0", "close"];
    check_table(
        "querying-cold",
        querying_cold,
        &[
            ("tick", Q, NONE),
            ("connected", Q, &["reset-query v1"]),
            ("disconnected", D, NONE),
            ("decode-error", D, ERR),
            ("serial-notify", Q, NONE),
            ("serial-query", D, NEG_ERR),
            ("reset-query", D, NEG_ERR),
            ("cache-response", State::Receiving, &["negotiated v1"]),
            ("ipv4-prefix", D, NEG_ERR),
            ("ipv6-prefix", D, NEG_ERR),
            ("end-of-data", D, NEG_ERR),
            // RFC 8210 §5.9: a Cache Reset answers a Serial Query only.
            ("cache-reset", D, NEG_ERR),
            ("router-key", D, NEG_ERR),
            ("no-data", State::Idle, &["negotiated v1"]),
            ("error-report", D, &["close"]),
        ],
    );
}

#[test]
fn table_receiving_reset() {
    use State::{Disconnected as D, Receiving as R};
    check_table(
        "receiving-reset",
        receiving_reset,
        &[
            ("tick", R, NONE),
            ("connected", State::Querying, &["reset-query v1"]),
            ("disconnected", D, NONE),
            ("decode-error", D, ERR),
            ("serial-notify", R, NONE),
            ("serial-query", D, ERR),
            ("reset-query", D, ERR),
            ("cache-response", D, ERR),
            ("ipv4-prefix", R, NONE),
            // RFC 8210 §5.5: a reply to a Reset Query only announces.
            ("ipv6-prefix", D, ERR),
            // The first data replaces the RIB's source: every route.
            ("end-of-data", State::Idle, &["commit 0 all"]),
            ("cache-reset", D, ERR),
            ("router-key", R, NONE),
            ("no-data", State::Idle, NONE),
            ("error-report", D, &["close"]),
        ],
    );
}

#[test]
fn table_idle() {
    use State::{Disconnected as D, Idle as I};
    check_table(
        "idle",
        idle,
        &[
            ("tick", I, NONE),
            ("connected", State::Querying, &["serial-query v1 7/5"]),
            ("disconnected", D, NONE),
            ("decode-error", D, ERR),
            ("serial-notify", State::Querying, &["serial-query v1 7/5"]),
            ("serial-query", D, ERR),
            ("reset-query", D, ERR),
            ("cache-response", D, ERR),
            ("ipv4-prefix", D, ERR),
            ("ipv6-prefix", D, ERR),
            ("end-of-data", D, ERR),
            ("cache-reset", D, ERR),
            ("router-key", D, ERR),
            ("no-data", I, NONE),
            ("error-report", D, &["close"]),
        ],
    );
}

#[test]
fn table_querying_serial() {
    use State::{Disconnected as D, Querying as Q};
    check_table(
        "querying-serial",
        querying_serial,
        &[
            ("tick", Q, NONE),
            ("connected", Q, &["serial-query v1 7/5"]),
            ("disconnected", D, NONE),
            ("decode-error", D, ERR),
            // A hint while a query is out: remembered, not acted on.
            ("serial-notify", Q, NONE),
            ("serial-query", D, ERR),
            ("reset-query", D, ERR),
            ("cache-response", State::Receiving, NONE),
            ("ipv4-prefix", D, ERR),
            ("ipv6-prefix", D, ERR),
            ("end-of-data", D, ERR),
            // RFC 8210 §8.3.
            ("cache-reset", Q, &["reset-query v1"]),
            ("router-key", D, ERR),
            ("no-data", State::Idle, NONE),
            ("error-report", D, &["close"]),
        ],
    );
}

#[test]
fn table_receiving_serial() {
    use State::{Disconnected as D, Receiving as R};
    check_table(
        "receiving-serial",
        receiving_serial,
        &[
            ("tick", R, NONE),
            ("connected", State::Querying, &["serial-query v1 7/5"]),
            ("disconnected", D, NONE),
            ("decode-error", D, ERR),
            ("serial-notify", R, NONE),
            ("serial-query", D, ERR),
            ("reset-query", D, ERR),
            ("cache-response", D, ERR),
            ("ipv4-prefix", R, NONE),
            ("ipv6-prefix", R, NONE),
            // An empty delta changes nothing, so nothing is committed.
            ("end-of-data", State::Idle, NONE),
            ("cache-reset", D, ERR),
            ("router-key", R, NONE),
            ("no-data", State::Idle, NONE),
            ("error-report", D, &["close"]),
        ],
    );
}

#[test]
fn table_no_data() {
    use State::{Disconnected as D, Idle as I};
    check_table(
        "no-data",
        no_data,
        &[
            ("tick", I, NONE),
            ("connected", State::Querying, &["reset-query v1"]),
            ("disconnected", D, NONE),
            ("decode-error", D, ERR),
            // The cache has data again: ask for it at once.
            ("serial-notify", State::Querying, &["reset-query v1"]),
            ("serial-query", D, ERR),
            ("reset-query", D, ERR),
            ("cache-response", D, ERR),
            ("ipv4-prefix", D, ERR),
            ("ipv6-prefix", D, ERR),
            ("end-of-data", D, ERR),
            ("cache-reset", D, ERR),
            ("router-key", D, ERR),
            ("no-data", I, NONE),
            ("error-report", D, &["close"]),
        ],
    );
}

// ------------------------------------------------------ RFC 8210 §8.1

#[test]
fn cold_start_commits_only_at_end_of_data() {
    // Issue #58: the RIB never sees part of a reply.
    let mut h = receiving_reset();
    assert_eq!(tags(&h.pdu(announce(V1, a()))), NONE);
    assert_eq!(tags(&h.pdu(router_key())), NONE);
    assert_eq!(tags(&h.pdu(announce(V1, b()))), NONE);
    assert!(h.s.vrps().is_none());
    assert_eq!(h.s.serial(), None);
    let actions = h.pdu(eod(SID, 5));
    let commit = commits(&actions);
    assert_eq!(commit.len(), 1);
    assert_eq!(*commit[0].vrps, set(&[a(), b()]));
    assert_eq!(commit[0].affected, AffectedPrefixes::All);
    assert_eq!(h.vrps(), set(&[a(), b()]));
    assert_eq!(h.s.session_id(), Some(SID));
    assert_eq!(h.s.serial(), Some(5));
    assert_eq!(h.s.intervals(), Intervals::DEFAULT);
    assert_eq!(h.s.synced_at(), Some(h.now));
    // RFC 8210 §6: Refresh and Expire count from End of Data.
    assert_eq!(h.s.expires_at(), Some(h.secs(7_200)));
    assert_eq!(h.s.next_deadline(), Some(h.secs(3_600)));
    assert!(
        logs(&actions)
            .iter()
            .any(|l| l.message == "rtr in sync with the cache"
                && field_of(l, "serial") == Some("5")
                && field_of(l, "vrps") == Some("2"))
    );
}

#[test]
fn first_commit_affects_every_route_even_when_empty() {
    let mut h = receiving_reset();
    assert_eq!(tags(&h.pdu(eod(SID, 1))), ["commit 0 all"]);
    // A reload to the same set changes nothing: no commit.
    h.wait(3_600);
    assert_eq!(
        tags(&h.pdu(Pdu::CacheReset { version: V1 })),
        ["reset-query v1"]
    );
    assert_eq!(tags(&h.pdus(&[response(V1, SID), eod(SID, 2)])), NONE);
    assert_eq!(h.s.serial(), Some(2));
}

// ------------------------------------------------------ RFC 8210 §8.2

#[test]
fn incremental_update_commits_the_delta() {
    let mut h = receiving_serial();
    assert_eq!(tags(&h.pdus(&[withdraw(V1, b()), announce(V1, c())])), NONE);
    assert_eq!(
        h.vrps(),
        set(&[a(), b()]),
        "nothing applied before End of Data"
    );
    let actions = h.pdu(eod(SID, 6));
    assert_eq!(tags(&actions), ["commit 2 ~2"]);
    let commit = commits(&actions)[0];
    assert_eq!(*commit.vrps, set(&[a(), c()]));
    assert_eq!(commit.affected, AffectedPrefixes::from_vrps([b(), c()]));
    assert_eq!(h.s.serial(), Some(6));
    // The next poll asks from the new serial.
    assert_eq!(tags(&h.wait(3_600)), ["serial-query v1 7/6"]);
}

#[test]
fn withdraw_and_announce_again_affects_nothing() {
    // RFC 8210 §5.3: at most one withdrawal followed by one announcement.
    let mut h = receiving_serial();
    let actions = h.pdus(&[withdraw(V1, a()), announce(V1, a()), eod(SID, 6)]);
    assert_eq!(commits(&actions), NO_COMMITS);
    assert_eq!(h.s.serial(), Some(6));
}

#[test]
fn a_reply_that_fails_half_way_is_dropped_whole() {
    let mut h = receiving_serial();
    assert_eq!(tags(&h.pdus(&[withdraw(V1, b()), announce(V1, c())])), NONE);
    let bad = announce(V1, c());
    let actions = h.pdu(bad.clone());
    assert_eq!(tags(&actions), ["report v1 code 7", "close"]);
    assert_eq!(reports(&actions)[0].erroneous_pdu(), bad.encode());
    assert_eq!(h.vrps(), set(&[a(), b()]));
    assert_eq!(commits(&actions), NO_COMMITS);
}

// ------------------------------------------- RFC 8210 §5.6, §12 codes 6, 7

#[test]
fn withdrawal_of_an_unknown_record_is_code_6() {
    let mut h = receiving_serial();
    let bad = withdraw(V1, c());
    let actions = h.pdu(bad.clone());
    assert_eq!(tags(&actions), ["report v1 code 6", "close"]);
    let r = reports(&actions)[0];
    assert_eq!(r.code(), ErrorCode::WithdrawalOfUnknownRecord);
    assert_eq!(r.erroneous_pdu(), bad.encode());
    assert!(
        r.text().contains("198.51.100.0/24-24 AS64498"),
        "{}",
        r.text()
    );
    // §12: fatal. The data stays; the serial does not, so that the next
    // connection reloads everything (§8.1).
    assert_eq!(h.s.state(), State::Disconnected);
    assert_eq!(h.vrps(), set(&[a(), b()]));
    assert_eq!(h.s.serial(), None);
    assert_eq!(tags(&h.wait(599)), NONE);
    assert_eq!(tags(&h.wait(1)), ["connect"]);
    assert_eq!(tags(&h.step(Event::Connected)), ["reset-query v1"]);
}

#[test]
fn duplicate_announcement_is_code_7() {
    // In a Serial reply: already in the committed data.
    let mut h = receiving_serial();
    assert_eq!(
        tags(&h.pdu(announce(V1, a()))),
        ["report v1 code 7", "close"]
    );
    // In a reset reply: announced twice.
    let mut h = receiving_reset();
    assert_eq!(tags(&h.pdu(announce(V1, a()))), NONE);
    assert_eq!(
        tags(&h.pdu(announce(V1, a()))),
        ["report v1 code 7", "close"]
    );
    assert!(h.s.vrps().is_none());
}

#[test]
fn withdrawal_in_a_reset_reply_is_corrupt_data() {
    // RFC 8210 §5.5: such a reply only announces.
    let mut h = idle();
    h.wait(3_600);
    h.pdu(Pdu::CacheReset { version: V1 });
    h.pdu(response(V1, SID));
    let actions = h.pdu(withdraw(V1, a()));
    assert_eq!(tags(&actions), ["report v1 code 0", "close"]);
    assert!(reports(&actions)[0].text().contains("Reset Query"));
    assert_eq!(h.vrps(), set(&[a(), b()]));
}

// ------------------------------------------------------ RFC 8210 §8.3

#[test]
fn cache_reset_reloads_and_commits_the_diff() {
    let mut h = querying_serial();
    assert_eq!(
        tags(&h.pdu(Pdu::CacheReset { version: V1 })),
        ["reset-query v1"]
    );
    // §5.5: a reply to a Reset Query may bring a new Session ID.
    let actions = h.pdus(&[
        response(V1, 8),
        announce(V1, a()),
        announce(V1, c()),
        eod(8, 1),
    ]);
    assert_eq!(tags(&actions), ["commit 2 ~2"]);
    // Issue #59: only what differs, b and c, is validated again.
    let commit = commits(&actions)[0];
    assert_eq!(commit.affected, AffectedPrefixes::from_vrps([b(), c()]));
    assert!(!commit.affected.covers(a().prefix()));
    assert_eq!(h.s.session_id(), Some(8));
    assert_eq!(h.s.serial(), Some(1));
    assert_eq!(tags(&h.wait(3_600)), ["serial-query v1 8/1"]);
}

// ------------------------------------------------------ RFC 8210 §8.4

#[test]
fn no_data_keeps_the_data_and_polls_with_reset_queries() {
    let mut h = querying_serial();
    let actions = h.pdu(report(V1, ErrorCode::NoDataAvailable));
    assert!(tags(&actions).is_empty(), "not fatal: the session stays up");
    assert!(logs(&actions).iter().any(|l| l.level == Level::Warn
        && field_of(l, "serving_vrps") == Some("2")
        && field_of(l, "text") == Some("from the cache")));
    assert_eq!(h.s.state(), State::Idle);
    assert_eq!(h.vrps(), set(&[a(), b()]));
    // §8.4: periodic Reset Queries, every Retry Interval (§6).
    assert_eq!(tags(&h.wait(599)), NONE);
    assert_eq!(tags(&h.wait(1)), ["reset-query v1"]);
    assert_eq!(tags(&h.pdu(report(V1, ErrorCode::NoDataAvailable))), NONE);
    assert_eq!(tags(&h.wait(600)), ["reset-query v1"]);
    let actions = h.pdus(&[response(V1, SID), announce(V1, a()), eod(SID, 9)]);
    assert_eq!(tags(&actions), ["commit 1 ~1"]);
    assert_eq!(h.s.serial(), Some(9));
}

// ------------------------------------------- RFC 8210 §5.2 Serial Notify

#[test]
fn serial_notify_when_idle_queries_at_once() {
    let mut h = idle();
    // The router has serial 5 already.
    assert_eq!(tags(&h.pdu(notify(V1, SID, 5))), NONE);
    assert_eq!(h.s.state(), State::Idle);
    assert_eq!(tags(&h.pdu(notify(V1, SID, 6))), ["serial-query v1 7/5"]);
}

#[test]
fn serial_notify_during_negotiation_is_ignored() {
    // RFC 8210 §7: "regardless of the Protocol Version field".
    let mut h = querying_cold();
    assert_eq!(h.pdu(notify(V1, 99, 1)), NO_ACTIONS);
    assert_eq!(h.pdu(notify(V0, 99, 1)), NO_ACTIONS);
    assert_eq!(h.s.negotiated(), None);
    assert_eq!(h.s.state(), State::Querying);
    // The reply then settles version 1 as usual.
    assert_eq!(tags(&h.pdu(response(V1, SID))), ["negotiated v1"]);
}

#[test]
fn serial_notify_while_busy_asks_again_after_end_of_data() {
    let mut h = querying_serial();
    assert_eq!(tags(&h.pdu(notify(V1, SID, 7))), NONE);
    h.pdu(response(V1, SID));
    assert_eq!(tags(&h.pdu(notify(V1, SID, 7))), NONE);
    // The reply reaches serial 6 only: ask again for 7.
    let actions = h.pdus(&[announce(V1, c()), eod(SID, 6)]);
    assert_eq!(tags(&actions), ["commit 3 ~1", "serial-query v1 7/6"]);
}

#[test]
fn serial_notify_while_busy_for_the_serial_reached_is_dropped() {
    let mut h = querying_serial();
    h.pdu(notify(V1, SID, 6));
    let actions = h.pdus(&[response(V1, SID), eod(SID, 6)]);
    assert_eq!(tags(&actions), NONE);
    assert_eq!(h.s.state(), State::Idle);
}

// ------------------------------------------------- RFC 8210 §5.1 Session ID

#[test]
fn cache_response_with_another_session_id_flushes_the_data() {
    let mut h = querying_serial();
    let bad = response(V1, 9);
    let actions = h.pdu(bad.clone());
    // Error Report code 0, drop the session, flush the data: every route
    // is NotFound against the empty set.
    assert_eq!(tags(&actions), ["report v1 code 0", "close", "commit 0 ~2"]);
    let r = reports(&actions)[0];
    assert_eq!(r.erroneous_pdu(), bad.encode());
    assert!(
        r.text().contains("Session ID 9 where 7 was expected"),
        "{}",
        r.text()
    );
    let commit = commits(&actions)[0];
    assert!(commit.vrps.is_empty());
    assert_eq!(commit.affected, AffectedPrefixes::from_vrps([a(), b()]));
    assert_eq!(
        commit
            .vrps
            .validate(a().prefix(), RouteOrigin::As(Asn(64_496))),
        RovState::NotFound
    );
    assert_eq!(h.s.serial(), None);
    assert_eq!(h.s.expires_at(), None);
    assert_eq!(h.s.state(), State::Disconnected);
    // The next connection reloads, and the new Session ID is taken.
    h.wait(600);
    assert_eq!(tags(&h.step(Event::Connected)), ["reset-query v1"]);
    let actions = h.pdus(&[response(V1, 9), announce(V1, a()), eod(9, 1)]);
    assert_eq!(tags(&actions), ["negotiated v1", "commit 1 ~1"]);
    assert_eq!(h.s.session_id(), Some(9));
}

#[test]
fn end_of_data_with_another_session_id_flushes_the_data() {
    // RFC 8210 §5.8: End of Data carries its Cache Response's Session ID.
    let mut h = receiving_serial();
    h.pdu(announce(V1, c()));
    let actions = h.pdu(eod(8, 6));
    assert_eq!(tags(&actions), ["report v1 code 0", "close", "commit 0 ~2"]);
    assert!(h.vrps().is_empty());
    // On a first load there is nothing to flush.
    let mut h = receiving_reset();
    h.pdu(announce(V1, a()));
    assert_eq!(tags(&h.pdu(eod(8, 1))), ["report v1 code 0", "close"]);
    assert!(h.s.vrps().is_none());
}

#[test]
fn serial_notify_with_another_session_id_flushes_the_data() {
    let mut h = idle();
    let actions = h.pdu(notify(V1, 9, 6));
    assert_eq!(tags(&actions), ["report v1 code 0", "close", "commit 0 ~2"]);
    // While a reply is under way, too.
    let mut h = receiving_serial();
    assert_eq!(
        tags(&h.pdu(notify(V1, 9, 6))),
        ["report v1 code 0", "close", "commit 0 ~2"]
    );
}

#[test]
fn a_reconnect_resumes_with_a_serial_query() {
    // RFC 8210 §8.1: unexpired data from a broken session.
    let mut h = disconnected();
    assert_eq!(h.s.session_id(), Some(SID));
    assert_eq!(h.vrps(), set(&[a(), b()]));
    assert_eq!(tags(&h.wait(600)), ["connect"]);
    assert_eq!(tags(&h.step(Event::Connected)), ["serial-query v1 7/5"]);
    let actions = h.pdus(&[response(V1, SID), withdraw(V1, a()), eod(SID, 6)]);
    assert_eq!(tags(&actions), ["negotiated v1", "commit 1 ~1"]);
}

#[test]
fn a_new_session_id_on_reconnect_flushes_the_data() {
    // The cache restarted while the router was away and answers the Serial
    // Query with its new Session ID (RFC 8210 §5.1).
    let mut h = disconnected();
    h.wait(600);
    h.step(Event::Connected);
    let actions = h.pdu(response(V1, 1));
    assert_eq!(
        tags(&actions),
        ["negotiated v1", "report v1 code 0", "close", "commit 0 ~2"]
    );
}

// ----------------------------------------------- RFC 8210 §7 negotiation

#[test]
fn a_version_0_reply_to_a_reset_query_downgrades() {
    // §7 case 2: the router downgrades and goes on in version 0.
    let mut h = querying_cold();
    let actions = h.pdu(response(V0, SID));
    assert_eq!(tags(&actions), ["downgrade v0", "negotiated v0"]);
    assert_eq!(h.s.version(), V0);
    assert_eq!(h.s.negotiated(), Some(V0));
    let actions = h.pdus(&[announce(V0, a()), eod0(SID, 1)]);
    assert_eq!(tags(&actions), ["commit 1 all"]);
    // RFC 6810 has no timing parameters: the RFC 8210 §6 defaults.
    assert_eq!(h.s.intervals(), Intervals::DEFAULT);
    assert_eq!(tags(&h.wait(3_600)), ["serial-query v0 7/1"]);
    // The downgrade holds for this cache: no upgrade on a new connection.
    h.step(Event::Disconnected);
    h.wait(600);
    assert_eq!(tags(&h.step(Event::Connected)), ["serial-query v0 7/1"]);
}

#[test]
fn a_version_0_reply_to_a_serial_query_downgrades_and_reloads() {
    // The query's serial belongs to the version 1 session (§5.1), so the
    // router starts over at once in version 0 (§6: a downgrade may skip
    // the Retry Interval).
    let mut h = disconnected();
    h.wait(600);
    h.step(Event::Connected);
    let actions = h.pdu(response(V0, SID));
    assert_eq!(tags(&actions), ["downgrade v0", "close", "connect"]);
    assert_eq!(h.s.serial(), None);
    assert_eq!(h.vrps(), set(&[a(), b()]), "the data stays until replaced");
    assert_eq!(tags(&h.step(Event::Connected)), ["reset-query v0"]);
    let actions = h.pdus(&[response(V0, SID), announce(V0, a()), eod0(SID, 1)]);
    assert_eq!(tags(&actions), ["negotiated v0", "commit 1 ~1"]);
}

#[test]
fn a_version_0_error_report_downgrades_and_reconnects_at_once() {
    // §7 case 1: "The cache may terminate the connection, perhaps with a
    // version 0 Error Report PDU. In this case, the router MAY retry the
    // connection using protocol version 0."
    for code in [
        ErrorCode::UnsupportedProtocolVersion,
        ErrorCode::InternalError,
        ErrorCode::Unknown(99),
    ] {
        let mut h = querying_cold();
        let actions = h.pdu(report(V0, code));
        assert_eq!(
            tags(&actions),
            ["downgrade v0", "close", "connect"],
            "{code}"
        );
        assert_eq!(h.s.state(), State::Connecting);
        assert_eq!(tags(&h.step(Event::Connected)), ["reset-query v0"]);
    }
}

#[test]
fn unsupported_version_in_version_1_downgrades() {
    let mut h = querying_cold();
    let actions = h.pdu(report(V1, ErrorCode::UnsupportedProtocolVersion));
    assert_eq!(tags(&actions), ["downgrade v0", "close", "connect"]);
    assert_eq!(tags(&h.step(Event::Connected)), ["reset-query v0"]);
    // In version 0 there is nothing lower: fatal.
    let actions = h.pdu(report(V0, ErrorCode::UnsupportedProtocolVersion));
    assert_eq!(tags(&actions), ["close"]);
    assert_eq!(h.s.version(), V0);
}

#[test]
fn no_data_in_version_0_downgrades_and_stays_connected() {
    let mut h = querying_cold();
    let actions = h.pdu(report(V0, ErrorCode::NoDataAvailable));
    assert_eq!(tags(&actions), ["downgrade v0", "negotiated v0"]);
    assert_eq!(h.s.state(), State::Idle);
    assert_eq!(tags(&h.wait(600)), ["reset-query v0"]);
}

#[test]
fn an_error_report_after_negotiation_is_not_a_downgrade() {
    // The version is stable for the life of the session (§7).
    let mut h = idle();
    h.wait(3_600);
    let actions = h.pdu(report(V1, ErrorCode::UnsupportedProtocolVersion));
    assert_eq!(tags(&actions), ["close"]);
    assert_eq!(h.s.version(), V1);
}

#[test]
fn a_version_1_reply_to_a_version_0_query_is_code_8() {
    let v0 = Config {
        version: V0,
        ..Config::default()
    };
    let mut h = H::with(v0);
    h.wait(0);
    assert_eq!(tags(&h.step(Event::Connected)), ["reset-query v0"]);
    let actions = h.pdu(response(V1, SID));
    assert_eq!(tags(&actions), ["report v0 code 8", "close"]);
    // A version 1 notify is ignored like any other during negotiation.
    let mut h = H::with(v0);
    h.wait(0);
    h.step(Event::Connected);
    assert_eq!(h.pdu(notify(V1, SID, 1)), NO_ACTIONS);
}

#[test]
fn a_cache_that_refuses_version_0_is_offered_version_1_next_time() {
    // §7: a version 1 cache may refuse a version 0 query with a version 1
    // Error Report, code 4.
    let mut h = querying_cold();
    h.pdu(report(V0, ErrorCode::InternalError));
    h.step(Event::Connected);
    assert_eq!(h.s.version(), V0);
    let actions = h.pdu(report(V1, ErrorCode::UnsupportedProtocolVersion));
    assert_eq!(tags(&actions), ["close"]);
    assert_eq!(h.s.version(), V1);
    assert_eq!(h.s.state(), State::Disconnected);
    // Not at once: after the Retry Interval.
    assert_eq!(tags(&h.wait(599)), NONE);
    assert_eq!(tags(&h.wait(1)), ["connect"]);
    assert_eq!(tags(&h.step(Event::Connected)), ["reset-query v1"]);

    // Never beyond the configured version.
    let mut h = H::with(Config {
        version: V0,
        ..Config::default()
    });
    h.wait(0);
    h.step(Event::Connected);
    let actions = h.pdu(report(V1, ErrorCode::UnsupportedProtocolVersion));
    assert_eq!(tags(&actions), ["close"]);
    assert_eq!(h.s.version(), V0);
}

#[test]
fn a_pdu_of_another_version_after_negotiation_is_code_8() {
    // §7: drop the session, with an Error Report of code 8 unless the PDU
    // is itself an Error Report.
    let mut h = receiving_reset();
    let bad = announce(V0, a());
    let actions = h.pdu(bad.clone());
    assert_eq!(tags(&actions), ["report v1 code 8", "close"]);
    assert_eq!(reports(&actions)[0].erroneous_pdu(), bad.encode());
    let mut h = receiving_reset();
    assert_eq!(tags(&h.pdu(eod0(SID, 1))), ["report v1 code 8", "close"]);
    let mut h = receiving_reset();
    assert_eq!(
        tags(&h.pdu(report(V0, ErrorCode::NoDataAvailable))),
        ["close"]
    );
    // A Serial Notify of the other version, once settled, as well.
    let mut h = idle();
    assert_eq!(
        tags(&h.pdu(notify(V0, SID, 6))),
        ["report v1 code 8", "close"]
    );
}

// --------------------------------------------------- decoding errors

#[test]
fn decoding_errors_are_reported_and_drop_the_session() {
    let mut h = idle();
    let octets = vec![1, 4, 0, 0, 0, 0, 0, 12];
    let actions = h.step(Event::DecodeError {
        error: RtrError::TooShort {
            pdu_type: 4,
            length: 12,
            min: 20,
        },
        erroneous_pdu: octets.clone(),
    });
    assert_eq!(tags(&actions), ["report v1 code 0", "close"]);
    let r = reports(&actions)[0];
    assert_eq!(r.erroneous_pdu(), octets);
    assert_eq!(
        r.text(),
        "IPv4 Prefix PDU: length 12 is below the minimum of 20"
    );
    assert_eq!(h.s.serial(), None);
    assert_eq!(h.vrps(), set(&[a(), b()]));
    // An unknown version is code 4 (§7).
    let mut h = querying_cold();
    let actions = h.step(Event::DecodeError {
        error: RtrError::UnsupportedVersion {
            version: 2,
            pdu_type: 3,
        },
        erroneous_pdu: vec![2, 3, 0, 7, 0, 0, 0, 8],
    });
    assert_eq!(tags(&actions), ["report v1 code 4", "close"]);
    // No Error Report about an Error Report (§5.11).
    let mut h = idle();
    let actions = h.step(Event::DecodeError {
        error: RtrError::ErrorTextNotUtf8,
        erroneous_pdu: vec![1, 10, 0, 0, 0, 0, 0, 17],
    });
    assert_eq!(tags(&actions), ["close"]);
}

#[test]
fn unexpected_pdus_name_the_state() {
    let mut h = idle();
    let actions = h.pdu(eod(SID, 6));
    assert_eq!(
        reports(&actions)[0].text(),
        "unexpected End of Data PDU while idle"
    );
}

// ------------------------------------------------- RFC 8210 §6 timers

#[test]
fn refresh_and_retry_follow_the_cache() {
    let intervals = Intervals {
        refresh: 120,
        retry: 30,
        expire: 900,
    };
    let mut h = receiving_reset();
    h.pdus(&[announce(V1, a()), eod_with(SID, 1, intervals)]);
    assert_eq!(h.s.intervals(), intervals);
    assert_eq!(h.s.next_deadline(), Some(h.secs(120)));
    assert_eq!(h.s.expires_at(), Some(h.secs(900)));
    assert_eq!(tags(&h.wait(119)), NONE);
    assert_eq!(tags(&h.wait(1)), ["serial-query v1 7/1"]);
    // A failed query waits the cache's Retry Interval.
    h.step(Event::Disconnected);
    assert_eq!(h.s.next_deadline(), Some(h.secs(30)));
    assert_eq!(tags(&h.wait(30)), ["connect"]);
    // The attempt fails: the countdown restarts (§6).
    h.step(Event::Disconnected);
    assert_eq!(tags(&h.wait(30)), ["connect"]);
}

#[test]
fn a_shell_can_pace_reconnects_itself() {
    let mut h = idle();
    // The delay set before a step applies to the failure in that step,
    // and shows in the log line about it.
    h.s.set_retry_delay(Some(Duration::from_secs(2)));
    let actions = h.step(Event::Disconnected);
    assert!(
        logs(&actions)
            .iter()
            .any(|l| l.message == "rtr cache connection lost"
                && field_of(l, "retry_in") == Some("2s"))
    );
    assert_eq!(h.s.next_deadline(), Some(h.secs(2)));
    assert_eq!(tags(&h.wait(1)), NONE);
    assert_eq!(tags(&h.wait(1)), ["connect"]);
    // A new delay does not move a failure already handled.
    h.step(Event::Disconnected);
    h.s.set_retry_delay(Some(Duration::from_secs(60)));
    assert_eq!(h.s.next_deadline(), Some(h.secs(2)));
    assert_eq!(tags(&h.wait(2)), ["connect"]);
    // The serial survives: the delay changes only the timing.
    assert_eq!(tags(&h.step(Event::Connected)), ["serial-query v1 7/5"]);
    // None goes back to the Retry Interval (RFC 8210 §6).
    h.s.set_retry_delay(None);
    let actions = h.step(Event::Disconnected);
    assert!(
        logs(&actions)
            .iter()
            .any(|l| field_of(l, "retry_in") == Some("600s"))
    );
    assert_eq!(h.s.next_deadline(), Some(h.secs(600)));
}

#[test]
fn the_shell_delay_applies_to_every_kind_of_failure() {
    // A protocol error.
    let mut h = idle();
    h.s.set_retry_delay(Some(Duration::from_secs(3)));
    h.pdu(eod(SID, 6));
    assert_eq!(h.s.state(), State::Disconnected);
    assert_eq!(h.s.next_deadline(), Some(h.secs(3)));
    // A connection attempt that times out.
    let mut h = connecting();
    h.s.set_retry_delay(Some(Duration::from_secs(3)));
    assert_eq!(tags(&h.wait(60)), ["close"]);
    assert_eq!(h.s.next_deadline(), Some(h.secs(3)));
    // A cache that stops answering.
    let mut h = querying_cold();
    h.s.set_retry_delay(Some(Duration::from_secs(3)));
    assert_eq!(tags(&h.wait(60)), ["close"]);
    assert_eq!(h.s.next_deadline(), Some(h.secs(3)));
}

#[test]
fn no_data_keeps_the_retry_interval_whatever_the_shell_delay() {
    let mut h = querying_cold();
    h.s.set_retry_delay(Some(Duration::from_secs(1)));
    h.pdu(report(V1, ErrorCode::NoDataAvailable));
    assert_eq!(h.s.state(), State::Idle);
    // RFC 8210 §8.4: periodic Reset Queries on the open connection, at the
    // Retry Interval (§6).
    assert_eq!(h.s.next_deadline(), Some(h.secs(600)));
}

#[test]
fn the_first_connection_can_wait() {
    let now = Instant::now();
    let later = now + Duration::from_secs(5);
    let mut s = Session::new(Config::default(), later);
    assert_eq!(s.next_deadline(), Some(later));
    assert_eq!(tags(&s.step(Event::Tick, now)), NONE);
    assert_eq!(tags(&s.step(Event::Tick, later)), ["connect"]);
}

#[test]
fn intervals_out_of_range_are_ignored() {
    // §6: Refresh 1..=86400, Retry 1..=7200, Expire 600..=172800 and
    // larger than both.
    for bad in [
        Intervals {
            refresh: 0,
            retry: 30,
            expire: 900,
        },
        Intervals {
            refresh: 120,
            retry: 7_201,
            expire: 9_000,
        },
        Intervals {
            refresh: 120,
            retry: 30,
            expire: 599,
        },
        Intervals {
            refresh: 1_000,
            retry: 30,
            expire: 900,
        },
    ] {
        let mut h = receiving_reset();
        let actions = h.pdu(eod_with(SID, 1, bad));
        assert_eq!(h.s.intervals(), Intervals::DEFAULT, "{bad:?}");
        assert!(
            logs(&actions)
                .iter()
                .any(|l| l.level == Level::Warn && l.message.contains("out of range")),
            "{bad:?}"
        );
    }
    // The ones in force stay, not the defaults.
    let good = Intervals {
        refresh: 120,
        retry: 30,
        expire: 900,
    };
    let mut h = receiving_reset();
    h.pdu(eod_with(SID, 1, good));
    h.wait(120);
    h.pdus(&[
        response(V1, SID),
        eod_with(SID, 2, Intervals { refresh: 0, ..good }),
    ]);
    assert_eq!(h.s.intervals(), good);
}

#[test]
fn version_0_uses_the_default_intervals() {
    let mut h = querying_cold();
    h.pdus(&[response(V0, SID), eod0(SID, 1)]);
    assert_eq!(h.s.intervals(), Intervals::DEFAULT);
    assert_eq!(h.s.expires_at(), Some(h.secs(7_200)));
}

#[test]
fn before_any_success_retry_uses_the_default_interval() {
    // §6: "it SHOULD retry periodically using the default Retry Interval".
    let mut h = connecting();
    let actions = h.step(Event::Disconnected);
    assert!(
        logs(&actions)
            .iter()
            .any(|l| l.message == "rtr cache connection failed" && l.level == Level::Warn)
    );
    assert_eq!(h.s.next_deadline(), Some(h.secs(600)));
    assert_eq!(tags(&h.wait(599)), NONE);
    assert_eq!(tags(&h.wait(1)), ["connect"]);
}

#[test]
fn a_silent_cache_times_out_and_the_serial_is_kept() {
    let mut h = querying_serial();
    assert_eq!(tags(&h.wait(59)), NONE);
    assert_eq!(tags(&h.wait(1)), ["close"]);
    assert_eq!(h.s.state(), State::Disconnected);
    assert_eq!(h.s.serial(), Some(5));
    h.wait(600);
    assert_eq!(tags(&h.step(Event::Connected)), ["serial-query v1 7/5"]);
}

#[test]
fn the_response_timer_restarts_with_each_pdu() {
    let mut h = receiving_reset();
    for vrp in [a(), b(), c()] {
        h.now += Duration::from_secs(50);
        assert_eq!(tags(&h.pdu(announce(V1, vrp))), NONE);
        assert_eq!(h.s.state(), State::Receiving);
    }
    assert_eq!(tags(&h.wait(60)), ["close"]);
    assert!(h.s.vrps().is_none(), "half a reply is never committed");
}

#[test]
fn connecting_times_out() {
    let mut h = connecting();
    assert_eq!(tags(&h.wait(59)), NONE);
    assert_eq!(tags(&h.wait(1)), ["close"]);
    assert_eq!(h.s.state(), State::Disconnected);
    assert_eq!(tags(&h.wait(600)), ["connect"]);
}

#[test]
fn next_deadline_is_the_earliest_timer() {
    let mut h = idle();
    assert_eq!(h.s.next_deadline(), Some(h.secs(3_600)));
    h.now += Duration::from_secs(100);
    h.step(Event::Disconnected);
    // Retry at +600 from now; expiry at +7100.
    assert_eq!(h.s.next_deadline(), Some(h.secs(600)));
    assert_eq!(h.s.expires_at(), Some(h.secs(7_100)));
}

#[test]
fn huge_timeouts_do_not_overflow() {
    let mut h = H::with(Config {
        response_timeout: Duration::MAX,
        ..Config::default()
    });
    assert_eq!(tags(&h.wait(0)), ["connect"]);
    assert_eq!(h.s.next_deadline(), None, "past what Instant holds: never");
    assert_eq!(tags(&h.step(Event::Connected)), ["reset-query v1"]);
}

// ------------------------------------------ stale data, issue #57

#[test]
fn stale_data_is_served_until_it_expires() {
    let mut h = idle();
    let t = h.now;
    h.now += Duration::from_secs(100);
    let actions = h.step(Event::Disconnected);
    assert!(logs(&actions).iter().any(|l| l.level == Level::Warn
        && l.message == "rtr cache connection lost"
        && field_of(l, "serving_vrps") == Some("2")
        && field_of(l, "expires_in") == Some("7100s")));
    // Every failed attempt says so again, and the data stays in use.
    let mut attempts = 0;
    while h.now + Duration::from_secs(600) < t + Duration::from_secs(7_200) {
        assert_eq!(tags(&h.wait(600)), ["connect"]);
        let actions = h.step(Event::Disconnected);
        assert!(
            logs(&actions)
                .iter()
                .any(|l| l.level == Level::Warn && field_of(l, "serving_vrps") == Some("2"))
        );
        assert_eq!(h.vrps(), set(&[a(), b()]));
        attempts += 1;
    }
    assert_eq!(attempts, 11);
    // §6: not past the Expire Interval.
    h.now = t + Duration::from_secs(7_199);
    assert_eq!(commits(&h.step(Event::Tick)), NO_COMMITS);
    h.now = t + Duration::from_secs(7_200);
    let actions = h.step(Event::Tick);
    assert_eq!(tags(&actions), ["commit 0 ~2"]);
    assert!(logs(&actions).iter().any(|l| l.level == Level::Error));
    assert!(h.vrps().is_empty());
    assert_eq!(h.s.expires_at(), None);
    // The serial went with the data: the next connection reloads.
    while h.s.state() != State::Connecting {
        h.wait(60);
    }
    assert_eq!(tags(&h.step(Event::Connected)), ["reset-query v1"]);
}

#[test]
fn data_expires_while_the_cache_has_none() {
    let mut h = querying_serial();
    h.pdu(report(V1, ErrorCode::NoDataAvailable));
    let mut flushed = false;
    for _ in 0..12 {
        let actions = h.wait(600);
        if !commits(&actions).is_empty() {
            assert!(h.vrps().is_empty());
            flushed = true;
        }
        h.pdu(report(V1, ErrorCode::NoDataAvailable));
    }
    assert!(flushed);
}

#[test]
fn the_configured_expiry_caps_the_cache_s() {
    let mut h = H::with(Config {
        max_expire: Duration::from_secs(5_000),
        ..Config::default()
    });
    h.wait(0);
    h.step(Event::Connected);
    let actions = h.pdus(&[response(V1, SID), announce(V1, a()), eod(SID, 1)]);
    assert_eq!(h.s.expires_at(), Some(h.secs(5_000)));
    assert!(
        !logs(&actions)
            .iter()
            .any(|l| l.message.contains("before the next poll"))
    );
    // A cache with a shorter Expire Interval wins.
    let short = Intervals {
        refresh: 120,
        retry: 30,
        expire: 900,
    };
    h.wait(3_600);
    h.pdus(&[response(V1, SID), eod_with(SID, 2, short)]);
    assert_eq!(h.s.expires_at(), Some(h.secs(900)));
    // A cap at or below the Refresh Interval lets data lapse between
    // polls: logged.
    let mut h = H::with(Config {
        max_expire: Duration::from_secs(3_600),
        ..Config::default()
    });
    h.wait(0);
    h.step(Event::Connected);
    let actions = h.pdus(&[response(V1, SID), eod(SID, 1)]);
    assert!(
        logs(&actions)
            .iter()
            .any(|l| l.level == Level::Warn && l.message.contains("before the next poll"))
    );
}

#[test]
fn the_configured_expiry_stays_within_the_rfc_range() {
    let s = Session::new(
        Config {
            max_expire: Duration::from_hours(240),
            response_timeout: Duration::ZERO,
            ..Config::default()
        },
        Instant::now(),
    );
    assert_eq!(s.config().max_expire, Config::MAX_EXPIRE);
    assert_eq!(s.config().response_timeout, Duration::from_secs(1));
    let s = Session::new(
        Config {
            max_expire: Duration::from_secs(1),
            ..Config::default()
        },
        Instant::now(),
    );
    assert_eq!(s.config().max_expire, Config::MIN_EXPIRE);
    assert_eq!(Config::MAX_EXPIRE.as_secs(), 172_800);
}

#[test]
fn expiry_during_a_serial_reply_reloads() {
    let intervals = Intervals {
        refresh: 600,
        retry: 60,
        expire: 700,
    };
    let mut h = receiving_reset();
    h.pdus(&[announce(V1, a()), eod_with(SID, 1, intervals)]);
    assert_eq!(tags(&h.wait(600)), ["serial-query v1 7/1"]);
    h.now += Duration::from_secs(50);
    h.pdu(response(V1, SID));
    // The data expires half-way through the reply.
    let actions = h.wait(50);
    assert_eq!(tags(&actions), ["commit 0 ~1"]);
    assert_eq!(h.s.state(), State::Receiving);
    // The rest of the reply has nothing to update: no code 6 for a
    // withdrawal of what is gone, nothing committed, and a reload.
    assert_eq!(tags(&h.pdu(withdraw(V1, a()))), NONE);
    assert_eq!(tags(&h.pdu(eod(SID, 2))), ["reset-query v1"]);
    let actions = h.pdus(&[response(V1, SID), announce(V1, b()), eod(SID, 2)]);
    assert_eq!(tags(&actions), ["commit 1 ~1"]);
}

#[test]
fn expiry_while_a_serial_query_is_out_reloads() {
    let intervals = Intervals {
        refresh: 600,
        retry: 60,
        expire: 650,
    };
    let mut h = receiving_reset();
    h.pdus(&[announce(V1, a()), eod_with(SID, 1, intervals)]);
    h.wait(600);
    assert_eq!(tags(&h.wait(50)), ["commit 0 ~1"]);
    let actions = h.pdus(&[response(V1, SID), announce(V1, b()), eod(SID, 2)]);
    assert_eq!(tags(&actions), ["reset-query v1"]);
    assert!(h.vrps().is_empty());
    // A Cache Reset is a reload anyway.
    let mut h = receiving_reset();
    h.pdus(&[announce(V1, a()), eod_with(SID, 1, intervals)]);
    h.wait(600);
    h.wait(50);
    assert_eq!(
        tags(&h.pdu(Pdu::CacheReset { version: V1 })),
        ["reset-query v1"]
    );
}

// ---------------------------------------------------------- odds and ends

#[test]
fn router_keys_are_accepted_and_ignored() {
    // RFC 8210 §5.10; RFC 8205 is out of scope.
    let mut h = receiving_reset();
    let actions = h.pdus(&[router_key(), announce(V1, a()), router_key(), eod(SID, 1)]);
    assert_eq!(tags(&actions), ["commit 1 all"]);
    let mut h = receiving_serial();
    let actions = h.pdus(&[router_key(), eod(SID, 6)]);
    assert_eq!(tags(&actions), NONE);
}

#[test]
fn connected_while_connected_starts_over() {
    let mut h = receiving_serial();
    h.pdu(withdraw(V1, a()));
    let actions = h.step(Event::Connected);
    assert_eq!(tags(&actions), ["serial-query v1 7/5"]);
    assert_eq!(h.s.negotiated(), None);
    // The staged withdrawal went with the old connection.
    let actions = h.pdus(&[response(V1, SID), withdraw(V1, b()), eod(SID, 6)]);
    assert_eq!(tags(&actions), ["negotiated v1", "commit 1 ~1"]);
    assert_eq!(h.vrps(), set(&[a()]));
}

#[test]
fn a_commit_is_a_validation_change() {
    let mut h = receiving_reset();
    let actions = h.pdus(&[announce(V1, a()), eod(SID, 1)]);
    let commit = commits(&actions)[0].clone();
    let change: ValidationChange = commit.clone().into();
    assert_eq!(change.affected, AffectedPrefixes::All);
    assert_eq!(
        change
            .source
            .rov(a().prefix(), RouteOrigin::As(Asn(64_496))),
        RovState::Valid
    );
    assert_eq!(
        change
            .source
            .rov(a().prefix(), RouteOrigin::As(Asn(64_499))),
        RovState::Invalid
    );
    assert_eq!(commit.into_change().affected, AffectedPrefixes::All);
}

#[test]
fn log_lines_and_states_print() {
    let line = LogLine {
        level: Level::Trace,
        message: "test",
        fields: vec![("k", "v".to_owned())],
    };
    // The logger is off in tests: this only runs the plumbing.
    line.write(&[("cache", &"192.0.2.1:323")]);
    let names: Vec<String> = [
        State::Disconnected,
        State::Connecting,
        State::Querying,
        State::Receiving,
        State::Idle,
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    assert_eq!(
        names,
        [
            "disconnected",
            "connecting",
            "querying",
            "receiving",
            "idle"
        ]
    );
}

//! The client thread against an in-process cache: a `TcpListener` on the
//! loopback that each test drives PDU by PDU through the sequences of
//! RFC 8210 §8, with millisecond back-offs and a clock the test moves
//! forward to reach the Expire Interval (§6). The pure parts, the back-off
//! and the cache list, come first and also run under Miri, which has no
//! sockets.

use std::collections::HashSet;
use std::time::Duration;

use super::*;

const MS: Duration = Duration::from_millis(1);
const SEC: Duration = Duration::from_secs(1);

fn null_sink() -> impl ValidationSink {
    |_: ValidationChange| -> Result<(), bgpfc_rpki::RpkiError> { Ok(()) }
}

/// The delay before the jitter, as the [`Backoff`] docs give it.
fn nominal(backoff: Backoff, failures: u32) -> Duration {
    let doublings = failures.saturating_sub(1).min(40);
    backoff
        .min
        .checked_mul(1 << doublings.min(31))
        .map_or(backoff.max, |d| d.min(backoff.max))
}

// ------------------------------------------------------------ back-off

#[test]
fn the_back_off_doubles_up_to_its_bound() {
    let backoff = Backoff::DEFAULT;
    assert_eq!(nominal(backoff, 0), SEC);
    assert_eq!(nominal(backoff, 1), SEC);
    assert_eq!(nominal(backoff, 2), 2 * SEC);
    assert_eq!(nominal(backoff, 10), 512 * SEC);
    assert_eq!(nominal(backoff, 11), 600 * SEC);
    for seed in [0, 1, 0xDEAD_BEEF, u64::MAX] {
        for failures in [0, 1, 2, 3, 9, 10, 11, 12, 31, 32, 33, 1_000, u32::MAX] {
            let delay = backoff.delay(failures, seed);
            let nominal = nominal(backoff, failures);
            // The jitter only lengthens, by less than half.
            assert!(delay >= nominal, "{failures} failures: {delay:?}");
            assert!(delay < nominal * 3 / 2, "{failures} failures: {delay:?}");
        }
    }
}

#[test]
fn the_jitter_is_fixed_by_the_seed_and_differs_between_seeds() {
    let backoff = Backoff::DEFAULT;
    for failures in 0..20 {
        assert_eq!(backoff.delay(failures, 42), backoff.delay(failures, 42));
    }
    // A hundred routers that lost the cache at the same moment spread
    // their third attempt over most of [4 s, 6 s).
    let delays: HashSet<Duration> = (0..100).map(|seed| backoff.delay(3, seed)).collect();
    assert!(delays.len() > 95);
    let first = delays.iter().min().copied().unwrap_or_default();
    let last = delays.iter().max().copied().unwrap_or_default();
    assert!(first < 4_200 * MS, "{first:?}");
    assert!(last > 5_800 * MS, "{last:?}");
    // One router does not repeat the same fraction attempt after attempt.
    let fractions: HashSet<Duration> = (12..40).map(|n| backoff.delay(n, 7)).collect();
    assert!(fractions.len() > 25);
}

#[test]
fn back_off_bounds_are_made_sane() {
    // A zero minimum would reconnect in a tight loop.
    let zero = Backoff {
        min: Duration::ZERO,
        max: Duration::ZERO,
    };
    for failures in 0..5 {
        let delay = zero.delay(failures, 3);
        assert!(delay >= MS && delay < MS * 3 / 2, "{delay:?}");
    }
    // A maximum below the minimum is the minimum.
    let inverted = Backoff {
        min: 10 * SEC,
        max: SEC,
    };
    let delay = inverted.delay(8, 3);
    assert!(delay >= 10 * SEC && delay < 15 * SEC, "{delay:?}");
    // Huge values saturate rather than overflow.
    let huge = Backoff {
        min: Duration::MAX,
        max: Duration::MAX,
    };
    assert_eq!(huge.delay(7, 3), Duration::MAX);
    assert_eq!(Backoff::default(), Backoff::DEFAULT);
}

// ---------------------------------------------------------- the caches

#[test]
fn caches_print_as_host_and_port() {
    assert_eq!(Cache::new("192.0.2.1").to_string(), "192.0.2.1:323");
    assert_eq!(Cache::new("2001:db8::1").to_string(), "[2001:db8::1]:323");
    let named = Cache {
        port: 3323,
        ..Cache::new("rtr.example.net")
    };
    assert_eq!(named.to_string(), "rtr.example.net:3323");
}

#[test]
fn defaults_follow_rfc_8210() {
    // §9: the rpki-rtr port.
    assert_eq!(DEFAULT_PORT, 323);
    let cache = Cache::new("192.0.2.1");
    assert_eq!((cache.port, cache.preference), (323, 0));
    let config = Config::new(vec![cache.clone()]);
    assert_eq!(config.caches, [cache]);
    assert_eq!(config.connect_timeout, 10 * SEC);
    assert_eq!(config.backoff, Backoff::DEFAULT);
    assert_eq!(config.jitter_seed, 0);
    assert_eq!(config.session, session::Config::default());
}

#[test]
fn caches_are_tried_in_order_of_preference() {
    let cache = |host: &str, preference| Cache {
        preference,
        ..Cache::new(host)
    };
    let config = Config::new(vec![
        cache("c", 30),
        cache("a1", 10),
        cache("b", 20),
        cache("a2", 10),
    ]);
    let worker = Worker::new(
        config,
        null_sink(),
        Arc::new(Shared::default()),
        Clock::default(),
    );
    // RFC 8210 §10: lower is more preferred; ties keep their order.
    let hosts: Vec<&str> = worker.caches.iter().map(|c| c.host.as_str()).collect();
    assert_eq!(hosts, ["a1", "a2", "b", "c"]);
    let status = lock(&worker.status).clone();
    assert_eq!(status.cache.host, "a1");
    assert_eq!(status.state, State::Disconnected);
    assert!(status.running && !status.connected);
}

#[test]
fn the_connect_timeout_fits_the_response_timeout() {
    let mut config = Config::new(vec![Cache::new("192.0.2.1")]);
    config.connect_timeout = Duration::from_secs(600);
    let worker = Worker::new(
        config.clone(),
        null_sink(),
        Arc::new(Shared::default()),
        Clock::default(),
    );
    assert_eq!(worker.connect_timeout, 60 * SEC);
    config.connect_timeout = Duration::ZERO;
    let worker = Worker::new(
        config,
        null_sink(),
        Arc::new(Shared::default()),
        Clock::default(),
    );
    assert_eq!(worker.connect_timeout, MS);
}

#[test]
fn a_client_needs_a_cache() {
    let error = Client::start(Config::new(Vec::new()), null_sink()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
}

#[test]
fn durations_print_for_people() {
    assert_eq!(Millis(5 * MS).to_string(), "5ms");
    assert_eq!(Millis(1_250 * MS).to_string(), "1.2s");
    assert_eq!(Millis(600 * SEC).to_string(), "600.0s");
}

// ------------------------------------------------- against a real cache

/// Miri has no sockets.
#[cfg(not(miri))]
mod net {
    use std::io::{ErrorKind, Read as _, Write as _};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc::{self, Receiver, Sender};
    use std::thread;

    use bgpfc_rpki::{RouteOrigin, RovState, ValidationChange, Vrp, VrpSet};
    use bgpfc_wire::types::Asn;

    use super::*;
    use crate::error::ErrorCode;
    use crate::pdu::{ErrorReport, Intervals};

    /// How long a test waits for the client before it fails.
    const WAIT: Duration = Duration::from_secs(5);
    const V0: Version = Version::V0;
    const V1: Version = Version::V1;
    const SID: u16 = 7;

    /// Short, but within RFC 8210 §6: the Expire Interval cannot go below
    /// ten minutes, which the tests reach by moving the clock.
    const INTERVALS: Intervals = Intervals {
        refresh: 300,
        retry: 60,
        expire: 600,
    };

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

    fn eod(session_id: u16, serial: u32) -> Pdu {
        Pdu::EndOfData {
            session_id,
            serial,
            intervals: Some(INTERVALS),
        }
    }

    fn notify(session_id: u16, serial: u32) -> Pdu {
        Pdu::SerialNotify {
            version: V1,
            session_id,
            serial,
        }
    }

    fn serial_query(session_id: u16, serial: u32) -> Pdu {
        Pdu::SerialQuery {
            version: V1,
            session_id,
            serial,
        }
    }

    const RESET_V1: Pdu = Pdu::ResetQuery { version: V1 };

    /// The validation state `change` gives a route.
    fn rov(change: &ValidationChange, prefix: &str, asn: u32) -> RovState {
        change
            .source
            .rov(prefix.parse().unwrap(), RouteOrigin::As(Asn(asn)))
    }

    fn covers(change: &ValidationChange, prefix: &str) -> bool {
        change.affected.covers(prefix.parse().unwrap())
    }

    /// Poll until `done` holds, for at most [`WAIT`].
    fn eventually(what: &str, mut done: impl FnMut() -> bool) {
        let deadline = Instant::now() + WAIT;
        while !done() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            thread::sleep(MS);
        }
    }

    fn next_change(rx: &Receiver<ValidationChange>) -> ValidationChange {
        rx.recv_timeout(WAIT).expect("a validation change")
    }

    /// A cache on the loopback, driven by the test.
    struct TestCache {
        listener: TcpListener,
    }

    impl TestCache {
        fn new() -> TestCache {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            TestCache { listener }
        }

        /// Its entry in the client's cache list.
        fn entry(&self, preference: u32) -> Cache {
            Cache {
                host: "127.0.0.1".to_owned(),
                port: self.listener.local_addr().unwrap().port(),
                preference,
            }
        }

        /// The client's next connection.
        fn accept(&self) -> Router {
            let deadline = Instant::now() + WAIT;
            loop {
                match self.listener.accept() {
                    Ok((stream, _)) => {
                        stream.set_nonblocking(false).unwrap();
                        stream.set_read_timeout(Some(WAIT)).unwrap();
                        return Router {
                            stream,
                            framer: Framer::new(),
                        };
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "the client did not connect");
                        thread::sleep(MS);
                    }
                    Err(e) => panic!("accept: {e}"),
                }
            }
        }

        /// Whether the client leaves the cache alone for `period`.
        fn quiet_for(&self, period: Duration) -> bool {
            let deadline = Instant::now() + period;
            while Instant::now() < deadline {
                if self.listener.accept().is_ok() {
                    return false;
                }
                thread::sleep(MS);
            }
            true
        }
    }

    /// The cache's end of a connection from the client.
    struct Router {
        stream: TcpStream,
        framer: Framer,
    }

    impl Router {
        /// The next PDU from the client.
        fn recv(&mut self) -> Pdu {
            loop {
                if let Some(pdu) = self.framer.next_pdu().expect("a well-formed PDU") {
                    return pdu;
                }
                let mut buf = [0; 4096];
                let n = self.stream.read(&mut buf).expect("a PDU from the client");
                assert!(n > 0, "the client closed the connection");
                self.framer.feed(&buf[..n]);
            }
        }

        fn send(&mut self, pdus: &[Pdu]) {
            let mut octets = Vec::new();
            for pdu in pdus {
                pdu.encode_into(&mut octets);
            }
            self.send_raw(&octets);
        }

        fn send_raw(&mut self, octets: &[u8]) {
            self.stream.write_all(octets).unwrap();
        }

        /// Answer a Reset Query with `vrps` at `serial`.
        fn serve_reset(&mut self, session_id: u16, serial: u32, vrps: &[Vrp]) {
            assert_eq!(self.recv(), RESET_V1);
            let mut pdus = vec![response(V1, session_id)];
            pdus.extend(vrps.iter().map(|&v| announce(V1, v)));
            pdus.push(eod(session_id, serial));
            self.send(&pdus);
        }

        /// The client closes the connection and sends nothing more.
        fn expect_close(&mut self) {
            assert_eq!(self.framer.buffered(), 0, "unread octets from the client");
            let mut buf = [0; 64];
            match self.stream.read(&mut buf) {
                Ok(0) => {}
                Ok(n) => panic!("the client sent {n} more octets"),
                Err(e) if e.kind() == ErrorKind::ConnectionReset => {}
                Err(e) => panic!("the client did not close the connection: {e}"),
            }
        }
    }

    fn config(caches: Vec<Cache>) -> Config {
        Config {
            caches,
            connect_timeout: SEC,
            backoff: Backoff {
                min: 5 * MS,
                max: 40 * MS,
            },
            jitter_seed: 1,
            session: session::Config {
                response_timeout: SEC,
                ..session::Config::default()
            },
            check: None,
        }
    }

    fn start(caches: Vec<Cache>) -> (Client, Receiver<ValidationChange>) {
        start_with(config(caches))
    }

    fn start_with(config: Config) -> (Client, Receiver<ValidationChange>) {
        let (tx, rx): (Sender<ValidationChange>, _) = mpsc::channel();
        (Client::start(config, tx).unwrap(), rx)
    }

    /// A client in sync with `cache` at serial 1, holding {a, b}.
    fn in_sync(cache: &TestCache) -> (Client, Receiver<ValidationChange>, Router) {
        let (client, rx) = start(vec![cache.entry(0)]);
        let mut router = cache.accept();
        router.serve_reset(SID, 1, &[a(), b()]);
        let change = next_change(&rx);
        assert_eq!(change.affected, AffectedPrefixes::All);
        eventually("the client to be in sync", || {
            client.status().synced_at.is_some()
        });
        (client, rx, router)
    }

    #[test]
    fn cold_start_publishes_the_whole_set() {
        let cache = TestCache::new();
        let (mut client, rx) = start(vec![cache.entry(5)]);
        let mut router = cache.accept();
        // RFC 8210 §8.1: no data yet, so a Reset Query, in version 1 (§7).
        router.serve_reset(SID, 1, &[a(), b()]);
        let change = next_change(&rx);
        // The first set replaces the RIB's NullSource: every route.
        assert_eq!(change.affected, AffectedPrefixes::All);
        assert_eq!(rov(&change, "192.0.2.0/24", 64_496), RovState::Valid);
        assert_eq!(rov(&change, "192.0.2.0/24", 64_497), RovState::Invalid);
        assert_eq!(rov(&change, "2001:db8:5::/48", 64_497), RovState::Valid);
        assert_eq!(rov(&change, "203.0.113.0/24", 64_496), RovState::NotFound);
        eventually("the status", || client.status().state == State::Idle);
        let status = client.status();
        assert_eq!(status.cache, cache.entry(5));
        assert_eq!(status.source, Some(cache.entry(5)));
        assert!(status.connected && status.running);
        assert_eq!(status.version, V1);
        assert_eq!((status.session_id, status.serial), (Some(SID), Some(1)));
        assert_eq!((status.vrps_ipv4, status.vrps_ipv6), (1, 1));
        assert_eq!(status.vrps.as_deref(), Some(&set(&[a(), b()])));
        assert!(status.synced_at.is_some() && status.last_commit.is_some());
        let expires = status.expires_at.unwrap() - status.synced_at.unwrap();
        assert_eq!(
            expires,
            Duration::from_secs(600),
            "the cache's Expire Interval"
        );
        assert_eq!(status.failures, 0);
        assert_eq!(status.last_error, None);
        client.stop();
        router.expect_close();
        assert!(!client.status().running);
        assert!(rx.try_recv().is_err(), "nothing more was published");
    }

    #[test]
    fn serial_notify_brings_an_incremental_update() {
        let cache = TestCache::new();
        let (client, rx, mut router) = in_sync(&cache);
        // RFC 8210 §8.2: Serial Notify, then a Serial Query from serial 1.
        router.send(&[notify(SID, 2)]);
        assert_eq!(router.recv(), serial_query(SID, 1));
        router.send(&[
            response(V1, SID),
            withdraw(V1, a()),
            announce(V1, c()),
            eod(SID, 2),
        ]);
        let change = next_change(&rx);
        // Only the changed prefixes are validated again (issue #59).
        assert!(covers(&change, "192.0.2.0/24") && covers(&change, "198.51.100.0/24"));
        assert!(!covers(&change, "2001:db8::/32"));
        assert_eq!(rov(&change, "192.0.2.0/24", 64_496), RovState::NotFound);
        assert_eq!(rov(&change, "198.51.100.0/24", 64_498), RovState::Valid);
        assert_eq!(rov(&change, "2001:db8::/48", 64_497), RovState::Valid);
        eventually("serial 2", || client.status().serial == Some(2));
        assert_eq!(client.status().vrps.as_deref(), Some(&set(&[b(), c()])));
    }

    #[test]
    fn cache_reset_brings_a_full_reload() {
        let cache = TestCache::new();
        let (client, rx, mut router) = in_sync(&cache);
        router.send(&[notify(SID, 9)]);
        assert_eq!(router.recv(), serial_query(SID, 1));
        // RFC 8210 §8.3: the cache cannot go on from serial 1; the router
        // reloads with a Reset Query.
        router.send(&[Pdu::CacheReset { version: V1 }]);
        router.serve_reset(SID, 9, &[a(), c()]);
        let change = next_change(&rx);
        // The old and new sets differ in b and c only.
        assert!(covers(&change, "2001:db8::/32") && covers(&change, "198.51.100.0/24"));
        assert!(!covers(&change, "192.0.2.0/24"));
        assert_eq!(rov(&change, "2001:db8::/48", 64_497), RovState::NotFound);
        eventually("serial 9", || client.status().serial == Some(9));
    }

    #[test]
    fn the_client_reconnects_when_the_cache_closes_the_connection() {
        let cache = TestCache::new();
        let (client, rx, router) = in_sync(&cache);
        // The validator restarts: the connection closes, and the next few
        // close again before an answer.
        drop(router);
        for _ in 0..3 {
            let mut router = cache.accept();
            // RFC 8210 §8.1: unexpired data from a broken session with the
            // same cache: a Serial Query.
            assert_eq!(router.recv(), serial_query(SID, 1));
        }
        // The data stays in use meanwhile (§10, issue #57).
        let status = client.status();
        assert_eq!(status.vrps.as_deref(), Some(&set(&[a(), b()])));
        assert!(status.failures >= 2, "{}", status.failures);
        assert!(status.last_error.is_some());
        let mut router = cache.accept();
        assert_eq!(router.recv(), serial_query(SID, 1));
        router.send(&[response(V1, SID), eod(SID, 1)]);
        eventually("the client to be back in sync", || {
            let status = client.status();
            status.connected && status.state == State::Idle
        });
        // Nothing changed, so nothing is published.
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn a_sync_ends_the_run_of_failures() {
        let cache = TestCache::new();
        let (client, rx) = start(vec![cache.entry(0)]);
        // The cache drops the first connections before it answers.
        for _ in 0..3 {
            drop(cache.accept());
        }
        let mut router = cache.accept();
        eventually("three failures", || client.status().failures == 3);
        router.serve_reset(SID, 1, &[a()]);
        next_change(&rx);
        eventually("in sync, the failures behind it", || {
            let status = client.status();
            status.synced_at.is_some() && status.failures == 0
        });
        // An error long after: the first failure of a new run, which waits
        // the shortest back-off (Backoff).
        router.send_raw(&[
            1, 4, 0, 0, 0, 0, 0, 20, 1, 33, 33, 0, 192, 0, 2, 0, 0, 0, 0xFB, 0xF0,
        ]);
        assert!(matches!(router.recv(), Pdu::ErrorReport(_)));
        router.expect_close();
        eventually("one failure", || client.status().failures == 1);
        let mut router = cache.accept();
        assert_eq!(router.recv(), RESET_V1);
    }

    #[test]
    fn a_version_0_cache_that_refuses_version_1_gets_version_0() {
        let cache = TestCache::new();
        let (client, rx) = start(vec![cache.entry(0)]);
        let mut router = cache.accept();
        assert_eq!(router.recv(), RESET_V1);
        // RFC 8210 §7: "The cache may terminate the connection, perhaps
        // with a version 0 Error Report PDU. In this case, the router MAY
        // retry the connection using protocol version 0."
        let query = RESET_V1.encode();
        router.send(&[Pdu::ErrorReport(ErrorReport::new(
            V0,
            ErrorCode::UnsupportedProtocolVersion,
            &query,
            "version 0 only",
        ))]);
        drop(router);
        let mut router = cache.accept();
        assert_eq!(router.recv(), Pdu::ResetQuery { version: V0 });
        router.send(&[
            response(V0, SID),
            announce(V0, a()),
            Pdu::EndOfData {
                session_id: SID,
                serial: 1,
                intervals: None,
            },
        ]);
        let change = next_change(&rx);
        assert_eq!(change.affected, AffectedPrefixes::All);
        assert_eq!(rov(&change, "192.0.2.0/24", 64_496), RovState::Valid);
        eventually("version 0 in sync", || client.status().synced_at.is_some());
        let status = client.status();
        assert_eq!(status.version, V0);
        // Version 0 takes the RFC 8210 §6 defaults: expiry after 7200 s.
        let expires = status.expires_at.unwrap() - status.synced_at.unwrap();
        assert_eq!(expires, Duration::from_secs(7_200));
    }

    #[test]
    fn a_version_0_reply_downgrades_on_the_same_connection() {
        let cache = TestCache::new();
        let (client, rx) = start(vec![cache.entry(0)]);
        let mut router = cache.accept();
        assert_eq!(router.recv(), RESET_V1);
        // RFC 8210 §7: "The cache may reply with a version 0 response. In
        // this case, the router MUST either downgrade to version 0 or
        // terminate the connection."
        router.send(&[
            response(V0, SID),
            announce(V0, c()),
            Pdu::EndOfData {
                session_id: SID,
                serial: 3,
                intervals: None,
            },
        ]);
        let change = next_change(&rx);
        assert_eq!(rov(&change, "198.51.100.0/24", 64_498), RovState::Valid);
        eventually("version 0 in sync", || client.status().serial == Some(3));
        let status = client.status();
        assert_eq!(status.version, V0);
        assert!(status.connected);
        // The next query is a version 0 one on the same connection.
        router.send(&[Pdu::SerialNotify {
            version: V0,
            session_id: SID,
            serial: 4,
        }]);
        assert_eq!(
            router.recv(),
            Pdu::SerialQuery {
                version: V0,
                session_id: SID,
                serial: 3
            }
        );
    }

    #[test]
    fn garbage_gets_an_error_report_and_a_fresh_start() {
        let cache = TestCache::new();
        let (client, rx) = start(vec![cache.entry(0)]);
        let mut router = cache.accept();
        assert_eq!(router.recv(), RESET_V1);
        // Not RTR at all: "G" is no protocol version the router knows.
        router.send_raw(b"GET / HTTP/1.1\r\n\r\n");
        // RFC 8210 §7, §12: Unsupported Protocol Version (4), with the
        // header in error (§5.11), then the session is dropped.
        let Pdu::ErrorReport(report) = router.recv() else {
            panic!("an Error Report");
        };
        assert_eq!(report.version(), V1);
        assert_eq!(report.code(), ErrorCode::UnsupportedProtocolVersion);
        assert_eq!(report.erroneous_pdu(), b"GET / HT");
        router.expect_close();

        // The client comes back, and gets data.
        let mut router = cache.accept();
        router.serve_reset(SID, 1, &[a()]);
        next_change(&rx);
        eventually("the client to be in sync", || {
            client.status().synced_at.is_some()
        });

        // An IPv4 Prefix PDU with a prefix length of 33 (RFC 8210 §5.6:
        // 0..32): Corrupt Data, with the whole PDU in error.
        let bad = [
            1, 4, 0, 0, 0, 0, 0, 20, 1, 33, 33, 0, 192, 0, 2, 0, 0, 0, 0xFB, 0xF0,
        ];
        router.send_raw(&bad);
        let Pdu::ErrorReport(report) = router.recv() else {
            panic!("an Error Report");
        };
        assert_eq!(report.code(), ErrorCode::CorruptData);
        assert_eq!(report.erroneous_pdu(), bad);
        router.expect_close();
        // A fatal error keeps the data until it expires (§10) ...
        assert!(rx.try_recv().is_err());
        assert_eq!(client.status().vrps.as_deref(), Some(&set(&[a()])));
        // ... but forgets the serial: the next connection starts afresh
        // (§8.1).
        let mut router = cache.accept();
        assert_eq!(router.recv(), RESET_V1);

        // An Error Report whose encapsulated PDU runs past its end: no
        // Error Report goes back about an Error Report (§5.11).
        router.send_raw(&[1, 10, 0, 0, 0, 0, 0, 16, 0, 0, 0, 100, 0, 0, 0, 0]);
        router.expect_close();
        let mut router = cache.accept();
        assert_eq!(router.recv(), RESET_V1);

        let status = client.status();
        assert!(status.running, "the client never gives up");
        assert!(status.failures >= 2, "{}", status.failures);
        let error = status.last_error.unwrap();
        assert!(error.contains("rtr malformed PDU"), "{error}");
    }

    #[test]
    fn an_error_report_from_the_cache_drops_the_session_without_a_reply() {
        let cache = TestCache::new();
        let (client, _rx, mut router) = in_sync(&cache);
        router.send(&[notify(SID, 2)]);
        assert_eq!(router.recv(), serial_query(SID, 1));
        // RFC 8210 §12: Internal Error is fatal; §5.11: no report back.
        router.send(&[Pdu::ErrorReport(ErrorReport::new(
            V1,
            ErrorCode::InternalError,
            &[],
            "disk full",
        ))]);
        router.expect_close();
        let mut router = cache.accept();
        assert_eq!(router.recv(), RESET_V1);
        let error = client.status().last_error.unwrap();
        assert!(error.contains("disk full"), "{error}");
    }

    #[test]
    fn the_last_error_quotes_what_the_cache_wrote() {
        // RFC 8210 §5.11: the Error Text is any UTF-8, so a newline, a line
        // of its own after it, or a terminal escape. The last error reads
        // as the log line does: such a value quoted and escaped.
        let cache = TestCache::new();
        let (client, _rx, mut router) = in_sync(&cache);
        router.send(&[Pdu::ErrorReport(ErrorReport::new(
            V1,
            ErrorCode::InternalError,
            &[],
            "boom\n.\nstate idle\u{1b}[2J",
        ))]);
        router.expect_close();
        let _router = cache.accept();
        let error = client.status().last_error.unwrap();
        assert!(!error.chars().any(char::is_control), "{error:?}");
        assert!(
            error.starts_with("rtr cache reported an error; dropping the session cache=127.0.0.1:"),
            "{error}"
        );
        assert!(
            error.ends_with(
                r#" code="Internal Error (1)" version=1 text="boom\n.\nstate idle\u{001b}[2J""#
            ),
            "{error}"
        );
    }

    #[test]
    fn data_expires_when_no_cache_answers() {
        let cache = TestCache::new();
        let (client, rx, router) = in_sync(&cache);
        drop(router);
        let mut router = cache.accept();
        assert_eq!(router.recv(), serial_query(SID, 1));
        // The cache never answers, and ten minutes pass: RFC 8210 §6, "The
        // router MUST NOT retain the data past the time indicated by" the
        // Expire Interval.
        client.advance(Duration::from_secs(601));
        // Wake the client's read; the PDU itself does not matter.
        router.send(&[notify(SID, 2)]);
        let change = next_change(&rx);
        assert!(covers(&change, "192.0.2.0/24") && covers(&change, "2001:db8::/32"));
        assert_eq!(rov(&change, "192.0.2.0/24", 64_496), RovState::NotFound);
        assert_eq!(rov(&change, "192.0.2.0/24", 64_497), RovState::NotFound);
        eventually("the status to show no data", || {
            let status = client.status();
            status.vrps_ipv4 == 0 && status.vrps_ipv6 == 0 && status.expires_at.is_none()
        });
        assert_eq!(client.status().vrps.as_deref(), Some(&VrpSet::new()));
        // Without data, the next connection starts with a Reset Query.
        let mut router = cache.accept();
        assert_eq!(router.recv(), RESET_V1);
    }

    #[test]
    fn caches_fail_over_in_order_of_preference() {
        let first = TestCache::new();
        let second = TestCache::new();
        // Configured out of order; preference decides (RFC 8210 §10).
        let (client, rx) = start(vec![second.entry(20), first.entry(10)]);
        // The preferred cache drops the connection before answering.
        drop(first.accept());
        let mut router = second.accept();
        router.serve_reset(SID, 1, &[a(), b()]);
        let change = next_change(&rx);
        assert_eq!(change.affected, AffectedPrefixes::All);
        eventually("the second cache in use", || {
            let status = client.status();
            status.cache == second.entry(20) && status.synced_at.is_some()
        });
        // The second cache goes away after it was in sync: back to the
        // most preferred one, which starts a session of its own.
        drop(router);
        let mut router = first.accept();
        assert_eq!(router.recv(), RESET_V1);
        // Until the first cache has sent a full set, the second cache's
        // data stays in use (§10), and the status says where it came from.
        assert!(rx.try_recv().is_err());
        let status = client.status();
        assert_eq!(status.vrps.as_deref(), Some(&set(&[a(), b()])));
        assert_eq!(status.cache, first.entry(10));
        assert_eq!(status.source, Some(second.entry(20)));
        router.send(&[
            response(V1, 9),
            announce(V1, a()),
            announce(V1, c()),
            eod(9, 1),
        ]);
        let change = next_change(&rx);
        // The new set replaces the old one whole, and only the routes the
        // two disagree on are validated again.
        assert!(covers(&change, "2001:db8::/32") && covers(&change, "198.51.100.0/24"));
        assert!(!covers(&change, "192.0.2.0/24"));
        assert_eq!(rov(&change, "2001:db8::/48", 64_497), RovState::NotFound);
        assert_eq!(rov(&change, "198.51.100.0/24", 64_498), RovState::Valid);
        eventually("the first cache in use", || {
            let status = client.status();
            status.cache == first.entry(10) && status.session_id == Some(9)
        });
        assert_eq!(client.status().source, Some(first.entry(10)));
    }

    #[test]
    fn data_held_over_from_the_previous_cache_expires() {
        let first = TestCache::new();
        let second = TestCache::new();
        let (client, rx) = start(vec![first.entry(1), second.entry(2)]);
        drop(first.accept());
        let mut router = second.accept();
        router.serve_reset(SID, 1, &[a()]);
        next_change(&rx);
        eventually("the second cache in sync", || {
            client.status().synced_at.is_some()
        });
        drop(router);
        // The first cache takes the connection and never answers.
        let mut router = first.accept();
        assert_eq!(router.recv(), RESET_V1);
        assert!(
            client.status().expires_at.is_some(),
            "the held data expires"
        );
        client.advance(Duration::from_secs(601));
        router.send(&[notify(9, 1)]);
        // RFC 8210 §6: not past the Expire Interval, whichever cache the
        // client talks to now.
        let change = next_change(&rx);
        assert!(covers(&change, "192.0.2.0/24"));
        assert_eq!(rov(&change, "192.0.2.0/24", 64_496), RovState::NotFound);
        eventually("the status to show no data", || {
            client.status().vrps.as_deref() == Some(&VrpSet::new())
        });
        assert!(client.status().last_error.unwrap().contains("expired"));
        assert_eq!(client.status().source, None, "no cache's data is in use");
    }

    /// A client of `cache` that takes over `held`.
    fn start_holding(cache: &TestCache, held: Held) -> (Client, Receiver<ValidationChange>) {
        let (tx, rx): (Sender<ValidationChange>, _) = mpsc::channel();
        let config = config(vec![cache.entry(0)]);
        (Client::start_holding(config, tx, Some(held)).unwrap(), rx)
    }

    #[test]
    fn a_new_client_keeps_the_old_one_s_data_until_a_cache_sends_a_full_set() {
        // A reconfiguration: the client in sync with one cache stops, and
        // one for another cache takes over what it published.
        let old_cache = TestCache::new();
        let (mut old, old_rx, _router) = in_sync(&old_cache);
        old.stop();
        assert!(old_rx.try_recv().is_err());
        let held = old.status().held().expect("the old client published");
        assert_eq!(*held.vrps, set(&[a(), b()]));
        assert_eq!(held.source, Some(old_cache.entry(0)));
        assert_eq!(held.expires_at, old.status().expires_at);
        assert!(held.expires_at.is_some());
        let cache = TestCache::new();
        let (client, rx) = start_holding(&cache, held);
        // RFC 8210 §10: the old data stays in use, and shows, until the new
        // cache has sent a full set.
        let status = client.status();
        assert_eq!(status.vrps.as_deref(), Some(&set(&[a(), b()])));
        assert_eq!((status.vrps_ipv4, status.vrps_ipv6), (1, 1));
        assert_eq!(status.expires_at, old.status().expires_at);
        assert_eq!(status.last_commit, None);
        // From the old client's cache, which the new one does not use.
        assert_eq!(status.source, Some(old_cache.entry(0)));
        assert_eq!(status.cache, cache.entry(0));
        let mut router = cache.accept();
        assert_eq!(router.recv(), RESET_V1, "a session of its own");
        assert!(rx.try_recv().is_err());
        router.send(&[
            response(V1, 9),
            announce(V1, a()),
            announce(V1, c()),
            eod(9, 1),
        ]);
        // The new set replaces the old one whole; only the routes the two
        // disagree on are validated again.
        let change = next_change(&rx);
        assert!(covers(&change, "2001:db8::/32") && covers(&change, "198.51.100.0/24"));
        assert!(!covers(&change, "192.0.2.0/24"));
        assert_eq!(rov(&change, "198.51.100.0/24", 64_498), RovState::Valid);
        eventually("the new cache's data", || {
            client.status().vrps.as_deref() == Some(&set(&[a(), c()]))
        });
        assert_eq!(client.status().source, Some(cache.entry(0)));
    }

    #[test]
    fn data_a_new_client_takes_over_expires_without_a_full_set() {
        // The new cache takes the connection and never answers.
        let cache = TestCache::new();
        let held = Held {
            vrps: Arc::new(set(&[a(), b()])),
            expires_at: Some(Instant::now() + 50 * MS),
            source: Some(Cache::new("192.0.2.9")),
        };
        let (client, rx) = start_holding(&cache, held);
        let mut router = cache.accept();
        assert_eq!(router.recv(), RESET_V1);
        // RFC 8210 §6: not past its Expire Interval, whichever client holds
        // it.
        let change = next_change(&rx);
        assert!(covers(&change, "192.0.2.0/24") && covers(&change, "2001:db8::/32"));
        assert_eq!(rov(&change, "192.0.2.0/24", 64_496), RovState::NotFound);
        eventually("the status to show no data", || {
            let status = client.status();
            status.vrps.as_deref() == Some(&VrpSet::new()) && status.expires_at.is_none()
        });
        assert!(client.status().last_error.unwrap().contains("expired"));
        // What it holds now is nothing, for good, and from no cache.
        let held = client.status().held().unwrap();
        assert!(held.vrps.is_empty() && held.expires_at.is_none());
        assert_eq!(held.source, None);
    }

    #[test]
    fn warnings_tell_the_data_a_new_client_holds() {
        // An earlier client's data, which the RIB still uses (RFC 8210
        // §10), and a cache that refuses the connection: the warning says
        // what is served, and for how long.
        let gone = TestCache::new().entry(0);
        let held = Held {
            vrps: Arc::new(set(&[a(), b()])),
            expires_at: Some(Instant::now() + 3_600 * SEC),
            source: None,
        };
        let (tx, _rx): (Sender<ValidationChange>, _) = mpsc::channel();
        let client = Client::start_holding(config(vec![gone]), tx, Some(held)).unwrap();
        eventually("a failed attempt", || client.status().failures > 0);
        let error = client.status().last_error.unwrap();
        assert!(
            error.starts_with("rtr cache connection failed cache=127.0.0.1:"),
            "{error}"
        );
        assert!(error.contains(" serving_vrps=2 expires_in=35"), "{error}");
    }

    #[test]
    fn warnings_tell_the_data_held_from_the_previous_cache() {
        let first = TestCache::new();
        let second = TestCache::new().entry(1);
        let (client, rx) = start(vec![first.entry(0), second.clone()]);
        let mut router = first.accept();
        router.serve_reset(SID, 1, &[a(), b()]);
        next_change(&rx);
        eventually("in sync", || client.status().synced_at.is_some());
        // The first cache goes away, takes the next connection and drops it
        // before answering: the client moves on to the second, which
        // refuses. Its warning tells the first cache's data, still in use.
        drop(router);
        drop(first.accept());
        let refused = format!("rtr cache connection failed cache={second} ");
        eventually("the second cache refused", || {
            client
                .status()
                .last_error
                .is_some_and(|e| e.starts_with(&refused))
        });
        let error = client.status().last_error.unwrap();
        assert!(error.contains(" serving_vrps=2 expires_in=59"), "{error}");
    }

    #[test]
    fn a_client_that_never_published_hands_nothing_over() {
        let cache = TestCache::new();
        let (mut client, _rx) = start(vec![cache.entry(0)]);
        drop(cache.accept());
        client.stop();
        assert_eq!(client.status().held(), None);
    }

    fn no_data() -> Pdu {
        Pdu::ErrorReport(ErrorReport::new(
            V1,
            ErrorCode::NoDataAvailable,
            &RESET_V1.encode(),
            "still loading",
        ))
    }

    #[test]
    fn a_cache_without_data_is_left_for_the_next() {
        // RFC 8210 §8.4: "the router SHOULD attempt to connect to any other
        // caches in its cache list, in preference order."
        let first = TestCache::new();
        let second = TestCache::new();
        let (client, rx) = start(vec![first.entry(0), second.entry(1)]);
        let mut router = first.accept();
        assert_eq!(router.recv(), RESET_V1);
        router.send(&[no_data()]);
        router.expect_close();
        let mut router = second.accept();
        router.serve_reset(SID, 1, &[a()]);
        let change = next_change(&rx);
        assert_eq!(rov(&change, "192.0.2.0/24", 64_496), RovState::Valid);
        eventually("the second cache in sync", || {
            let status = client.status();
            status.cache == second.entry(1) && status.synced_at.is_some()
        });
    }

    #[test]
    fn the_only_cache_without_data_is_asked_again_after_the_back_off() {
        // RFC 8210 §8.4: "If no other caches are available, the router MUST
        // issue periodic Reset Queries", here after the back-off rather
        // than ten minutes, so that a validator still loading is picked up
        // soon after it has data.
        let cache = TestCache::new();
        let (client, rx) = start(vec![cache.entry(0)]);
        let mut router = cache.accept();
        for failures in 1..=3 {
            assert_eq!(router.recv(), RESET_V1, "on the same connection");
            router.send(&[no_data()]);
            eventually("the No Data counted", || {
                client.status().failures == failures
            });
        }
        assert!(rx.try_recv().is_err());
        router.serve_reset(SID, 1, &[a()]);
        next_change(&rx);
        eventually("in sync", || {
            let status = client.status();
            status.synced_at.is_some() && status.failures == 0
        });
    }

    #[test]
    fn a_cache_reset_sends_the_client_to_a_more_preferred_cache() {
        let first = TestCache::new();
        let second = TestCache::new();
        let (client, rx) = start(vec![first.entry(0), second.entry(1)]);
        // The most preferred cache is away at first.
        drop(first.accept());
        let mut router = second.accept();
        router.serve_reset(SID, 1, &[a(), b()]);
        next_change(&rx);
        eventually("the second cache in sync", || {
            client.status().synced_at.is_some()
        });
        router.send(&[notify(SID, 2)]);
        assert_eq!(router.recv(), serial_query(SID, 1));
        // RFC 8210 §8.3: "the router SHOULD attempt to connect to any
        // more-preferred caches in its cache list."
        router.send(&[Pdu::CacheReset { version: V1 }]);
        router.expect_close();
        let mut router = first.accept();
        assert_eq!(router.recv(), RESET_V1);
        // The second cache's data stays in use until then (§10).
        assert!(rx.try_recv().is_err());
        assert_eq!(client.status().vrps.as_deref(), Some(&set(&[a(), b()])));
        router.send(&[response(V1, 9), announce(V1, a()), eod(9, 1)]);
        let change = next_change(&rx);
        assert!(covers(&change, "2001:db8::/32") && !covers(&change, "192.0.2.0/24"));
        eventually("the first cache in use", || {
            client.status().cache == first.entry(0)
        });
    }

    #[test]
    fn the_client_returns_to_a_more_preferred_cache_that_comes_back() {
        // The most preferred cache is gone at first: its port refuses.
        let first = TestCache::new();
        let port = first.listener.local_addr().unwrap().port();
        drop(first);
        let second = TestCache::new();
        let first_entry = Cache {
            host: "127.0.0.1".to_owned(),
            port,
            preference: 0,
        };
        let (client, rx) = start(vec![first_entry.clone(), second.entry(1)]);
        let mut router = second.accept();
        router.serve_reset(SID, 1, &[a(), b()]);
        next_change(&rx);
        eventually("the second cache in sync", || {
            client.status().synced_at.is_some()
        });
        // It comes back.
        let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let first = TestCache { listener };
        // Not before the Retry Interval of the cache in use, 60 s (RFC 8210
        // §6). A Serial Notify for the serial the client has wakes it and
        // asks for nothing.
        client.advance(59 * SEC);
        router.send(&[notify(SID, 1)]);
        assert!(first.quiet_for(100 * MS));
        // Then RFC 8210 §4, the most preferred cache that accepts: one
        // connection to see that it does, which the client closes at once,
        // and one for the session with it.
        client.advance(2 * SEC);
        router.send(&[notify(SID, 1)]);
        first.accept().expect_close();
        let mut back = first.accept();
        back.serve_reset(9, 1, &[a(), c()]);
        // Its full set replaces the second cache's, which stayed in use
        // until then (§10).
        let change = next_change(&rx);
        assert!(covers(&change, "2001:db8::/32") && covers(&change, "198.51.100.0/24"));
        assert!(!covers(&change, "192.0.2.0/24"));
        router.expect_close();
        eventually("the first cache in use", || {
            let status = client.status();
            status.cache == first_entry && status.source == Some(first_entry.clone())
        });
        // With the most preferred cache in use, nothing is looked for.
        client.advance(61 * SEC);
        back.send(&[notify(9, 1)]);
        assert!(first.quiet_for(100 * MS) && second.quiet_for(100 * MS));
        assert!(
            client
                .status()
                .last_error
                .is_none_or(|e| !e.contains("preferred")),
            "{:?}",
            client.status().last_error
        );
    }

    #[test]
    fn a_more_preferred_cache_that_stays_away_is_tried_each_retry_interval() {
        let gone = TestCache::new().entry(0);
        let second = TestCache::new();
        let (client, rx) = start(vec![gone, second.entry(1)]);
        let mut router = second.accept();
        router.serve_reset(SID, 1, &[a()]);
        next_change(&rx);
        eventually("the second cache in sync", || {
            client.status().synced_at.is_some()
        });
        // Each look finds the first cache still refusing: the client stays
        // with the second, on the same connection, its data untouched.
        for _ in 0..3 {
            client.advance(61 * SEC);
            router.send(&[notify(SID, 1)]);
            thread::sleep(50 * MS);
        }
        assert!(second.quiet_for(100 * MS), "no new connection");
        assert!(rx.try_recv().is_err());
        let status = client.status();
        assert_eq!(status.cache, second.entry(1));
        assert!(status.connected && status.state == State::Idle);
        assert_eq!(status.session_id, Some(SID));
    }

    #[test]
    fn stop_closes_the_connection_and_joins_the_thread() {
        let cache = TestCache::new();
        let (mut client, _rx, mut router) = in_sync(&cache);
        let handle = client.status_handle();
        // The thread is blocked in a read until the Refresh Interval, five
        // minutes away.
        let started = Instant::now();
        client.stop();
        assert!(started.elapsed() < SEC, "{:?}", started.elapsed());
        router.expect_close();
        assert!(cache.quiet_for(50 * MS), "no thread is left to reconnect");
        assert!(!handle.status().running);
        // Stopping twice is harmless.
        client.stop();
    }

    /// A listener that never accepts, with its accept queue full: the
    /// kernel drops a new SYN for it, so a connection attempt hangs until
    /// its timeout, like one to a cache whose host is gone.
    fn unanswered() -> (TcpListener, Vec<TcpStream>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut queued = Vec::new();
        loop {
            match TcpStream::connect_timeout(&addr, 200 * MS) {
                Ok(stream) => queued.push(stream),
                Err(e) if e.kind() == ErrorKind::TimedOut => return (listener, queued),
                Err(e) => panic!("filling the accept queue: {e}"),
            }
            assert!(queued.len() < 4_096, "the accept queue never filled");
        }
    }

    #[test]
    fn a_stop_cuts_a_connection_attempt_short() {
        let (listener, _queued) = unanswered();
        let mut config = config(vec![Cache {
            host: "127.0.0.1".to_owned(),
            port: listener.local_addr().unwrap().port(),
            preference: 0,
        }]);
        config.connect_timeout = 30 * SEC;
        config.session.response_timeout = 60 * SEC;
        let (mut client, rx) = start_with(config);
        // The status shows the attempt while it lasts.
        eventually("the attempt", || client.status().state == State::Connecting);
        thread::sleep(100 * MS);
        assert_eq!(client.status().state, State::Connecting);
        let started = Instant::now();
        client.stop();
        assert!(started.elapsed() < SEC, "{:?}", started.elapsed());
        assert!(!client.status().running);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn dropping_the_client_stops_it_while_it_backs_off() {
        let cache = TestCache::new();
        let mut config = config(vec![cache.entry(0)]);
        config.backoff = Backoff {
            min: Duration::from_secs(30),
            max: Duration::from_secs(30),
        };
        let (client, _rx) = start_with(config);
        drop(cache.accept());
        eventually("the client to back off", || client.status().failures == 1);
        let handle = client.status_handle();
        let started = Instant::now();
        drop(client);
        assert!(started.elapsed() < SEC, "{:?}", started.elapsed());
        assert!(!handle.status().running);
        assert!(cache.quiet_for(50 * MS));
    }

    #[test]
    fn a_closed_sink_stops_the_client() {
        let cache = TestCache::new();
        let (tx, rx) = mpsc::channel();
        drop(rx);
        let client = Client::start(config(vec![cache.entry(0)]), tx).unwrap();
        let mut router = cache.accept();
        router.serve_reset(SID, 1, &[a()]);
        // Publishing fails: the RIB is gone, and so is the client's reason
        // to run.
        eventually("the client to stop", || !client.status().running);
        router.expect_close();
        assert!(
            client
                .status()
                .last_error
                .unwrap()
                .contains("nowhere to go")
        );
    }

    /// A connection the caller's check refuses is closed before anything
    /// is sent or read on it, and fails like an attempt that found no
    /// cache: logged with the check's reason, counted for the back-off,
    /// and tried again. Once the check lets one through, the client goes
    /// on as ever. The check sees each connection to the cache.
    #[test]
    fn a_connection_the_check_refuses_is_never_used() {
        let cache = TestCache::new();
        let port = cache.entry(0).port;
        let allow = Arc::new(AtomicBool::new(false));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let check = {
            let (allow, seen) = (Arc::clone(&allow), Arc::clone(&seen));
            ConnectionCheck::new(move |stream: &TcpStream| {
                lock(&seen).push(stream.peer_addr()?.port());
                if allow.load(Ordering::Acquire) {
                    Ok(())
                } else {
                    Err(io::Error::other("not the cache we started"))
                }
            })
        };
        assert_eq!(check, check.clone());
        assert_eq!(format!("{check:?}"), "ConnectionCheck(..)");
        let config = Config {
            check: Some(check),
            ..config(vec![cache.entry(0)])
        };
        let (mut client, rx) = start_with(config);
        // Closed before the client wrote a query on it.
        cache.accept().expect_close();
        eventually("the refusal in the status", || {
            client
                .status()
                .last_error
                .is_some_and(|e| e.contains("not the cache we started"))
        });
        assert!(client.status().failures >= 1);
        assert!(client.status().vrps.is_none());
        assert!(rx.try_recv().is_err());

        // Let through: the first connection that carries a query is used.
        allow.store(true, Ordering::Release);
        let mut router = loop {
            let mut router = cache.accept();
            let mut buf = [0; 64];
            match router.stream.read(&mut buf) {
                Ok(0) | Err(_) => {}
                Ok(n) => {
                    router.framer.feed(&buf[..n]);
                    break router;
                }
            }
        };
        router.serve_reset(SID, 1, &[a(), b()]);
        assert_eq!(next_change(&rx).affected, AffectedPrefixes::All);
        assert!(lock(&seen).iter().all(|&p| p == port));
        client.stop();
    }
}

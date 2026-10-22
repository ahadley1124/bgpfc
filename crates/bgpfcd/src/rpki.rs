//! Route origin validation from RPKI caches (AGENTS.md §9 step 12): the
//! `rpki` block run as the RTR client of `bgpfc-rtr`, feeding the RIB
//! thread.
//!
//! With `mode external` the coordinator starts a [`Client`] whose sink
//! hands every [`ValidationChange`] to the RIB thread as a
//! [`RibMsg::Validation`] on the RIB's bounded channel. Like an UPDATE, a
//! change waits behind what is queued: the client cannot outrun the RIB
//! (AGENTS.md §3, "Backpressure"), and the RIB applies the changes in the
//! order the client published them (RFC 6811 §4). The RIB starts with no
//! source, every route `disabled`, and the client's first full set
//! replaces that for every route.
//!
//! [`Rpki::stop`] joins the client thread, which may be waiting for room
//! on the RIB channel. The RIB thread makes that room as long as it runs,
//! and it runs until the process exits, so the coordinator stops the
//! client first at shutdown, and nothing the RIB thread waits for waits
//! for the client in turn.
//!
//! The client logs through `bgpfc_log`, so the daemon's `log { level }`
//! applies to it: a lost cache is a warning, its return an info line,
//! expired data an error.
//!
//! Implements: RFC 8210 §6 (the Expire Interval cap and the reconnect
//! back-off configured), §7 (the version offered first), §9 (unprotected
//! TCP to the configured port, 323 by default), §10 (the cache list with
//! preferences); RFC 6811 §4 (each change of the VRPs reaches the RIB,
//! which validates the affected routes again).

use std::io;
use std::net::ToSocketAddrs as _;
use std::sync::mpsc::SyncSender;

use bgpfc_config::ast::{self, RpkiMode};
use bgpfc_rpki::{RpkiError, ValidationChange, ValidationSink};
use bgpfc_rtr::Version;
use bgpfc_rtr::client::{self, Backoff, Cache, Client};
use bgpfc_rtr::session;
use bgpfc_wire::types::RouterId;

use crate::messages::RibMsg;

/// Look up every cache of an external `rpki` block, so that a name that
/// does not resolve stops the daemon at start with an error naming it,
/// rather than leaving every route unvalidated without a word (issue
/// #60).
///
/// It is done where the daemon runs, not when the file is checked:
/// `bgpfcd --check` judges the file alone, wherever it runs, and the
/// configuration crate does no I/O. The client looks each name up again
/// at every connection attempt, so a cache that moves is followed.
///
/// # Errors
/// Every cache that has no address, with the reason.
pub(crate) fn resolve(rpki: &ast::Rpki) -> Result<(), String> {
    if rpki.mode != RpkiMode::External {
        return Ok(());
    }
    let failures: Vec<String> = rpki
        .caches
        .iter()
        .filter_map(|c| match (c.host.as_str(), c.port).to_socket_addrs() {
            Ok(mut addrs) => addrs
                .next()
                .is_none()
                .then(|| format!("{}: no address", c.host)),
            Err(e) => Some(format!("{}: {e}", c.host)),
        })
        .collect();
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!("cannot resolve rpki cache {}", failures.join("; ")))
    }
}

/// The client's configuration for `rpki`, or `None` in a mode without a
/// client.
pub(crate) fn client_config(rpki: &ast::Rpki, router_id: RouterId) -> Option<client::Config> {
    if rpki.mode != RpkiMode::External {
        return None;
    }
    let caches = rpki
        .caches
        .iter()
        .map(|c| Cache {
            host: c.host.clone(),
            port: c.port,
            preference: c.preference,
        })
        .collect();
    let mut config = client::Config::new(caches);
    config.connect_timeout = rpki.connect_timeout;
    config.backoff = Backoff {
        min: rpki.backoff_min,
        max: rpki.backoff_max,
    };
    // The jitter spreads the reconnects of routers that lost a cache at
    // the same moment. The BGP Identifier differs between routers (RFC
    // 6286 §2.1) and stays the same across restarts, so a router's
    // schedule can be reproduced.
    config.jitter_seed = u64::from(router_id.to_u32());
    config.session = session::Config {
        // RFC 8210 §7: offer version 1 and fall back, unless pinned to 0.
        version: if rpki.version == 0 {
            Version::V0
        } else {
            Version::V1
        },
        max_expire: rpki.max_expire,
        response_timeout: rpki.response_timeout,
        reply_timeout: rpki.reply_timeout,
        max_vrps: usize::try_from(rpki.max_vrps).unwrap_or(usize::MAX),
    };
    Some(config)
}

/// Where the client publishes: the RIB thread's bounded channel. A send
/// waits while the channel is full, and fails once the RIB thread is
/// gone, which stops the client.
fn sink(rib: SyncSender<RibMsg>) -> impl ValidationSink {
    move |change: ValidationChange| {
        rib.send(RibMsg::Validation(change))
            .map_err(|_| RpkiError::SinkClosed)
    }
}

/// The running `rpki` block: the RTR client, if its mode has one.
#[derive(Debug)]
pub(crate) struct Rpki {
    client: Option<Client>,
}

impl Rpki {
    /// Start what `config` asks for, publishing to `rib`. The caller has
    /// checked with [`resolve`] that the caches can be found.
    ///
    /// # Errors
    /// The client thread could not be spawned.
    pub(crate) fn start(
        config: &ast::Rpki,
        router_id: RouterId,
        rib: SyncSender<RibMsg>,
    ) -> io::Result<Rpki> {
        let Some(client_config) = client_config(config, router_id) else {
            return Ok(Rpki { client: None });
        };
        bgpfc_log::info!(
            "rpki: starting the rtr client",
            caches = config
                .caches
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(","),
            version = config.version
        );
        let client = Client::start(client_config, sink(rib))?;
        Ok(Rpki {
            client: Some(client),
        })
    }

    /// Stop the client for good, at shutdown. It returns once the client
    /// thread has ended; see the module documentation.
    pub(crate) fn stop(&mut self) {
        if let Some(mut client) = self.client.take() {
            client.stop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::{ErrorKind, Read as _, Write as _};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc::{Receiver, sync_channel};
    use std::thread;
    use std::time::{Duration, Instant};

    use bgpfc_config::Config;
    use bgpfc_rpki::{AffectedPrefixes, RouteOrigin, RovState, Vrp};
    use bgpfc_rtr::{Framer, Intervals, Pdu};
    use bgpfc_wire::types::Asn;

    const WAIT: Duration = Duration::from_secs(10);
    const SID: u16 = 7;

    fn config(rpki: &str) -> Config {
        bgpfc_config::parse_str("t", &format!("router-id 192.0.2.1; local-as 65000; {rpki}"))
            .unwrap()
    }

    fn vrp(prefix: &str, max_len: u8, asn: u32) -> Vrp {
        Vrp::new(prefix.parse().unwrap(), max_len, Asn(asn)).unwrap()
    }

    fn rov(change: &ValidationChange, prefix: &str, asn: u32) -> RovState {
        change
            .source
            .rov(prefix.parse().unwrap(), RouteOrigin::As(Asn(asn)))
    }

    /// The next validation change on the RIB channel.
    fn next_change(rx: &Receiver<RibMsg>) -> ValidationChange {
        match rx.recv_timeout(WAIT) {
            Ok(RibMsg::Validation(change)) => change,
            other => panic!("expected a validation change, got {other:?}"),
        }
    }

    fn status(rpki: &Rpki) -> Option<client::Status> {
        rpki.client.as_ref().map(Client::status)
    }

    fn eventually(what: &str, mut done: impl FnMut() -> bool) {
        let deadline = Instant::now() + WAIT;
        while !done() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            thread::sleep(Duration::from_millis(5));
        }
    }

    /// An RTR cache on the loopback that answers Reset Queries.
    struct StubCache {
        listener: TcpListener,
    }

    impl StubCache {
        fn new() -> StubCache {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            StubCache { listener }
        }

        fn port(&self) -> u16 {
            self.listener.local_addr().unwrap().port()
        }

        /// The block of a daemon that uses this cache alone.
        fn block(&self) -> String {
            format!(
                "rpki {{ mode external; cache 127.0.0.1 port {}; }}",
                self.port()
            )
        }

        /// Take the client's next connection and its first query.
        fn accept(&self) -> (TcpStream, Pdu) {
            let deadline = Instant::now() + WAIT;
            let mut stream = loop {
                match self.listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "the client did not connect");
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => panic!("accept: {e}"),
                }
            };
            stream.set_nonblocking(false).unwrap();
            stream.set_read_timeout(Some(WAIT)).unwrap();
            let mut framer = Framer::new();
            let query = loop {
                if let Some(pdu) = framer.next_pdu().unwrap() {
                    break pdu;
                }
                let mut buf = [0; 64];
                let n = stream.read(&mut buf).unwrap();
                assert!(n > 0, "the client closed the connection");
                framer.feed(&buf[..n]);
            };
            (stream, query)
        }

        /// Take the client's next connection and answer its Reset Query
        /// with `vrps` (RFC 8210 §8.1).
        fn serve(&self, vrps: &[Vrp]) -> TcpStream {
            let (mut stream, query) = self.accept();
            assert!(matches!(query, Pdu::ResetQuery { .. }), "{query:?}");
            let version = query.version();
            let mut out = Pdu::CacheResponse {
                version,
                session_id: SID,
            }
            .encode();
            for &vrp in vrps {
                Pdu::Prefix {
                    version,
                    announce: true,
                    vrp,
                }
                .encode_into(&mut out);
            }
            Pdu::EndOfData {
                session_id: SID,
                serial: 1,
                intervals: Some(Intervals::DEFAULT),
            }
            .encode_into(&mut out);
            stream.write_all(&out).unwrap();
            stream
        }
    }

    /// Whether the client closed `conn`.
    fn closed(conn: &mut TcpStream) -> bool {
        let mut buf = [0; 16];
        match conn.read(&mut buf) {
            Ok(n) => n == 0,
            Err(e) => e.kind() == ErrorKind::ConnectionReset,
        }
    }

    #[test]
    fn the_client_is_configured_from_the_block() {
        let router_id = RouterId::new(0xC000_0201).unwrap();
        let cfg = config(
            "rpki {
                mode external;
                cache rtr.example.net port 3323 preference 10;
                cache 127.0.0.1;
                version 0; connect-timeout 5; response-timeout 30; reply-timeout 600;
                max-expire 3600; max-vrps 1000; backoff 2 300;
            }",
        );
        let c = client_config(&cfg.rpki, router_id).unwrap();
        assert_eq!(
            c.caches,
            [
                Cache {
                    host: "rtr.example.net".to_owned(),
                    port: 3323,
                    preference: 10
                },
                Cache::new("127.0.0.1"),
            ]
        );
        assert_eq!(c.connect_timeout, Duration::from_secs(5));
        assert_eq!(
            c.backoff,
            Backoff {
                min: Duration::from_secs(2),
                max: Duration::from_secs(300)
            }
        );
        assert_eq!(c.jitter_seed, 0xC000_0201);
        assert_eq!(
            c.session,
            session::Config {
                version: Version::V0,
                max_expire: Duration::from_secs(3_600),
                response_timeout: Duration::from_secs(30),
                reply_timeout: Duration::from_secs(600),
                max_vrps: 1_000,
            }
        );
        // The block's defaults are the client's.
        let cfg = config("rpki { mode external; cache 192.0.2.10; }");
        let c = client_config(&cfg.rpki, router_id).unwrap();
        let defaults = client::Config::new(vec![Cache::new("192.0.2.10")]);
        assert_eq!(c.caches, defaults.caches);
        assert_eq!(c.connect_timeout, defaults.connect_timeout);
        assert_eq!(c.backoff, defaults.backoff);
        assert_eq!(c.session, defaults.session);
        assert_eq!(ast::Rpki::DEFAULT_PORT, client::DEFAULT_PORT);
        assert_eq!(ast::Rpki::MIN_EXPIRE, session::Config::MIN_EXPIRE);
        assert_eq!(ast::Rpki::MAX_EXPIRE, session::Config::MAX_EXPIRE);
        // No client without the block, or with `mode disabled`.
        assert!(client_config(&config("").rpki, router_id).is_none());
        let disabled = config("rpki { mode disabled; cache 192.0.2.10; }");
        assert!(client_config(&disabled.rpki, router_id).is_none());
    }

    #[test]
    fn caches_that_cannot_be_found_are_named() {
        let ok = config("rpki { mode external; cache 127.0.0.1; cache ::1; cache localhost; }");
        assert_eq!(resolve(&ok.rpki), Ok(()));
        // RFC 2606 §2: `.invalid` never resolves.
        let bad = config(
            "rpki { mode external; cache 127.0.0.1; cache rtr.invalid;
             cache other.invalid preference 1; }",
        );
        let e = resolve(&bad.rpki).unwrap_err();
        assert!(
            e.starts_with("cannot resolve rpki cache rtr.invalid: "),
            "{e}"
        );
        assert!(e.contains("; other.invalid: "), "{e}");
        assert!(!e.contains("127.0.0.1"), "{e}");
        // Nothing is looked up for a mode without a client.
        let off = config("rpki { mode disabled; cache rtr.invalid; }");
        assert_eq!(resolve(&off.rpki), Ok(()));
    }

    #[test]
    fn the_cache_s_data_reaches_the_rib_channel() {
        let cache = StubCache::new();
        let cfg = config(&cache.block());
        let (tx, rx) = sync_channel(4);
        let mut rpki = Rpki::start(&cfg.rpki, cfg.router_id, tx).unwrap();
        let mut conn = cache.serve(&[vrp("192.0.2.0/24", 24, 64_496)]);
        // The first set replaces the RIB's lack of a source: every route.
        let change = next_change(&rx);
        assert_eq!(change.affected, AffectedPrefixes::All);
        assert_eq!(rov(&change, "192.0.2.0/24", 64_496), RovState::Valid);
        assert_eq!(rov(&change, "192.0.2.0/24", 64_497), RovState::Invalid);
        assert_eq!(rov(&change, "198.51.100.0/24", 64_496), RovState::NotFound);
        eventually("the client in sync", || {
            status(&rpki).is_some_and(|s| s.synced_at.is_some())
        });
        assert_eq!(status(&rpki).unwrap().vrps_ipv4, 1);
        rpki.stop();
        assert!(status(&rpki).is_none());
        assert!(closed(&mut conn), "no client is left");
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn without_a_client_nothing_is_published() {
        let (tx, rx) = sync_channel(4);
        let cfg = config("rpki { mode disabled; cache 127.0.0.1; }");
        let mut rpki = Rpki::start(&cfg.rpki, cfg.router_id, tx).unwrap();
        assert!(status(&rpki).is_none());
        rpki.stop();
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn stopping_waits_for_a_full_rib_channel_to_drain() {
        // The client publishes while the RIB thread is busy and its
        // channel full: stopping it waits for the RIB to make room, and
        // the change is delivered, not lost.
        let cache = StubCache::new();
        let cfg = config(&cache.block());
        let (tx, rx) = sync_channel(1);
        tx.send(RibMsg::PeerDown {
            peer: "192.0.2.2".parse().unwrap(),
        })
        .unwrap();
        let mut rpki = Rpki::start(&cfg.rpki, cfg.router_id, tx).unwrap();
        let mut conn = cache.serve(&[vrp("192.0.2.0/24", 24, 64_496)]);
        // The RIB thread drains the channel a while later.
        let rib = thread::spawn(move || {
            thread::sleep(Duration::from_secs(1));
            let mut messages = Vec::new();
            while let Ok(m) = rx.recv_timeout(Duration::from_secs(2)) {
                messages.push(m);
            }
            messages
        });
        // Long enough for the client to read the reply and wait to publish.
        thread::sleep(Duration::from_millis(500));
        let stopping = Instant::now();
        rpki.stop();
        assert!(stopping.elapsed() >= Duration::from_millis(300));
        assert!(closed(&mut conn));
        let messages = rib.join().unwrap();
        assert!(
            matches!(messages[0], RibMsg::PeerDown { .. }),
            "{messages:?}"
        );
        assert!(
            matches!(&messages[1..], [RibMsg::Validation(_)]),
            "{messages:?}"
        );
    }
}

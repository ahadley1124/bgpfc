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
//! A reload that changes the block stops the client and starts another
//! with the new settings, which keeps the data the old one published until
//! a cache sends a full set, or until it expires (RFC 8210 §10, §6; see
//! [`Client::start_holding`]): the routes keep their states meanwhile, and
//! a new set validates again only the routes it judges differently. A
//! change to `mode disabled` sends [`ValidationChange::disabled`] instead,
//! so that every route is `disabled` again. A reload that leaves the block
//! alone leaves the client alone.
//!
//! Stopping the client, at a reload or at shutdown, joins its thread,
//! which a stop wakes from its sleep, its reads and writes, and its wait
//! for a connection attempt (see [`Client::stop`]): a cache that does not
//! answer holds up neither. The thread may still be waiting for room on
//! the RIB channel; the RIB thread makes that room, as it runs until the
//! process exits, and waits for nothing that waits for the client. At
//! shutdown the coordinator stops the client last, after the Ceases and
//! the FIB cleanup, which do not need it.
//!
//! The client logs through `bgpfc_log`, so the daemon's `log { level }`
//! applies to it: a lost cache is a warning, its return an info line,
//! expired data an error.
//!
//! Implements: RFC 8210 §6 (the Expire Interval cap and the reconnect
//! back-off configured), §7 (the version offered first), §9 (unprotected
//! TCP to the configured port, 323 by default), §10 (the cache list with
//! preferences; the data kept across a new cache list); RFC 6811 §4 (each
//! change of the VRPs reaches the RIB, which validates the affected routes
//! again).

use std::io;
use std::net::ToSocketAddrs as _;
use std::sync::mpsc::SyncSender;

use bgpfc_config::ast::{self, RpkiMode};
use bgpfc_rpki::{RpkiError, ValidationChange, ValidationSink};
use bgpfc_rtr::Version;
use bgpfc_rtr::client::{self, Backoff, Cache, Client, Held, Status};
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
    rib: SyncSender<RibMsg>,
    router_id: RouterId,
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
        let mut rpki = Rpki {
            rib,
            router_id,
            client: None,
        };
        rpki.client = rpki.spawn(config, None)?;
        Ok(rpki)
    }

    /// A client for `config`, holding `held`, if its mode runs one.
    fn spawn(&self, config: &ast::Rpki, held: Option<Held>) -> io::Result<Option<Client>> {
        let Some(client_config) = client_config(config, self.router_id) else {
            return Ok(None);
        };
        bgpfc_log::info!(
            "rpki: starting the rtr client",
            caches = config
                .caches
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(","),
            version = config.version,
            held_vrps = held.as_ref().map_or(0, |h| h.vrps.len())
        );
        let client = Client::start_holding(client_config, sink(self.rib.clone()), held)?;
        Ok(Some(client))
    }

    /// Apply `new`, the block of a reloaded configuration, in place of
    /// `old`, the running one; what was done, for the reload's summary.
    /// The caller has checked with [`resolve`] that the new caches can be
    /// found.
    ///
    /// # Errors
    /// The new client thread could not be spawned. Validation is then
    /// off, as with `mode disabled`, since nothing would expire the data
    /// the old client left in the RIB.
    pub(crate) fn reconfigure(
        &mut self,
        old: &ast::Rpki,
        new: &ast::Rpki,
    ) -> Result<&'static str, String> {
        if old.same_as(new) {
            return Ok("rpki unchanged");
        }
        let ran = self.client.is_some();
        let held = self.stop_client();
        match self.spawn(new, held) {
            Ok(Some(client)) => {
                self.client = Some(client);
                Ok(if ran {
                    "rpki: rtr client restarted"
                } else {
                    "rpki: rtr client started"
                })
            }
            Ok(None) if ran => {
                self.disable();
                Ok("rpki: validation disabled")
            }
            Ok(None) => Ok("rpki: validation stays disabled"),
            Err(e) => {
                self.disable();
                Err(format!(
                    "rpki: cannot start the rtr client ({e}); validation disabled"
                ))
            }
        }
    }

    /// Stop the client, if one runs, and return what it published.
    fn stop_client(&mut self) -> Option<Held> {
        let mut client = self.client.take()?;
        client.stop();
        // Read once the thread has ended: it publishes nothing after.
        client.status().held()
    }

    /// Turn validation off in the RIB: every route `disabled`.
    fn disable(&self) {
        bgpfc_log::info!("rpki: validation disabled; every route is disabled again");
        // A RIB thread that is gone has no routes to tell.
        let _ = self
            .rib
            .send(RibMsg::Validation(ValidationChange::disabled()));
    }

    /// Stop the client for good, at shutdown. It returns once the client
    /// thread has ended; see the module documentation.
    pub(crate) fn stop(&mut self) {
        self.stop_client();
    }

    /// The client's status, if one runs.
    pub(crate) fn status(&self) -> Option<Status> {
        self.client.as_ref().map(Client::status)
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
                "rpki {{ mode external; invalid policy; cache 127.0.0.1 port {}; }}",
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
                mode external; invalid policy;
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
        let cfg = config("rpki { mode external; invalid policy; cache 192.0.2.10; }");
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
        let ok = config(
            "rpki { mode external; invalid policy; cache 127.0.0.1; cache ::1; cache localhost; }",
        );
        assert_eq!(resolve(&ok.rpki), Ok(()));
        // RFC 2606 §2: `.invalid` never resolves.
        let bad = config(
            "rpki { mode external; invalid policy; cache 127.0.0.1; cache rtr.invalid;
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
            rpki.status().is_some_and(|s| s.synced_at.is_some())
        });
        assert_eq!(rpki.status().unwrap().vrps_ipv4, 1);
        rpki.stop();
        assert!(rpki.status().is_none());
        assert!(closed(&mut conn), "no client is left");
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn without_a_client_nothing_is_published() {
        let (tx, rx) = sync_channel(4);
        let cfg = config("rpki { mode disabled; cache 127.0.0.1; }");
        let mut rpki = Rpki::start(&cfg.rpki, cfg.router_id, tx).unwrap();
        assert!(rpki.status().is_none());
        rpki.stop();
        assert!(rx.try_recv().is_err());
    }

    /// A client in sync with `cache`, which sent `vrps`, and the RIB
    /// channel it publishes to.
    fn in_sync(cache: &StubCache, vrps: &[Vrp]) -> (Rpki, Receiver<RibMsg>, TcpStream) {
        let cfg = config(&cache.block());
        let (tx, rx) = sync_channel(4);
        let rpki = Rpki::start(&cfg.rpki, cfg.router_id, tx).unwrap();
        let conn = cache.serve(vrps);
        assert_eq!(next_change(&rx).affected, AffectedPrefixes::All);
        (rpki, rx, conn)
    }

    #[test]
    fn an_unchanged_block_leaves_the_client_alone() {
        let cache = StubCache::new();
        let (mut rpki, rx, mut conn) = in_sync(&cache, &[vrp("192.0.2.0/24", 24, 64_496)]);
        let cfg = config(&cache.block());
        assert_eq!(rpki.reconfigure(&cfg.rpki, &cfg.rpki), Ok("rpki unchanged"));
        // The same session goes on: no new connection, nothing published.
        conn.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut buf = [0; 16];
        let quiet = conn.read(&mut buf).unwrap_err().kind();
        assert!(
            matches!(quiet, ErrorKind::WouldBlock | ErrorKind::TimedOut),
            "{quiet:?}"
        );
        assert_eq!(
            cache.listener.accept().map_err(|e| e.kind()).err(),
            Some(ErrorKind::WouldBlock)
        );
        assert!(rx.try_recv().is_err());
        assert!(rpki.status().is_some_and(|s| s.connected));
        rpki.stop();
    }

    #[test]
    fn a_respelled_cache_leaves_the_client_alone() {
        // The parser takes a name in another case, or with its final dot,
        // for the same cache; so does a reload.
        let cache = StubCache::new();
        let named = |host: &str| {
            config(&format!(
                "rpki {{ mode external; invalid policy; cache {host} port {}; }}",
                cache.port()
            ))
        };
        let (old, new) = (named("localhost"), named("LocalHost."));
        let (tx, rx) = sync_channel(4);
        let mut rpki = Rpki::start(&old.rpki, old.router_id, tx).unwrap();
        let _conn = cache.serve(&[vrp("192.0.2.0/24", 24, 64_496)]);
        assert_eq!(next_change(&rx).affected, AffectedPrefixes::All);
        assert_eq!(rpki.reconfigure(&old.rpki, &new.rpki), Ok("rpki unchanged"));
        thread::sleep(Duration::from_millis(200));
        assert_eq!(
            cache.listener.accept().map_err(|e| e.kind()).err(),
            Some(ErrorKind::WouldBlock),
            "no new connection"
        );
        assert!(rx.try_recv().is_err());
        assert!(rpki.status().is_some_and(|s| s.connected));
        rpki.stop();
    }

    #[test]
    fn a_new_cache_list_keeps_the_old_data_until_a_full_set() {
        let first = StubCache::new();
        let (a, b, c) = (
            vrp("192.0.2.0/24", 24, 64_496),
            vrp("198.51.100.0/24", 24, 64_497),
            vrp("203.0.113.0/24", 24, 64_498),
        );
        let (mut rpki, rx, mut old_conn) = in_sync(&first, &[a, b]);
        let second = StubCache::new();
        let (old, new) = (config(&first.block()), config(&second.block()));
        assert_eq!(
            rpki.reconfigure(&old.rpki, &new.rpki),
            Ok("rpki: rtr client restarted")
        );
        assert!(closed(&mut old_conn), "the old client is gone");
        // RFC 8210 §10: until the new cache has sent a full set, the old
        // data stays in use; the RIB hears nothing.
        let (mut conn, query) = second.accept();
        assert!(matches!(query, Pdu::ResetQuery { .. }), "{query:?}");
        let held = rpki.status().unwrap();
        assert_eq!(held.vrps.as_deref().map(bgpfc_rpki::VrpSet::len), Some(2));
        assert!(held.expires_at.is_some());
        assert!(rx.try_recv().is_err());
        // The new cache's set replaces it, and only the routes the two
        // sets disagree on are validated again.
        let version = query.version();
        let mut out = Pdu::CacheResponse {
            version,
            session_id: SID,
        }
        .encode();
        for vrp in [a, c] {
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
        conn.write_all(&out).unwrap();
        let change = next_change(&rx);
        let p = |s: &str| s.parse().unwrap();
        assert!(!change.affected.covers(p("192.0.2.0/24")));
        assert!(change.affected.covers(p("198.51.100.0/24")));
        assert!(change.affected.covers(p("203.0.113.0/24")));
        assert_eq!(rov(&change, "198.51.100.0/24", 64_497), RovState::NotFound);
        assert_eq!(rov(&change, "203.0.113.0/24", 64_498), RovState::Valid);
        rpki.stop();
    }

    #[test]
    fn switching_to_disabled_sends_the_disabled_change() {
        let cache = StubCache::new();
        let (mut rpki, rx, mut conn) = in_sync(&cache, &[vrp("192.0.2.0/24", 24, 64_496)]);
        let (old, new) = (
            config(&cache.block()),
            config(&format!(
                "rpki {{ mode disabled; cache 127.0.0.1 port {}; }}",
                cache.port()
            )),
        );
        assert_eq!(
            rpki.reconfigure(&old.rpki, &new.rpki),
            Ok("rpki: validation disabled")
        );
        assert!(rpki.status().is_none());
        assert!(closed(&mut conn));
        // ValidationChange::disabled: no source, for every route.
        let change = next_change(&rx);
        assert_eq!(change.affected, AffectedPrefixes::All);
        assert_eq!(rov(&change, "192.0.2.0/24", 64_496), RovState::Disabled);
        assert!(rx.try_recv().is_err());
        // From disabled to disabled nothing is sent; back to external
        // starts a client, whose first set is for every route again.
        assert_eq!(
            rpki.reconfigure(&new.rpki, &config("").rpki),
            Ok("rpki: validation stays disabled")
        );
        assert!(rx.try_recv().is_err());
        assert_eq!(
            rpki.reconfigure(&new.rpki, &old.rpki),
            Ok("rpki: rtr client started")
        );
        let _conn = cache.serve(&[vrp("192.0.2.0/24", 24, 64_496)]);
        let change = next_change(&rx);
        assert_eq!(change.affected, AffectedPrefixes::All);
        assert_eq!(rov(&change, "192.0.2.0/24", 64_496), RovState::Valid);
        rpki.stop();
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

    /// A port where a connection attempt hangs until its timeout, like one
    /// to a cache whose host is gone: a listener that never accepts, with
    /// its accept queue full, so that the kernel drops a new SYN.
    fn unanswered() -> (TcpListener, Vec<TcpStream>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut queued = Vec::new();
        loop {
            match TcpStream::connect_timeout(&addr, Duration::from_millis(200)) {
                Ok(stream) => queued.push(stream),
                Err(e) if e.kind() == ErrorKind::TimedOut => return (listener, queued),
                Err(e) => panic!("filling the accept queue: {e}"),
            }
            assert!(queued.len() < 4_096, "the accept queue never filled");
        }
    }

    #[test]
    fn a_cache_that_never_answers_holds_up_neither_reload_nor_stop() {
        let (listener, _queued) = unanswered();
        let hanging = config(&format!(
            "rpki {{ mode external; invalid policy; cache 127.0.0.1 port {};
             connect-timeout 30; response-timeout 60; }}",
            listener.local_addr().unwrap().port()
        ));
        let (tx, rx) = sync_channel(4);
        let mut rpki = Rpki::start(&hanging.rpki, hanging.router_id, tx).unwrap();
        let connecting = |rpki: &Rpki| {
            rpki.status()
                .is_some_and(|s| s.state == bgpfc_rtr::session::State::Connecting)
        };
        eventually("the attempt", || connecting(&rpki));
        thread::sleep(Duration::from_millis(100));
        // A reload to another cache while the attempt lasts: the old client
        // stops at once, and the new one takes over.
        let cache = StubCache::new();
        let working = config(&cache.block());
        let reloading = Instant::now();
        assert_eq!(
            rpki.reconfigure(&hanging.rpki, &working.rpki),
            Ok("rpki: rtr client restarted")
        );
        assert!(
            reloading.elapsed() < Duration::from_secs(2),
            "{:?}",
            reloading.elapsed()
        );
        let _conn = cache.serve(&[vrp("192.0.2.0/24", 24, 64_496)]);
        assert_eq!(next_change(&rx).affected, AffectedPrefixes::All);
        // Back to the cache that never answers, then shutdown during the
        // attempt.
        assert_eq!(
            rpki.reconfigure(&working.rpki, &hanging.rpki),
            Ok("rpki: rtr client restarted")
        );
        eventually("the attempt", || connecting(&rpki));
        thread::sleep(Duration::from_millis(100));
        let stopping = Instant::now();
        rpki.stop();
        assert!(
            stopping.elapsed() < Duration::from_secs(2),
            "{:?}",
            stopping.elapsed()
        );
        assert!(rpki.status().is_none());
        assert!(rx.try_recv().is_err());
    }
}

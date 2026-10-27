//! Route origin validation from RPKI caches (AGENTS.md §9 steps 12 and
//! 14): the `rpki` block run as the RTR client of `bgpfc-rtr`, feeding the
//! RIB thread, and with `mode sidecar` Routinator run by `bgpfc-sidecar`
//! as that client's one cache (issues #26, #70-#72).
//!
//! With `mode external` or `mode sidecar` the coordinator starts a
//! [`Client`] whose sink hands every [`ValidationChange`] to the RIB
//! thread as a [`RibMsg::Validation`] on the RIB's bounded channel. Like
//! an UPDATE, a change waits behind what is queued: the client cannot
//! outrun the RIB (AGENTS.md §3, "Backpressure"), and the RIB applies the
//! changes in the order the client published them (RFC 6811 §4). The RIB
//! starts with no source, every route `disabled`, and the client's first
//! full set replaces that for every route. Until then the block's
//! `startup` decides whether those routes are used or held ([`startup`]):
//! the RIB holds a `disabled` route under `hold`, so the setting is in
//! effect only while a client runs, and [`Rpki::disable`] turns the hold
//! off before it turns validation off.
//!
//! With `mode sidecar`, [`Rpki::start`] first creates Routinator's
//! repository directory and starts a [`Sidecar`]: it checks the binary's
//! version, picks the RTR port when the block leaves it to bgpfcd, and
//! supervises Routinator from a thread of its own, which spawns every
//! child (`PR_SET_PDEATHSIG` follows the spawning thread). Then the client
//! starts with [`Sidecar::rtr_addr`] as its one cache, on loopback (RFC
//! 8210 §9; issue #71: no operator configuration names it). That address
//! stays the same for the life of the `Sidecar`, across every restart of
//! Routinator, so the client's own reconnect finds a restarted Routinator
//! with no special case (issue #71), and the data it holds stays in use
//! meanwhile (RFC 8210 §10, §6). The coordinator starts the block after
//! the privilege drop, so that Routinator, which fetches and parses data
//! from the internet, is born with the service user's credentials and no
//! capabilities (m14 design §4.1).
//!
//! A reload that changes the block stops the client and starts another
//! with the new settings, which keeps the data the old one published until
//! a cache sends a full set, or until it expires (RFC 8210 §10, §6; see
//! [`Client::start_holding`]): the routes keep their states meanwhile, and
//! a new set validates again only the routes it judges differently. A
//! change to `mode disabled` sends [`ValidationChange::disabled`] instead,
//! so that every route is `disabled` again. A reload that leaves the block
//! alone leaves the client alone, and so does one that changes only the
//! `tcp-keepalive`, which [`Rpki::set_tcp_keepalive`] sets on the
//! connection in use and every later one. Routinator is restarted only
//! when its own settings change, since each start costs a validation run
//! before it listens again, and the held data covers that gap; it is
//! started and stopped as the mode comes to `sidecar` and leaves it (m14
//! design §5.2).
//! [`preflight`] checks before anything changes what a start of
//! Routinator would refuse, so that a reload onto a binary that would not
//! start fails and the running one goes on.
//!
//! Stopping the client, at a reload or at shutdown, joins its thread,
//! which a stop wakes from its sleep, its reads and writes, and its wait
//! for a connection attempt (see [`Client::stop`]): a cache that does not
//! answer holds up neither. The thread may still be waiting for room on
//! the RIB channel; the RIB thread makes that room, as it runs until the
//! process exits, and waits for nothing that waits for the client. At
//! shutdown the coordinator stops the block right after the Ceases, since
//! neither they nor the FIB cleanup need it ([`Rpki::begin_stop`]): the
//! client first, so that it neither warns about the cache it loses nor
//! publishes to a RIB whose FIB is going, then Routinator (`SIGTERM`,
//! `SIGKILL` after `stop-timeout`) on a thread of its own while the FIB is
//! cleaned up. The supervisor restarts nothing once it is asked to stop,
//! so from the start of the shutdown on no Routinator is started again
//! (issue #70), even one that exits meanwhile.
//!
//! The client and the sidecar log through `bgpfc_log`, so the daemon's
//! `log { level }` applies to them: a lost cache is a warning, its return
//! an info line, expired data an error; Routinator's standard error is
//! logged at warn, and a sidecar that keeps failing at error.
//!
//! Implements: RFC 8210 §6 (the Expire Interval cap and the reconnect
//! back-off configured), §7 (the version offered first), §9 and §13
//! (unprotected TCP to the configured port, 323 by default, with TCP
//! keep-alive on every connection, as `tcp-keepalive` has it; the
//! sidecar's RTR on loopback only, and used only from a server of
//! bgpfcd's own user), §10 (the cache list with preferences; the data
//! kept across a new cache list, and across a restart of Routinator); RFC
//! 6811 §4 (each change of the VRPs reaches the RIB, which validates the
//! affected routes again), §2 (routes not validated yet held only as
//! configured, `startup hold`, and only while validation waits for data).

use std::ffi::OsString;
use std::fs::DirBuilder;
use std::io;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs as _};
use std::os::unix::fs::DirBuilderExt as _;
use std::path::Path;
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::Instant;

use bgpfc_config::ast::{self, RpkiMode};
use bgpfc_config::{ConfigError, Pos};
use bgpfc_rpki::{RpkiError, Startup, ValidationChange, ValidationSink};
use bgpfc_rtr::Version;
use bgpfc_rtr::client::{self, Backoff, Cache, Client, ConnectionCheck, Held, Status};
use bgpfc_rtr::session;
use bgpfc_sidecar::{BackoffConfig, Sidecar, SidecarConfig, TalConfig};
use bgpfc_sys::TcpKeepalive;
use bgpfc_wire::types::RouterId;

use crate::messages::{RibMsg, RpkiReport, SidecarReport};
use crate::{owner, privileges};

/// The startup setting the RIB applies while `rpki` is the block in
/// effect ([`Rpki::in_effect`]): its own `startup` in a mode that
/// validates, and `accept` with `mode disabled`.
///
/// The RIB holds every route used with state `disabled` under
/// [`Startup::Hold`]. While a client waits for its first full set those
/// are the routes not validated yet, which `hold` is meant for (RFC 6811
/// §2: only routes "explicitly configured" to leave the decision process
/// for their state do). With validation off they are every route, for
/// good, as no data will come to release them: so `hold` applies with
/// `mode external` and `mode sidecar` only, and a block that could not be
/// started, which [`Rpki::in_effect`] gives as `mode disabled`, holds
/// nothing either.
pub(crate) fn startup(rpki: &ast::Rpki) -> Startup {
    match rpki.mode {
        RpkiMode::Disabled => Startup::Accept,
        RpkiMode::External | RpkiMode::Sidecar => rpki.startup,
    }
}

/// The reload summary's note on a changed `startup`: the new setting, and
/// that it holds nothing with validation off ([`startup`]).
pub(crate) fn startup_note(rpki: &ast::Rpki) -> String {
    if rpki.mode == RpkiMode::Disabled {
        format!(
            "rpki startup {} (holds nothing with mode disabled)",
            rpki.startup
        )
    } else {
        format!("rpki startup {}", rpki.startup)
    }
}

/// The checks of the `rpki` block that need more than the configuration
/// crate knows, as the hook of [`bgpfc_config::parse_file_with`]: their
/// errors are reported with the file's own, at their positions in it, by
/// `bgpfcd --check`, at start and at a reload. They judge the file alone,
/// like the configuration crate, and run nothing.
///
/// With `mode sidecar`, the `sidecar` block as Routinator would take it
/// ([`SidecarConfig::validate`]): TAL names, the ARIN agreement, settings
/// that leave no trust anchor, and the options the escape hatches may not
/// carry (issue #72). That is Routinator knowledge, which lives in
/// `bgpfc-sidecar` alone. The error, `rpki sidecar: ...`, is reported at
/// the `sidecar` block, or at the `mode` statement without one. With
/// another mode the block is only read, so that turning validation off
/// stays a one-word change (issue #60). Nothing runs here: the binary's
/// version is checked when the sidecar starts, where bgpfcd runs, not
/// wherever `--check` does.
pub(crate) fn check_config(config: &bgpfc_config::Config) -> Vec<ConfigError> {
    let rpki = &config.rpki;
    if rpki.mode != RpkiMode::Sidecar {
        return Vec::new();
    }
    match sidecar_config(&rpki.sidecar).validate() {
        Ok(()) => Vec::new(),
        Err(e) => {
            // The configuration crate places every `mode sidecar` block;
            // the start of the file stands in for a hand-built one.
            let pos = rpki.sidecar.pos.unwrap_or(Pos { line: 1, col: 1 });
            vec![ConfigError::new(pos, format!("rpki sidecar: {e}"))]
        }
    }
}

/// The `sidecar` block as the sidecar crate takes it. Pure.
///
/// The block's durations are whole seconds, so they meet the crate's
/// floors below a second ([`SidecarConfig::MIN_BACKOFF`],
/// [`SidecarConfig::MIN_BACKOFF_CAP`]) by construction; the configuration
/// crate's bounds are the crate's others.
pub(crate) fn sidecar_config(s: &ast::RpkiSidecar) -> SidecarConfig {
    // Destructured, so that a new setting cannot be left out.
    let ast::RpkiSidecar {
        pos: _,
        binary,
        repository_dir,
        rtr_listen,
        rir_tals,
        tals,
        extra_tals_dir,
        accept_arin_rpa,
        refresh,
        config_file,
        global_args,
        server_args,
        restart_initial,
        restart_cap,
        stable_after,
        stop_timeout,
        failure_threshold,
    } = s;
    SidecarConfig {
        binary: binary.clone(),
        rtr_listen: *rtr_listen,
        repository_dir: repository_dir.clone(),
        tals: TalConfig {
            rir_tals: *rir_tals,
            bundled: tals.clone(),
            extra_dir: extra_tals_dir.clone(),
        },
        accept_arin_rpa: *accept_arin_rpa,
        refresh: *refresh,
        config_file: config_file.clone(),
        extra_global_args: global_args.iter().map(OsString::from).collect(),
        extra_server_args: server_args.iter().map(OsString::from).collect(),
        backoff: BackoffConfig {
            initial: *restart_initial,
            cap: *restart_cap,
            stable: *stable_after,
        },
        stop_timeout: *stop_timeout,
        failure_threshold: *failure_threshold,
    }
}

/// What a reload checks before it changes anything, so that a reload that
/// would fail fails with the running configuration kept (m14 design
/// §5.1). A block that has not changed ([`ast::Rpki::same_as`]) needs
/// nothing. Otherwise:
///
/// - With `mode external`, every cache can be found, as [`resolve`]
///   checks at start (issue #60).
/// - When Routinator will start, because the mode becomes `sidecar` or
///   the `sidecar` block changes: bgpfcd is not root, since root now means
///   that no `--user` dropped it ([`privileges::sidecar_as_root`]); the
///   repository directory can be created; and [`Sidecar::check`] passes,
///   the settings, the binary's `--version` (issue #72) and the
///   `rtr-listen` address, bound with port 0 as the start binds it.
///   Without this, a reload onto a Routinator that cannot start would
///   stop the running one first, and only then fail. A change to the
///   client's settings alone starts no Routinator and checks none of
///   this.
///
/// # Errors
/// What fails, for the reload's error.
pub(crate) fn preflight(old: &ast::Rpki, new: &ast::Rpki) -> Result<(), String> {
    preflight_as(old, new, bgpfc_sys::is_root())
}

/// [`preflight`] for a bgpfcd that is `root` or not.
fn preflight_as(old: &ast::Rpki, new: &ast::Rpki, root: bool) -> Result<(), String> {
    if old.same_as(new) {
        return Ok(());
    }
    match new.mode {
        RpkiMode::Disabled => Ok(()),
        RpkiMode::External => resolve(new),
        RpkiMode::Sidecar if old.mode == RpkiMode::Sidecar && old.sidecar.same_as(&new.sidecar) => {
            Ok(())
        }
        RpkiMode::Sidecar => {
            if let Some(refused) = privileges::sidecar_as_root(root, None, new.mode) {
                return Err(format!("{refused}: {}", privileges::SIDECAR_AS_ROOT_HINT));
            }
            create_repository_dir(&new.sidecar.repository_dir)?;
            Sidecar::check(&sidecar_config(&new.sidecar))
                .map_err(|e| format!("rpki sidecar: {e}"))?;
            Ok(())
        }
    }
}

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
/// client. `sidecar` is where the running sidecar serves RTR, which with
/// `mode sidecar` is the client's one cache, at preference 0 (issue #71:
/// wired without operator configuration); `mode external` lists its
/// caches itself.
///
/// The client turns TCP keep-alive on for every connection it makes, as
/// `keepalive` has it when the connection is made (RFC 8210 §9). With
/// `mode sidecar` it also uses a connection only if its other end belongs
/// to bgpfcd's own user, as Routinator, its child, does
/// ([`owner::same_user`]): until Routinator binds its port, after its
/// first validation run, any local process could bind it and serve VRPs
/// of its own (RFC 8210 §9, §13). Both go through [`prepare`].
pub(crate) fn client_config(
    rpki: &ast::Rpki,
    router_id: RouterId,
    sidecar: Option<SocketAddr>,
    keepalive: &Keepalive,
) -> Option<client::Config> {
    let caches = match rpki.mode {
        RpkiMode::Disabled => return None,
        RpkiMode::External => rpki
            .caches
            .iter()
            .map(|c| Cache {
                host: c.host.clone(),
                port: c.port,
                preference: c.preference,
            })
            .collect(),
        RpkiMode::Sidecar => {
            let Some(addr) = sidecar else {
                debug_assert!(false, "mode sidecar without the sidecar's address");
                return None;
            };
            // An address, so the client's lookup cannot fail; and on
            // loopback, as the configuration crate and the sidecar crate
            // both insist (RFC 8210 §9).
            vec![Cache {
                host: addr.ip().to_string(),
                port: addr.port(),
                preference: 0,
            }]
        }
    };
    let mut config = client::Config::new(caches);
    config.check = Some(prepare(rpki.mode == RpkiMode::Sidecar, keepalive.clone()));
    config.connect_timeout = rpki.connect_timeout;
    // With `mode sidecar` the block's default is `1 30` rather than
    // `1 600` (`ast::Rpki::default_backoff`), so that the client finds
    // Routinator soon after its first validation run lets it listen.
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

/// The `tcp-keepalive` of a block as the kernel takes it.
pub(crate) fn tcp_keepalive(k: &ast::RpkiKeepalive) -> TcpKeepalive {
    TcpKeepalive {
        idle: k.idle,
        interval: k.interval,
        probes: k.count,
    }
}

/// The TCP keep-alive every connection to a cache gets (RFC 8210 §9:
/// routers "SHOULD enable keep-alives when available"), as the block's
/// `tcp-keepalive` has it (see [`ast::RpkiKeepalive`] for what the
/// defaults are for): shared between the running block and its client's
/// [`ConnectionCheck`], which reads it as it prepares each connection.
#[derive(Clone, Debug)]
pub(crate) struct Keepalive(Arc<Mutex<TcpKeepalive>>);

impl Keepalive {
    /// The keep-alive `k` says.
    pub(crate) fn new(k: &ast::RpkiKeepalive) -> Keepalive {
        Keepalive(Arc::new(Mutex::new(tcp_keepalive(k))))
    }

    /// What the next connection gets.
    pub(crate) fn get(&self) -> TcpKeepalive {
        *lock(&self.0)
    }

    /// Have the next connection get `k`; whether that is a change.
    fn set(&self, k: &ast::RpkiKeepalive) -> bool {
        let new = tcp_keepalive(k);
        let mut current = lock(&self.0);
        let changed = *current != new;
        *current = new;
        changed
    }
}

/// What the client does with each connection it makes, before it sends
/// or reads anything on it: with `owner_check` (`mode sidecar`), refuse
/// one whose other end does not belong to bgpfcd's own user
/// ([`owner::same_user`]); then, in every mode, turn on TCP keep-alive
/// as `keepalive` has it then (RFC 8210 §9).
///
/// The keep-alive goes through the client's [`ConnectionCheck`] because
/// that hook already runs on every connection the client makes, to every
/// cache, after each reconnect, on the attempt's thread and before the
/// first PDU, which is where a socket option belongs; and `bgpfc-rtr`
/// may not reach `bgpfc-sys`, which sets it (AGENTS.md §2), while bgpfcd
/// may. A second hook for the client would run at the same point.
///
/// A connection on which the kernel refuses the option is still used: §9
/// asks for keep-alives "when available", and without them the polls
/// and timeouts of §6 still find a dead cache, only later. The refusal is
/// a warning, once per connection.
fn prepare(owner_check: bool, keepalive: Keepalive) -> ConnectionCheck {
    ConnectionCheck::new(move |stream: &TcpStream| {
        if owner_check {
            owner::same_user(stream)?;
        }
        if let Err(e) = bgpfc_sys::set_tcp_keepalive(stream, keepalive.get()) {
            let cache = stream
                .peer_addr()
                .map_or_else(|_| "unknown".to_owned(), |a| a.to_string());
            bgpfc_log::warn!(
                "rtr cannot turn on tcp keep-alive; a cache that vanishes is noticed at the next poll",
                cache = cache,
                error = e
            );
        }
        Ok(())
    })
}

/// Create Routinator's repository directory, with the parents it lacks,
/// as the user bgpfcd runs as: `0750`, for Routinator and bgpfcd's group
/// alone. One that exists is left as it is.
///
/// # Errors
/// The directory could not be created, naming it.
fn create_repository_dir(path: &Path) -> Result<(), String> {
    DirBuilder::new()
        .recursive(true)
        .mode(0o750)
        .create(path)
        .map_err(|e| {
            format!(
                "cannot create the rpki repository directory {}: {e}",
                path.display()
            )
        })
}

/// Start Routinator as `s` says: its repository directory, then
/// [`Sidecar::start`], which checks the binary's version (issue #72: a
/// mismatch is reported at startup), picks the RTR port if `s` leaves it
/// to bgpfcd, and starts supervising.
///
/// # Errors
/// What failed, for `cannot start rpki` or a reload's notes.
fn start_sidecar(s: &ast::RpkiSidecar) -> Result<Sidecar, String> {
    create_repository_dir(&s.repository_dir)?;
    bgpfc_log::info!(
        "rpki: starting the routinator sidecar",
        binary = s.binary.display(),
        repository_dir = s.repository_dir.display(),
        rtr_listen = s.rtr_listen
    );
    Sidecar::start(sidecar_config(s)).map_err(|e| format!("rpki sidecar: {e}"))
}

/// The line logged when a client starts with no data to hold, so that the
/// routes wait for its first full set: what becomes of them meanwhile,
/// under `startup` (issue #71: the startup window is not silent).
pub(crate) const fn waiting_line(startup: Startup) -> &'static str {
    match startup {
        Startup::Accept => {
            "rpki: no validation data yet; routes are used unvalidated until the first full set"
        }
        Startup::Hold => {
            "rpki: no validation data yet; routes are held until the first full set (startup hold)"
        }
    }
}

/// Where the client publishes: the RIB thread's bounded channel. A send
/// waits while the channel is full, and fails once the RIB thread is
/// gone, which stops the client. The first change ends the wait for
/// validation data, if routes were waiting, and says so (issue #71: the
/// startup window is not silent; m14 design §3.3).
fn sink(rib: SyncSender<RibMsg>, waiting: Arc<Mutex<Option<Instant>>>) -> impl ValidationSink {
    move |change: ValidationChange| {
        let since = lock(&waiting).take();
        if let Some(since) = since {
            // The RIB's `rib: validation states changed` line follows,
            // and the client's `rtr validation data committed`, with the
            // number of VRPs, came just before.
            bgpfc_log::info!(
                "rpki: validation data arrived; routes are validated from now on",
                waited = format!("{}s", since.elapsed().as_secs())
            );
        }
        rib.send(RibMsg::Validation(change))
            .map_err(|_| RpkiError::SinkClosed)
    }
}

/// The lock, also after a panic elsewhere: nothing that holds it can
/// panic halfway through an update.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Routinator on its way down, from [`Rpki::begin_stop`].
#[must_use = "Stopping::finish waits until Routinator is gone"]
pub(crate) struct Stopping(Option<JoinHandle<()>>);

impl Stopping {
    /// Return once Routinator is gone: reaped with its process group,
    /// every thread of its sidecar joined.
    pub(crate) fn finish(self) {
        if let Some(stopping) = self.0 {
            // `Sidecar::stop` itself reports a supervisor thread that
            // panicked, which killed Routinator as it unwound.
            let _ = stopping.join();
        }
    }
}

/// The running `rpki` block: the RTR client, if its mode has one, and
/// Routinator, with `mode sidecar`.
#[derive(Debug)]
pub(crate) struct Rpki {
    rib: SyncSender<RibMsg>,
    router_id: RouterId,
    client: Option<Client>,
    /// Routinator, supervised; the client's one cache.
    sidecar: Option<Sidecar>,
    /// The keep-alive the client's connections get, from the block in
    /// effect.
    keepalive: Keepalive,
    /// Since when every route has waited for the first full set, unused
    /// for validation: set when a client starts with no data to hold,
    /// cleared by the first change it publishes, or when validation is
    /// disabled (m14 design §3.3).
    waiting: Arc<Mutex<Option<Instant>>>,
}

impl Rpki {
    /// Start what `config` asks for, publishing to `rib`: with `mode
    /// sidecar`, the repository directory and Routinator, then the client
    /// at Routinator's address. The caller has checked with [`resolve`]
    /// that external caches can be found, and calls this after the
    /// privilege drop, so that Routinator runs as the service user (m14
    /// design §4.1).
    ///
    /// # Errors
    /// What could not be started, for `cannot start rpki`: the repository
    /// directory, Routinator (a binary that is missing, fails or reports
    /// another release), or the client thread. A sidecar already started
    /// is stopped again.
    pub(crate) fn start(
        config: &ast::Rpki,
        router_id: RouterId,
        rib: SyncSender<RibMsg>,
    ) -> Result<Rpki, String> {
        let mut rpki = Rpki {
            rib,
            router_id,
            client: None,
            sidecar: None,
            keepalive: Keepalive::new(&config.tcp_keepalive),
            waiting: Arc::default(),
        };
        if config.mode == RpkiMode::Sidecar {
            rpki.sidecar = Some(start_sidecar(&config.sidecar)?);
        }
        // On an error `rpki` is dropped, and with it the sidecar, which
        // stops it.
        rpki.client = rpki
            .spawn_client(config, None)
            .map_err(|e| format!("cannot start the rtr client: {e}"))?;
        Ok(rpki)
    }

    /// A client for `config`, holding `held`, if its mode runs one; with
    /// `mode sidecar`, at the running sidecar's address. Its connections
    /// get the block's keep-alive. A client with no data to hold leaves the
    /// routes waiting for its first full set.
    fn spawn_client(&self, config: &ast::Rpki, held: Option<Held>) -> io::Result<Option<Client>> {
        let sidecar = self.sidecar.as_ref().map(Sidecar::rtr_addr);
        self.keepalive.set(&config.tcp_keepalive);
        let Some(client_config) = client_config(config, self.router_id, sidecar, &self.keepalive)
        else {
            return Ok(None);
        };
        bgpfc_log::info!(
            "rpki: starting the rtr client",
            caches = client_config
                .caches
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(","),
            version = config.version,
            tcp_keepalive = config.tcp_keepalive,
            held_vrps = held.as_ref().map_or(0, |h| h.vrps.len())
        );
        if held.is_none() {
            self.wait_for_data(config);
        }
        let sink = sink(self.rib.clone(), Arc::clone(&self.waiting));
        let client = Client::start_holding(client_config, sink, held)?;
        Ok(Some(client))
    }

    /// Note that the routes wait for the first full set, from now unless
    /// they waited already, and say so (issue #71). Until it arrives every
    /// route is `disabled`: used as received under `startup accept`, the
    /// default, since RFC 6811 §2 lets no route leave route selection for
    /// its state without configuration, and held under `startup hold`,
    /// which is that configuration ([`waiting_line`]). With the sidecar the
    /// wait is Routinator's first validation run, minutes from a cold
    /// repository, so it is a warning; an external cache answers within a
    /// moment, which is no news, unless the routes are held meanwhile.
    fn wait_for_data(&self, config: &ast::Rpki) {
        let line = waiting_line(config.startup);
        lock(&self.waiting).get_or_insert_with(Instant::now);
        if config.mode == RpkiMode::Sidecar {
            bgpfc_log::warn!(
                line,
                mode = config.mode,
                enforcement = config.enforcement,
                startup = config.startup,
                hint = "Routinator serves RTR once its first validation run ends: minutes from a cold cache"
            );
        } else if config.startup == Startup::Hold {
            bgpfc_log::warn!(
                line,
                mode = config.mode,
                enforcement = config.enforcement,
                startup = config.startup
            );
        } else {
            bgpfc_log::info!(
                line,
                mode = config.mode,
                enforcement = config.enforcement,
                startup = config.startup
            );
        }
    }

    /// Apply `new`, the block of a reloaded configuration, in place of
    /// `old`, the running one; what was done, for the reload's summary.
    /// The caller has checked `new` with [`preflight`].
    ///
    /// A block that has not changed ([`ast::Rpki::same_as`]) changes
    /// nothing; an `enforcement` alone is no change here, as the RIB
    /// judges the routes again. Otherwise the client is restarted, holding
    /// the data the old one published until a cache sends a full set or
    /// the data expires (RFC 8210 §10, §6), and Routinator (m14 design
    /// §5.2):
    ///
    /// - is left running when only the client's settings change: the new
    ///   client connects to the same address;
    /// - is stopped and started again when its own settings change. Its
    ///   address may change with it; the held data covers the validation
    ///   run before it listens again;
    /// - is started when the mode becomes `sidecar`, from `external` with
    ///   the external cache's data held, from `disabled` with nothing to
    ///   hold, so that the routes wait for its first full set;
    /// - is stopped when the mode leaves `sidecar`, after the client.
    ///
    /// A Routinator that keeps failing is not restarted by a reload that
    /// leaves its block alone: its supervisor keeps retrying.
    ///
    /// # Errors
    /// Routinator or the client could not be started although the
    /// preflight passed, as when the binary changed in between. Validation
    /// is then off, as with `mode disabled`: with no client, nothing would
    /// expire the data the old one left in the RIB. [`Rpki::in_effect`] is
    /// then `mode disabled`, so the next reload starts the block again.
    pub(crate) fn reconfigure(
        &mut self,
        old: &ast::Rpki,
        new: &ast::Rpki,
    ) -> Result<&'static str, String> {
        if old.same_as(new) {
            return Ok("rpki unchanged");
        }
        let sidecar = new.mode == RpkiMode::Sidecar;
        let had_sidecar = self.sidecar.is_some();
        // Also when an earlier start failed and none runs.
        let starting = sidecar && (!had_sidecar || !old.sidecar.same_as(&new.sidecar));
        let ran = self.client.is_some();
        let held = self.stop_client();
        if starting || !sidecar {
            self.stop_sidecar();
        }
        if starting {
            match start_sidecar(&new.sidecar) {
                Ok(started) => self.sidecar = Some(started),
                Err(e) => {
                    self.disable();
                    bgpfc_log::error!("rpki: cannot start the sidecar", error = e);
                    return Err(format!(
                        "rpki: cannot start the sidecar ({e}); validation disabled"
                    ));
                }
            }
        }
        let stopped = had_sidecar && !sidecar;
        match self.spawn_client(new, held) {
            Ok(Some(client)) => {
                self.client = Some(client);
                Ok(match (starting, had_sidecar, stopped, ran) {
                    (true, true, _, _) => "rpki: sidecar restarted",
                    (true, false, _, _) => "rpki: sidecar started",
                    (false, _, true, true) => "rpki: rtr client restarted; sidecar stopped",
                    (false, _, true, false) => "rpki: rtr client started; sidecar stopped",
                    (false, _, false, true) => "rpki: rtr client restarted",
                    (false, _, false, false) => "rpki: rtr client started",
                })
            }
            Ok(None) if ran || stopped => {
                self.disable();
                Ok(if stopped {
                    "rpki: validation disabled; sidecar stopped"
                } else {
                    "rpki: validation disabled"
                })
            }
            Ok(None) => Ok("rpki: validation stays disabled"),
            Err(e) => {
                // A Routinator that no client reads is of no use.
                self.stop_sidecar();
                self.disable();
                bgpfc_log::error!("rpki: cannot start the rtr client", error = e);
                Err(format!(
                    "rpki: cannot start the rtr client ({e}); validation disabled"
                ))
            }
        }
    }

    /// Apply `new`'s `tcp-keepalive`, which a reload changed, and return
    /// the reload summary's note on it. Every later connection to a cache
    /// gets it, and so does the one in use, at once
    /// ([`Client::check_again`]): with no new connection, and no new
    /// client, which would load the cache's data afresh for a socket
    /// option (RFC 8210 §9). Without a client, the next one gets it.
    ///
    /// With `mode sidecar` the owner check runs again on the connection in
    /// use too; should it fail now, the connection is closed, and the
    /// client connects again.
    pub(crate) fn set_tcp_keepalive(&self, new: &ast::Rpki) -> String {
        self.keepalive.set(&new.tcp_keepalive);
        let Some(client) = &self.client else {
            return format!(
                "rpki tcp-keepalive {} (no rtr client runs)",
                new.tcp_keepalive
            );
        };
        match client.check_again() {
            Ok(()) => {
                bgpfc_log::info!(
                    "rpki: tcp keep-alive changed; the connection in use and every later one have it",
                    tcp_keepalive = new.tcp_keepalive
                );
                format!("rpki tcp-keepalive {}", new.tcp_keepalive)
            }
            Err(e) => {
                bgpfc_log::warn!(
                    "rpki: tcp keep-alive changed; the connection in use no longer passes its check and is closed",
                    tcp_keepalive = new.tcp_keepalive,
                    error = e
                );
                format!(
                    "rpki tcp-keepalive {} (connection in use closed: {e})",
                    new.tcp_keepalive
                )
            }
        }
    }

    /// The block in effect, for a reload to compare the new one with:
    /// `config`, the running configuration's, while what it runs is
    /// running, and otherwise `mode disabled`, which is what then holds:
    /// after a reload that could not start Routinator or the client (see
    /// [`Rpki::reconfigure`]), no client runs and every route is
    /// `disabled`. So a later reload checks and starts what is missing even
    /// when the file has not changed, rather than leave validation off
    /// until the block is edited or bgpfcd restarted.
    pub(crate) fn in_effect(&self, config: &ast::Rpki) -> ast::Rpki {
        let running = match config.mode {
            RpkiMode::Disabled => true,
            RpkiMode::External => self.client.is_some(),
            RpkiMode::Sidecar => self.client.is_some() && self.sidecar.is_some(),
        };
        if running {
            config.clone()
        } else {
            ast::Rpki::defaults(RpkiMode::Disabled)
        }
    }

    /// Stop the client, if one runs, and return what it published.
    fn stop_client(&mut self) -> Option<Held> {
        let mut client = self.client.take()?;
        client.stop();
        // Read once the thread has ended: it publishes nothing after.
        client.status().held()
    }

    /// Stop Routinator, if it runs, and return once it is gone: `SIGTERM`,
    /// `SIGKILL` after `stop-timeout`, reaped with its process group, every
    /// thread joined. The sidecar logs the stop itself.
    fn stop_sidecar(&mut self) {
        if let Some(sidecar) = self.sidecar.take() {
            sidecar.stop();
        }
    }

    /// Turn validation off in the RIB: every route `disabled`, used, and
    /// no longer waiting for data.
    ///
    /// The hold of `startup hold` goes first ([`startup`]): the RIB holds
    /// every `disabled` route under it, and no data would come to release
    /// them. On the same channel, so the RIB applies the two in this
    /// order, and no route that was used is withdrawn on the way.
    fn disable(&self) {
        *lock(&self.waiting) = None;
        bgpfc_log::info!("rpki: validation disabled; every route is disabled again");
        // A RIB thread that is gone has no routes to tell.
        let _ = self.rib.send(RibMsg::SetStartup(Startup::Accept));
        let _ = self
            .rib
            .send(RibMsg::Validation(ValidationChange::disabled()));
    }

    /// Begin to stop the block for good, at shutdown: the client, which
    /// has stopped when this returns, then Routinator, on a thread of its
    /// own that [`Stopping::finish`] waits for. The client goes first, so
    /// that it neither warns about the cache it loses nor publishes what
    /// it would read from a Routinator on its way down (m14 design §4.3).
    /// Routinator's supervisor restarts nothing once it is asked to stop,
    /// even a Routinator that exits by itself meanwhile, as one that an
    /// init system signals with bgpfcd does (issue #70: "restarting the
    /// child during our own shutdown is a bug"), and the caller goes on
    /// with the rest of its shutdown, such as a FIB cleanup that takes
    /// seconds, while Routinator takes up to its `stop-timeout`.
    pub(crate) fn begin_stop(&mut self) -> Stopping {
        self.stop_client();
        let Some(sidecar) = self.sidecar.take() else {
            return Stopping(None);
        };
        // Should no thread be had, the closure is dropped, and with it the
        // sidecar, which stops it before this returns.
        let stopping = thread::Builder::new()
            .name("sidecar-stop".to_owned())
            .spawn(move || sidecar.stop())
            .ok();
        Stopping(stopping)
    }

    /// Stop the block for good, and return once the client and Routinator
    /// are gone: [`Rpki::begin_stop`], then [`Stopping::finish`]. The
    /// daemon's shutdown does more between the two.
    #[cfg(test)]
    pub(crate) fn stop(&mut self) {
        self.begin_stop().finish();
    }

    /// The client's status, if one runs.
    pub(crate) fn status(&self) -> Option<Status> {
        self.client.as_ref().map(Client::status)
    }

    /// What the control plane shows of the running block `config`: the
    /// client's status, since when the routes have waited for the first
    /// full set, and Routinator's status and version, read now rather than
    /// kept, since a restart after the binary was replaced may change the
    /// version (issue #70: a validator that is not running must be
    /// visible).
    pub(crate) fn report(&self, config: &ast::Rpki) -> RpkiReport {
        RpkiReport {
            config: config.clone(),
            status: self.status(),
            waiting_since: *lock(&self.waiting),
            // A sidecar runs only with `mode sidecar`, started from this
            // block's `sidecar` settings: a change to them restarts it.
            sidecar: self.sidecar.as_ref().map(|s| SidecarReport {
                status: s.status(),
                version: s.version(),
                binary: config.sidecar.binary.clone(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::io::{ErrorKind, Read as _, Write as _};
    use std::net::{Ipv4Addr, TcpListener, TcpStream};
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc::{Receiver, sync_channel};
    use std::thread;
    use std::time::{Duration, Instant};

    use bgpfc_config::diff::GlobalChange;
    use bgpfc_config::{Config, ConfigDiff};
    use bgpfc_rpki::{AffectedPrefixes, RouteOrigin, RovState, Vrp};
    use bgpfc_rtr::{Framer, Intervals, Pdu};
    use bgpfc_sidecar::{SidecarState, TESTED_VERSION};
    use bgpfc_wire::types::Asn;

    const WAIT: Duration = Duration::from_secs(10);
    const SID: u16 = 7;

    fn config(rpki: &str) -> Config {
        bgpfc_config::parse_str("t", &format!("router-id 192.0.2.1; local-as 65000; {rpki}"))
            .unwrap()
    }

    /// The keep-alive the block gives the client's connections.
    fn keepalive(rpki: &ast::Rpki) -> Keepalive {
        Keepalive::new(&rpki.tcp_keepalive)
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

    /// What turning validation off sends the RIB: the hold of `startup
    /// hold` off first, then no source for every route, which with the
    /// hold still on would hold every route.
    fn next_disabled(rx: &Receiver<RibMsg>) -> ValidationChange {
        match rx.recv_timeout(WAIT) {
            Ok(RibMsg::SetStartup(Startup::Accept)) => {}
            other => panic!("expected the startup hold off first, got {other:?}"),
        }
        let change = next_change(rx);
        assert_eq!(change.affected, AffectedPrefixes::All);
        change
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
        let c = client_config(&cfg.rpki, router_id, None, &keepalive(&cfg.rpki)).unwrap();
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
        let c = client_config(&cfg.rpki, router_id, None, &keepalive(&cfg.rpki)).unwrap();
        let defaults = client::Config::new(vec![Cache::new("192.0.2.10")]);
        assert_eq!(c.caches, defaults.caches);
        assert_eq!(c.connect_timeout, defaults.connect_timeout);
        assert_eq!(c.backoff, defaults.backoff);
        assert_eq!(c.session, defaults.session);
        assert_eq!(ast::Rpki::DEFAULT_PORT, client::DEFAULT_PORT);
        assert_eq!(ast::Rpki::MIN_EXPIRE, session::Config::MIN_EXPIRE);
        assert_eq!(ast::Rpki::MAX_EXPIRE, session::Config::MAX_EXPIRE);
        // No client without the block, or with `mode disabled`.
        let none = config("");
        assert!(client_config(&none.rpki, router_id, None, &keepalive(&none.rpki)).is_none());
        let disabled = config("rpki { mode disabled; cache 192.0.2.10; }");
        assert!(
            client_config(&disabled.rpki, router_id, None, &keepalive(&disabled.rpki)).is_none()
        );
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

    /// The parse hook finds nothing in a file the sidecar crate accepts,
    /// so such a file loads as the configuration crate alone judges it.
    #[test]
    fn the_parse_hook_accepts_the_modes_bgpfcd_runs() {
        for rpki in [
            "",
            "rpki { mode disabled; }",
            "rpki { mode external; cache 192.0.2.10; }",
            "rpki { mode sidecar; }",
        ] {
            let errors = check_config(&config(rpki));
            assert!(errors.is_empty(), "{rpki}: {errors:?}");
        }
    }

    /// The golden file with every sidecar statement written out, read
    /// from the configuration crate's tests.
    const FULL_SIDECAR: &str = include_str!("../../bgpfc-config/tests/golden/rpki-sidecar.conf");
    /// The golden file with the one-line sidecar block.
    const DEFAULT_SIDECAR: &str =
        include_str!("../../bgpfc-config/tests/golden/rpki-sidecar-defaults.conf");

    #[test]
    fn the_sidecar_settings_lower_to_the_sidecar_crate() {
        let cfg = bgpfc_config::parse_str("rpki-sidecar.conf", FULL_SIDECAR).unwrap();
        let expected = SidecarConfig {
            binary: "/opt/routinator/bin/routinator".into(),
            rtr_listen: "[::1]:3323".parse().unwrap(),
            repository_dir: "/var/lib/bgpfc/rpki cache".into(),
            tals: TalConfig {
                rir_tals: false,
                bundled: vec!["ripe".to_owned(), "ripe-pilot".to_owned()],
                extra_dir: Some("/etc/bgpfc/tals".into()),
            },
            accept_arin_rpa: true,
            refresh: Duration::from_secs(300),
            config_file: Some("/etc/bgpfc/routinator.conf".into()),
            extra_global_args: vec![
                "--strict".into(),
                "--exceptions=/etc/bgpfc/slurm;local.json".into(),
            ],
            extra_server_args: vec![
                "--rtr-tcp-keepalive=30".into(),
                "--http=127.0.0.1:8323".into(),
            ],
            backoff: BackoffConfig {
                initial: Duration::from_secs(2),
                cap: Duration::from_secs(600),
                stable: Duration::from_mins(15),
            },
            stop_timeout: Duration::from_secs(20),
            failure_threshold: 3,
        };
        assert_eq!(sidecar_config(&cfg.rpki.sidecar), expected);
    }

    /// The defaults and bounds of the `sidecar` block are those of the
    /// sidecar crate (m14 design §1.2), as m12 checks the RTR client's.
    #[test]
    fn the_sidecar_defaults_are_the_sidecar_crates() {
        use bgpfc_config::ast::RpkiSidecar as S;
        assert_eq!(
            sidecar_config(&S::default()),
            SidecarConfig::new(S::DEFAULT_BINARY, S::DEFAULT_REPOSITORY_DIR)
        );
        let cfg = bgpfc_config::parse_str("defaults", DEFAULT_SIDECAR).unwrap();
        assert_eq!(
            sidecar_config(&cfg.rpki.sidecar),
            SidecarConfig::new(S::DEFAULT_BINARY, S::DEFAULT_REPOSITORY_DIR)
        );
        assert_eq!(S::DEFAULT_REFRESH, SidecarConfig::DEFAULT_REFRESH);
        assert_eq!(S::DEFAULT_STOP_TIMEOUT, SidecarConfig::DEFAULT_STOP_TIMEOUT);
        assert_eq!(
            S::DEFAULT_FAILURE_THRESHOLD,
            SidecarConfig::DEFAULT_FAILURE_THRESHOLD
        );
        let backoff = BackoffConfig::default();
        assert_eq!(S::DEFAULT_RESTART_INITIAL, backoff.initial);
        assert_eq!(S::DEFAULT_RESTART_CAP, backoff.cap);
        assert_eq!(S::DEFAULT_STABLE_AFTER, backoff.stable);
        // The bounds the language allows are the crate's: whole seconds
        // meet its sub-second floors, and the longest values are its own.
        assert_eq!(S::MAX_RESTART_BACKOFF, SidecarConfig::MAX_DELAY);
        assert_eq!(S::MAX_STOP_TIMEOUT, SidecarConfig::MAX_DELAY);
        assert_eq!(S::MAX_STABLE_AFTER, SidecarConfig::MAX_STABLE);
        assert!(Duration::from_secs(1) >= SidecarConfig::MIN_BACKOFF);
        assert!(Duration::from_secs(1) >= SidecarConfig::MIN_BACKOFF_CAP);
        assert_eq!(S::MAX_REFRESH, Duration::from_secs(7_199));
        // So the extremes the language accepts pass the crate's checks,
        // and one second past the longest refresh does not.
        let extremes = [
            "refresh 1; restart-backoff 1 1; stable-after 1; stop-timeout 1; \
             failure-threshold 1;",
            "refresh 7199; restart-backoff 3600 3600; stable-after 86400; \
             stop-timeout 3600; failure-threshold 4294967295;",
        ];
        for settings in extremes {
            let cfg = config(&format!(
                "rpki {{ mode sidecar; sidecar {{ {settings} }} }}"
            ));
            assert_eq!(sidecar_config(&cfg.rpki.sidecar).validate(), Ok(()));
        }
        let mut past = sidecar_config(&S::default());
        past.refresh = S::MAX_REFRESH + Duration::from_secs(1);
        assert!(past.validate().is_err());
    }

    #[test]
    fn every_sidecar_block_the_parser_accepts_passes_validate() {
        for (name, text) in [
            ("rpki-sidecar.conf", FULL_SIDECAR),
            ("rpki-sidecar-defaults.conf", DEFAULT_SIDECAR),
        ] {
            let cfg = bgpfc_config::parse_str_with(name, text, &check_config);
            assert!(cfg.is_ok(), "{name}: {}", cfg.unwrap_err());
        }
    }

    /// Issue #72: what only Routinator's rules refuse is reported at the
    /// `sidecar` block, with the file's position and caret, as any other
    /// error; under `mode disabled` the same block is only read.
    #[test]
    fn routinator_rules_are_reported_at_the_sidecar_block() {
        let cases = [
            (
                "tals ripe-ncc;",
                "rpki sidecar: Routinator 0.15 bundles no TAL named \"ripe-ncc\"; it knows \
                 afrinic, apnic, arin, lacnic, ripe, apnic-testbed, arin-ote, ripe-pilot, \
                 nlnetlabs-testbed",
            ),
            (
                "tals arin;",
                "rpki sidecar: the ARIN TAL is listed, but ARIN's Relying Party Agreement \
                 has not been accepted",
            ),
            (
                "rir-tals no;",
                "rpki sidecar: no trust anchors: enable the RIR TALs, name a bundled TAL or \
                 give an extra TAL directory",
            ),
            (
                "global-args \"-d\";",
                "rpki sidecar: extra Routinator argument \"-d\" is not allowed: a detached \
                 Routinator leaves bgpfcd's supervision",
            ),
            (
                "server-args \"--rtr=0.0.0.0:323\";",
                "rpki sidecar: extra Routinator argument \"--rtr=0.0.0.0:323\" is not \
                 allowed: bgpfcd passes --rtr; RTR is served on the configured loopback \
                 address only",
            ),
        ];
        let head = "router-id 192.0.2.1;\nlocal-as 65000;\n";
        for (statement, message) in cases {
            let block = format!("  sidecar {{ {statement} }}");
            let text = format!("{head}rpki {{\n  mode sidecar;\n{block}\n}}\n");
            let errors = bgpfc_config::parse_str_with("t", &text, &check_config).unwrap_err();
            assert_eq!(
                errors.to_string(),
                format!("t:5:3: {message}\n  {block}\n    ^"),
                "{statement}"
            );
            let disabled = text.replace("mode sidecar", "mode disabled");
            let cfg = bgpfc_config::parse_str_with("t", &disabled, &check_config);
            assert!(cfg.is_ok(), "{statement}: {}", cfg.unwrap_err());
        }
        // Without a block, at the mode, which is all there is to point to.
        let config = bgpfc_config::Config {
            rpki: ast::Rpki {
                sidecar: ast::RpkiSidecar {
                    pos: Some(Pos { line: 3, col: 8 }),
                    rir_tals: false,
                    ..ast::RpkiSidecar::default()
                },
                ..ast::Rpki::defaults(RpkiMode::Sidecar)
            },
            ..config("")
        };
        let errors = check_config(&config);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].pos, Pos { line: 3, col: 8 });
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

    /// The time left on the keep-alive timer of this host's TCP socket at
    /// `local`, from the kernel's socket table (`proc(5)`: `tr` 2 is the
    /// socket's own timer, which an established connection uses for
    /// keep-alive, and `tm->when` the clock ticks left), or `None` while
    /// another timer, or none, runs.
    fn keep_alive_ticks(local: SocketAddr) -> Option<u64> {
        let table = fs::read_to_string("/proc/net/tcp").unwrap();
        let ip = match local.ip() {
            std::net::IpAddr::V4(v4) => v4,
            std::net::IpAddr::V6(_) => panic!("an IPv4 test"),
        };
        let address = format!(
            "{:08X}:{:04X}",
            u32::from_ne_bytes(ip.octets()),
            local.port()
        );
        let line = table
            .lines()
            .skip(1)
            .find(|l| l.split_whitespace().nth(1) == Some(address.as_str()))?;
        let (timer, when) = line.split_whitespace().nth(5)?.split_once(':')?;
        (timer == "02").then(|| u64::from_str_radix(when, 16).ok())?
    }

    /// RFC 8210 §9: a reload's new `tcp-keepalive` reaches the connection
    /// in use at once, with no new connection, no new client and nothing
    /// published, as the kernel's keep-alive timer of the client's end
    /// shows: no longer than 30 s before, about 3000 s after.
    #[test]
    fn a_new_keep_alive_reaches_the_connection_in_use() {
        let cache = StubCache::new();
        let block = |idle: u32| {
            config(&format!(
                "rpki {{ mode external; cache 127.0.0.1 port {}; tcp-keepalive idle {idle}; }}",
                cache.port()
            ))
        };
        let (old, new) = (block(30), block(3000));
        let (tx, rx) = sync_channel(4);
        let mut rpki = Rpki::start(&old.rpki, old.router_id, tx).unwrap();
        let conn = cache.serve(&[vrp("192.0.2.0/24", 24, 64_496)]);
        assert_eq!(next_change(&rx).affected, AffectedPrefixes::All);
        let client = conn.peer_addr().unwrap();
        let mut before = 0;
        eventually("the keep-alive timer of the client's end", || {
            keep_alive_ticks(client).is_some_and(|t| {
                before = t;
                t > 0
            })
        });

        let diff = ConfigDiff::between(&old, &new);
        assert_eq!(diff.global, [GlobalChange::RpkiKeepalive]);
        assert_eq!(rpki.reconfigure(&old.rpki, &new.rpki), Ok("rpki unchanged"));
        assert_eq!(
            rpki.set_tcp_keepalive(&new.rpki),
            "rpki tcp-keepalive idle 3000 interval 10 count 6"
        );
        // The kernel restarts the timer with the new idle time, less what
        // has gone by: a hundred times as long, whatever the clock tick.
        let after = keep_alive_ticks(client).expect("the keep-alive timer");
        assert!(after > 50 * before, "{before} ticks before, {after} after");
        assert_eq!(
            cache.listener.accept().map_err(|e| e.kind()).err(),
            Some(ErrorKind::WouldBlock),
            "no new connection"
        );
        assert!(rx.try_recv().is_err());
        assert!(rpki.status().is_some_and(|s| s.connected));
        rpki.stop();
        // No client: the next one gets it.
        assert_eq!(
            rpki.set_tcp_keepalive(&old.rpki),
            "rpki tcp-keepalive idle 30 interval 10 count 6 (no rtr client runs)"
        );
        assert_eq!(rpki.keepalive.get().idle, Duration::from_secs(30));
    }

    #[test]
    fn a_respelled_cache_leaves_the_client_alone() {
        // The parser takes a name in another case, or with its final dot,
        // for the same cache; so does a reload.
        let cache = StubCache::new();
        let named = |host: &str| {
            config(&format!(
                "rpki {{ mode external; cache {host} port {}; }}",
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
        // ValidationChange::disabled: no source, for every route, after
        // the hold of `startup hold` is off.
        let change = next_disabled(&rx);
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
            "rpki {{ mode external; cache 127.0.0.1 port {};
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

    /// A directory of its own for one test, under the system's temporary
    /// directory, removed afterwards.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Scratch {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let name = format!("bgpfcd-rpki-{tag}-{}-{n}", std::process::id());
            let path = std::env::temp_dir().join(name);
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Scratch(path)
        }

        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }

        /// An executable `#!/bin/sh` script `name` running `body`.
        ///
        /// Another process writes it, as bgpfc-sidecar's tests do: were
        /// this process to hold it open for writing while a parallel test
        /// forks, the forked child would hold it too until it executes,
        /// and running the script meanwhile would fail with `ETXTBSY`.
        fn script(&self, name: &str, body: &str) -> PathBuf {
            let path = self.join(name);
            let status = Command::new("/bin/sh")
                .args([
                    "-c",
                    "printf '%s' \"$1\" > \"$2\" && chmod 755 \"$2\"",
                    "sh",
                ])
                .arg(format!("#!/bin/sh\n{body}\n"))
                .arg(&path)
                .status()
                .unwrap();
            assert!(status.success(), "writing {}", path.display());
            path
        }

        /// A stub Routinator, never the real one (AGENTS.md §5): it
        /// answers `--version` with `Routinator {version}` and otherwise
        /// runs `body`.
        fn routinator(&self, version: &str, body: &str) -> PathBuf {
            let version =
                format!("if [ \"$1\" = --version ]; then echo 'Routinator {version}'; exit 0; fi");
            self.script("routinator", &format!("{version}\n{body}"))
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// The release the sidecar crate drives, as `--version` prints it.
    fn tested() -> String {
        TESTED_VERSION.to_string()
    }

    /// A block that runs `binary` with its repository in `repository`,
    /// serving RTR on 127.0.0.1 at `port`, or at one picked at start for 0.
    fn sidecar_block(binary: &Path, repository: &Path, port: u16) -> String {
        sidecar_block_with(binary, repository, port, "", "")
    }

    /// [`sidecar_block`] with more statements: `rpki` in the `rpki` block,
    /// `sidecar` in the `sidecar` block.
    fn sidecar_block_with(
        binary: &Path,
        repository: &Path,
        port: u16,
        rpki: &str,
        sidecar: &str,
    ) -> String {
        format!(
            "rpki {{ mode sidecar; {rpki} sidecar {{ binary \"{}\"; repository-dir \"{}\"; \
             rtr-listen 127.0.0.1 port {port}; {sidecar} }} }}",
            binary.display(),
            repository.display()
        )
    }

    /// Routinator's process id, once it runs.
    fn routinator_pid(rpki: &Rpki) -> u32 {
        let sidecar = rpki.sidecar.as_ref().expect("a sidecar");
        let deadline = Instant::now() + WAIT;
        loop {
            if let SidecarState::Running { pid, .. } = sidecar.status().state {
                return pid;
            }
            assert!(Instant::now() < deadline, "routinator did not start");
            thread::sleep(Duration::from_millis(5));
        }
    }

    /// Whether process `pid` exists, if only as a zombie.
    fn alive(pid: u32) -> bool {
        Path::new(&format!("/proc/{pid}")).exists()
    }

    /// Since when the routes have waited for the first full set.
    fn waiting(rpki: &Rpki) -> Option<Instant> {
        *lock(&rpki.waiting)
    }

    /// Issue #71, m14 design §3.3: a client that starts with no data
    /// leaves the routes waiting until its first full set; one that takes
    /// data over does not; disabling validation ends the wait.
    /// RFC 6811 §2: the hold applies while a mode that validates waits
    /// for its data, never with validation off, where nothing would
    /// release the routes.
    #[test]
    fn the_startup_in_effect_holds_only_where_data_will_come() {
        for (block, startup) in [
            ("", Startup::Accept),
            ("rpki { mode disabled; startup hold; }", Startup::Accept),
            ("rpki { mode external; cache 192.0.2.10; }", Startup::Accept),
            (
                "rpki { mode external; startup hold; cache 192.0.2.10; }",
                Startup::Hold,
            ),
            ("rpki { mode sidecar; startup hold; }", Startup::Hold),
            ("rpki { mode sidecar; startup accept; }", Startup::Accept),
        ] {
            assert_eq!(super::startup(&config(block).rpki), startup, "{block}");
        }
        // A block a reload could not start is in effect as `mode disabled`
        // (`Rpki::in_effect`).
        let off = ast::Rpki::defaults(RpkiMode::Disabled);
        assert_eq!(super::startup(&off), Startup::Accept);
        // A reload that changes it says so, and when it holds nothing.
        let hold = config("rpki { mode sidecar; startup hold; }");
        assert_eq!(startup_note(&hold.rpki), "rpki startup hold");
        let off = config("rpki { mode disabled; startup hold; }");
        assert_eq!(
            startup_note(&off.rpki),
            "rpki startup hold (holds nothing with mode disabled)"
        );
        // The line of a client that starts with nothing says what becomes
        // of the routes meanwhile.
        assert_eq!(
            waiting_line(Startup::Accept),
            "rpki: no validation data yet; routes are used unvalidated until the first full set"
        );
        assert_eq!(
            waiting_line(Startup::Hold),
            "rpki: no validation data yet; routes are held until the first full set (startup hold)"
        );
    }

    #[test]
    fn validation_waits_for_the_first_full_set() {
        let first = StubCache::new();
        let cfg = config(&first.block());
        let (tx, rx) = sync_channel(4);
        let mut rpki = Rpki::start(&cfg.rpki, cfg.router_id, tx).unwrap();
        let since = waiting(&rpki).expect("waiting from the start");
        let report = rpki.report(&cfg.rpki);
        assert_eq!(report.waiting_since, Some(since));
        assert!(report.sidecar.is_none(), "an external cache has no sidecar");
        // Until the cache answers, nothing ends the wait.
        let (mut conn, query) = first.accept();
        assert!(matches!(query, Pdu::ResetQuery { .. }), "{query:?}");
        assert_eq!(waiting(&rpki), Some(since));
        drop(conn);
        let _conn = first.serve(&[vrp("192.0.2.0/24", 24, 64_496)]);
        next_change(&rx);
        assert_eq!(waiting(&rpki), None);

        // A new cache list: the new client holds the old data, which stays
        // in use until the new cache answers, so nothing waits.
        let second = StubCache::new();
        let moved = config(&second.block());
        assert_eq!(
            rpki.reconfigure(&cfg.rpki, &moved.rpki),
            Ok("rpki: rtr client restarted")
        );
        let (mut taken_over, _) = second.accept();
        assert_eq!(waiting(&rpki), None);

        // Back from `mode disabled` there is nothing to hold: the routes
        // wait again, and disabling ends that.
        let off = config("rpki { mode disabled; }");
        assert_eq!(
            rpki.reconfigure(&moved.rpki, &off.rpki),
            Ok("rpki: validation disabled")
        );
        assert!(closed(&mut taken_over));
        next_disabled(&rx);
        assert_eq!(
            rpki.reconfigure(&off.rpki, &moved.rpki),
            Ok("rpki: rtr client started")
        );
        assert!(waiting(&rpki).is_some());
        conn = second.accept().0;
        assert_eq!(
            rpki.reconfigure(&moved.rpki, &off.rpki),
            Ok("rpki: validation disabled")
        );
        assert!(closed(&mut conn));
        assert_eq!(waiting(&rpki), None);
        rpki.stop();
    }

    /// Issue #71: with `mode sidecar` the client's one cache is the
    /// sidecar's loopback address, with the block's client settings and
    /// the sidecar's own back-off default.
    #[test]
    fn the_client_uses_the_sidecar_alone() {
        let router_id = RouterId::new(0xC000_0201).unwrap();
        let cfg = config(
            "rpki { mode sidecar; version 0; connect-timeout 5; response-timeout 30;
             reply-timeout 600; max-expire 3600; max-vrps 1000; }",
        );
        let addr: SocketAddr = "127.0.0.1:3323".parse().unwrap();
        let c = client_config(&cfg.rpki, router_id, Some(addr), &keepalive(&cfg.rpki)).unwrap();
        let sidecar = Cache {
            host: "127.0.0.1".to_owned(),
            port: 3323,
            preference: 0,
        };
        assert_eq!(c.caches, [sidecar]);
        // m14 design §3.4: `1 30`, so that the client finds Routinator
        // soon after it starts to listen.
        let backoff = Backoff {
            min: Duration::from_secs(1),
            max: Duration::from_secs(30),
        };
        assert_eq!(c.backoff, backoff);
        assert_eq!(c.connect_timeout, Duration::from_secs(5));
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
        // RFC 8210 §9, §13: only a server of bgpfcd's own user is used,
        // and with keep-alive (see `every_rtr_connection_has_tcp_keep_alive`).
        assert!(c.check.is_some());
        let v6 = client_config(
            &cfg.rpki,
            router_id,
            Some("[::1]:3323".parse().unwrap()),
            &keepalive(&cfg.rpki),
        )
        .unwrap();
        assert_eq!(v6.caches[0].host, "::1");
        assert_eq!(v6.caches[0].to_string(), "[::1]:3323");
        // A written back-off is the block's.
        let written = config("rpki { mode sidecar; backoff 2 5; }");
        let c = client_config(
            &written.rpki,
            router_id,
            Some(addr),
            &keepalive(&written.rpki),
        )
        .unwrap();
        assert_eq!(c.backoff.min, Duration::from_secs(2));
        assert_eq!(c.backoff.max, Duration::from_secs(5));
        // Only `mode sidecar` uses the sidecar's address.
        let external = config("rpki { mode external; cache 192.0.2.10; }");
        let c = client_config(
            &external.rpki,
            router_id,
            Some(addr),
            &keepalive(&external.rpki),
        )
        .unwrap();
        assert_eq!(c.caches, [Cache::new("192.0.2.10")]);
        // An external cache is another host's, so no owner check; but its
        // connections get keep-alive too.
        assert!(c.check.is_some());
        let disabled = config("rpki { mode disabled; }");
        assert!(
            client_config(
                &disabled.rpki,
                router_id,
                Some(addr),
                &keepalive(&disabled.rpki)
            )
            .is_none()
        );
    }

    /// RFC 8210 §9: every connection the client makes to a cache has TCP
    /// keep-alive on, as the block's `tcp-keepalive` has it, its defaults
    /// where it is not written, before the client sends its first query,
    /// with `mode external` and with `mode sidecar`, whose owner check
    /// passes for a cache of this process.
    #[test]
    fn every_rtr_connection_has_tcp_keep_alive() {
        let router_id = RouterId::new(0xC000_0201).unwrap();
        let cache = StubCache::new();
        let addr = SocketAddr::from(([127, 0, 0, 1], cache.port()));
        let defaults = TcpKeepalive {
            idle: Duration::from_secs(60),
            interval: Duration::from_secs(10),
            probes: 6,
        };
        let written = TcpKeepalive {
            idle: Duration::from_secs(45),
            interval: Duration::from_secs(5),
            probes: 3,
        };
        let external = format!(
            "rpki {{ mode external; cache 127.0.0.1 port {}; }}",
            cache.port()
        );
        let external_written = format!(
            "rpki {{ mode external; cache 127.0.0.1 port {}; \
             tcp-keepalive count 3 idle 45 interval 5; }}",
            cache.port()
        );
        for (block, sidecar, expected) in [
            (external, None, defaults),
            (external_written, None, written),
            ("rpki { mode sidecar; }".to_owned(), Some(addr), defaults),
            (
                "rpki { mode sidecar; tcp-keepalive idle 45 interval 5 count 3; }".to_owned(),
                Some(addr),
                written,
            ),
        ] {
            let rpki = config(&block).rpki;
            let mut c = client_config(&rpki, router_id, sidecar, &keepalive(&rpki)).unwrap();
            // What the kernel has on the client's end once bgpfcd's check
            // has run on it.
            let prepare = c.check.take().expect("a check of every connection");
            let (seen_tx, seen_rx) = std::sync::mpsc::channel();
            c.check = Some(ConnectionCheck::new(move |stream: &TcpStream| {
                let verdict = prepare.run(stream);
                let kernel = bgpfc_sys::tcp_keepalive(stream).map_err(|e| e.to_string());
                let _ = seen_tx.send((verdict.is_ok(), kernel));
                verdict
            }));
            let (tx, _changes) = sync_channel::<ValidationChange>(4);
            let mut client = Client::start(c, tx).unwrap();
            let (_stream, query) = cache.accept();
            assert!(
                matches!(query, Pdu::ResetQuery { .. }),
                "{block}: {query:?}"
            );
            assert_eq!(
                seen_rx.recv_timeout(WAIT).unwrap(),
                (true, Ok(Some(expected))),
                "{block}"
            );
            client.stop();
        }
        // Two minutes from the last segment to a dead cache noticed.
        assert_eq!(defaults.detection_time(), Duration::from_secs(120));
    }

    /// The bounds of `tcp-keepalive` are the kernel's: it takes the
    /// longest the block allows, and refuses one more of each.
    #[test]
    fn the_block_s_keep_alive_bounds_are_the_kernel_s() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let longest = ast::RpkiKeepalive {
            idle: ast::RpkiKeepalive::MAX_IDLE,
            interval: ast::RpkiKeepalive::MAX_INTERVAL,
            count: ast::RpkiKeepalive::MAX_COUNT,
        };
        bgpfc_sys::set_tcp_keepalive(&stream, tcp_keepalive(&longest)).unwrap();
        assert_eq!(
            bgpfc_sys::tcp_keepalive(&stream).unwrap(),
            Some(tcp_keepalive(&longest))
        );
        let one_more = |k: TcpKeepalive| bgpfc_sys::set_tcp_keepalive(&stream, k).is_err();
        let longest = tcp_keepalive(&longest);
        assert!(one_more(TcpKeepalive {
            idle: longest.idle + Duration::from_secs(1),
            ..longest
        }));
        assert!(one_more(TcpKeepalive {
            interval: longest.interval + Duration::from_secs(1),
            ..longest
        }));
        assert!(one_more(TcpKeepalive {
            probes: longest.probes + 1,
            ..longest
        }));
    }

    /// Issues #26 and #71: `mode sidecar` starts Routinator and wires the
    /// client to it with no cache written; the data it serves reaches the
    /// RIB; stopping ends the client, then Routinator. The stub sleeps,
    /// and the module's cache serves the port it was told to use (m14
    /// design §7.3), so this tests the wiring without an RTR server.
    #[test]
    fn the_sidecar_serves_the_rib() {
        let dir = Scratch::new("serves");
        let binary = dir.routinator(&tested(), "exec sleep 600");
        let cache = StubCache::new();
        let cfg = config(&sidecar_block(&binary, &dir.join("repo"), cache.port()));
        let (tx, rx) = sync_channel(4);
        let mut rpki = Rpki::start(&cfg.rpki, cfg.router_id, tx).unwrap();
        let rtr = SocketAddr::from((Ipv4Addr::LOCALHOST, cache.port()));
        let sidecar = rpki.sidecar.as_ref().unwrap();
        assert_eq!(sidecar.rtr_addr(), rtr);
        assert_eq!(sidecar.status().rtr, rtr);
        assert_eq!(sidecar.version(), TESTED_VERSION);
        let pid = routinator_pid(&rpki);
        assert!(waiting(&rpki).is_some(), "routes wait for Routinator");
        // What the control plane shows (m14 design §4.6), read from the
        // sidecar at the request.
        let report = rpki.report(&cfg.rpki);
        assert_eq!(report.waiting_since, waiting(&rpki));
        let shown = report.sidecar.expect("the sidecar is reported");
        assert!(
            matches!(shown.status.state, SidecarState::Running { pid: p, .. } if p == pid),
            "{:?}",
            shown.status
        );
        assert_eq!(shown.status.rtr, rtr);
        assert_eq!(shown.version, TESTED_VERSION);
        assert_eq!(shown.binary, binary);

        let mut conn = cache.serve(&[vrp("192.0.2.0/24", 24, 64_496)]);
        let change = next_change(&rx);
        assert_eq!(waiting(&rpki), None);
        assert_eq!(rpki.report(&cfg.rpki).waiting_since, None);
        assert_eq!(change.affected, AffectedPrefixes::All);
        assert_eq!(rov(&change, "192.0.2.0/24", 64_496), RovState::Valid);
        assert_eq!(rov(&change, "192.0.2.0/24", 64_497), RovState::Invalid);
        eventually("the client in sync", || {
            rpki.status().is_some_and(|s| s.synced_at.is_some())
        });
        let status = rpki.status().unwrap();
        assert_eq!(status.cache.to_string(), rtr.to_string());
        assert_eq!(status.vrps_ipv4, 1);

        rpki.stop();
        assert!(closed(&mut conn), "no client is left");
        assert!(!alive(pid), "routinator is gone");
        assert!(rpki.sidecar.is_none());
        assert!(rpki.status().is_none());
        let report = rpki.report(&cfg.rpki);
        assert!(report.sidecar.is_none() && report.status.is_none());
        assert!(rx.try_recv().is_err());
    }

    /// m14 design §4.3: at shutdown the client lets go of Routinator
    /// before Routinator gets its `SIGTERM`.
    #[test]
    fn the_client_stops_before_routinator() {
        let dir = Scratch::new("order");
        let (ready, termed) = (dir.join("ready"), dir.join("termed"));
        // It marks the SIGTERM, then takes a second to exit: stopped
        // first, it would see the client connected all that second.
        let body = format!(
            "trap 'touch \"{}\"; sleep 1; exit 0' TERM\ntouch \"{}\"\nsleep 600 &\nwait",
            termed.display(),
            ready.display()
        );
        let binary = dir.routinator(&tested(), &body);
        let cache = StubCache::new();
        let cfg = config(&sidecar_block(&binary, &dir.join("repo"), cache.port()));
        let (tx, rx) = sync_channel(4);
        let mut rpki = Rpki::start(&cfg.rpki, cfg.router_id, tx).unwrap();
        let pid = routinator_pid(&rpki);
        let mut conn = cache.serve(&[vrp("192.0.2.0/24", 24, 64_496)]);
        next_change(&rx);
        // From here on the stub has its trap.
        eventually("the stub's trap", || ready.exists());
        conn.set_nonblocking(true).unwrap();
        let watcher = thread::spawn(move || {
            let deadline = Instant::now() + WAIT;
            while !termed.exists() {
                assert!(Instant::now() < deadline, "routinator got no SIGTERM");
                thread::sleep(Duration::from_millis(5));
            }
            let mut buf = [0; 16];
            match conn.read(&mut buf) {
                Ok(n) => n == 0,
                Err(e) => e.kind() == ErrorKind::ConnectionReset,
            }
        });
        rpki.stop();
        let client_gone = watcher.join().unwrap();
        assert!(
            client_gone,
            "routinator was stopped under a connected client"
        );
        assert!(!alive(pid));
    }

    /// Issue #70: "restarting the child during our own shutdown is a bug".
    /// The coordinator's shutdown begins to stop Routinator right after the
    /// Ceases, so that a Routinator that exits by itself during the FIB
    /// cleanup, as one an init system signals with bgpfcd does, is not
    /// started again. Here the cleanup takes longer than the restart
    /// back-off, and Routinator exits during it: stopped only after the
    /// cleanup, as it once was, it would be started again meanwhile.
    #[test]
    fn nothing_restarts_routinator_during_the_shutdown() {
        let dir = Scratch::new("shutdown");
        let (starts, exit) = (dir.join("starts"), dir.join("exit"));
        let body = format!(
            "echo $$ >> '{}'\nwhile [ ! -e '{}' ]; do sleep 0.05; done\nexit 1",
            starts.display(),
            exit.display()
        );
        let binary = dir.routinator(&tested(), &body);
        let cache = StubCache::new();
        let block = sidecar_block_with(
            &binary,
            &dir.join("repo"),
            cache.port(),
            "",
            "restart-backoff 1 1;",
        );
        let cfg = config(&block);
        let (rib_tx, rib_rx) = sync_channel(4);
        let rpki = Rpki::start(&cfg.rpki, cfg.router_id, rib_tx.clone()).unwrap();
        let pid = routinator_pid(&rpki);
        let _conn = cache.serve(&[vrp("192.0.2.0/24", 24, 64_496)]);
        next_change(&rib_rx);
        eventually("the stub's start", || starts.exists());
        // The FIB thread's cleanup: Routinator exits as it begins, and it
        // lasts more than the back-off of one second, jitter included.
        let (fib_tx, fib_rx) = sync_channel(1);
        let fib = thread::spawn(move || {
            let Ok(crate::messages::FibMsg::Shutdown(done)) = fib_rx.recv() else {
                panic!("no FIB shutdown");
            };
            fs::write(&exit, "").unwrap();
            thread::sleep(Duration::from_millis(2_500));
            done.send(()).unwrap();
        });
        let opts = crate::args::parse(&["-c".to_owned(), "unused.conf".to_owned()]).unwrap();
        let mut coordinator = crate::Coordinator {
            opts: &opts,
            config: cfg,
            table: crate::coordinator::PeerTable::default(),
            rib_tx,
            fib_tx,
            rpki,
        };
        coordinator.shutdown();
        fib.join().unwrap();
        let started = fs::read_to_string(&starts).unwrap();
        assert_eq!(
            started.lines().count(),
            1,
            "routinator was started again during the shutdown: {started}"
        );
        assert!(!alive(pid));
        assert!(coordinator.rpki.sidecar.is_none());
    }

    /// Issue #72: a version mismatch is reported clearly at startup, and
    /// no server is started.
    #[test]
    fn a_routinator_of_another_release_stops_the_start() {
        let dir = Scratch::new("release");
        let served = dir.join("served");
        let body = format!("touch '{}'\nexec sleep 600", served.display());
        let binary = dir.routinator("0.14.1", &body);
        let cfg = config(&sidecar_block(&binary, &dir.join("repo"), 0));
        let (tx, rx) = sync_channel(4);
        let err = Rpki::start(&cfg.rpki, cfg.router_id, tx).unwrap_err();
        assert!(
            err.starts_with("rpki sidecar: Routinator 0.14.1 is not supported: "),
            "{err}"
        );
        assert!(err.contains("0.15"), "{err}");
        assert!(!served.exists(), "a server was started");
        assert!(rx.try_recv().is_err());
    }

    /// Issue #60: a binary that is not there stops the start, naming it.
    #[test]
    fn a_missing_routinator_stops_the_start() {
        let dir = Scratch::new("missing");
        let binary = dir.join("routinator");
        let cfg = config(&sidecar_block(&binary, &dir.join("repo"), 0));
        let (tx, rx) = sync_channel(4);
        let err = Rpki::start(&cfg.rpki, cfg.router_id, tx).unwrap_err();
        let expected = format!(
            "rpki sidecar: `{} --version` could not be started: ",
            binary.display()
        );
        assert!(err.starts_with(&expected), "{err}");
        assert!(rx.try_recv().is_err());
    }

    /// The repository directory is created with its parents, for
    /// Routinator and bgpfcd's group alone; one that cannot be created
    /// stops the start before Routinator runs at all.
    #[test]
    fn the_repository_directory_is_created() {
        let dir = Scratch::new("repository");
        let binary = dir.routinator(&tested(), "exec sleep 600");
        let repository = dir.join("state/bgpfc/rpki");
        let cfg = config(&sidecar_block(&binary, &repository, 0));
        let (tx, _rx) = sync_channel(4);
        let mut rpki = Rpki::start(&cfg.rpki, cfg.router_id, tx).unwrap();
        let meta = fs::metadata(&repository).unwrap();
        assert!(meta.is_dir());
        let mode = meta.permissions().mode() & 0o777;
        // 0750, less what the umask takes away.
        assert_eq!(mode & !0o750, 0, "{mode:o}");
        // Port 0: one picked at start, on the configured address, which
        // the client uses.
        let rtr = rpki.sidecar.as_ref().unwrap().rtr_addr();
        assert_eq!(rtr.ip(), Ipv4Addr::LOCALHOST);
        assert_ne!(rtr.port(), 0);
        assert_eq!(rpki.status().unwrap().cache.port, rtr.port());
        rpki.stop();

        let ran = dir.join("ran");
        let body = format!("touch '{}'\necho 'Routinator {}'", ran.display(), tested());
        let marking = dir.script("marking", &body);
        fs::write(dir.join("file"), "").unwrap();
        let blocked = dir.join("file/rpki");
        let cfg = config(&sidecar_block(&marking, &blocked, 0));
        let (tx, rx) = sync_channel(4);
        let err = Rpki::start(&cfg.rpki, cfg.router_id, tx).unwrap_err();
        let expected = format!(
            "cannot create the rpki repository directory {}: ",
            blocked.display()
        );
        assert!(err.starts_with(&expected), "{err}");
        assert!(!ran.exists(), "routinator ran");
        assert!(rx.try_recv().is_err());
    }

    /// A Routinator stub that sleeps, in sync through the module's cache,
    /// which served one VRP.
    struct Running {
        dir: Scratch,
        binary: PathBuf,
        cache: StubCache,
        cfg: Config,
        rpki: Rpki,
        rx: Receiver<RibMsg>,
        conn: TcpStream,
        pid: u32,
    }

    impl Running {
        fn new(tag: &str) -> Running {
            let dir = Scratch::new(tag);
            let binary = dir.routinator(&tested(), "exec sleep 600");
            let cache = StubCache::new();
            let cfg = config(&sidecar_block(&binary, &dir.join("repo"), cache.port()));
            let (tx, rx) = sync_channel(4);
            let rpki = Rpki::start(&cfg.rpki, cfg.router_id, tx).unwrap();
            let pid = routinator_pid(&rpki);
            let conn = cache.serve(&[vrp("192.0.2.0/24", 24, 64_496)]);
            next_change(&rx);
            Running {
                dir,
                binary,
                cache,
                cfg,
                rpki,
                rx,
                conn,
                pid,
            }
        }

        /// The block, with `rpki` and `sidecar` statements added.
        fn with(&self, rpki: &str, sidecar: &str) -> Config {
            let repository = self.dir.join("repo");
            let block =
                sidecar_block_with(&self.binary, &repository, self.cache.port(), rpki, sidecar);
            config(&block)
        }

        /// The VRPs the client holds.
        fn vrps(&self) -> Option<usize> {
            self.rpki.status()?.vrps.map(|v| v.len())
        }
    }

    /// m14 design §5.2: a block that has not changed, written another way,
    /// or with another `enforcement`, which the RIB applies, touches
    /// neither Routinator nor the client.
    #[test]
    fn an_unchanged_block_leaves_the_sidecar_alone() {
        let mut r = Running::new("unchanged");
        let respelled = r.with(
            "enforcement prefer-valid; backoff 1 30;",
            "refresh 600; rir-tals yes;",
        );
        assert_eq!(preflight_as(&r.cfg.rpki, &respelled.rpki, true), Ok(()));
        let done = r.rpki.reconfigure(&r.cfg.rpki, &respelled.rpki);
        assert_eq!(done, Ok("rpki unchanged"));
        assert_eq!(routinator_pid(&r.rpki), r.pid);
        assert!(r.rpki.status().is_some_and(|s| s.connected));
        r.conn
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut buf = [0; 16];
        assert!(r.conn.read(&mut buf).is_err(), "the session goes on");
        r.rpki.stop();
        assert!(!alive(r.pid));
    }

    /// A change to the client's settings alone restarts the client at the
    /// same address, holding its data, and leaves Routinator running; it
    /// needs no check of Routinator, not even as root.
    #[test]
    fn a_client_setting_leaves_the_sidecar_running() {
        let mut r = Running::new("client");
        let new = r.with("backoff 1 3;", "");
        assert_eq!(preflight_as(&r.cfg.rpki, &new.rpki, true), Ok(()));
        let done = r.rpki.reconfigure(&r.cfg.rpki, &new.rpki);
        assert_eq!(done, Ok("rpki: rtr client restarted"));
        assert!(closed(&mut r.conn), "the old client is gone");
        assert_eq!(routinator_pid(&r.rpki), r.pid, "the same routinator");
        let (_conn, query) = r.cache.accept();
        assert!(matches!(query, Pdu::ResetQuery { .. }), "{query:?}");
        assert_eq!(r.vrps(), Some(1), "the data is held");
        assert_eq!(waiting(&r.rpki), None);
        assert!(r.rx.try_recv().is_err());
        r.rpki.stop();
    }

    /// RFC 8210 §10: a change to the `sidecar` block restarts Routinator,
    /// and the client keeps the data in use until the new one has sent a
    /// full set.
    #[test]
    fn a_sidecar_setting_restarts_it_and_keeps_the_data() {
        let mut r = Running::new("restart");
        let new = r.with("", "refresh 300;");
        assert_eq!(preflight_as(&r.cfg.rpki, &new.rpki, false), Ok(()));
        let done = r.rpki.reconfigure(&r.cfg.rpki, &new.rpki);
        assert_eq!(done, Ok("rpki: sidecar restarted"));
        assert!(closed(&mut r.conn));
        assert!(!alive(r.pid), "the old routinator is gone");
        let pid = routinator_pid(&r.rpki);
        assert_ne!(pid, r.pid);
        assert_eq!(r.vrps(), Some(1), "the data is held");
        assert_eq!(waiting(&r.rpki), None);
        // The new client asks the new Routinator, at the same fixed port.
        let (_conn, query) = r.cache.accept();
        assert!(matches!(query, Pdu::ResetQuery { .. }), "{query:?}");
        assert!(r.rx.try_recv().is_err(), "nothing changed for the RIB");
        r.rpki.stop();
        assert!(!alive(pid));
    }

    /// From `mode external` the external cache's data stays in use until
    /// Routinator's first full set, so the routes never wait; that set
    /// validates again only the routes the two judge differently.
    #[test]
    fn switching_from_external_keeps_the_data_until_routinator_answers() {
        let external = StubCache::new();
        let (a, b) = (
            vrp("192.0.2.0/24", 24, 64_496),
            vrp("198.51.100.0/24", 24, 64_497),
        );
        let (mut rpki, rx, mut old_conn) = in_sync(&external, &[a]);
        let dir = Scratch::new("from-external");
        let binary = dir.routinator(&tested(), "exec sleep 600");
        let sidecar = StubCache::new();
        let old = config(&external.block());
        let new = config(&sidecar_block(&binary, &dir.join("repo"), sidecar.port()));
        assert_eq!(preflight_as(&old.rpki, &new.rpki, false), Ok(()));
        assert_eq!(
            rpki.reconfigure(&old.rpki, &new.rpki),
            Ok("rpki: sidecar started")
        );
        assert!(closed(&mut old_conn));
        let pid = routinator_pid(&rpki);
        let held = rpki.status().unwrap();
        assert_eq!(held.vrps.as_deref().map(bgpfc_rpki::VrpSet::len), Some(1));
        assert_eq!(waiting(&rpki), None, "no startup window");
        assert!(rx.try_recv().is_err());
        let _conn = sidecar.serve(&[a, b]);
        let change = next_change(&rx);
        let p = |s: &str| s.parse().unwrap();
        assert!(!change.affected.covers(p("192.0.2.0/24")));
        assert!(change.affected.covers(p("198.51.100.0/24")));
        rpki.stop();
        assert!(!alive(pid));
    }

    /// Leaving `mode sidecar` stops Routinator after the client: for
    /// `mode disabled` every route is `disabled` again; for `mode
    /// external` its data stays in use until an external cache answers.
    #[test]
    fn switching_to_disabled_stops_the_sidecar_and_disables() {
        let mut r = Running::new("to-disabled");
        let off = config("rpki { mode disabled; }");
        assert_eq!(preflight_as(&r.cfg.rpki, &off.rpki, true), Ok(()));
        assert_eq!(
            r.rpki.reconfigure(&r.cfg.rpki, &off.rpki),
            Ok("rpki: validation disabled; sidecar stopped")
        );
        assert!(closed(&mut r.conn));
        assert!(!alive(r.pid));
        assert!(r.rpki.sidecar.is_none() && r.rpki.status().is_none());
        let change = next_disabled(&r.rx);
        assert_eq!(rov(&change, "192.0.2.0/24", 64_496), RovState::Disabled);

        let mut r = Running::new("to-external");
        let external = StubCache::new();
        let new = config(&external.block());
        assert_eq!(
            r.rpki.reconfigure(&r.cfg.rpki, &new.rpki),
            Ok("rpki: rtr client restarted; sidecar stopped")
        );
        assert!(!alive(r.pid));
        assert!(r.rpki.sidecar.is_none());
        let (_conn, query) = external.accept();
        assert!(matches!(query, Pdu::ResetQuery { .. }), "{query:?}");
        assert_eq!(r.vrps(), Some(1), "the sidecar's data is held");
        assert!(r.rx.try_recv().is_err());
        r.rpki.stop();
    }

    /// Issue #72, m14 design §5.1: a Routinator that would not start fails
    /// the reload before anything changes, and the running one goes on.
    #[test]
    fn a_sidecar_that_fails_its_check_fails_the_reload_before_anything_changes() {
        let mut r = Running::new("preflight");
        let old_release = r.dir.script(
            "routinator-0.14",
            "if [ \"$1\" = --version ]; then echo 'Routinator 0.14.1'; exit 0; fi\nexec sleep 600",
        );
        let repository = r.dir.join("repo");
        let port = r.cache.port();
        let new = config(&sidecar_block(&old_release, &repository, port));
        let err = preflight_as(&r.cfg.rpki, &new.rpki, false).unwrap_err();
        assert!(
            err.starts_with("rpki sidecar: Routinator 0.14.1 is not supported: "),
            "{err}"
        );
        assert_eq!(routinator_pid(&r.rpki), r.pid, "the running one goes on");
        assert!(r.rpki.status().is_some_and(|s| s.connected));
        r.conn
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut buf = [0; 16];
        assert!(r.conn.read(&mut buf).is_err(), "the client is untouched");

        // A missing binary, and settings Routinator refuses, likewise.
        let missing = config(&sidecar_block(&r.dir.join("missing"), &repository, port));
        let err = preflight_as(&r.cfg.rpki, &missing.rpki, false).unwrap_err();
        assert!(err.contains("--version` could not be started"), "{err}");
        let tal = r.with("", "tals arin;");
        let err = preflight_as(&r.cfg.rpki, &tal.rpki, false).unwrap_err();
        assert!(
            err.starts_with("rpki sidecar: the ARIN TAL is listed"),
            "{err}"
        );

        // Into `mode sidecar` as root: refused before anything runs, even
        // `--version`. Otherwise the repository directory is created.
        let ran = r.dir.join("ran");
        let body = format!("touch '{}'\necho 'Routinator {}'", ran.display(), tested());
        let marking = r.dir.script("marking", &body);
        let fresh = r.dir.join("fresh/rpki");
        let into = config(&sidecar_block(&marking, &fresh, 0));
        let off = config("rpki { mode disabled; }");
        let err = preflight_as(&off.rpki, &into.rpki, true).unwrap_err();
        assert_eq!(
            err,
            format!(
                "mode sidecar would run Routinator as root: {}",
                privileges::SIDECAR_AS_ROOT_HINT
            )
        );
        assert!(!ran.exists() && !fresh.exists());
        assert_eq!(preflight_as(&off.rpki, &into.rpki, false), Ok(()));
        assert!(ran.exists() && fresh.is_dir());
        assert!(r.rx.try_recv().is_err());
        r.rpki.stop();
    }

    /// A reload onto an `rtr-listen` address this host cannot bind, such as
    /// `::1` without IPv6, fails the preflight as it would fail the start,
    /// so the running Routinator and its client go on; where the host can
    /// bind it, both pass. Before the preflight bound the address, such a
    /// reload stopped the working Routinator, failed to start the new one,
    /// and left validation off.
    #[test]
    fn an_rtr_address_that_cannot_be_bound_fails_the_preflight() {
        let mut r = Running::new("unbindable");
        let v6 = |port: u16| {
            config(&format!(
                "rpki {{ mode sidecar; sidecar {{ binary \"{}\"; repository-dir \"{}\"; \
                 rtr-listen ::1 port {port}; }} }}",
                r.binary.display(),
                r.dir.join("repo").display()
            ))
        };
        let bindable = TcpListener::bind("[::1]:0").is_ok();
        for (port, action) in [
            (0, "picking a free RTR port"),
            (3323, "trying the RTR address"),
        ] {
            let new = v6(port);
            let checked = preflight_as(&r.cfg.rpki, &new.rpki, false);
            if bindable {
                assert_eq!(checked, Ok(()), "{port}");
            } else {
                let err = checked.unwrap_err();
                assert!(
                    err.starts_with(&format!("rpki sidecar: {action}: ")),
                    "{port}: {err}"
                );
            }
        }
        assert_eq!(routinator_pid(&r.rpki), r.pid, "the running one goes on");
        assert!(r.rpki.status().is_some_and(|s| s.connected));
        r.conn
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut buf = [0; 16];
        assert!(r.conn.read(&mut buf).is_err(), "the client is untouched");
        assert!(r.rx.try_recv().is_err());
        // What the reload then does: the start agrees with the preflight.
        let new = v6(0);
        if bindable {
            assert_eq!(
                r.rpki.reconfigure(&r.cfg.rpki, &new.rpki),
                Ok("rpki: sidecar restarted")
            );
        } else {
            let err = r.rpki.reconfigure(&r.cfg.rpki, &new.rpki).unwrap_err();
            assert!(
                err.starts_with("rpki: cannot start the sidecar (rpki sidecar: picking a free"),
                "{err}"
            );
        }
        r.rpki.stop();
        assert!(!alive(r.pid));
    }

    /// The preflight checks only what the reload will start: new external
    /// caches are looked up, as at start; a block that has not changed, or
    /// one that turns validation off, needs nothing, not even as root.
    #[test]
    fn the_preflight_checks_what_will_start() {
        let external = config("rpki { mode external; cache 127.0.0.1; }");
        let bad = config("rpki { mode external; cache rtr.invalid; }");
        let err = preflight_as(&external.rpki, &bad.rpki, false).unwrap_err();
        assert!(
            err.starts_with("cannot resolve rpki cache rtr.invalid: "),
            "{err}"
        );
        assert_eq!(preflight_as(&bad.rpki, &bad.rpki, false), Ok(()));
        let sidecar = config("rpki { mode sidecar; }");
        let prefer = config("rpki { mode sidecar; enforcement prefer-valid; }");
        assert_eq!(preflight_as(&sidecar.rpki, &prefer.rpki, true), Ok(()));
        let off = config("rpki { mode disabled; }");
        assert_eq!(preflight_as(&sidecar.rpki, &off.rpki, true), Ok(()));
        assert_eq!(preflight_as(&sidecar.rpki, &external.rpki, true), Ok(()));
    }

    /// A Routinator that passed the preflight but cannot start, as when
    /// the binary went away in between, leaves validation off rather than
    /// the old data unexpired.
    #[test]
    fn a_sidecar_that_fails_to_start_after_the_preflight_disables_validation() {
        let mut r = Running::new("late");
        let missing = r.dir.join("missing");
        let new = config(&sidecar_block(&missing, &r.dir.join("repo"), 0));
        let err = r.rpki.reconfigure(&r.cfg.rpki, &new.rpki).unwrap_err();
        assert!(
            err.starts_with("rpki: cannot start the sidecar (rpki sidecar: "),
            "{err}"
        );
        assert!(err.ends_with("); validation disabled"), "{err}");
        assert!(closed(&mut r.conn));
        assert!(!alive(r.pid));
        assert!(r.rpki.sidecar.is_none() && r.rpki.status().is_none());
        let change = next_disabled(&r.rx);
        assert_eq!(rov(&change, "192.0.2.0/24", 64_496), RovState::Disabled);
        // What is in effect now is `mode disabled`, which a reload compares
        // the file with: one of the same file checks the block again, and
        // fails while the binary is missing, ...
        let off = ast::Rpki::defaults(RpkiMode::Disabled);
        assert_eq!(r.rpki.in_effect(&new.rpki), off);
        let err = preflight_as(&off, &new.rpki, false).unwrap_err();
        assert!(err.contains("--version` could not be started"), "{err}");
        // ... and starts it once the binary is there; the routes then wait
        // for its first full set.
        let version = format!(
            "if [ \"$1\" = --version ]; then echo 'Routinator {}'; exit 0; fi\nexec sleep 600",
            tested()
        );
        r.dir.script("missing", &version);
        assert_eq!(preflight_as(&off, &new.rpki, false), Ok(()));
        assert_eq!(
            r.rpki.reconfigure(&off, &new.rpki),
            Ok("rpki: sidecar started")
        );
        let pid = routinator_pid(&r.rpki);
        assert!(waiting(&r.rpki).is_some());
        assert_eq!(r.rpki.in_effect(&new.rpki), new.rpki);
        r.rpki.stop();
        assert!(!alive(pid));
    }

    /// What is in effect is the configured block while what it runs runs:
    /// nothing for `mode disabled`, the client for `mode external`.
    #[test]
    fn the_block_in_effect_is_the_configured_one_while_it_runs() {
        let cache = StubCache::new();
        let (mut rpki, _rx, _conn) = in_sync(&cache, &[vrp("192.0.2.0/24", 24, 64_496)]);
        let external = config(&cache.block());
        assert_eq!(rpki.in_effect(&external.rpki), external.rpki);
        rpki.stop();
        let off = ast::Rpki::defaults(RpkiMode::Disabled);
        assert_eq!(rpki.in_effect(&external.rpki), off);
        let disabled = config("rpki { mode disabled; cache 192.0.2.10; }");
        assert_eq!(rpki.in_effect(&disabled.rpki), disabled.rpki);
    }
}

//! `bgpfcd`: the bgpfc BGP-4 routing daemon.
//!
//! Milestone 8 shape (AGENTS.md §3): the configuration file, listener
//! threads, one thread per neighbour driving its FSM, the RIB thread, the
//! FIB thread, the control threads, and a main thread (the coordinator)
//! that owns the configuration and the peer table and acts on signals
//! and reload requests. Since step 12 the coordinator also runs the RTR
//! client of the `rpki` block, which feeds the RIB thread. Since step 16 a
//! daemon that restarts in install mode keeps the kernel routes of its
//! protocol number for the families of the neighbors with
//! `graceful-restart yes` until their End-of-RIB (RFC 4724 §4.1, see
//! [`restart`] and `start_fib`).
#![forbid(unsafe_code)]

mod args;
mod control;
mod coordinator;
mod fib;
mod messages;
mod peer;
mod privileges;
#[cfg(feature = "profiling")]
mod profiling;
mod reader;
mod restart;
mod rib;
mod rpki;
mod wiring;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::mpsc::{SyncSender, sync_channel};
use std::sync::{Arc, RwLock};
use std::time::Instant;

use bgpfc_config::diff::{ConfigDiff, GlobalChange};
use bgpfc_wire::error::CeaseSubcode;

use crate::control::CoordMsg;
use crate::coordinator::PeerTable;
use crate::messages::{FibMsg, PeerInput, RibMsg};
use crate::restart::RestartState;

/// docs/PROFILING.md: a profiling build counts every allocation.
#[cfg(feature = "profiling")]
#[global_allocator]
static ALLOCATOR: bgpfc_sys::alloc::Counting = bgpfc_sys::alloc::Counting::new();

/// Updates the RIB thread may have queued before peers block.
const RIB_QUEUE: usize = 1024;

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    #[cfg(feature = "profiling")]
    if argv.iter().any(|a| a == "--print-sizes") {
        profiling::print_sizes();
        return;
    }
    let opts = match args::parse(&argv) {
        Ok(a) => a,
        Err(msg) => {
            if !msg.is_empty() {
                eprintln!("bgpfcd: {msg}");
            }
            eprint!("{}", args::USAGE);
            #[cfg(feature = "profiling")]
            eprint!("{}", args::PROFILING_USAGE);
            std::process::exit(2);
        }
    };
    let (config, engine) = load(&opts);
    if opts.check {
        println!(
            "{}: ok ({} neighbors, {} policies)",
            opts.config.display(),
            config.neighbors.len(),
            config.policies.len()
        );
        return;
    }
    bgpfc_log::init(config.log_level);
    #[cfg(feature = "profiling")]
    profiling::init();
    bgpfc_log::info!(
        "bgpfcd starting",
        version = env!("CARGO_PKG_VERSION"),
        config = opts.config.display(),
        local_as = config.local_as,
        router_id = config.router_id,
        fib_mode = config.fib.mode,
        rpki = config.rpki.mode,
        invalid = config.rpki.invalid
    );
    // Issue #60: a cache that cannot be found stops the start, before
    // anything is opened, rather than leaving every route unvalidated.
    if let Err(e) = rpki::resolve(&config.rpki) {
        bgpfc_log::error!("cannot start", error = e);
        std::process::exit(1);
    }
    run(&opts, config, engine);
}

/// Parse, validate and compile the configuration file, with the command
/// line overrides applied; exits with the errors printed otherwise.
fn load(opts: &args::Args) -> (bgpfc_config::Config, bgpfc_policy::Engine) {
    let mut config = match bgpfc_config::parse_file(&opts.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    // Policies compile after validation: only AS-path regexes can fail.
    let engine = match bgpfc_policy::Engine::new(&config) {
        Ok(e) => e,
        Err(errors) => {
            for e in errors {
                eprintln!("{}:{e}", opts.config.display());
            }
            std::process::exit(1);
        }
    };
    if let Some(level) = opts.log_level {
        config.log_level = level;
    }
    if let Some(mode) = opts.fib {
        config.fib.mode = mode;
    }
    (config, engine)
}

/// Bring everything up in the order privileges require, then run the
/// coordinator loop.
fn run(opts: &args::Args, config: bgpfc_config::Config, engine: bgpfc_policy::Engine) {
    // Signals first, so every thread inherits the handlers (AGENTS.md §3).
    let signals = match bgpfc_sys::Signals::install() {
        Ok(s) => s,
        Err(e) => {
            bgpfc_log::error!("cannot install signal handlers", error = e);
            std::process::exit(1);
        }
    };
    privileges::check(&config, opts.user.as_deref());

    // The netlink socket and the listeners are opened while still
    // privileged (README, "Option B"); the FIB thread flushes stale
    // routes right away.
    let restart = Arc::new(RestartState::default());
    let (fib_tx, kept) = start_fib(&config, &restart);
    let (rib_tx, rib_rx) = sync_channel(RIB_QUEUE);
    let table: PeerTable = Arc::new(RwLock::new(HashMap::new()));
    let mut peers = Vec::new();
    for n in &config.neighbors {
        peers.push(prepare_peer(&config, n, &rib_tx, &table, &restart));
    }
    for addr in &config.listen {
        if let Err(e) = coordinator::listen(*addr, Arc::clone(&table)) {
            bgpfc_log::error!("cannot listen", address = addr, error = e);
            std::process::exit(1);
        }
    }
    let (coord_tx, coord_rx) = sync_channel::<CoordMsg>(16);
    start_control(
        &config,
        control::Ctx {
            peers: Arc::clone(&table),
            rib: rib_tx.clone(),
            fib: fib_tx.clone(),
            coord: coord_tx.clone(),
            local_as: config.local_as,
            router_id: config.router_id,
            writes: config.control.http.as_ref().is_some_and(|h| h.writes),
            token: read_token(&config),
        },
    );
    if let Some(user) = &opts.user {
        privileges::drop(user, opts.group.as_deref());
    }

    // No validation source yet (issue #56): every route is `disabled`
    // until the RTR client sends its first full set.
    let mut rib = bgpfc_rib::Rib::with_policies(config.local_as, Box::new(engine));
    // RFC 4271 §10: the advertisement intervals are jittered too.
    rib.set_jitter_seed(wiring::jitter_seed(&"rib"));
    // RFC 6811 §5, RFC 8481 §5: what is done with Invalid routes is what
    // the file says, from the first route on. No route is held yet, so
    // there is nothing to judge again.
    rib.set_invalid_action(config.rpki.invalid, Instant::now(), &mut Vec::new());
    defer_selection(&config, &kept, &mut rib, &restart);
    rib::spawn(
        rib,
        wiring::rib_settings(&config),
        rib_rx,
        Arc::clone(&table),
        fib_tx.clone(),
        Arc::clone(&restart),
    );
    // Before the peers, so that the VRPs often arrive before the routes
    // and most routes are validated once, on arrival.
    let rpki = start_rpki(&config, &rib_tx);
    for peer in peers {
        peer.start();
    }
    forward_signals(signals, coord_tx);

    let mut coord = Coordinator {
        opts,
        config,
        table,
        rib_tx,
        fib_tx,
        rpki,
        restart,
    };
    while let Ok(msg) = coord_rx.recv() {
        match msg {
            CoordMsg::Signal(bgpfc_sys::Signal::Hup) => match coord.reload() {
                Ok(summary) => bgpfc_log::info!("reloaded", summary = summary),
                Err(e) => bgpfc_log::error!("reload failed; running configuration kept", error = e),
            },
            CoordMsg::Signal(sig) => {
                bgpfc_log::info!("shutting down", signal = format!("{sig:?}"));
                coord.shutdown();
                return;
            }
            CoordMsg::Rpki(reply) => {
                let _ = reply.send(coord.rpki_report());
            }
            CoordMsg::Reload(reply) => {
                let r = coord.reload();
                match &r {
                    Ok(summary) => bgpfc_log::info!("reloaded", summary = summary),
                    Err(e) => {
                        bgpfc_log::error!("reload failed; running configuration kept", error = e);
                    }
                }
                let _ = reply.send(r);
            }
        }
    }
}

/// Open the netlink socket, flush the routes of our protocol number that
/// are in the kernel, and start the FIB thread. Except, in install mode,
/// the routes of a family a neighbor with `graceful-restart yes` can send
/// again: RFC 4724 §4.1 has a daemon that restarted keep its forwarding
/// state until then (AGENTS.md §3, "FIB"). In dry-run mode nothing was
/// installed, so nothing is kept. The families that have routes kept are
/// returned with the thread's queue.
fn start_fib(
    config: &bgpfc_config::Config,
    restart: &Arc<RestartState>,
) -> (SyncSender<FibMsg>, Vec<bgpfc_wire::types::AddressFamily>) {
    let keep = if config.fib.mode == bgpfc_config::ast::FibMode::Install {
        restart::keepable(config)
    } else {
        Vec::new()
    };
    let fib = bgpfc_fib::Fib::new(
        fib::mode_of(config.fib.mode),
        config.fib.table,
        config.fib.protocol,
    );
    match fib::start(fib, &keep, Arc::clone(restart)) {
        Ok(started) => started,
        Err(e) => {
            bgpfc_log::error!("cannot start the fib", error = e);
            std::process::exit(1);
        }
    }
}

/// RFC 4724 §4.1: if we restarted with forwarding state kept (`kept` are
/// the families that have routes in the kernel), route selection waits for
/// the End-of-RIB of the neighbors that can send the routes again, and our
/// OPENs say that we have restarted.
fn defer_selection(
    config: &bgpfc_config::Config,
    kept: &[bgpfc_wire::types::AddressFamily],
    rib: &mut bgpfc_rib::Rib,
    restart: &RestartState,
) {
    let Some(deferral) = restart::deferral(config, kept, Instant::now()) else {
        return;
    };
    bgpfc_log::info!(
        "restarted with forwarding state kept, deferring route selection",
        families = kept
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(","),
        neighbors = deferral.waiting.len(),
        seconds = deferral
            .until
            .saturating_duration_since(Instant::now())
            .as_secs()
    );
    rib.defer_selection(&deferral);
    restart.set_restarting(true);
}

/// Run the `rpki` block, publishing to the RIB thread; exits if the RTR
/// client cannot be started.
fn start_rpki(config: &bgpfc_config::Config, rib_tx: &SyncSender<RibMsg>) -> rpki::Rpki {
    match rpki::Rpki::start(&config.rpki, config.router_id, rib_tx.clone()) {
        Ok(r) => r,
        Err(e) => {
            bgpfc_log::error!("cannot start the rtr client", error = e);
            std::process::exit(1);
        }
    }
}

/// The bearer token from `token-file`, if configured; exits if the file
/// cannot be read.
fn read_token(config: &bgpfc_config::Config) -> Option<String> {
    let path = config.control.http.as_ref()?.token_file.as_ref()?;
    match std::fs::read_to_string(path) {
        Ok(t) => Some(t.trim().to_owned()),
        Err(e) => {
            bgpfc_log::error!("cannot read token file", path = path.display(), error = e);
            std::process::exit(1);
        }
    }
}

/// Bind the control socket and the HTTP API, if configured.
fn start_control(config: &bgpfc_config::Config, ctx: control::Ctx) {
    if let Some(path) = &config.control.socket
        && let Err(e) = control::serve_unix(path, ctx.clone())
    {
        bgpfc_log::error!(
            "cannot bind control socket",
            path = path.display(),
            error = e
        );
        std::process::exit(1);
    }
    if let Some(h) = &config.control.http
        && let Err(e) = control::serve_http(h.listen, ctx)
    {
        bgpfc_log::error!("cannot bind http api", address = h.listen, error = e);
        std::process::exit(1);
    }
}

/// Read the signal pipe on its own thread so the coordinator can wait on
/// one channel.
fn forward_signals(mut signals: bgpfc_sys::Signals, tx: SyncSender<CoordMsg>) {
    let _ = std::thread::Builder::new()
        .name("signals".to_owned())
        .spawn(move || {
            while let Ok(sig) = signals.wait() {
                if tx.send(CoordMsg::Signal(sig)).is_err() {
                    return;
                }
            }
        });
}

/// Build a peer's thread state and register its handle.
fn prepare_peer(
    config: &bgpfc_config::Config,
    n: &bgpfc_config::ast::Neighbor,
    rib_tx: &SyncSender<RibMsg>,
    table: &PeerTable,
    restart: &Arc<RestartState>,
) -> peer::Peer {
    let cfg = wiring::peer_config(config.local_as, config.router_id, n);
    bgpfc_log::info!(
        "neighbor configured",
        peer = cfg.addr,
        remote_as = cfg.fsm.remote_as,
        passive = cfg.fsm.passive,
        import = n.import,
        export = n.export
    );
    let (handle, peer) = peer::prepare(cfg, rib_tx.clone(), Arc::clone(restart));
    if let Ok(mut t) = table.write() {
        t.insert(handle.addr, handle);
    }
    peer
}

/// The main thread's state: the running configuration and what reload
/// and shutdown need.
struct Coordinator<'a> {
    opts: &'a args::Args,
    config: bgpfc_config::Config,
    table: PeerTable,
    rib_tx: SyncSender<RibMsg>,
    fib_tx: SyncSender<FibMsg>,
    /// The `rpki` block at work: the RTR client, if one runs.
    rpki: rpki::Rpki,
    /// What the OPENs of new sessions say of a restart.
    restart: Arc<RestartState>,
}

impl Coordinator<'_> {
    fn stop_peer(&self, addr: IpAddr, subcode: CeaseSubcode) {
        let handle = self.table.write().ok().and_then(|mut t| t.remove(&addr));
        if let Some(h) = handle {
            let _ = h.tx.try_send(PeerInput::Stop(subcode));
        }
    }

    /// A neighbor the configuration no longer has: its session ends with
    /// Cease / Peer De-configured, and, RFC 4724 §4.2 keeping the routes of
    /// a session that ended for a neighbor that is coming back, the RIB
    /// is told that this one is not. For one whose session is up the peer
    /// thread says so itself, with the end of the session; this is for one
    /// that is down.
    fn remove_peer(&self, addr: IpAddr) {
        self.stop_peer(addr, CeaseSubcode::PeerDeconfigured);
        let _ = self.rib_tx.send(RibMsg::PeerDown {
            peer: addr,
            retain: None,
        });
    }

    /// Re-read the configuration file and apply the difference
    /// (`docs/config.md`, "Reload"). On any error nothing changes.
    fn reload(&mut self) -> Result<String, String> {
        let (new, engine) = load_checked(self.opts)?;
        let diff = ConfigDiff::between(&self.config, &new);
        // Issue #60: a new cache that cannot be found fails the reload
        // before anything changes, as it fails the start.
        if diff.global.contains(&GlobalChange::Rpki) {
            rpki::resolve(&new.rpki)?;
        }
        let mut notes = Vec::new();
        for g in &diff.global {
            match g {
                GlobalChange::Identity => {
                    return Err("router-id or local-as changed: restart the daemon".to_owned());
                }
                GlobalChange::Listen | GlobalChange::Control => {
                    notes.push(format!("{g:?} changed: takes effect at the next restart"));
                }
                GlobalChange::Rpki => {
                    let done = self.rpki.reconfigure(&self.config.rpki, &new.rpki);
                    notes.push(done.map_or_else(|e| e, str::to_owned));
                }
                GlobalChange::RpkiInvalid => notes.push(format!(
                    "invalid routes: {} (was {})",
                    new.rpki.invalid, self.config.rpki.invalid
                )),
                GlobalChange::Log => bgpfc_log::init(new.log_level),
                GlobalChange::Fib => self.reload_fib(&new, &mut notes),
            }
        }
        // RFC 4486 §4: de-configured peers and peers whose session
        // parameters changed get the matching Cease subcode.
        for addr in &diff.removed {
            self.remove_peer(*addr);
        }
        for addr in &diff.reset {
            self.stop_peer(*addr, CeaseSubcode::OtherConfigurationChange);
        }
        // Policies always follow the new file: the engine knows every
        // neighbor's policy names.
        let _ = self.rib_tx.send(RibMsg::SetPolicies {
            policies: messages::NewPolicies(Box::new(engine)),
            reexport: diff.policy_changed.clone(),
        });
        // RFC 6811 §5: so does what is done with Invalid routes. After the
        // new policies, which the routes are judged by again.
        if diff.global.contains(&GlobalChange::RpkiInvalid) {
            let _ = self.rib_tx.send(RibMsg::SetInvalidAction(new.rpki.invalid));
        }
        // RFC 4271 §9.2.1.1: the advertisement intervals follow the new
        // file without a reset. Sent before new peers start, so their
        // sessions come up with the new values.
        let _ = self
            .rib_tx
            .send(RibMsg::SetIntervals(wiring::advertisement_intervals(&new)));
        // RFC 4271 §6.7: so do the prefix limits; a session already over a
        // lowered limit ends.
        let _ = self
            .rib_tx
            .send(RibMsg::SetPrefixLimits(wiring::prefix_limits(&new)));
        // RFC 7911 §5: and the number of paths each ADD-PATH session sends.
        let _ = self
            .rib_tx
            .send(RibMsg::SetAddPathLimits(wiring::add_path_limits(&new)));
        // Import policy changes need the peer's routes again (RFC 2918).
        if let Ok(t) = self.table.read() {
            for addr in &diff.policy_changed {
                if let Some(h) = t.get(addr) {
                    let _ = h.tx.try_send(PeerInput::RequestRoutes);
                }
            }
        }
        let mut started = Vec::new();
        for addr in diff.added.iter().chain(&diff.reset) {
            if let Some(n) = new.neighbor(*addr) {
                started.push(prepare_peer(
                    &new,
                    n,
                    &self.rib_tx,
                    &self.table,
                    &self.restart,
                ));
            }
        }
        for p in started {
            p.start();
        }
        let summary = format!(
            "added {} removed {} reset {} policy {} interval {} limit {} paths {} unchanged {}{}",
            diff.added.len(),
            diff.removed.len(),
            diff.reset.len(),
            diff.policy_changed.len(),
            diff.interval_changed.len(),
            diff.prefix_limit_changed.len(),
            diff.add_path_send_changed.len(),
            diff.unchanged.len(),
            if notes.is_empty() {
                String::new()
            } else {
                format!("; {}", notes.join("; "))
            }
        );
        self.config = new;
        Ok(summary)
    }

    /// Apply a changed `fib` block: the mode at once, the table and the
    /// protocol number at the next restart.
    fn reload_fib(&self, new: &bgpfc_config::Config, notes: &mut Vec<String>) {
        if new.fib.table != self.config.fib.table || new.fib.protocol != self.config.fib.protocol {
            notes
                .push("fib table or protocol changed: takes effect at the next restart".to_owned());
        }
        if new.fib.mode != self.config.fib.mode {
            let (tx, rx) = sync_channel(1);
            if self
                .rib_tx
                .send(RibMsg::FibMode(fib::mode_of(new.fib.mode), tx))
                .is_ok()
            {
                let _ = rx.recv_timeout(std::time::Duration::from_secs(30));
            }
        }
    }

    /// The running `rpki` block and its client's status.
    fn rpki_report(&self) -> messages::RpkiReport {
        messages::RpkiReport {
            config: self.config.rpki.clone(),
            status: self.rpki.status(),
        }
    }

    /// Stop every session with a Cease (RFC 4486 §4 Administrative
    /// Shutdown), remove our routes from the kernel, then stop the RTR
    /// client.
    fn shutdown(&mut self) {
        if let Ok(t) = self.table.read() {
            for handle in t.values() {
                let _ = handle
                    .tx
                    .try_send(PeerInput::Stop(CeaseSubcode::AdministrativeShutdown));
            }
        }
        // Give the peer threads a moment to write their NOTIFICATIONs.
        std::thread::sleep(std::time::Duration::from_millis(300));
        let (done_tx, done_rx) = sync_channel(1);
        if self.fib_tx.send(FibMsg::Shutdown(done_tx)).is_ok() {
            let _ = done_rx.recv_timeout(std::time::Duration::from_secs(10));
        }
        if let Some(path) = &self.config.control.socket {
            let _ = std::fs::remove_file(path);
        }
        // Last: neither the Ceases nor the FIB cleanup need it, and it may
        // first have to hand the RIB thread a change (see `rpki`).
        self.rpki.stop();
        #[cfg(feature = "profiling")]
        profiling::emit(&profiling::report("shutdown", |_| {}));
        bgpfc_log::info!("bgpfcd stopped");
    }
}

/// [`load`] without exiting: for reload, where the running configuration
/// must survive a bad file.
fn load_checked(opts: &args::Args) -> Result<(bgpfc_config::Config, bgpfc_policy::Engine), String> {
    let mut config = bgpfc_config::parse_file(&opts.config).map_err(|e| e.to_string())?;
    let engine = bgpfc_policy::Engine::new(&config).map_err(|errors| {
        errors
            .iter()
            .map(|e| format!("{}:{e}", opts.config.display()))
            .collect::<Vec<_>>()
            .join("\n")
    })?;
    if let Some(level) = opts.log_level {
        config.log_level = level;
    }
    if let Some(mode) = opts.fib {
        config.fib.mode = mode;
    }
    Ok((config, engine))
}

//! The FIB thread: owns the netlink socket through `bgpfc_fib::Fib` and
//! follows the Loc-RIB (AGENTS.md §3, "FIB thread"; README, "FIB
//! dry-run").
//!
//! Implements: RFC 4724 §4.1 (a daemon that restarted with graceful
//! restart on keeps the routes of its protocol number that are in the
//! kernel, in the families it may learn again, until its RIB reconciles
//! them; the thread also says which families have forwarding state, for
//! the Forwarding State bit).

use std::sync::Arc;
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::thread;

use bgpfc_fib::{Applied, Change, Fib, Merge, Mode, Op};
use bgpfc_wire::types::{AddressFamily, Afi};

use crate::messages::{FibMsg, FibReport, PAGE};
use crate::restart::RestartState;

/// Batches of changes the RIB thread may queue before it blocks. A batch
/// is one RIB input's changes, or [`crate::rib::FIB_BATCH`] of a long one.
const QUEUE: usize = 64;

/// Open the socket, flush stale routes (AGENTS.md §3: only those with
/// our protocol number), and start the thread. The routes of the families
/// in `keep` are left where they are, believed installed: the forwarding
/// state a restart preserved, which RFC 4724 §4.1 has the daemon replace
/// only once it has learned its routes again. The families among `keep`
/// that have some are returned. `state` is told which families have
/// forwarding state, now and as the routes change.
///
/// # Errors
/// If the socket cannot be opened or the startup dump fails.
pub(crate) fn start(
    mut fib: Fib,
    keep: &[Afi],
    state: Arc<RestartState>,
) -> Result<(SyncSender<FibMsg>, Vec<AddressFamily>), bgpfc_fib::FibError> {
    fib.open()?;
    let flushed = fib.sync_keeping(keep)?;
    report(&flushed);
    let kept: Vec<AddressFamily> = keep
        .iter()
        .filter(|afi| fib.installed_count(**afi) > 0)
        .map(|afi| AddressFamily {
            afi: *afi,
            safi: bgpfc_wire::types::Safi::Unicast,
        })
        .collect();
    publish(&fib, &state);
    let (tx, rx) = sync_channel(QUEUE);
    thread::Builder::new()
        .name("fib".to_owned())
        .spawn(move || run(fib, &rx, &state))
        .expect("spawning the fib thread");
    Ok((tx, kept))
}

/// Tell the peer threads which families have forwarding state: routes of
/// ours installed in the kernel, which only install mode does (RFC 4724
/// §4.1: the Forwarding State bit "can be set only if the forwarding state
/// has indeed been preserved").
fn publish(fib: &Fib, state: &RestartState) {
    let install = fib.mode() == Mode::Install;
    state.set_forwarding(
        install && fib.installed_count(Afi::Ipv4) > 0,
        install && fib.installed_count(Afi::Ipv6) > 0,
    );
}

fn run(mut fib: Fib, rx: &Receiver<FibMsg>, state: &RestartState) {
    // Kept between batches, so that applying one allocates nothing.
    let mut applied = Vec::new();
    // A reconcile in progress, and the operations taken since the mode
    // was set.
    let mut merge: Option<Merge> = None;
    let mut ops = 0;
    while let Ok(msg) = rx.recv() {
        applied.clear();
        match msg {
            FibMsg::Changes(changes) => {
                let changes = changes.iter().map(|c| Change {
                    prefix: c.prefix,
                    gateway: c.next_hop,
                    previous: c.previous,
                });
                fib.set_all(changes, &mut applied);
            }
            FibMsg::SetMode(mode) => {
                bgpfc_log::info!("fib: mode", mode = mode);
                fib.set_mode(mode);
                merge = None;
                ops = 0;
            }
            FibMsg::ReconcileFamily(family) => {
                if let Some(m) = merge.take() {
                    fib.reconcile_end(m, &mut applied);
                }
                merge = Some(family.map_or_else(Merge::default, Merge::of));
            }
            FibMsg::Reconcile(routes) => {
                if let Some(m) = &mut merge {
                    fib.reconcile(m, &routes, &mut applied);
                }
            }
            FibMsg::ReconcileEnd(reply) => {
                if let Some(m) = merge.take() {
                    fib.reconcile_end(m, &mut applied);
                }
                ops += applied.len();
                report(&applied);
                publish(&fib, state);
                let _ = reply.send(ops);
                ops = 0;
                continue;
            }
            FibMsg::Mode(reply) => {
                let _ = reply.send(fib.mode());
            }
            FibMsg::Query { after, reply } => {
                let _ = reply.send(FibReport {
                    mode: fib.mode(),
                    installed: fib.installed_after(after, PAGE),
                });
            }
            FibMsg::Shutdown(done) => {
                report(&fib.clear());
                let _ = done.send(());
                return;
            }
        }
        ops += applied.len();
        report(&applied);
        publish(&fib, state);
    }
}

fn report(applied: &[Applied]) {
    // Below info only failures are written: test the level once rather
    // than for each of a batch's operations.
    let info = bgpfc_log::enabled(bgpfc_log::Level::Info);
    for a in applied {
        if a.result.is_ok() && !info {
            continue;
        }
        let (what, prefix, gateway) = match &a.op {
            Op::Set { prefix, gateway } => ("install", prefix, gateway),
            Op::Delete { prefix, gateway } => ("delete", prefix, gateway),
        };
        match (&a.result, a.dry_run) {
            (Ok(()), true) => {
                bgpfc_log::info!(
                    "fib: dry-run",
                    op = what,
                    prefix = prefix,
                    gateway = gateway
                );
            }
            (Ok(()), false) => {
                bgpfc_log::info!(
                    "fib: applied",
                    op = what,
                    prefix = prefix,
                    gateway = gateway
                );
            }
            (Err(e), _) => {
                bgpfc_log::error!(
                    "fib: failed",
                    op = what,
                    prefix = prefix,
                    gateway = gateway,
                    error = e
                );
            }
        }
    }
}

/// The mode a config value means.
pub(crate) const fn mode_of(m: bgpfc_config::ast::FibMode) -> Mode {
    match m {
        bgpfc_config::ast::FibMode::DryRun => Mode::DryRun,
        bgpfc_config::ast::FibMode::Install => Mode::Install,
    }
}

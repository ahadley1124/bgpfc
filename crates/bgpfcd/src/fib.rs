//! The FIB thread: owns the netlink socket through `bgpfc_fib::Fib` and
//! follows the Loc-RIB (AGENTS.md §3, "FIB thread"; README, "FIB
//! dry-run").

use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::thread;

use bgpfc_fib::{Applied, Change, Fib, Merge, Mode, Op};

use crate::messages::{FibMsg, FibReport, PAGE};

/// Batches of changes the RIB thread may queue before it blocks. A batch
/// is one RIB input's changes, or [`crate::rib::FIB_BATCH`] of a long one.
const QUEUE: usize = 64;

/// Open the socket, flush stale routes (AGENTS.md §3: only those with
/// our protocol number), and start the thread.
///
/// # Errors
/// If the socket cannot be opened or the startup dump fails.
pub(crate) fn start(mut fib: Fib) -> Result<SyncSender<FibMsg>, bgpfc_fib::FibError> {
    fib.open()?;
    let flushed = fib.sync()?;
    report(&flushed);
    let (tx, rx) = sync_channel(QUEUE);
    thread::Builder::new()
        .name("fib".to_owned())
        .spawn(move || run(fib, &rx))
        .expect("spawning the fib thread");
    Ok(tx)
}

fn run(mut fib: Fib, rx: &Receiver<FibMsg>) {
    // Kept between batches, so that applying one allocates nothing.
    let mut applied = Vec::new();
    // A switch to install in progress, and the operations it took.
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
                merge = (mode == Mode::Install).then(Merge::default);
                ops = 0;
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
                let _ = reply.send(ops + applied.len());
                ops = 0;
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

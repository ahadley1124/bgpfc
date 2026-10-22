//! The FIB thread: owns the netlink socket through `bgpfc_fib::Fib` and
//! follows the Loc-RIB (AGENTS.md §3, "FIB thread"; README, "FIB
//! dry-run").

use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::thread;

use bgpfc_fib::{Applied, Fib, Mode, Op};

use crate::messages::{FibMsg, FibReport};

/// Changes the RIB thread may queue before it blocks.
const QUEUE: usize = 4096;

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
    while let Ok(msg) = rx.recv() {
        match msg {
            FibMsg::Change(c) => report(&fib.set(c.prefix, c.next_hop)),
            FibMsg::SetMode(mode, reply) => {
                bgpfc_log::info!("fib: mode", mode = mode);
                let applied = fib.set_mode(mode);
                report(&applied);
                let _ = reply.send(applied.len());
            }
            FibMsg::Query(reply) => {
                let _ = reply.send(FibReport {
                    mode: fib.mode(),
                    desired: fib.desired().clone(),
                    installed: fib.installed().clone(),
                });
            }
            FibMsg::Shutdown(done) => {
                report(&fib.clear());
                let _ = done.send(());
                return;
            }
        }
    }
}

fn report(applied: &[Applied]) {
    for a in applied {
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

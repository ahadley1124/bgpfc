//! The FIB thread: owns the netlink socket through `bgpfc_fib::Fib` and
//! follows the Loc-RIB (AGENTS.md §3, "FIB thread"; README, "FIB
//! dry-run").
//!
//! # Logging
//!
//! The thread logs what it does once per change, as the RIB logs a change
//! of the validation source: a line at info (`fib: changes`) with the mode
//! the change ran in (`dry-run`, only reported, or `install`), the routes
//! it installed or replaced and those it removed, the operations that
//! failed, and its first few prefixes. A change is
//!
//! - what the RIB made of one of its inputs: an UPDATE, a session that
//!   went down, a change of the VRPs or of `enforcement`, a reload; the
//!   RIB sends it in batches of [`FIB_BATCH`](crate::rib::FIB_BATCH) at
//!   most and marks the last ([`FibMsg::Changes`]);
//! - a switch to install mode, with its reconcile;
//! - the removal of stale routes at startup, and of every route at
//!   shutdown.
//!
//! A change that moves a whole table, such as VRPs that expire or a new
//! `enforcement`, thus costs one line rather than one per route. Each
//! operation also has a line of its own at debug (`fib: dry-run` or
//! `fib: applied`, with the prefix and gateway). A failed one has a line
//! at error (`fib: failed`) instead, for the first [`FAILURES_LOGGED`] of
//! a change and at debug after them, and the change's line is then at
//! error too, counting them all.

use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::thread;

use bgpfc_fib::{Applied, Change, Fib, Merge, Mode, Op};
use bgpfc_log::Level;
use bgpfc_wire::prefix::Prefix;

use crate::messages::{FibMsg, FibReport, PAGE};
use crate::rib::{Line, listed, log_line};

/// Batches of changes the RIB thread may queue before it blocks. A batch
/// is one RIB input's changes, or [`crate::rib::FIB_BATCH`] of a long one.
const QUEUE: usize = 64;

/// The message of the line logged for each change.
const CHANGES: &str = "fib: changes";

/// Prefixes the line of a change names, the first it operated on; `...`
/// marks the rest.
const SAMPLE: usize = 8;

/// Failed operations of one change that get a line at error each; the
/// rest are counted on the change's line, and have a line at debug. A
/// kernel that refuses one route often refuses the whole table, as when
/// bgpfcd lacks `CAP_NET_ADMIN` or a peer's next hop is not reachable
/// directly, and then the first already names the reason; a line for
/// each of a million would bury the rest of the log. Three rather than
/// one, so that a change whose routes fail for different reasons, such
/// as a next hop that is unreachable for some of them, shows more than
/// one of the reasons at error.
pub(crate) const FAILURES_LOGGED: usize = 3;

/// Open the socket, flush stale routes (AGENTS.md §3: only those with
/// our protocol number), and start the thread.
///
/// # Errors
/// If the socket cannot be opened or the startup dump fails.
pub(crate) fn start(mut fib: Fib) -> Result<SyncSender<FibMsg>, bgpfc_fib::FibError> {
    fib.open()?;
    let flushed = fib.sync()?;
    // The flush is a change of its own.
    let mut change = Tally::default();
    let mut log = logger();
    report(&mut change, &flushed, debug(), &mut log);
    finish(&mut change, &mut log);
    let (tx, rx) = sync_channel(QUEUE);
    thread::Builder::new()
        .name("fib".to_owned())
        .spawn(move || serve(fib, &rx, &debug, &mut logger()))
        .expect("spawning the fib thread");
    Ok(tx)
}

/// What writes the thread's lines to the log; the tests keep them
/// instead.
fn logger() -> impl FnMut(Line) {
    |line: Line| log_line(line.level, line.msg, &line.fields)
}

/// Whether lines at debug are written, asked once per batch rather than
/// for each of its operations.
fn debug() -> bool {
    bgpfc_log::enabled(Level::Debug)
}

/// The thread's loop, until a shutdown or until every sender is gone,
/// the lines it logs going to `out`.
fn serve(
    mut fib: Fib,
    rx: &Receiver<FibMsg>,
    debug: &impl Fn() -> bool,
    out: &mut impl FnMut(Line),
) {
    // Kept between batches, so that applying one allocates nothing.
    let mut applied = Vec::new();
    // A switch to install in progress, and the operations it took.
    let mut merge: Option<Merge> = None;
    let mut ops = 0;
    // What the change under way did so far.
    let mut change = Tally::default();
    while let Ok(msg) = rx.recv() {
        applied.clear();
        // Whether the message ends the change it belongs to. The control
        // thread's queries come between a change's batches too, and leave
        // it open.
        let mut ends = false;
        match msg {
            FibMsg::Changes { changes, more } => {
                let changes = changes.iter().map(|c| Change {
                    prefix: c.prefix,
                    gateway: c.next_hop,
                    previous: c.previous,
                });
                fib.set_all(changes, &mut applied);
                ends = !more;
            }
            FibMsg::SetMode(mode) => {
                // A switch is a change of its own; the RIB sends it
                // between inputs, so no change of the RIB is open.
                finish(&mut change, out);
                out(Line {
                    level: Level::Info,
                    msg: "fib: mode",
                    fields: vec![("mode", mode.to_string())],
                });
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
                ends = true;
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
                // What the RIB sent of a change it had not finished,
                // then the cleanup, a change of its own.
                finish(&mut change, out);
                report(&mut change, &fib.clear(), debug(), out);
                finish(&mut change, out);
                let _ = done.send(());
                return;
            }
        }
        ops += applied.len();
        report(&mut change, &applied, debug(), out);
        if ends {
            finish(&mut change, out);
        }
    }
    finish(&mut change, out);
}

/// Count `applied` into `change` and write the lines of its operations.
fn report(change: &mut Tally, applied: &[Applied], debug: bool, out: &mut impl FnMut(Line)) {
    for a in applied {
        if let Some(line) = change.add(a, debug) {
            out(line);
        }
    }
}

/// Write the line of `change`, if it did anything, and start the next.
fn finish(change: &mut Tally, out: &mut impl FnMut(Line)) {
    if let Some(line) = std::mem::take(change).summary() {
        out(line);
    }
}

/// What the FIB thread did for one change, for the change's line.
#[derive(Debug, Default)]
struct Tally {
    /// Routes installed or replaced, or in dry-run that would be.
    install: usize,
    /// Routes removed, or in dry-run that would be.
    delete: usize,
    /// Operations that failed.
    failed: usize,
    /// Whether the operations were only reported (dry-run).
    dry_run: bool,
    /// The first [`SAMPLE`] prefixes operated on.
    sample: Vec<Prefix>,
}

impl Tally {
    /// The operations counted.
    fn ops(&self) -> usize {
        self.install + self.delete + self.failed
    }

    /// Count `a`, and return its own line, if it gets one: a failure at
    /// error while fewer than [`FAILURES_LOGGED`] failed before it in the
    /// change, and any operation at debug with `debug`.
    fn add(&mut self, a: &Applied, debug: bool) -> Option<Line> {
        let (op, prefix, gateway) = match &a.op {
            Op::Set { prefix, gateway } => ("install", prefix, gateway),
            Op::Delete { prefix, gateway } => ("delete", prefix, gateway),
        };
        if self.ops() == 0 {
            self.dry_run = a.dry_run;
        }
        if self.sample.len() < SAMPLE {
            self.sample.push(*prefix);
        }
        // Counted first; the fields are built only for a line written.
        let (level, msg, error) = match &a.result {
            Ok(()) => {
                match a.op {
                    Op::Set { .. } => self.install += 1,
                    Op::Delete { .. } => self.delete += 1,
                }
                if !debug {
                    return None;
                }
                let msg = if a.dry_run {
                    "fib: dry-run"
                } else {
                    "fib: applied"
                };
                (Level::Debug, msg, None)
            }
            Err(e) => {
                self.failed += 1;
                let level = if self.failed <= FAILURES_LOGGED {
                    Level::Error
                } else if debug {
                    Level::Debug
                } else {
                    return None;
                };
                (level, "fib: failed", Some(e))
            }
        };
        let mut fields = vec![
            ("op", op.to_owned()),
            ("prefix", prefix.to_string()),
            ("gateway", gateway.to_string()),
        ];
        if let Some(e) = error {
            fields.push(("error", e.to_string()));
        }
        Some(Line { level, msg, fields })
    }

    /// The change's line, or `None` if it did nothing: at error if an
    /// operation failed.
    fn summary(self) -> Option<Line> {
        let ops = self.ops();
        if ops == 0 {
            return None;
        }
        let mode = if self.dry_run {
            Mode::DryRun
        } else {
            Mode::Install
        };
        Some(Line {
            level: if self.failed > 0 {
                Level::Error
            } else {
                Level::Info
            },
            msg: CHANGES,
            fields: vec![
                ("mode", mode.to_string()),
                ("install", self.install.to_string()),
                ("delete", self.delete.to_string()),
                ("failed", self.failed.to_string()),
                ("prefixes", listed(&self.sample, ops)),
            ],
        })
    }
}

/// The mode a config value means.
pub(crate) const fn mode_of(m: bgpfc_config::ast::FibMode) -> Mode {
    match m {
        bgpfc_config::ast::FibMode::DryRun => Mode::DryRun,
        bgpfc_config::ast::FibMode::Install => Mode::Install,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::IpAddr;

    use bgpfc_fib::FibError;
    use bgpfc_rib::FibChange;
    use bgpfc_wire::types::AddressFamily;

    fn p(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// The `i`th of a run of /24s, 10.0.0.0/24 first.
    fn nth(i: usize) -> String {
        format!("10.{}.{}.0/24", i / 256, i % 256)
    }

    fn set(prefix: &str, dry_run: bool) -> Applied {
        Applied {
            op: Op::Set {
                prefix: p(prefix),
                gateway: ip("192.0.2.1"),
            },
            result: Ok(()),
            dry_run,
        }
    }

    fn delete(prefix: &str, dry_run: bool) -> Applied {
        Applied {
            op: Op::Delete {
                prefix: p(prefix),
                gateway: ip("192.0.2.1"),
            },
            result: Ok(()),
            dry_run,
        }
    }

    /// An operation the kernel refused with `EPERM`.
    fn refused(prefix: &str) -> Applied {
        Applied {
            result: Err(FibError::Kernel(1)),
            ..set(prefix, false)
        }
    }

    /// The lines as the log writes them, at the epoch.
    fn written(lines: &[Line]) -> Vec<String> {
        lines
            .iter()
            .map(|l| {
                let fields: Vec<bgpfc_log::Field<'_>> = l
                    .fields
                    .iter()
                    .map(|(k, v)| (*k, v as &dyn std::fmt::Display))
                    .collect();
                bgpfc_log::format_line(std::time::UNIX_EPOCH, l.level, l.msg, &fields)
            })
            .collect()
    }

    /// The lines of `applied`, in batches, as one change.
    fn change_lines(batches: &[&[Applied]], debug: bool) -> Vec<Line> {
        let mut lines = Vec::new();
        let mut change = Tally::default();
        for batch in batches {
            report(&mut change, batch, debug, &mut |l| lines.push(l));
        }
        finish(&mut change, &mut |l| lines.push(l));
        // Finished: the next change starts empty.
        finish(&mut change, &mut |l| lines.push(l));
        lines
    }

    /// A change that moves a table is one line at info however many
    /// routes it moved, in however many batches: the counts by
    /// operation, the mode and the first prefixes.
    #[test]
    fn a_change_is_one_line_at_info() {
        let installs: Vec<Applied> = (0..1000).map(|i| set(&nth(i), true)).collect();
        let deletes = [delete("192.0.2.0/24", true), delete("2001:db8::/32", true)];
        let lines = change_lines(&[&installs[..256], &installs[256..], &deletes], false);
        assert_eq!(
            written(&lines),
            [
                "1970-01-01T00:00:00.000Z INFO  msg=\"fib: changes\" mode=dry-run install=1000 \
                 delete=2 failed=0 prefixes=10.0.0.0/24,10.0.1.0/24,10.0.2.0/24,10.0.3.0/24,\
                 10.0.4.0/24,10.0.5.0/24,10.0.6.0/24,10.0.7.0/24,...\n"
            ]
        );
        // Install mode, one route: its prefix alone.
        let lines = change_lines(&[&[delete("192.0.2.0/24", false)]], false);
        assert_eq!(
            written(&lines),
            [
                "1970-01-01T00:00:00.000Z INFO  msg=\"fib: changes\" mode=install install=0 \
              delete=1 failed=0 prefixes=192.0.2.0/24\n"
            ]
        );
        // A change that did nothing has no line.
        assert_eq!(change_lines(&[&[], &[]], true), []);
    }

    /// At debug every operation has a line of its own too, as before the
    /// change's line, with its prefix and gateway.
    #[test]
    fn each_operation_has_a_line_at_debug() {
        let lines = change_lines(
            &[
                &[set("192.0.2.0/24", true)],
                &[delete("198.51.100.0/24", true)],
            ],
            true,
        );
        assert_eq!(
            written(&lines),
            [
                "1970-01-01T00:00:00.000Z DEBUG msg=\"fib: dry-run\" op=install \
                 prefix=192.0.2.0/24 gateway=192.0.2.1\n",
                "1970-01-01T00:00:00.000Z DEBUG msg=\"fib: dry-run\" op=delete \
                 prefix=198.51.100.0/24 gateway=192.0.2.1\n",
                "1970-01-01T00:00:00.000Z INFO  msg=\"fib: changes\" mode=dry-run install=1 \
                 delete=1 failed=0 prefixes=192.0.2.0/24,198.51.100.0/24\n",
            ]
        );
        let lines = change_lines(&[&[set("192.0.2.0/24", false)]], true);
        assert_eq!(lines[0].msg, "fib: applied");
        assert_eq!(lines[1].fields[0], ("mode", "install".to_owned()));
    }

    /// The first failures of a change are at error, the others at debug,
    /// and the change's line is at error, counting them all.
    #[test]
    fn failures_are_at_error_up_to_a_bound() {
        let ops: Vec<Applied> = (0..FAILURES_LOGGED + 5)
            .map(|i| refused(&nth(i)))
            .chain([set("192.0.2.0/24", false)])
            .collect();
        let lines = change_lines(&[&ops], false);
        assert_eq!(lines.len(), FAILURES_LOGGED + 1);
        assert!(
            lines[..FAILURES_LOGGED]
                .iter()
                .all(|l| l.level == Level::Error)
        );
        assert_eq!(
            written(&lines[..1]),
            [
                "1970-01-01T00:00:00.000Z ERROR msg=\"fib: failed\" op=install \
              prefix=10.0.0.0/24 gateway=192.0.2.1 \
              error=\"kernel refused: Operation not permitted (os error 1)\"\n"
            ]
        );
        let summary = &written(&lines)[FAILURES_LOGGED];
        assert_eq!(FAILURES_LOGGED, 3);
        assert!(
            summary.starts_with(
                "1970-01-01T00:00:00.000Z ERROR msg=\"fib: changes\" mode=install \
                 install=1 delete=0 failed=8 prefixes=10.0.0.0/24,"
            ),
            "{summary}"
        );
        // At debug, the rest of the failures and the success too.
        let lines = change_lines(&[&ops], true);
        assert_eq!(lines.len(), FAILURES_LOGGED + 5 + 1 + 1);
        assert!(
            lines[FAILURES_LOGGED..FAILURES_LOGGED + 5]
                .iter()
                .all(|l| l.level == Level::Debug && l.msg == "fib: failed")
        );
        // The bound is per change: the next one starts again.
        let mut change = Tally::default();
        let mut errors = 0;
        for _ in 0..2 {
            report(&mut change, &ops, false, &mut |l| {
                errors += usize::from(l.msg == "fib: failed");
            });
            finish(&mut change, &mut |_| {});
        }
        assert_eq!(errors, 2 * FAILURES_LOGGED);
    }

    /// The thread writes a line per change: once the RIB's last batch of
    /// an input is in, however many came and whatever the control thread
    /// asked in between; for a switch to install mode, with its
    /// reconcile; and for what is left of a change at shutdown.
    #[test]
    fn the_thread_writes_a_line_per_change() {
        let batch = |range: std::ops::Range<usize>| -> Vec<FibChange> {
            range
                .map(|i| FibChange {
                    family: AddressFamily::IPV4_UNICAST,
                    prefix: p(&nth(i)),
                    next_hop: Some(ip("192.0.2.1")),
                    previous: None,
                })
                .collect()
        };
        let (tx, rx) = sync_channel(16);
        let send = |msg| tx.send(msg).unwrap();
        // An input of two full batches and a closing empty one, with a
        // query of the control thread between them.
        send(FibMsg::Changes {
            changes: batch(0..256),
            more: true,
        });
        let (mode_tx, mode_rx) = sync_channel(1);
        send(FibMsg::Mode(mode_tx));
        send(FibMsg::Changes {
            changes: batch(256..512),
            more: true,
        });
        send(FibMsg::Changes {
            changes: Vec::new(),
            more: false,
        });
        // An input of one route.
        send(FibMsg::Changes {
            changes: batch(512..513),
            more: false,
        });
        // A switch to install: with no socket, every operation of its
        // reconcile fails.
        send(FibMsg::SetMode(Mode::Install));
        send(FibMsg::Reconcile(vec![(
            p("192.0.2.0/24"),
            ip("192.0.2.1"),
        )]));
        let (end_tx, end_rx) = sync_channel(1);
        send(FibMsg::ReconcileEnd(end_tx));
        // Half an input, then the shutdown.
        send(FibMsg::Changes {
            changes: batch(600..610),
            more: true,
        });
        let (done_tx, done_rx) = sync_channel(1);
        send(FibMsg::Shutdown(done_tx));
        let mut lines = Vec::new();
        serve(Fib::new(Mode::DryRun, 254, 186), &rx, &|| false, &mut |l| {
            lines.push(l);
        });
        assert_eq!(mode_rx.try_recv().unwrap(), Mode::DryRun);
        assert_eq!(end_rx.try_recv().unwrap(), 1);
        assert!(done_rx.try_recv().is_ok());
        let summary = |l: &Line| {
            let value = |k| l.fields.iter().find(|(f, _)| *f == k).unwrap().1.clone();
            (l.msg, value("mode"), value("install"), value("failed"))
        };
        let changes: Vec<_> = lines
            .iter()
            .filter(|l| l.msg != "fib: failed" && l.msg != "fib: mode")
            .map(summary)
            .collect();
        let own = |mode: &str, install: &str, failed: &str| {
            (
                CHANGES,
                mode.to_owned(),
                install.to_owned(),
                failed.to_owned(),
            )
        };
        assert_eq!(
            changes,
            [
                own("dry-run", "512", "0"),
                own("dry-run", "1", "0"),
                own("install", "0", "1"),
                own("install", "0", "10"),
            ]
        );
        // The mode line comes before the switch's line.
        let mode = lines.iter().position(|l| l.msg == "fib: mode").unwrap();
        assert_eq!(lines[mode].fields, [("mode", "install".to_owned())]);
        assert_eq!(lines[mode + 1].msg, "fib: failed");
    }
}

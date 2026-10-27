//! The FIB thread: owns the netlink socket through `bgpfc_fib::Fib` and
//! follows the Loc-RIB (AGENTS.md §3, "FIB thread"; README, "FIB
//! dry-run").
//!
//! # Logging
//!
//! The thread folds what it does into lines at info (`fib: changes`), as
//! the RIB folds a change of the validation source: each with the mode its
//! operations ran in (`dry-run`, only reported, or `install`), the routes
//! installed or replaced and those removed, the operations that failed,
//! and the first few prefixes. A line counts what was done since the line
//! before, and comes
//!
//! - at once for a change that ends at least [`FOLD`] after the line
//!   before, so that a lone UPDATE is logged as it is applied;
//! - otherwise [`FOLD`] after the line before, with everything done since:
//!   a table that loads from a peer, an UPDATE at a time, or a burst of
//!   VRP changes, costs a line a second however many changes it makes;
//! - [`FOLD`] after the first operation it counts while that operation's
//!   change goes on, so that a change that takes longer has a line a
//!   second with the counts so far;
//! - at once before a switch of mode, so that no line mixes the modes,
//!   and at shutdown, so that nothing counted goes unwritten.
//!
//! The thread wakes for a line that is due even when nothing else comes,
//! so the last one is written within [`FOLD`] of the last change.
//!
//! A change is
//!
//! - what the RIB made of one of its inputs: an UPDATE, a session that
//!   went down, a change of the VRPs or of `enforcement`, a reload; the
//!   RIB sends it in batches of [`FIB_BATCH`](crate::rib::FIB_BATCH) at
//!   most and marks the last ([`FibMsg::Changes`]);
//! - a switch to install mode, with its reconcile;
//! - the removal of stale routes at startup, and of every route at
//!   shutdown.
//!
//! Each operation also has a line of its own at debug (`fib: dry-run` or
//! `fib: applied`, with the prefix, the gateway and the interface it is
//! reached on; `fib: already gone` for a delete the kernel answered
//! `ESRCH`, having removed the route itself, as IPv4 does with the routes
//! through an interface that goes down, which counts as a delete), written
//! as it is done. A
//! failed one has a line at error (`fib: failed`) instead, at once, for
//! the first [`FAILURES_LOGGED`] of a change, and for no more than
//! [`FAILURES_LOGGED`] in all between two `fib: changes` lines, and at
//! debug after them; the line that counts it is at error too. The second
//! bound is the one a table that loads from a peer meets, a change an
//! UPDATE: with every route refused, its failures cost three lines a
//! second at most, as its counts cost one.

use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel};
use std::thread;
use std::time::{Duration, Instant};

use bgpfc_fib::{Applied, Change, Fib, Hop, Merge, Mode, Op};
use bgpfc_log::Level;
use bgpfc_wire::prefix::Prefix;

use crate::messages::{FibMsg, FibReport, PAGE};
use crate::rib::{Line, listed, log_line};

/// Batches of changes the RIB thread may queue before it blocks. A batch
/// is one RIB input's changes, or [`crate::rib::FIB_BATCH`] of a long one.
const QUEUE: usize = 64;

/// The message of the lines that count what the thread did.
const CHANGES: &str = "fib: changes";

/// Prefixes a line names, the first operated on since the line before;
/// `...` marks the rest.
const SAMPLE: usize = 8;

/// The shortest time between two lines while the routes keep changing,
/// and the longest a change waits for its line. A table that loads from a
/// peer comes in tens of thousands of UPDATEs, each a change: a line a
/// second shows its progress, at a few hundred bytes a second, where a
/// line per UPDATE would bury the rest of the log; and a change that comes
/// alone is still logged at once.
pub(crate) const FOLD: Duration = Duration::from_secs(1);

/// Failed operations that get a line at error each: the first of one
/// change, and no more in all between two `fib: changes` lines; the rest
/// are counted on those lines, and have a line at debug. A kernel that
/// refuses one route often refuses the whole table, as when bgpfcd lacks
/// `CAP_NET_ADMIN` or a peer's next hop is not reachable directly, and
/// then the first already names the reason; a line for each of a million
/// would bury the rest of the log. The bound per change alone would not
/// do: a table that loads from a peer is a change per UPDATE, a few
/// routes each, so it would still cost about a line a route. Between two
/// lines, which come a second apart while changes keep coming ([`FOLD`]),
/// it costs three a second. Three rather than one, so that a change whose
/// routes fail for different reasons, such as a next hop that is
/// unreachable for some of them, shows more than one of the reasons at
/// error.
pub(crate) const FAILURES_LOGGED: usize = 3;

/// Open the socket, flush stale routes (AGENTS.md §3: only those with
/// our protocol number), and start the thread.
///
/// # Errors
/// If the socket cannot be opened or the startup dump fails.
pub(crate) fn start(mut fib: Fib) -> Result<SyncSender<FibMsg>, bgpfc_fib::FibError> {
    fib.open()?;
    let flushed = fib.sync()?;
    // The flush is a change of its own, written at once.
    let mut fold = Fold::default();
    let mut log = logger();
    fold.add(&flushed, debug(), Instant::now(), &mut log);
    fold.end_change();
    fold.flush(Instant::now(), &mut log);
    let (tx, rx) = sync_channel(QUEUE);
    thread::Builder::new()
        .name("fib".to_owned())
        .spawn(move || {
            serve(
                fib,
                fold,
                &mut receiver(&rx),
                &Instant::now,
                &debug,
                &mut logger(),
            );
        })
        .expect("spawning the fib thread");
    Ok(tx)
}

/// The RIB's hop of a route as the FIB takes it: the gateway, and the
/// interface of the kernel route that resolves the next hop, with its
/// `onlink`; none while the RIB has no kernel table, and the kernel
/// chooses (the two crates are siblings, AGENTS.md §2, so their types
/// meet here).
pub(crate) fn fib_hop(hop: bgpfc_rib::nexthop::Hop) -> Hop {
    Hop {
        gateway: hop.gateway,
        oif: hop.oif,
        onlink: hop.onlink,
    }
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

/// The thread's wait for its next message on `rx`: until a deadline, if
/// it has one, when a line is due. The tests script the messages and the
/// time instead.
fn receiver(
    rx: &Receiver<FibMsg>,
) -> impl FnMut(Option<Instant>) -> Result<FibMsg, RecvTimeoutError> + '_ {
    move |deadline| match deadline {
        None => rx.recv().map_err(|_| RecvTimeoutError::Disconnected),
        Some(at) => rx.recv_timeout(at.saturating_duration_since(Instant::now())),
    }
}

/// The thread's loop, until a shutdown or until every sender is gone:
/// messages from `recv`, which waits no longer than the deadline it is
/// given, the time from `now`, and the lines it logs going to `out`.
fn serve(
    mut fib: Fib,
    mut fold: Fold,
    recv: &mut impl FnMut(Option<Instant>) -> Result<FibMsg, RecvTimeoutError>,
    now: &impl Fn() -> Instant,
    debug: &impl Fn() -> bool,
    out: &mut impl FnMut(Line),
) {
    // Kept between batches, so that applying one allocates nothing.
    let mut applied = Vec::new();
    // A switch to install in progress, and the operations it took.
    let mut merge: Option<Merge> = None;
    let mut ops = 0;
    loop {
        let msg = match recv(fold.due()) {
            Ok(msg) => msg,
            // Nothing came before a line was due.
            Err(RecvTimeoutError::Timeout) => {
                fold.flush_due(now(), out);
                continue;
            }
            Err(RecvTimeoutError::Disconnected) => break,
        };
        applied.clear();
        match msg {
            FibMsg::Changes { changes, more } => {
                let changes = changes.iter().map(|c| Change {
                    prefix: c.prefix,
                    hop: c.next_hop.map(fib_hop),
                    previous: c.previous.map(fib_hop),
                });
                fib.set_all(changes, &mut applied);
                fold.add(&applied, debug(), now(), out);
                // The control thread's queries come between a change's
                // batches too, and leave it open.
                if !more {
                    fold.end_change();
                }
            }
            FibMsg::SetMode(mode) => {
                // No line mixes the modes. The RIB sends a switch between
                // its inputs, so no change of the RIB is open.
                fold.flush(now(), out);
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
                ops += applied.len();
                fold.add(&applied, debug(), now(), out);
            }
            FibMsg::ReconcileEnd(reply) => {
                if let Some(m) = merge.take() {
                    fib.reconcile_end(m, &mut applied);
                }
                let _ = reply.send(ops + applied.len());
                ops = 0;
                fold.add(&applied, debug(), now(), out);
                fold.end_change();
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
                // What was counted, of a change the RIB may not have
                // finished, then the cleanup, a change of its own: both
                // at once, as nothing follows.
                fold.end_change();
                fold.flush(now(), out);
                fold.add(&fib.clear(), debug(), now(), out);
                fold.end_change();
                fold.flush(now(), out);
                let _ = done.send(());
                return;
            }
        }
        fold.flush_due(now(), out);
    }
    fold.flush(now(), out);
}

/// What the thread did since its last `fib: changes` line, and when the
/// next is due (see the module documentation, "Logging").
#[derive(Debug, Default)]
struct Fold {
    /// The operations since the last line.
    tally: Tally,
    /// When the first of them was counted; `None` while there is none.
    since: Option<Instant>,
    /// When the last line was written.
    last_line: Option<Instant>,
    /// Whether the change under way has more to come: further batches of
    /// a RIB input, or the rest of a reconcile.
    in_change: bool,
    /// The failed operations of the change under way, for
    /// [`FAILURES_LOGGED`].
    change_failed: usize,
    /// The `fib: failed` lines written at error since the last line, for
    /// [`FAILURES_LOGGED`].
    logged: usize,
}

impl Fold {
    /// Count `applied`, done at `now` in the change under way, and write
    /// the lines of its operations: at debug with `debug`, and at error
    /// for the first failures of the change, unless as many were written
    /// since the last line.
    fn add(&mut self, applied: &[Applied], debug: bool, now: Instant, out: &mut impl FnMut(Line)) {
        self.in_change = true;
        if applied.is_empty() {
            return;
        }
        self.since.get_or_insert(now);
        for a in applied {
            self.tally.add(a);
            let (level, msg) = match a.result {
                Ok(()) if debug => (
                    Level::Debug,
                    if a.dry_run {
                        "fib: dry-run"
                    } else if a.already_gone {
                        "fib: already gone"
                    } else {
                        "fib: applied"
                    },
                ),
                Ok(()) => continue,
                Err(_) => {
                    self.change_failed += 1;
                    if self.change_failed <= FAILURES_LOGGED && self.logged < FAILURES_LOGGED {
                        self.logged += 1;
                        (Level::Error, "fib: failed")
                    } else if debug {
                        (Level::Debug, "fib: failed")
                    } else {
                        continue;
                    }
                }
            };
            out(op_line(a, level, msg));
        }
    }

    /// The change under way has ended: the next operation starts another.
    fn end_change(&mut self) {
        self.in_change = false;
        self.change_failed = 0;
    }

    /// When the operations counted are to be written, if there are any:
    /// [`FOLD`] after the first of them while their change goes on;
    /// otherwise [`FOLD`] after the line before, or at once after none.
    fn due(&self) -> Option<Instant> {
        let since = self.since?;
        let after = |t: Instant| t.checked_add(FOLD).unwrap_or(t);
        Some(if self.in_change {
            after(since)
        } else {
            self.last_line.map_or(since, after)
        })
    }

    /// Write the line of what was counted if it is due at `now`.
    fn flush_due(&mut self, now: Instant, out: &mut impl FnMut(Line)) {
        if self.due().is_some_and(|due| due <= now) {
            self.flush(now, out);
        }
    }

    /// Write the line of what was counted, if anything was, at `now`.
    fn flush(&mut self, now: Instant, out: &mut impl FnMut(Line)) {
        if let Some(line) = std::mem::take(&mut self.tally).summary() {
            out(line);
            self.last_line = Some(now);
            self.logged = 0;
        }
        self.since = None;
    }
}

/// The line of one operation: its kind, prefix, gateway and, when known,
/// the index of the interface the gateway is reached on (`oif`, the
/// kernel's `RTA_OIF`), `onlink=yes` for a gateway on that interface's
/// link that no route covers, and the kernel's error if it failed.
fn op_line(a: &Applied, level: Level, msg: &'static str) -> Line {
    let (op, prefix, hop) = match &a.op {
        Op::Set { prefix, hop } => ("install", prefix, hop),
        Op::Delete { prefix, hop } => ("delete", prefix, hop),
    };
    let mut fields = vec![
        ("op", op.to_owned()),
        ("prefix", prefix.to_string()),
        ("gateway", hop.gateway.to_string()),
    ];
    if let Some(oif) = hop.oif {
        fields.push(("oif", oif.to_string()));
    }
    if hop.onlink {
        fields.push(("onlink", "yes".to_owned()));
    }
    if let Err(e) = &a.result {
        fields.push(("error", e.to_string()));
    }
    Line { level, msg, fields }
}

/// What the operations of one line did.
#[derive(Debug, Default)]
struct Tally {
    /// Routes installed or replaced, or in dry-run that would be.
    install: usize,
    /// Routes removed, or in dry-run that would be.
    delete: usize,
    /// Operations that failed.
    failed: usize,
    /// Whether the operations were only reported (dry-run). A switch of
    /// mode writes the line before it, so all of them were or none.
    dry_run: bool,
    /// The first [`SAMPLE`] prefixes operated on.
    sample: Vec<Prefix>,
}

impl Tally {
    /// The operations counted.
    fn ops(&self) -> usize {
        self.install + self.delete + self.failed
    }

    /// Count `a`.
    fn add(&mut self, a: &Applied) {
        let prefix = match &a.op {
            Op::Set { prefix, .. } | Op::Delete { prefix, .. } => prefix,
        };
        if self.ops() == 0 {
            self.dry_run = a.dry_run;
        }
        if self.sample.len() < SAMPLE {
            self.sample.push(*prefix);
        }
        match (&a.result, &a.op) {
            (Err(_), _) => self.failed += 1,
            (Ok(()), Op::Set { .. }) => self.install += 1,
            (Ok(()), Op::Delete { .. }) => self.delete += 1,
        }
    }

    /// The line, or `None` if nothing was done: at error if an operation
    /// failed.
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

    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;
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

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    /// The `i`th of a run of /24s, 10.0.0.0/24 first.
    fn nth(i: usize) -> String {
        format!("10.{}.{}.0/24", i / 256, i % 256)
    }

    /// A hop through `gateway`, with no interface.
    fn gw(gateway: &str) -> Hop {
        Hop {
            gateway: ip(gateway),
            oif: None,
            onlink: false,
        }
    }

    /// The hop of [`set`] and [`delete`]: through 192.0.2.1 on interface
    /// 2.
    fn hop() -> Hop {
        Hop {
            oif: Some(2),
            ..gw("192.0.2.1")
        }
    }

    fn set(prefix: &str, dry_run: bool) -> Applied {
        Applied {
            op: Op::Set {
                prefix: p(prefix),
                hop: hop(),
            },
            result: Ok(()),
            dry_run,
            already_gone: false,
        }
    }

    fn delete(prefix: &str, dry_run: bool) -> Applied {
        Applied {
            op: Op::Delete {
                prefix: p(prefix),
                hop: hop(),
            },
            result: Ok(()),
            dry_run,
            already_gone: false,
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

    /// The value of the field `key` of `line`.
    fn field(line: &Line, key: &str) -> String {
        let (_, value) = line
            .fields
            .iter()
            .find(|(k, _)| *k == key)
            .unwrap_or_else(|| panic!("no {key} in {line:?}"));
        value.clone()
    }

    /// The number in the field `key` of `line`.
    fn count(line: &Line, key: &str) -> usize {
        field(line, key).parse().unwrap()
    }

    /// The lines of `applied`, in batches, as one change that comes alone.
    fn change_lines(batches: &[&[Applied]], debug: bool) -> Vec<Line> {
        let mut lines = Vec::new();
        let mut fold = Fold::default();
        let now = Instant::now();
        for batch in batches {
            fold.add(batch, debug, now, &mut |l| lines.push(l));
        }
        fold.end_change();
        fold.flush_due(now, &mut |l| lines.push(l));
        // Written: nothing is left to write.
        assert_eq!(fold.due(), None);
        fold.flush(now, &mut |l| lines.push(l));
        lines
    }

    /// A change that moves a table, and comes alone, is one line at info
    /// at once however many routes it moved, in however many batches: the
    /// counts by operation, the mode and the first prefixes.
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

    /// At debug every operation has a line of its own too, as it is done,
    /// with its prefix, gateway and interface, when known.
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
                 prefix=192.0.2.0/24 gateway=192.0.2.1 oif=2\n",
                "1970-01-01T00:00:00.000Z DEBUG msg=\"fib: dry-run\" op=delete \
                 prefix=198.51.100.0/24 gateway=192.0.2.1 oif=2\n",
                "1970-01-01T00:00:00.000Z INFO  msg=\"fib: changes\" mode=dry-run install=1 \
                 delete=1 failed=0 prefixes=192.0.2.0/24,198.51.100.0/24\n",
            ]
        );
        let lines = change_lines(&[&[set("192.0.2.0/24", false)]], true);
        assert_eq!(lines[0].msg, "fib: applied");
        assert_eq!(lines[1].fields[0], ("mode", "install".to_owned()));
        // A hop with no interface known has no `oif`.
        let mut op = set("192.0.2.0/24", false);
        op.op = Op::Set {
            prefix: p("192.0.2.0/24"),
            hop: gw("192.0.2.1"),
        };
        let lines = change_lines(&[&[op]], true);
        assert_eq!(
            written(&lines[..1]),
            [
                "1970-01-01T00:00:00.000Z DEBUG msg=\"fib: applied\" op=install \
              prefix=192.0.2.0/24 gateway=192.0.2.1\n"
            ]
        );
    }

    /// A delete the kernel answered `ESRCH` had nothing left to remove:
    /// the kernel removed the route itself. It has a line of its own at
    /// debug that says so, and counts as a delete, not a failure.
    #[test]
    fn a_route_already_gone_counts_as_deleted() {
        let gone = Applied {
            already_gone: true,
            ..delete("198.51.100.0/24", false)
        };
        let lines = change_lines(&[&[gone]], true);
        assert_eq!(
            written(&lines),
            [
                "1970-01-01T00:00:00.000Z DEBUG msg=\"fib: already gone\" op=delete \
                 prefix=198.51.100.0/24 gateway=192.0.2.1 oif=2\n",
                "1970-01-01T00:00:00.000Z INFO  msg=\"fib: changes\" mode=install install=0 \
                 delete=1 failed=0 prefixes=198.51.100.0/24\n",
            ]
        );
    }

    /// The first three failures of a change are at error, the others at
    /// debug, and the change's line is at error, counting them all.
    #[test]
    fn failures_are_at_error_up_to_a_bound() {
        assert_eq!(FAILURES_LOGGED, 3);
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
              prefix=10.0.0.0/24 gateway=192.0.2.1 oif=2 \
              error=\"kernel refused: Operation not permitted (os error 1)\"\n"
            ]
        );
        let summary = &written(&lines)[FAILURES_LOGGED];
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
        // The bound holds between two lines too: a change that starts
        // before the line of the one before is written has no error line
        // of its own once three were written, and is counted all the same;
        // after the line, the next change has its three again.
        let mut fold = Fold::default();
        let now = Instant::now();
        let mut errors = Vec::new();
        for _ in 0..2 {
            fold.add(&ops, false, now, &mut |l| errors.push(l));
            fold.end_change();
        }
        assert_eq!(errors.len(), FAILURES_LOGGED);
        assert!(errors.iter().all(|l| l.msg == "fib: failed"));
        fold.flush(now, &mut |l| errors.push(l));
        assert_eq!(count(&errors[FAILURES_LOGGED], "failed"), 16);
        fold.add(&ops, false, now, &mut |l| errors.push(l));
        assert_eq!(errors.len(), 2 * FAILURES_LOGGED + 1);
        assert!(
            errors[FAILURES_LOGGED + 1..]
                .iter()
                .all(|l| l.level == Level::Error && l.msg == "fib: failed")
        );
        // Under the bound between lines, a change has no more than its own
        // three: one that starts after a single error line was written
        // gets three, not more.
        let mut fold = Fold::default();
        let mut errors = Vec::new();
        fold.add(&ops[..1], false, now, &mut |l| errors.push(l));
        fold.end_change();
        fold.add(&ops, false, now, &mut |l| errors.push(l));
        assert_eq!(errors.len(), FAILURES_LOGGED);
    }

    /// Changes that keep coming get a line a second, each counting what
    /// was done since the line before; one that comes after a quiet
    /// second gets its line at once.
    #[test]
    fn changes_that_keep_coming_get_a_line_a_second() {
        let t0 = Instant::now();
        let mut fold = Fold::default();
        let mut lines = Vec::new();
        let change = |fold: &mut Fold, at: Duration, prefix: &str, lines: &mut Vec<_>| {
            let mut out = |l| lines.push((at, l));
            fold.add(&[set(prefix, true)], false, t0 + at, &mut out);
            fold.end_change();
            fold.flush_due(t0 + at, &mut out);
        };
        // The first comes alone: written at once.
        change(&mut fold, ms(0), "192.0.2.0/24", &mut lines);
        assert_eq!(lines.len(), 1);
        assert_eq!(fold.due(), None);
        // Two more within the second: folded, due a second after the
        // first line, and written then, or once the thread wakes after.
        change(&mut fold, ms(100), "198.51.100.0/24", &mut lines);
        change(&mut fold, ms(300), "203.0.113.0/24", &mut lines);
        assert_eq!(lines.len(), 1);
        assert_eq!(fold.due(), Some(t0 + ms(1000)));
        fold.flush_due(t0 + ms(999), &mut |l| lines.push((ms(999), l)));
        assert_eq!(lines.len(), 1);
        fold.flush_due(t0 + ms(1000), &mut |l| lines.push((ms(1000), l)));
        assert_eq!(lines.len(), 2);
        let (at, line) = &lines[1];
        assert_eq!(*at, ms(1000));
        assert_eq!(count(line, "install"), 2);
        assert_eq!(field(line, "prefixes"), "198.51.100.0/24,203.0.113.0/24");
        // One within a second of that line waits for the next second.
        change(&mut fold, ms(1500), "192.0.2.0/24", &mut lines);
        assert_eq!(fold.due(), Some(t0 + ms(2000)));
        fold.flush_due(t0 + ms(2000), &mut |l| lines.push((ms(2000), l)));
        // After a quiet second, one is written at once again.
        change(&mut fold, ms(5000), "192.0.2.0/24", &mut lines);
        let times: Vec<Duration> = lines.iter().map(|(at, _)| *at).collect();
        assert_eq!(times, [ms(0), ms(1000), ms(2000), ms(5000)]);
    }

    /// A change that takes longer than a second, such as one that moves a
    /// whole table, has a line a second with the counts so far, and the
    /// rest when it ends; nothing is counted twice or lost.
    #[test]
    fn a_long_change_has_a_line_a_second_with_the_counts_so_far() {
        let t0 = Instant::now();
        let mut fold = Fold::default();
        let mut lines = Vec::new();
        // A batch of 256 every 400 ms, the last at 2.4 s ending it.
        for (n, at) in (0..=6).map(|n| (n, ms(400 * n))) {
            let batch: Vec<Applied> = (0..256)
                .map(|i| set(&nth(usize::try_from(n).unwrap() * 256 + i), true))
                .collect();
            let mut out = |l| lines.push((at, l));
            fold.add(&batch, false, t0 + at, &mut out);
            if n == 6 {
                fold.end_change();
            }
            fold.flush_due(t0 + at, &mut out);
        }
        let seen: Vec<(Duration, usize)> = lines
            .iter()
            .map(|(at, l)| (*at, count(l, "install")))
            .collect();
        // Due a second after the first batch: written with the batch at
        // 1.2 s. The next due a second after the batch at 1.6 s; the end
        // of the change makes it due a second after the line at 1.2 s.
        assert_eq!(seen, [(ms(1200), 4 * 256), (ms(2400), 3 * 256)]);
        assert_eq!(fold.due(), None);
    }

    /// The message sequence the tests feed the thread: a message, or a
    /// wait with nothing coming.
    enum Step {
        Msg(FibMsg),
        Wait(Duration),
    }

    /// Run the thread over `script` in dry-run (see [`run_in`]).
    fn run(t0: Instant, script: Vec<Step>) -> Vec<(Duration, Line)> {
        run_in(Mode::DryRun, t0, script)
    }

    /// Run the thread over `script`, starting in `mode` with no socket,
    /// so that in install mode the kernel refuses every operation, on a
    /// clock of its own that starts at `t0` and moves only with the
    /// script's waits, and for as long as the thread waits for a line
    /// that is due. The lines it writes, with the time from `t0` at which
    /// it wrote them.
    fn run_in(mode: Mode, t0: Instant, script: Vec<Step>) -> Vec<(Duration, Line)> {
        let clock = Cell::new(t0);
        let script = RefCell::new(VecDeque::from(script));
        let mut recv = |deadline: Option<Instant>| loop {
            let step = script.borrow_mut().pop_front();
            match step {
                None => return Err(RecvTimeoutError::Disconnected),
                Some(Step::Msg(msg)) => return Ok(msg),
                Some(Step::Wait(d)) => {
                    let until = clock.get() + d;
                    match deadline {
                        // The thread wakes at its deadline; the rest of
                        // the wait follows.
                        Some(due) if due <= until => {
                            clock.set(due.max(clock.get()));
                            script
                                .borrow_mut()
                                .push_front(Step::Wait(until - clock.get()));
                            return Err(RecvTimeoutError::Timeout);
                        }
                        _ => clock.set(until),
                    }
                }
            }
        };
        let mut lines = Vec::new();
        serve(
            Fib::new(mode, 254, 186),
            Fold::default(),
            &mut recv,
            &|| clock.get(),
            &|| false,
            &mut |l| lines.push((clock.get() - t0, l)),
        );
        lines
    }

    fn batch(range: std::ops::Range<usize>) -> Vec<FibChange> {
        range
            .map(|i| FibChange {
                family: AddressFamily::IPV4_UNICAST,
                prefix: p(&nth(i)),
                next_hop: Some(bgpfc_rib::nexthop::Hop {
                    gateway: ip("192.0.2.1"),
                    oif: None,
                    onlink: false,
                }),
                previous: None,
            })
            .collect()
    }

    /// The RIB's hop reaches the FIB as it is: gateway, interface and
    /// `onlink`; the line of its operation says `onlink=yes` of such a
    /// gateway.
    #[test]
    fn rib_hops_reach_the_fib_with_their_interface() {
        for (oif, onlink) in [(None, false), (Some(3), false), (Some(3), true)] {
            let rib = bgpfc_rib::nexthop::Hop {
                gateway: ip("fe80::1"),
                oif,
                onlink,
            };
            assert_eq!(
                fib_hop(rib),
                Hop {
                    gateway: ip("fe80::1"),
                    oif,
                    onlink,
                }
            );
        }
        let applied = Applied {
            op: Op::Set {
                prefix: "203.0.113.0/24".parse().unwrap(),
                hop: Hop {
                    gateway: ip("192.168.77.1"),
                    oif: Some(3),
                    onlink: true,
                },
            },
            result: Ok(()),
            dry_run: false,
            already_gone: false,
        };
        assert_eq!(
            op_line(&applied, Level::Debug, "fib: applied").fields,
            [
                ("op", "install".to_owned()),
                ("prefix", "203.0.113.0/24".to_owned()),
                ("gateway", "192.168.77.1".to_owned()),
                ("oif", "3".to_owned()),
                ("onlink", "yes".to_owned()),
            ]
        );
    }

    fn changes(range: std::ops::Range<usize>, more: bool) -> Step {
        Step::Msg(FibMsg::Changes {
            changes: batch(range),
            more,
        })
    }

    /// The thread writes a line at once for a change that comes alone,
    /// once the RIB's last batch of it is in, whatever the control thread
    /// asked in between; folds those that follow within a second, and
    /// wakes to write them when nothing else comes; writes what it
    /// counted before a switch of mode, and at shutdown.
    #[test]
    fn the_thread_folds_its_lines_by_time() {
        let (mode_tx, mode_rx) = sync_channel(1);
        let (end_tx, end_rx) = sync_channel(1);
        let (done_tx, done_rx) = sync_channel(1);
        let lines = run(
            Instant::now(),
            vec![
                // An input of two full batches and a closing empty one,
                // with a query of the control thread between them.
                changes(0..256, true),
                Step::Msg(FibMsg::Mode(mode_tx)),
                changes(256..512, true),
                changes(0..0, false),
                // Two inputs of a few routes within the next second.
                Step::Wait(ms(100)),
                changes(512..513, false),
                Step::Wait(ms(200)),
                changes(513..515, false),
                // Nothing for two seconds: the thread wakes at 1 s.
                Step::Wait(ms(2000)),
                // A switch to install at 2.3 s: with no socket, every
                // operation of its reconcile fails.
                Step::Msg(FibMsg::SetMode(Mode::Install)),
                Step::Msg(FibMsg::Reconcile(vec![(
                    p("192.0.2.0/24"),
                    gw("192.0.2.1"),
                )])),
                Step::Msg(FibMsg::ReconcileEnd(end_tx)),
                // Half an input, then the shutdown, before its line is due.
                changes(600..610, true),
                Step::Wait(ms(500)),
                Step::Msg(FibMsg::Shutdown(done_tx)),
            ],
        );
        assert_eq!(mode_rx.try_recv().unwrap(), Mode::DryRun);
        assert_eq!(end_rx.try_recv().unwrap(), 1);
        assert!(done_rx.try_recv().is_ok());
        let summaries: Vec<_> = lines
            .iter()
            .filter(|(_, l)| l.msg == CHANGES)
            .map(|(at, l)| {
                (
                    *at,
                    field(l, "mode"),
                    count(l, "install"),
                    count(l, "failed"),
                )
            })
            .collect();
        let line = |at, mode: &str, install, failed| (ms(at), mode.to_owned(), install, failed);
        assert_eq!(
            summaries,
            [
                line(0, "dry-run", 512, 0),
                line(1000, "dry-run", 3, 0),
                line(2300, "install", 0, 1),
                line(2800, "install", 0, 10),
            ]
        );
        // The mode line comes before the switch's error line, which is
        // written at once; of the ten failures of the half input, the
        // first three are, at once too.
        let at = |msg: &str| -> Vec<Duration> {
            lines
                .iter()
                .filter(|(_, l)| l.msg == msg)
                .map(|(at, _)| *at)
                .collect()
        };
        assert_eq!(at("fib: mode"), [ms(2300)]);
        assert_eq!(at("fib: failed"), [ms(2300); 4]);
        let mode = lines
            .iter()
            .position(|(_, l)| l.msg == "fib: mode")
            .unwrap();
        assert_eq!(lines[mode + 1].1.msg, "fib: failed");
    }

    /// While changes keep coming, a line a second at most, each at least
    /// a second after the one before; the last within a second of the
    /// last change; and every operation counted once.
    #[test]
    fn a_stream_of_changes_is_a_line_a_second() {
        let mut script = Vec::new();
        for i in 0..1000 {
            script.push(changes(i..i + 1, false));
            script.push(Step::Wait(ms(10)));
        }
        script.push(Step::Wait(ms(5000)));
        let lines = run(Instant::now(), script);
        let times: Vec<Duration> = lines.iter().map(|(at, _)| *at).collect();
        assert_eq!(times.len(), 11, "{times:?}");
        assert!(
            times.windows(2).all(|w| w[1].saturating_sub(w[0]) >= FOLD),
            "{times:?}"
        );
        // The last change came at 9.99 s.
        assert!(times[10] <= ms(9990) + FOLD, "{times:?}");
        let total: usize = lines.iter().map(|(_, l)| count(l, "install")).sum();
        assert_eq!(total, 1000);
    }

    /// A table the kernel refuses route by route as it loads from a
    /// peer, a change an UPDATE: three error lines between two
    /// `fib: changes` lines at most, so a few a second rather than one a
    /// route, and every failure counted on those lines.
    #[test]
    fn a_refused_table_costs_three_error_lines_a_second() {
        // A thousand single-route UPDATEs within a second, then a thousand
        // more over ten seconds.
        let mut script = Vec::new();
        for i in 0..1000 {
            script.push(changes(i..i + 1, false));
            script.push(Step::Wait(ms(1)));
        }
        for i in 1000..2000 {
            script.push(changes(i..i + 1, false));
            script.push(Step::Wait(ms(10)));
        }
        script.push(Step::Wait(ms(5000)));
        let lines = run_in(Mode::Install, Instant::now(), script);
        assert!(
            lines
                .iter()
                .all(|(_, l)| l.level == Level::Error && [CHANGES, "fib: failed"].contains(&l.msg)),
            "{lines:?}"
        );
        // Between two lines, and before the first, three at most.
        let mut errors = 0;
        let mut summaries = Vec::new();
        for (at, l) in &lines {
            if l.msg == CHANGES {
                summaries.push((*at, count(l, "failed")));
                errors = 0;
            } else {
                errors += 1;
                assert!(errors <= FAILURES_LOGGED, "{lines:?}");
            }
        }
        // The first second: the first UPDATE's error and line at once,
        // three errors more, and the line that counts the rest.
        let second = lines
            .iter()
            .filter(|(_, l)| l.msg == CHANGES)
            .nth(1)
            .map(|(at, _)| *at);
        assert_eq!(second, Some(FOLD));
        let first = lines.iter().take_while(|(at, _)| *at < FOLD).count();
        assert_eq!(first, 1 + 1 + FAILURES_LOGGED, "{lines:?}");
        assert_eq!(summaries[..2], [(ms(0), 1), (FOLD, 999)]);
        // Then a line a second, eleven seconds in all, with three errors
        // at most each.
        assert_eq!(summaries.len(), 12, "{summaries:?}");
        let errors = lines.len() - summaries.len();
        assert!(errors <= FAILURES_LOGGED * summaries.len(), "{errors}");
        let failed: usize = summaries.iter().map(|(_, n)| n).sum();
        assert_eq!(failed, 2000);
    }

    /// Every sender gone: what was counted is written before the thread
    /// ends.
    #[test]
    fn nothing_counted_is_lost_when_the_senders_go() {
        let lines = run(
            Instant::now(),
            vec![changes(0..1, false), changes(1..3, false)],
        );
        let installs: Vec<usize> = lines.iter().map(|(_, l)| count(l, "install")).collect();
        assert_eq!(installs, [1, 2]);
    }
}

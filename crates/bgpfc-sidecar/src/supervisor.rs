//! The supervision state machine. Pure: `(state, event, now) -> (state,
//! actions)`. It never reads the clock, spawns or signals anything; the
//! I/O shell in bgpfcd feeds it what happened and carries out the actions
//! it returns.
//!
//! Implements: no RFC. The rules come from issue #70: a crashed validator
//! is restarted with backoff, repeated failure raises an alarm instead of
//! giving up, and a requested shutdown never leads to a restart.

use std::io;
use std::net::SocketAddr;
use std::process::ExitStatus;
use std::time::{Duration, Instant};

use bgpfc_log::Level;
use bgpfc_sys::ChildSignal;

use crate::backoff::Backoff;
use crate::config::SidecarConfig;
use crate::status::{ExitReason, SidecarState, SidecarStatus};

/// Something that happened, fed to [`Supervisor::step`].
#[derive(Debug)]
pub enum Event {
    /// Start the sidecar: from [`SidecarState::Stopped`], spawn it; while
    /// it waits to be restarted, retry now instead of at the deadline.
    /// Nothing changes while it starts or runs, and a start requested
    /// while it stops is refused (issue #70).
    StartRequested,
    /// The child asked for by [`Action::Spawn`] started, with this process
    /// id.
    Spawned(u32),
    /// The child asked for by [`Action::Spawn`] could not be started.
    SpawnFailed(io::Error),
    /// The child exited and has been reaped. Feed this as soon as the
    /// child is reaped and before any other event: from then on its
    /// process id may belong to another process, and the supervisor must
    /// learn that before it asks for a signal to be sent to it.
    Exited(ExitStatus),
    /// Stop the sidecar and do not restart it, as on daemon shutdown or
    /// when a reload disables it.
    StopRequested,
    /// Nothing happened but time passed: the wait for
    /// [`Supervisor::next_deadline`] ran out. Every step also checks the
    /// deadlines, so this is only needed when there is no other event.
    Tick,
}

/// A `key=value` field on a log line, in the order logged.
pub type LogField = (&'static str, String);

/// What the I/O shell must do, in order, after a step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Spawn Routinator: the configured binary with
    /// [`routinator_args`](crate::routinator_args), under
    /// [`set_parent_death_signal`](bgpfc_sys::set_parent_death_signal),
    /// from the long-lived supervisor thread. Report the outcome with
    /// [`Event::Spawned`] or [`Event::SpawnFailed`].
    Spawn,
    /// Send `SIGTERM` to this process: ask the child to stop.
    SendTerm(u32),
    /// Send `SIGKILL` to this process: the child did not stop within the
    /// stop timeout.
    Kill(u32),
    /// Log this message with these fields, via [`bgpfc_log::log`].
    Log(Level, &'static str, Vec<LogField>),
    /// [`Supervisor::status`] changed; publish it to the control plane.
    /// Always the last action of a step.
    StatusChanged,
}

impl Action {
    /// For [`Action::SendTerm`] and [`Action::Kill`], the process and the
    /// signal to pass to [`bgpfc_sys::send_signal`].
    #[must_use]
    pub const fn signal(&self) -> Option<(u32, ChildSignal)> {
        match *self {
            Action::SendTerm(pid) => Some((pid, ChildSignal::Term)),
            Action::Kill(pid) => Some((pid, ChildSignal::Kill)),
            Action::Spawn | Action::Log(..) | Action::StatusChanged => None,
        }
    }
}

/// Where supervision stands. [`SidecarState`] is the public view of it,
/// with the waiting phase split by the failure threshold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Stopped,
    Starting,
    Running {
        pid: u32,
        since: Instant,
    },
    /// The child failed; the next attempt starts at `until`.
    Waiting {
        until: Instant,
    },
    /// A stop was requested. `pid` is `None` until a spawn already asked
    /// for is reported. `kill_at` is when `SIGTERM` escalates to
    /// `SIGKILL`, and `None` before `SIGTERM` was sent or after `SIGKILL`
    /// was.
    Stopping {
        pid: Option<u32>,
        kill_at: Option<Instant>,
    },
}

/// Supervises one Routinator child with injected time.
///
/// The I/O shell runs it from one long-lived thread, the one that spawns
/// the child (the parent-death signal follows the spawning thread):
///
/// ```text
/// loop {
///     timeout = next_deadline() - now, or forever
///     event   = a start or stop request, a spawn result or a child exit,
///               or Event::Tick when the timeout runs out
///     for action in step(event, now) { carry it out }
/// }
/// ```
///
/// - A child that exits on its own is a failure, whatever its status:
///   `routinator server` runs until it is told to stop. It is restarted
///   after a [`Backoff`] delay. The failure count and the backoff reset
///   once a child has stayed up for the stable period.
/// - From the failure threshold on, the state is
///   [`SidecarState::Failed`], an alarm, and retries continue at the
///   backoff cap; it never gives up.
/// - [`Event::StopRequested`] sends `SIGTERM`, escalates to `SIGKILL`
///   after the stop timeout and ends in [`SidecarState::Stopped`]. An exit
///   while stopping is not a failure, and nothing is restarted during or
///   after a requested stop until the next [`Event::StartRequested`]
///   (issue #70). A start requested while stopping is refused.
///
/// Keep the supervisor in charge of stopping: if the service manager
/// signals every process of the service at once (systemd's default
/// `KillMode=control-group`), the child can exit before bgpfcd sees its
/// own `SIGTERM`, and that exit looks like a crash. `KillMode=mixed` sends
/// `SIGTERM` to bgpfcd alone.
///
/// ```
/// use std::time::Instant;
/// use bgpfc_sidecar::{Action, Event, SidecarConfig, SidecarState, Supervisor};
///
/// let config = SidecarConfig::new("/usr/bin/routinator", "/var/lib/bgpfc/rpki");
/// let rtr = "127.0.0.1:3323".parse().unwrap();
/// let mut sup = Supervisor::new(&config, rtr, 0x5eed);
/// let now = Instant::now();
/// let actions = sup.step(Event::StartRequested, now);
/// assert!(actions.contains(&Action::Spawn));
/// let _ = sup.step(Event::Spawned(4242), now);
/// assert_eq!(sup.state(), SidecarState::Running { pid: 4242, since: now });
/// let actions = sup.step(Event::StopRequested, now);
/// assert!(actions.contains(&Action::SendTerm(4242)));
/// ```
#[derive(Clone, Debug)]
pub struct Supervisor {
    phase: Phase,
    backoff: Backoff,
    stop_timeout: Duration,
    threshold: u32,
    failures: u32,
    restarts: u64,
    last_exit: Option<ExitReason>,
    rtr: SocketAddr,
}

impl Supervisor {
    /// A stopped supervisor for `config`, checked with
    /// [`SidecarConfig::validate`], whose child serves RTR on `rtr`:
    /// the configured address with a port 0 already replaced by the port
    /// bgpfcd picked. `seed` seeds the backoff jitter; give each process a
    /// different one, such as its process id mixed with the time, and
    /// zero for none.
    #[must_use]
    pub fn new(config: &SidecarConfig, rtr: SocketAddr, seed: u64) -> Supervisor {
        Supervisor {
            phase: Phase::Stopped,
            backoff: Backoff::new(config.backoff, seed),
            stop_timeout: config.stop_timeout,
            threshold: config.failure_threshold,
            failures: 0,
            restarts: 0,
            last_exit: None,
            rtr,
        }
    }

    /// Where supervision stands.
    #[must_use]
    pub fn state(&self) -> SidecarState {
        match self.phase {
            Phase::Stopped => SidecarState::Stopped,
            Phase::Starting => SidecarState::Starting,
            Phase::Running { pid, since } => SidecarState::Running { pid, since },
            Phase::Waiting { until } if self.failing() => SidecarState::Failed {
                until,
                failures: self.failures,
            },
            Phase::Waiting { until } => SidecarState::BackingOff {
                until,
                failures: self.failures,
            },
            Phase::Stopping { pid, .. } => SidecarState::ShuttingDown { pid },
        }
    }

    /// A snapshot for the control plane.
    #[must_use]
    pub fn status(&self) -> SidecarStatus {
        let pid = match self.phase {
            Phase::Running { pid, .. } => Some(pid),
            Phase::Stopping { pid, .. } => pid,
            Phase::Stopped | Phase::Starting | Phase::Waiting { .. } => None,
        };
        SidecarStatus {
            state: self.state(),
            pid,
            restarts: self.restarts,
            consecutive_failures: self.failures,
            last_exit: self.last_exit.clone(),
            rtr: self.rtr,
        }
    }

    /// The earliest moment at which time alone changes something: a
    /// restart, a `SIGKILL` escalation, or a running child becoming
    /// stable. Wait no longer than this before stepping again; `None`
    /// means wait for an event.
    #[must_use]
    pub fn next_deadline(&self) -> Option<Instant> {
        match self.phase {
            Phase::Running { since, .. } if self.failures > 0 => Some(self.stable_at(since)),
            Phase::Waiting { until } => Some(until),
            Phase::Stopping { kill_at, .. } => kill_at,
            Phase::Stopped | Phase::Starting | Phase::Running { .. } => None,
        }
    }

    /// Apply `event` at `now`, then whatever deadlines `now` has reached,
    /// and return the actions to carry out in order. Handling the event
    /// first means an exit reported together with an expired stop timeout
    /// does not lead to a `SIGKILL` for a reaped process id, and a stop
    /// reported together with an expired backoff does not lead to a
    /// restart.
    #[must_use = "the actions must be carried out"]
    pub fn step(&mut self, event: Event, now: Instant) -> Vec<Action> {
        let before = self.status();
        let mut out = Vec::new();
        self.on_event(event, now, &mut out);
        self.on_time(now, &mut out);
        if self.status() != before {
            out.push(Action::StatusChanged);
        }
        out
    }

    fn on_event(&mut self, event: Event, now: Instant, out: &mut Vec<Action>) {
        match (self.phase, event) {
            // Nothing to do: deadlines are handled after the event, and a
            // start or stop already under way is not repeated.
            (_, Event::Tick)
            | (Phase::Starting | Phase::Running { .. }, Event::StartRequested)
            | (Phase::Stopped | Phase::Stopping { .. }, Event::StopRequested) => {}
            (Phase::Stopped, Event::StartRequested) => {
                log(out, Level::Info, "starting the RPKI sidecar", Vec::new());
                self.spawn(out);
            }
            (Phase::Waiting { .. }, Event::StartRequested) => {
                self.restarts = self.restarts.saturating_add(1);
                let fields = vec![("failures", self.failures.to_string())];
                log(
                    out,
                    Level::Info,
                    "restarting the RPKI sidecar on request",
                    fields,
                );
                self.spawn(out);
            }
            (Phase::Stopping { pid, .. }, Event::StartRequested) => {
                // Issue #70: a stop in progress is never turned into a
                // restart. Ask again once the sidecar is stopped.
                log(
                    out,
                    Level::Warn,
                    "ignoring a start request while the RPKI sidecar stops",
                    pid_field(pid),
                );
            }
            (Phase::Starting, Event::Spawned(pid)) => {
                self.phase = Phase::Running { pid, since: now };
                let fields = vec![("pid", pid.to_string()), ("rtr", self.rtr.to_string())];
                log(out, Level::Info, "RPKI sidecar started", fields);
            }
            (Phase::Starting, Event::SpawnFailed(error)) => {
                self.failed(ExitReason::SpawnFailed(error.to_string()), None, now, out);
            }
            (Phase::Running { pid, since }, Event::Exited(status)) => {
                let uptime = now.saturating_duration_since(since);
                self.failed(ExitReason::from(status), Some((pid, uptime)), now, out);
            }
            (Phase::Stopping { pid: None, .. }, Event::Spawned(pid)) => {
                // The stop came while the spawn was under way.
                self.send_term(pid, now, out);
            }
            (Phase::Stopping { pid: None, .. }, Event::SpawnFailed(error)) => {
                self.stopped(Some(ExitReason::SpawnFailed(error.to_string())), out);
            }
            (Phase::Stopping { pid: Some(_), .. }, Event::Exited(status)) => {
                // Not a failure: the stop asked for it.
                self.stopped(Some(ExitReason::from(status)), out);
            }
            (Phase::Running { pid, .. }, Event::StopRequested) => {
                self.send_term(pid, now, out);
            }
            (Phase::Starting, Event::StopRequested) => {
                // Nothing to signal until the spawn is reported.
                self.phase = Phase::Stopping {
                    pid: None,
                    kill_at: None,
                };
                log(
                    out,
                    Level::Info,
                    "stopping the RPKI sidecar once it has started",
                    Vec::new(),
                );
            }
            (Phase::Waiting { .. }, Event::StopRequested) => self.stopped(None, out),
            (_, event) => self.unexpected(&event, out),
        }
    }

    /// Act on the deadlines `now` has reached.
    fn on_time(&mut self, now: Instant, out: &mut Vec<Action>) {
        match self.phase {
            Phase::Running { pid, since } if self.failures > 0 && now >= self.stable_at(since) => {
                self.failures = 0;
                self.backoff.reset();
                let fields = vec![
                    ("pid", pid.to_string()),
                    ("uptime", seconds(now.saturating_duration_since(since))),
                ];
                log(out, Level::Info, "RPKI sidecar is stable again", fields);
            }
            Phase::Waiting { until } if now >= until => {
                self.restarts = self.restarts.saturating_add(1);
                let fields = vec![("failures", self.failures.to_string())];
                log(out, Level::Info, "restarting the RPKI sidecar", fields);
                self.spawn(out);
            }
            Phase::Stopping {
                pid: Some(pid),
                kill_at: Some(at),
            } if now >= at => {
                self.phase = Phase::Stopping {
                    pid: Some(pid),
                    kill_at: None,
                };
                let fields = vec![
                    ("pid", pid.to_string()),
                    ("timeout", seconds(self.stop_timeout)),
                ];
                log(
                    out,
                    Level::Warn,
                    "RPKI sidecar did not stop in time; killing it",
                    fields,
                );
                out.push(Action::Kill(pid));
            }
            _ => {}
        }
    }

    /// The child exited on its own (`run` is its pid and uptime) or could
    /// not be started: count the failure and schedule the next attempt.
    fn failed(
        &mut self,
        reason: ExitReason,
        run: Option<(u32, Duration)>,
        now: Instant,
        out: &mut Vec<Action>,
    ) {
        // The step that saw the stable deadline pass has normally reset
        // the count already; this covers an exit reported in that step.
        if run.is_some_and(|(_, uptime)| self.backoff.record_uptime(uptime)) {
            self.failures = 0;
        }
        self.failures = self.failures.saturating_add(1);
        let delay = if self.failing() {
            self.backoff.cap_delay()
        } else {
            self.backoff.next_delay()
        };
        self.phase = Phase::Waiting {
            until: later(now, delay),
        };
        let mut fields = Vec::with_capacity(5);
        if let Some((pid, _)) = run {
            fields.push(("pid", pid.to_string()));
        }
        fields.push(("exit", reason.to_string()));
        if let Some((_, uptime)) = run {
            fields.push(("uptime", seconds(uptime)));
        }
        fields.push(("failures", self.failures.to_string()));
        fields.push(("retry_in", seconds(delay)));
        if self.failing() {
            log(
                out,
                Level::Error,
                "RPKI sidecar keeps failing; the validator is not running, retrying at the backoff cap",
                fields,
            );
        } else {
            log(
                out,
                Level::Warn,
                "RPKI sidecar failed; restarting after a backoff",
                fields,
            );
        }
        self.last_exit = Some(reason);
    }

    fn spawn(&mut self, out: &mut Vec<Action>) {
        self.phase = Phase::Starting;
        out.push(Action::Spawn);
    }

    fn send_term(&mut self, pid: u32, now: Instant, out: &mut Vec<Action>) {
        self.phase = Phase::Stopping {
            pid: Some(pid),
            kill_at: Some(later(now, self.stop_timeout)),
        };
        log(
            out,
            Level::Info,
            "stopping the RPKI sidecar",
            vec![("pid", pid.to_string())],
        );
        out.push(Action::SendTerm(pid));
    }

    /// A requested stop is complete; `exit` is how the child ended, if
    /// there was one. The next start begins afresh.
    fn stopped(&mut self, exit: Option<ExitReason>, out: &mut Vec<Action>) {
        self.phase = Phase::Stopped;
        self.failures = 0;
        self.backoff.reset();
        let mut fields = Vec::new();
        if let Some(reason) = exit {
            fields.push(("exit", reason.to_string()));
            self.last_exit = Some(reason);
        }
        log(out, Level::Info, "RPKI sidecar stopped", fields);
    }

    /// An event the current phase cannot produce, such as an exit with no
    /// child: a bug in the I/O shell. Nothing changes.
    fn unexpected(&self, event: &Event, out: &mut Vec<Action>) {
        let mut fields = vec![
            ("event", event_name(event).to_owned()),
            ("state", self.state().name().to_owned()),
        ];
        if let Event::Spawned(pid) = event {
            // A child nobody supervises: name it so it can be found.
            fields.push(("pid", pid.to_string()));
        }
        log(
            out,
            Level::Warn,
            "ignoring an unexpected RPKI sidecar event",
            fields,
        );
    }

    /// Whether the failure count has reached the alarm threshold.
    const fn failing(&self) -> bool {
        self.failures >= self.threshold
    }

    fn stable_at(&self, since: Instant) -> Instant {
        later(since, self.backoff.config().stable)
    }
}

/// `now + delay`. A validated config bounds every delay to a day, which
/// cannot overflow an `Instant`; the fallback only keeps the supervisor
/// total for an unvalidated one.
fn later(now: Instant, delay: Duration) -> Instant {
    now.checked_add(delay).unwrap_or(now)
}

fn log(out: &mut Vec<Action>, level: Level, msg: &'static str, fields: Vec<LogField>) {
    out.push(Action::Log(level, msg, fields));
}

fn pid_field(pid: Option<u32>) -> Vec<LogField> {
    pid.iter().map(|pid| ("pid", pid.to_string())).collect()
}

const fn event_name(event: &Event) -> &'static str {
    match event {
        Event::StartRequested => "start-requested",
        Event::Spawned(_) => "spawned",
        Event::SpawnFailed(_) => "spawn-failed",
        Event::Exited(_) => "exited",
        Event::StopRequested => "stop-requested",
        Event::Tick => "tick",
    }
}

/// A duration as seconds for a log field: `5s`, or `0.250s` with
/// millisecond precision.
fn seconds(d: Duration) -> String {
    match d.subsec_millis() {
        0 => format!("{}s", d.as_secs()),
        ms => format!("{}.{ms:03}s", d.as_secs()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backoff::BackoffConfig;
    use std::os::unix::process::ExitStatusExt;

    const PID: u32 = 7;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    fn rtr() -> SocketAddr {
        "127.0.0.1:3323".parse().unwrap()
    }

    /// A 1 s initial backoff doubling to a 60 s cap, stable after 30 s,
    /// and a 10 s stop timeout.
    fn config(threshold: u32) -> SidecarConfig {
        let mut c = SidecarConfig::new("/usr/bin/routinator", "/var/lib/bgpfc/rpki");
        c.backoff = BackoffConfig {
            initial: Duration::from_secs(1),
            cap: Duration::from_secs(60),
            stable: Duration::from_secs(30),
        };
        c.stop_timeout = Duration::from_secs(10);
        c.failure_threshold = threshold;
        c
    }

    /// Events for scripts: `Copy`, unlike [`Event`], so they fit tables.
    #[derive(Clone, Copy, Debug)]
    enum Ev {
        Start,
        Spawned(u32),
        SpawnFailed,
        /// Exited with this code.
        Exit(i32),
        /// Ended by this signal.
        Killed(i32),
        Stop,
        Tick,
    }

    impl Ev {
        fn event(self) -> Event {
            match self {
                Ev::Start => Event::StartRequested,
                Ev::Spawned(pid) => Event::Spawned(pid),
                Ev::SpawnFailed => Event::SpawnFailed(io::ErrorKind::NotFound.into()),
                Ev::Exit(code) => Event::Exited(ExitStatus::from_raw(code << 8)),
                Ev::Killed(signal) => Event::Exited(ExitStatus::from_raw(signal)),
                Ev::Stop => Event::StopRequested,
                Ev::Tick => Event::Tick,
            }
        }
    }

    /// An action in short form: `spawn`, `term 7`, `kill 7`, `status`, or
    /// the level of a log line.
    fn short(action: &Action) -> String {
        match action {
            Action::Spawn => "spawn".to_owned(),
            Action::SendTerm(pid) => format!("term {pid}"),
            Action::Kill(pid) => format!("kill {pid}"),
            Action::Log(level, ..) => level.to_string().to_lowercase(),
            Action::StatusChanged => "status".to_owned(),
        }
    }

    /// A supervisor driven by a script, with time in milliseconds from
    /// `t0`.
    struct Run {
        sup: Supervisor,
        t0: Instant,
    }

    /// A scripted step: at this many milliseconds, this event gives these
    /// actions and leaves this state.
    type Step<'a> = (u64, Ev, &'a [&'a str], &'a str);

    /// A script that brings a supervisor into the state a case starts in.
    type Setup = fn() -> Run;

    /// A stop case: its name, where it starts and its script.
    type StopCase<'a> = (&'a str, Setup, &'a [Step<'a>]);

    impl Run {
        fn new(threshold: u32) -> Run {
            Run {
                sup: Supervisor::new(&config(threshold), rtr(), 0),
                t0: Instant::now(),
            }
        }

        fn new_default() -> Run {
            Run::new(5)
        }

        fn at(&self, millis: u64) -> Instant {
            self.t0 + ms(millis)
        }

        fn step(&mut self, millis: u64, ev: Ev) -> Vec<Action> {
            let now = self.at(millis);
            self.sup.step(ev.event(), now)
        }

        /// The state, with times in milliseconds from `t0`.
        fn state(&self) -> String {
            let rel = |t: Instant| t.duration_since(self.t0).as_millis();
            match self.sup.state() {
                SidecarState::Stopped => "stopped".to_owned(),
                SidecarState::Starting => "starting".to_owned(),
                SidecarState::Running { pid, since } => {
                    format!("running {pid} since {}", rel(since))
                }
                SidecarState::BackingOff { until, failures } => {
                    format!("backing-off {failures} until {}", rel(until))
                }
                SidecarState::Failed { until, failures } => {
                    format!("failed {failures} until {}", rel(until))
                }
                SidecarState::ShuttingDown { pid: Some(pid) } => format!("shutting-down {pid}"),
                SidecarState::ShuttingDown { pid: None } => "shutting-down".to_owned(),
            }
        }

        fn expect(&mut self, millis: u64, ev: Ev, actions: &[&str], state: &str) {
            let got: Vec<String> = self.step(millis, ev).iter().map(short).collect();
            assert_eq!(got, actions, "{ev:?} at {millis} ms");
            assert_eq!(self.state(), state, "{ev:?} at {millis} ms");
        }

        fn script(&mut self, steps: &[Step<'_>]) {
            for &(millis, ev, actions, state) in steps {
                self.expect(millis, ev, actions, state);
            }
        }

        fn deadline(&self) -> Option<u128> {
            self.sup
                .next_deadline()
                .map(|t| t.duration_since(self.t0).as_millis())
        }
    }

    // Scripts that bring a supervisor into each state at time 0 or 100.

    fn starting() -> Run {
        let mut r = Run::new(5);
        r.expect(0, Ev::Start, &["info", "spawn", "status"], "starting");
        r
    }

    fn running() -> Run {
        let mut r = starting();
        r.expect(
            0,
            Ev::Spawned(PID),
            &["info", "status"],
            "running 7 since 0",
        );
        r
    }

    fn backing_off() -> Run {
        let mut r = running();
        r.expect(
            100,
            Ev::Exit(1),
            &["warn", "status"],
            "backing-off 1 until 1100",
        );
        r
    }

    fn failed() -> Run {
        let mut r = Run::new(1);
        r.script(&[
            (0, Ev::Start, &["info", "spawn", "status"], "starting"),
            (
                0,
                Ev::Spawned(PID),
                &["info", "status"],
                "running 7 since 0",
            ),
            (
                100,
                Ev::Exit(1),
                &["error", "status"],
                "failed 1 until 60100",
            ),
        ]);
        r
    }

    fn shutting_down() -> Run {
        let mut r = running();
        r.expect(
            100,
            Ev::Stop,
            &["info", "term 7", "status"],
            "shutting-down 7",
        );
        r
    }

    fn shutting_down_before_spawn() -> Run {
        let mut r = starting();
        r.expect(0, Ev::Stop, &["info", "status"], "shutting-down");
        r
    }

    #[test]
    fn starts_runs_and_stops() {
        let mut r = Run::new(5);
        r.script(&[
            (0, Ev::Tick, &[], "stopped"),
            (0, Ev::Start, &["info", "spawn", "status"], "starting"),
            (0, Ev::Start, &[], "starting"),
            (
                5,
                Ev::Spawned(PID),
                &["info", "status"],
                "running 7 since 5",
            ),
            (1000, Ev::Tick, &[], "running 7 since 5"),
            (1000, Ev::Start, &[], "running 7 since 5"),
            (
                2000,
                Ev::Stop,
                &["info", "term 7", "status"],
                "shutting-down 7",
            ),
            (2000, Ev::Stop, &[], "shutting-down 7"),
            (2500, Ev::Killed(15), &["info", "status"], "stopped"),
            (2500, Ev::Stop, &[], "stopped"),
            (86_400_000, Ev::Tick, &[], "stopped"),
        ]);
        assert_eq!(r.deadline(), None);
        assert_eq!(
            r.sup.status(),
            SidecarStatus {
                state: SidecarState::Stopped,
                pid: None,
                restarts: 0,
                consecutive_failures: 0,
                last_exit: Some(ExitReason::Signal {
                    number: 15,
                    core_dumped: false,
                }),
                rtr: rtr(),
            }
        );
        // A later start begins afresh.
        r.expect(
            90_000_000,
            Ev::Start,
            &["info", "spawn", "status"],
            "starting",
        );
    }

    #[test]
    fn backoff_grows_to_the_cap() {
        // A threshold out of reach, so the delays alone are under test.
        let mut r = starting();
        r.sup.threshold = 100;
        let mut now = 0;
        for (i, delay) in [1, 2, 4, 8, 16, 32, 60, 60, 60].into_iter().enumerate() {
            let failures = i + 1;
            r.expect(
                now,
                Ev::Spawned(PID),
                &["info", "status"],
                &format!("running 7 since {now}"),
            );
            now += 100;
            let until = now + delay * 1000;
            let waiting = format!("backing-off {failures} until {until}");
            r.expect(now, Ev::Exit(1), &["warn", "status"], &waiting);
            assert_eq!(r.deadline(), Some(u128::from(until)));
            r.expect(until - 1, Ev::Tick, &[], &waiting);
            now = until;
            r.expect(now, Ev::Tick, &["info", "spawn", "status"], "starting");
            assert_eq!(r.sup.status().restarts, u64::try_from(failures).unwrap());
        }
    }

    #[test]
    fn jitter_only_shortens_the_delay() {
        let mut c = config(5);
        c.backoff.initial = Duration::from_secs(8);
        for seed in 1..50 {
            let mut sup = Supervisor::new(&c, rtr(), seed);
            let t0 = Instant::now();
            let _ = sup.step(Event::StartRequested, t0);
            let _ = sup.step(Event::SpawnFailed(io::ErrorKind::NotFound.into()), t0);
            let Some(until) = sup.next_deadline() else {
                panic!("no restart scheduled");
            };
            let delay = until - t0;
            assert!(delay >= ms(4000) && delay <= ms(8000), "{delay:?}");
        }
    }

    /// Failures alternate between spawn failures and exits; both count.
    #[test]
    fn fails_after_threshold_consecutive_failures_and_keeps_retrying() {
        for threshold in [1, 3, 5] {
            let mut r = Run::new(threshold);
            r.expect(0, Ev::Start, &["info", "spawn", "status"], "starting");
            let mut now = 0;
            let mut nominal = 1000;
            for failures in 1..=8 {
                let actions = if failures % 2 == 1 {
                    r.step(now, Ev::SpawnFailed)
                } else {
                    let _ = r.step(now, Ev::Spawned(PID));
                    now += 100;
                    r.step(now, Ev::Exit(1))
                };
                let alarm = failures >= threshold;
                let (level, delay, state) = if alarm {
                    ("error", 60_000, "failed")
                } else {
                    let d = nominal;
                    nominal *= 2;
                    ("warn", d, "backing-off")
                };
                let until = now + delay;
                let got: Vec<String> = actions.iter().map(short).collect();
                assert_eq!(got, [level, "status"], "threshold {threshold}, {failures}");
                assert_eq!(
                    r.state(),
                    format!("{state} {failures} until {until}"),
                    "threshold {threshold}"
                );
                assert_eq!(r.sup.status().consecutive_failures, failures);
                // It never gives up: the retry comes at the deadline.
                now = until;
                r.expect(now, Ev::Tick, &["info", "spawn", "status"], "starting");
            }
        }
    }

    #[test]
    fn the_alarm_stays_raised_during_short_retries() {
        let mut r = failed();
        r.script(&[
            (60_100, Ev::Tick, &["info", "spawn", "status"], "starting"),
            (
                60_100,
                Ev::Spawned(8),
                &["info", "status"],
                "running 8 since 60100",
            ),
        ]);
        // Running again, but not yet for the stable period.
        assert_eq!(r.sup.status().consecutive_failures, 1);
        r.expect(
            60_200,
            Ev::Exit(1),
            &["error", "status"],
            "failed 2 until 120200",
        );
    }

    #[test]
    fn a_stable_child_resets_failures_and_backoff() {
        // Three failures (1 s, 2 s, 4 s), then a run that starts at 7.4 s.
        let three_failures = || {
            let mut r = backing_off();
            r.script(&[
                (1100, Ev::Tick, &["info", "spawn", "status"], "starting"),
                (
                    1100,
                    Ev::SpawnFailed,
                    &["warn", "status"],
                    "backing-off 2 until 3100",
                ),
                (3100, Ev::Tick, &["info", "spawn", "status"], "starting"),
                (
                    3100,
                    Ev::SpawnFailed,
                    &["warn", "status"],
                    "backing-off 3 until 7100",
                ),
                (7100, Ev::Tick, &["info", "spawn", "status"], "starting"),
                (
                    7400,
                    Ev::Spawned(8),
                    &["info", "status"],
                    "running 8 since 7400",
                ),
            ]);
            r
        };

        // Time alone resets the count once the child is stable.
        let mut r = three_failures();
        assert_eq!(r.deadline(), Some(37_400));
        r.expect(37_399, Ev::Tick, &[], "running 8 since 7400");
        assert_eq!(r.sup.status().consecutive_failures, 3);
        r.expect(
            37_400,
            Ev::Tick,
            &["info", "status"],
            "running 8 since 7400",
        );
        assert_eq!(r.sup.status().consecutive_failures, 0);
        assert_eq!(r.deadline(), None);
        r.expect(
            50_000,
            Ev::Exit(1),
            &["warn", "status"],
            "backing-off 1 until 51000",
        );

        // An exit reported in the step that reaches the stable deadline,
        // or after it without a tick, counts by the uptime.
        // (uptime in ms, failures after the exit, delay in ms)
        let cases: &[(u64, u32, u64)] = &[
            (0, 4, 8000),
            (29_999, 4, 8000),
            (30_000, 1, 1000),
            (3_600_000, 1, 1000),
        ];
        for &(uptime, failures, delay) in cases {
            let mut r = three_failures();
            let now = 7400 + uptime;
            let actions: Vec<String> = r.step(now, Ev::Exit(1)).iter().map(short).collect();
            assert_eq!(actions, ["warn", "status"], "uptime {uptime}");
            assert_eq!(
                r.state(),
                format!("backing-off {failures} until {}", now + delay),
                "uptime {uptime}"
            );
        }
    }

    #[test]
    fn a_stable_child_clears_the_alarm() {
        let mut r = failed();
        r.script(&[
            (60_100, Ev::Tick, &["info", "spawn", "status"], "starting"),
            (
                60_100,
                Ev::Spawned(8),
                &["info", "status"],
                "running 8 since 60100",
            ),
            (
                90_100,
                Ev::Tick,
                &["info", "status"],
                "running 8 since 60100",
            ),
        ]);
        assert_eq!(r.sup.status().consecutive_failures, 0);
    }

    /// Issue #70: nothing is restarted during or after a requested stop,
    /// and an exit while stopping is not a failure.
    #[test]
    fn no_restart_during_or_after_a_requested_stop() {
        let cases: &[StopCase<'_>] = &[
            (
                "stop while starting, then the spawn succeeds",
                starting,
                &[
                    (0, Ev::Stop, &["info", "status"], "shutting-down"),
                    (
                        50,
                        Ev::Spawned(PID),
                        &["info", "term 7", "status"],
                        "shutting-down 7",
                    ),
                    (60, Ev::Exit(0), &["info", "status"], "stopped"),
                ],
            ),
            (
                "stop while starting, then the spawn fails",
                starting,
                &[
                    (0, Ev::Stop, &["info", "status"], "shutting-down"),
                    (50, Ev::SpawnFailed, &["info", "status"], "stopped"),
                ],
            ),
            (
                "stop while running",
                running,
                &[
                    (
                        100,
                        Ev::Stop,
                        &["info", "term 7", "status"],
                        "shutting-down 7",
                    ),
                    (200, Ev::Killed(15), &["info", "status"], "stopped"),
                ],
            ),
            (
                "the child fails while stopping",
                running,
                &[
                    (
                        100,
                        Ev::Stop,
                        &["info", "term 7", "status"],
                        "shutting-down 7",
                    ),
                    (200, Ev::Exit(1), &["info", "status"], "stopped"),
                ],
            ),
            (
                "the child crashes while stopping",
                running,
                &[
                    (
                        100,
                        Ev::Stop,
                        &["info", "term 7", "status"],
                        "shutting-down 7",
                    ),
                    (200, Ev::Killed(11), &["info", "status"], "stopped"),
                ],
            ),
            (
                "stop while backing off",
                backing_off,
                &[(200, Ev::Stop, &["info", "status"], "stopped")],
            ),
            (
                "stop as the backoff runs out",
                backing_off,
                &[(1100, Ev::Stop, &["info", "status"], "stopped")],
            ),
            (
                "stop while failed",
                failed,
                &[(200, Ev::Stop, &["info", "status"], "stopped")],
            ),
            (
                "start requested while stopping",
                shutting_down,
                &[
                    (150, Ev::Start, &["warn"], "shutting-down 7"),
                    (200, Ev::Killed(15), &["info", "status"], "stopped"),
                ],
            ),
        ];
        for case in cases {
            check_stop_case(case);
        }
    }

    /// Run a stop case's script, then check that the supervisor ends
    /// stopped, without counting a failure, and that no amount of time
    /// brings the child back.
    fn check_stop_case(&(name, setup, steps): &StopCase<'_>) {
        let mut r = setup();
        let restarts = r.sup.status().restarts;
        for &(millis, ev, actions, state) in steps {
            let got: Vec<String> = r.step(millis, ev).iter().map(short).collect();
            assert_eq!(got, actions, "{name}: {ev:?} at {millis} ms");
            assert_eq!(r.state(), state, "{name}: {ev:?} at {millis} ms");
        }
        assert_eq!(r.deadline(), None, "{name}");
        for later in [60_000, 3_600_000, 86_400_000] {
            assert!(r.step(later, Ev::Tick).is_empty(), "{name} at {later} ms");
        }
        let status = r.sup.status();
        assert_eq!(status.state, SidecarState::Stopped, "{name}");
        assert_eq!(status.consecutive_failures, 0, "{name}");
        assert_eq!(status.restarts, restarts, "{name}");
    }

    #[test]
    fn term_escalates_to_kill_after_the_stop_timeout() {
        let mut r = shutting_down();
        assert_eq!(r.deadline(), Some(10_100));
        r.script(&[
            (10_099, Ev::Tick, &[], "shutting-down 7"),
            (10_100, Ev::Tick, &["warn", "kill 7"], "shutting-down 7"),
        ]);
        // SIGKILL is sent once; then the supervisor waits for the exit.
        assert_eq!(r.deadline(), None);
        r.script(&[
            (20_000, Ev::Tick, &[], "shutting-down 7"),
            (20_000, Ev::Stop, &[], "shutting-down 7"),
            (20_001, Ev::Killed(9), &["info", "status"], "stopped"),
        ]);
        assert_eq!(
            r.sup.status().last_exit,
            Some(ExitReason::Signal {
                number: 9,
                core_dumped: false,
            })
        );
    }

    #[test]
    fn no_kill_for_a_child_that_exits_in_time() {
        // (when the exit is reported, in ms; the stop timeout ends at 10100)
        for millis in [150, 10_099, 10_100, 50_000] {
            let mut r = shutting_down();
            // The exit is handled before the deadline: no SIGKILL for a
            // process id that may already be reused.
            r.expect(millis, Ev::Killed(15), &["info", "status"], "stopped");
        }
        // A stop requested before the spawn is reported times out from
        // when SIGTERM is sent.
        let mut r = shutting_down_before_spawn();
        assert_eq!(r.deadline(), None);
        r.expect(
            500,
            Ev::Spawned(PID),
            &["info", "term 7", "status"],
            "shutting-down 7",
        );
        assert_eq!(r.deadline(), Some(10_500));
        r.expect(10_500, Ev::Tick, &["warn", "kill 7"], "shutting-down 7");
    }

    #[test]
    fn start_while_waiting_retries_now() {
        let mut r = failed();
        r.script(&[
            (500, Ev::Start, &["info", "spawn", "status"], "starting"),
            (
                500,
                Ev::Spawned(8),
                &["info", "status"],
                "running 8 since 500",
            ),
        ]);
        let status = r.sup.status();
        assert_eq!(status.restarts, 1);
        // A retry on request does not clear the alarm; stability does.
        assert_eq!(status.consecutive_failures, 1);
    }

    #[test]
    fn unexpected_events_are_logged_and_ignored() {
        let cases: &[(&str, Setup, Ev)] = &[
            ("stopped", Run::new_default, Ev::Spawned(9)),
            ("stopped", Run::new_default, Ev::SpawnFailed),
            ("stopped", Run::new_default, Ev::Exit(0)),
            ("starting", starting, Ev::Exit(0)),
            ("starting", starting, Ev::Killed(9)),
            ("running", running, Ev::Spawned(9)),
            ("running", running, Ev::SpawnFailed),
            ("backing off", backing_off, Ev::Spawned(9)),
            ("backing off", backing_off, Ev::SpawnFailed),
            ("backing off", backing_off, Ev::Exit(1)),
            ("failed", failed, Ev::Exit(1)),
            ("shutting down", shutting_down, Ev::Spawned(9)),
            ("shutting down", shutting_down, Ev::SpawnFailed),
            (
                "shutting down before spawn",
                shutting_down_before_spawn,
                Ev::Exit(0),
            ),
        ];
        for (name, setup, ev) in cases {
            let mut r = setup();
            let before = r.sup.status();
            let actions = r.step(150, *ev);
            let [Action::Log(Level::Warn, msg, fields)] = actions.as_slice() else {
                panic!("{name}, {ev:?}: {actions:?}");
            };
            assert_eq!(*msg, "ignoring an unexpected RPKI sidecar event");
            assert_eq!(fields[1], ("state", before.state.name().to_owned()));
            if let Ev::Spawned(pid) = ev {
                assert_eq!(fields[2], ("pid", pid.to_string()), "{name}");
            }
            assert_eq!(r.sup.status(), before, "{name}, {ev:?}");
        }
    }

    #[test]
    fn log_lines() {
        let warn = |msg, fields: &[(&'static str, &str)]| {
            let fields = fields.iter().map(|&(k, v)| (k, v.to_owned())).collect();
            Action::Log(Level::Warn, msg, fields)
        };
        let failed = "RPKI sidecar failed; restarting after a backoff";

        let mut r = running();
        let actions = r
            .sup
            .step(Event::Exited(ExitStatus::from_raw(0x100)), r.at(1500));
        assert_eq!(
            actions[0],
            warn(
                failed,
                &[
                    ("pid", "7"),
                    ("exit", "exited with status 1"),
                    ("uptime", "1.500s"),
                    ("failures", "1"),
                    ("retry_in", "1s"),
                ]
            )
        );

        let mut r = starting();
        let error = io::Error::from_raw_os_error(13);
        let actions = r.sup.step(Event::SpawnFailed(error), r.at(0));
        assert_eq!(
            actions[0],
            warn(
                failed,
                &[
                    (
                        "exit",
                        "could not be started: Permission denied (os error 13)"
                    ),
                    ("failures", "1"),
                    ("retry_in", "1s"),
                ]
            )
        );

        let mut r = running();
        let actions = r.step(10, Ev::Stop);
        assert_eq!(
            actions[0],
            Action::Log(
                Level::Info,
                "stopping the RPKI sidecar",
                vec![("pid", "7".to_owned())]
            )
        );
        let actions = r.step(20, Ev::Killed(15));
        assert_eq!(
            actions[0],
            Action::Log(
                Level::Info,
                "RPKI sidecar stopped",
                vec![("exit", "killed by signal 15 (SIGTERM)".to_owned())]
            )
        );
    }

    #[test]
    fn status_snapshot() {
        let mut r = backing_off();
        r.script(&[
            (1100, Ev::Tick, &["info", "spawn", "status"], "starting"),
            (
                1200,
                Ev::Spawned(8),
                &["info", "status"],
                "running 8 since 1200",
            ),
        ]);
        assert_eq!(
            r.sup.status(),
            SidecarStatus {
                state: SidecarState::Running {
                    pid: 8,
                    since: r.at(1200),
                },
                pid: Some(8),
                restarts: 1,
                consecutive_failures: 1,
                last_exit: Some(ExitReason::Code(1)),
                rtr: rtr(),
            }
        );
        let r = shutting_down();
        assert_eq!(r.sup.status().pid, Some(PID));
        assert_eq!(shutting_down_before_spawn().sup.status().pid, None);
        assert_eq!(backing_off().sup.status().pid, None);
    }

    #[test]
    fn next_deadline_per_state() {
        let cases: &[(&str, Setup, Option<u128>)] = &[
            ("stopped", Run::new_default, None),
            ("starting", starting, None),
            ("running without failures", running, None),
            ("backing off", backing_off, Some(1100)),
            ("failed", failed, Some(60_100)),
            ("shutting down", shutting_down, Some(10_100)),
            (
                "shutting down before spawn",
                shutting_down_before_spawn,
                None,
            ),
        ];
        for (name, setup, deadline) in cases {
            assert_eq!(setup().deadline(), *deadline, "{name}");
        }
    }

    #[test]
    fn signals_to_send() {
        let cases = [
            (Action::SendTerm(7), Some((7, ChildSignal::Term))),
            (Action::Kill(8), Some((8, ChildSignal::Kill))),
            (Action::Spawn, None),
            (Action::StatusChanged, None),
            (Action::Log(Level::Info, "x", Vec::new()), None),
        ];
        for (action, signal) in cases {
            assert_eq!(action.signal(), signal, "{action:?}");
        }
    }

    /// `step` stays total for settings `validate` would refuse.
    #[test]
    fn unvalidated_durations_do_not_panic() {
        let mut c = config(0);
        c.backoff = BackoffConfig {
            initial: Duration::MAX,
            cap: Duration::MAX,
            stable: Duration::MAX,
        };
        c.stop_timeout = Duration::MAX;
        let mut sup = Supervisor::new(&c, rtr(), u64::MAX);
        let now = Instant::now();
        let _ = sup.step(Event::StartRequested, now);
        let _ = sup.step(Event::Spawned(PID), now);
        let _ = sup.next_deadline();
        let _ = sup.step(Event::Exited(ExitStatus::from_raw(0x100)), now);
        let _ = sup.step(Event::Tick, now);
        let _ = sup.step(Event::Spawned(PID), now);
        let _ = sup.step(Event::StopRequested, now);
        let _ = sup.step(Event::Tick, now);
        let _ = sup.step(Event::Exited(ExitStatus::from_raw(9)), now);
        assert_eq!(sup.state(), SidecarState::Stopped);
    }

    #[test]
    fn durations_in_log_fields() {
        let cases = [
            (Duration::ZERO, "0s"),
            (Duration::from_nanos(1), "0s"),
            (ms(250), "0.250s"),
            (ms(1000), "1s"),
            (ms(1500), "1.500s"),
            (ms(61_007), "61.007s"),
            (Duration::MAX, "18446744073709551615.999s"),
        ];
        for (d, text) in cases {
            assert_eq!(seconds(d), text, "{d:?}");
        }
    }
}

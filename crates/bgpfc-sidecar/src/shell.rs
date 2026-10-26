//! The I/O shell around [`Supervisor`]: [`Sidecar`] checks the binary,
//! picks the RTR port, spawns, signals and reaps Routinator on one
//! long-lived thread, logs what it prints, and publishes the supervisor's
//! status.
//!
//! Implements: no RFC. The rules come from issues #26, #70, #71 and #72.

use std::collections::VecDeque;
use std::fmt::{self, Display};
use std::fs;
use std::hash::{BuildHasher, RandomState};
use std::io;
use std::net::{SocketAddr, TcpListener};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use bgpfc_log::{Field, Level};
use bgpfc_sys::{ChildSignal, send_signal};

use crate::args::routinator_args;
use crate::child::{ChildProc, Threads, command, output_pair, spawn_thread, stdio, unknown_status};
use crate::config::SidecarConfig;
use crate::error::SidecarError;
use crate::output::{MAX_LINE, read_bounded, read_lines};
use crate::status::{ExitReason, SidecarState, SidecarStatus};
use crate::supervisor::{Action, Event, LogField, Supervisor};
use crate::version::{Version, check_version_output, excerpt};

/// How long `routinator --version` may take. It prints a constant
/// string, so a binary that takes longer is hung, not slow.
const VERSION_TIMEOUT: Duration = Duration::from_secs(10);

/// How much of what `routinator --version` prints is kept.
const VERSION_OUTPUT: usize = 4096;

/// The `sidecar` field on the lines the child prints.
const SIDECAR: &str = "routinator";

/// Where the shell's log lines go: [`bgpfc_log::log`] in the daemon, a
/// buffer in tests.
pub(crate) type Log = Arc<dyn Fn(Level, &str, &[Field<'_>]) + Send + Sync>;

/// Settings of the shell itself. The daemon uses [`Options::new`]; tests
/// shrink the timeouts and capture the log.
pub(crate) struct Options {
    /// How long `routinator --version` may take.
    pub(crate) version_timeout: Duration,
    /// The longest line of the child's output that is logged, in bytes.
    pub(crate) line_limit: usize,
    /// Seeds the backoff jitter; zero for none.
    pub(crate) seed: u64,
    /// Where log lines go.
    pub(crate) log: Log,
}

impl Options {
    pub(crate) fn new() -> Options {
        let log: Log = Arc::new(bgpfc_log::log);
        Options {
            version_timeout: VERSION_TIMEOUT,
            line_limit: MAX_LINE,
            seed: jitter_seed(),
            log,
        }
    }
}

/// Routinator, run and supervised as a child process (issue #70).
///
/// [`Sidecar::start`] checks the settings and the binary's version, picks
/// the RTR port and starts a supervisor thread. That thread spawns
/// Routinator and restarts it after every failure, as the [`Supervisor`]
/// decides: with backoff, and with [`SidecarState::Failed`] raised once it
/// keeps failing. [`Sidecar::stop`], or dropping the `Sidecar`, stops it:
/// `SIGTERM`, `SIGKILL` once the stop timeout has passed, reap, and join
/// every thread. [`Sidecar::status`] is the snapshot for the control
/// plane, and [`Sidecar::rtr_addr`] is where the RTR client connects.
///
/// # Threads
///
/// - **One supervisor thread** for the life of the `Sidecar`. It owns the
///   [`Supervisor`] and the child: it spawns every child, sends every
///   signal and reaps every child. A child's parent-death signal
///   (`PR_SET_PDEATHSIG`) fires when the *thread* that spawned it exits
///   (`prctl(2)`), so the spawning thread must outlive the child, and this
///   one ends only after [`Sidecar::stop`] has reaped the last child. If
///   it ends early, because bgpfcd crashed or the thread panicked, the
///   child gets `SIGKILL`: exactly when it would otherwise run on with
///   nobody supervising it. The death signal is `SIGKILL` rather than
///   `SIGTERM` because nobody is left then to escalate a `SIGTERM` the
///   child ignores, and a validator that outlives bgpfcd would keep the
///   RTR port from the next one; Routinator's cache survives a `SIGKILL`
///   as it must survive a power cut. A child that switches to another
///   user loses its death signal (`prctl(2)`), so Routinator's `--user`
///   and `--group` are refused and its config file must not set `user`
///   or `group`.
/// - **A waiter thread per child.** It blocks until the child exits and
///   tells the supervisor thread, without reaping it
///   ([`bgpfc_sys::wait_for_exit`]). It spawns nothing, so when it ends
///   does not matter to the death signal. As only the supervisor thread
///   reaps, a signal it sends always names its own child, even when the
///   child exits at the same moment, and never a process that reused the
///   id after a reap the supervisor thread has not heard of yet. That
///   needs nothing else in bgpfcd to reap children: if something does,
///   waiting fails, and the child's id and process group are not signalled
///   any more. Nothing polls: the supervisor thread sleeps until a message
///   arrives or the supervisor's next deadline.
/// - **Two reader threads per child** log what it prints, line by line,
///   through bgpfc-log, with the fields `sidecar=routinator`, `pid` and
///   `stream`: stdout at info, stderr at warn, where Routinator writes
///   its warnings and errors. Lines are cut at 4096 bytes, with a
///   `truncated` field counting what was dropped, so a chatty child
///   cannot make bgpfcd buffer without bound.
///
/// # The child
///
/// The configured binary, by its absolute path, with
/// [`routinator_args`](crate::routinator_args); standard input from
/// `/dev/null`; stdout and stderr on socket pairs, so that stopping can
/// end the readers even if a process the child started still holds the
/// other end; `/` as working directory; a process group of its own; and
/// an environment of two variables, nothing inherited:
///
/// - `HOME` is the repository directory. Without `--config`, Routinator
///   reads `$HOME/.routinator.conf`, and with `HOME` unset it would take
///   the service user's home from the password database instead. The
///   repository directory belongs to the validator and to bgpfcd, so no
///   stray file elsewhere can change the validator.
/// - `PATH` is systemd's default for services. The binary is never looked
///   up, but Routinator runs `rsync` by name.
///
/// Everything else is left out, such as `RSYNC_RSH`, which Routinator
/// 0.15.2 refuses to start with, and proxy and locale settings: the
/// child's behaviour depends on bgpfcd's settings only.
///
/// The child gets no ambient capabilities, so the `CAP_NET_ADMIN` and
/// `CAP_NET_BIND_SERVICE` that bgpfcd may hold that way (README, "Option
/// A") do not reach a validator that parses data from the internet. That
/// leaves it unprivileged only if bgpfcd is not root: a child of root gets
/// every capability when it executes. Start the sidecar after dropping
/// root (README, "Option B"), and configure an RTR port of 1024 or more
/// (or 0), which an unprivileged process may bind.
///
/// When the child exits, `SIGKILL` goes to its process group before it is
/// reaped, while its id still names the group, so nothing it started,
/// such as an `rsync`, is left behind as an orphan holding the repository
/// directory or the output sockets. The group also keeps a terminal's
/// Ctrl-C, which goes to the whole foreground group, from reaching the
/// child at the same moment as bgpfcd.
///
/// ```no_run
/// use bgpfc_sidecar::{Sidecar, SidecarConfig};
///
/// let config = SidecarConfig::new("/usr/bin/routinator", "/var/lib/bgpfc/rpki");
/// let sidecar = Sidecar::start(config)?;
/// println!("RTR on {}, {}", sidecar.rtr_addr(), sidecar.status().state);
/// sidecar.stop();
/// # Ok::<(), bgpfc_sidecar::SidecarError>(())
/// ```
#[must_use = "dropping a Sidecar stops Routinator"]
pub struct Sidecar {
    rtr: SocketAddr,
    /// Shared with the supervisor thread, which updates it when it checks
    /// a replaced binary.
    version: Arc<Mutex<Version>>,
    status: Arc<Mutex<SidecarStatus>>,
    control: Mutex<Option<Control>>,
    threads: Threads,
    log: Log,
}

/// The way to the supervisor thread, until it is stopped.
struct Control {
    tx: Sender<Msg>,
    thread: JoinHandle<()>,
}

impl Sidecar {
    /// Check `config` and the binary, pick the RTR port, and start
    /// supervising Routinator. Returns once the supervisor thread runs;
    /// the child is spawned from there, and [`status`](Self::status)
    /// shows how that goes.
    ///
    /// The binary must answer `--version` within ten seconds with a
    /// release of the series bgpfcd drives
    /// ([`TESTED_VERSION`](crate::TESTED_VERSION)); it runs with the
    /// child's environment and is killed if it takes longer.
    ///
    /// The check is repeated before a restart whenever the binary is no
    /// longer the file it was, as after a package upgrade: its device,
    /// inode, size or times differ (`stat(2)`). A binary that fails it is
    /// not run; the attempt counts as a failure to start, with the reason
    /// in [`SidecarStatus::last_exit`] and an error in the log, and the
    /// next attempt checks again. One that passes is run, and
    /// [`version`](Self::version) reports its version from then on. The
    /// check runs on the supervisor thread, so a [`stop`](Self::stop)
    /// during it waits for it, ten seconds at most. A binary replaced
    /// between the check and the `execve` that follows it runs unchecked
    /// until the restart after.
    ///
    /// A configured RTR port of 0 is replaced with a free one: bind the
    /// configured loopback address with port 0, read the port the kernel
    /// chose, and close the socket again. Something else may bind that
    /// port before Routinator does, and Routinator binds only after its
    /// first validation run. That is acceptable: the port comes from the
    /// ephemeral range, which the kernel hands out in rotation rather than
    /// reusing at once; loopback is open to this host only; and if the
    /// port is taken, Routinator fails to bind and exits, which the
    /// supervisor reports as failures and then as the
    /// [`SidecarState::Failed`] alarm, never silently. Handing Routinator
    /// the bound socket instead (`--systemd-listen`) would need
    /// `LISTEN_PID` set to the child's own id, which only the child knows,
    /// after `fork`, where nothing may allocate. Configure a fixed port to
    /// avoid the race.
    ///
    /// # Errors
    /// The [`SidecarError`] from [`SidecarConfig::validate`] or the
    /// version check: [`SidecarError::VersionCheck`] if the binary cannot
    /// be run or fails, [`SidecarError::VersionTimeout`] if it hangs,
    /// [`SidecarError::UnrecognizedVersion`] or
    /// [`SidecarError::IncompatibleVersion`]. [`SidecarError::Io`] if no
    /// RTR port or thread could be had.
    pub fn start(config: SidecarConfig) -> Result<Sidecar, SidecarError> {
        Sidecar::start_with(config, Options::new())
    }

    /// [`Sidecar::start`] with the shell's own settings given.
    pub(crate) fn start_with(
        config: SidecarConfig,
        options: Options,
    ) -> Result<Sidecar, SidecarError> {
        config.validate()?;
        let threads = Threads::default();
        // Before the check: a binary replaced during it differs from this
        // at the first spawn and is checked again.
        let binary = BinaryId::of(&config.binary);
        let version = check_version(&config, &options, &threads)?;
        let rtr = resolve_rtr(config.rtr_listen)?;
        (options.log)(
            Level::Info,
            "found a supported Routinator",
            &[
                ("binary", &config.binary.display()),
                ("version", &version),
                ("rtr", &rtr),
            ],
        );
        let supervisor = Supervisor::new(&config, rtr, options.seed);
        let status = Arc::new(Mutex::new(supervisor.status()));
        let version = Arc::new(Mutex::new(version));
        let (tx, rx) = mpsc::channel();
        let log = Arc::clone(&options.log);
        let shell = Shell {
            config,
            rtr,
            binary,
            version: Arc::clone(&version),
            supervisor,
            child: None,
            spawned: 0,
            rx,
            tx: tx.clone(),
            status: Arc::clone(&status),
            options,
            threads: Arc::clone(&threads),
        };
        let thread = spawn_thread("sidecar", &threads, move || shell.run())
            .map_err(|e| SidecarError::io("starting the RPKI sidecar's supervisor thread", &e))?;
        Ok(Sidecar {
            rtr,
            version,
            status,
            control: Mutex::new(Some(Control { tx, thread })),
            threads,
            log,
        })
    }

    /// Where Routinator serves RTR, for the RTR client: the configured
    /// loopback address, with the port picked at start if the configured
    /// one was 0.
    #[must_use]
    pub const fn rtr_addr(&self) -> SocketAddr {
        self.rtr
    }

    /// The version the binary reported when it was last checked: at
    /// start, and again before a restart whenever the binary had been
    /// replaced and passed the check (see [`start`](Self::start)).
    #[must_use]
    pub fn version(&self) -> Version {
        lock(&self.version).clone()
    }

    /// The supervisor's current status.
    #[must_use]
    pub fn status(&self) -> SidecarStatus {
        lock(&self.status).clone()
    }

    /// Ask the supervisor thread to stop Routinator, and return at once.
    ///
    /// From here on nothing is restarted, and an exit of the child is the
    /// stop and not a failure. A daemon that is told to shut down calls
    /// this first, so that the child stops while the sessions close
    /// instead of after them, and so that a child that exits by itself at
    /// the same time, as one does when systemd signals the whole control
    /// group, is not mistaken for a crash. [`stop`](Self::stop) then waits
    /// for the end. Calling it after `stop`, or twice, does nothing; while
    /// another thread is inside `stop` it waits for that to finish.
    pub fn request_stop(&self) {
        if let Some(control) = lock(&self.control).as_ref() {
            // Fails only if the thread has ended already.
            let _ = control.tx.send(Msg::Stop);
        }
    }

    /// Stop Routinator and return once it is gone: `SIGTERM`, then
    /// `SIGKILL` if it has not exited within the stop timeout, reap it and
    /// what it left in its process group, and join every thread. Nothing
    /// is restarted from the moment this is called. Later calls, and calls
    /// from other threads meanwhile, return once the first is done.
    pub fn stop(&self) {
        let mut control = lock(&self.control);
        let Some(Control { tx, thread }) = control.take() else {
            return;
        };
        // Fails only if the thread has ended already, which join reports.
        let _ = tx.send(Msg::Stop);
        if thread.join().is_err() {
            // The unwinding dropped the child, which killed and reaped it.
            let mut status = lock(&self.status);
            status.state = SidecarState::Stopped;
            status.pid = None;
            (self.log)(
                Level::Error,
                "the RPKI sidecar's supervisor thread panicked; Routinator was killed",
                &[],
            );
        }
    }

    /// How many of the threads this sidecar started have not finished.
    #[cfg(test)]
    pub(crate) fn threads(&self) -> usize {
        self.threads.load(Ordering::Acquire)
    }
}

impl Drop for Sidecar {
    /// [`Sidecar::stop`].
    fn drop(&mut self) {
        self.stop();
    }
}

impl fmt::Debug for Sidecar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sidecar")
            .field("rtr", &self.rtr)
            .field("version", &self.version())
            .field("status", &self.status())
            .field("threads", &self.threads.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

/// Check `config` and its binary as [`Sidecar::start`] does, and start
/// nothing: [`SidecarConfig::validate`], then `<binary> --version` (ten
/// seconds at most, killed with its process group if it takes longer) and
/// the release series it reports. The version is returned.
///
/// For a daemon that must know whether a new sidecar would start before it
/// stops the one that runs, as a reload does. The binary runs with the
/// child's environment, as the user the daemon runs as.
///
/// # Errors
/// As [`Sidecar::start`], but for the RTR port and the thread: the
/// [`SidecarError`] from [`SidecarConfig::validate`] or from the version
/// check.
pub fn check_binary(config: &SidecarConfig) -> Result<Version, SidecarError> {
    check_binary_with(config, &Options::new())
}

/// [`check_binary`] with the shell's own settings given.
fn check_binary_with(config: &SidecarConfig, options: &Options) -> Result<Version, SidecarError> {
    config.validate()?;
    check_version(config, options, &Threads::default())
}

/// A message to the supervisor thread.
#[derive(Debug)]
enum Msg {
    /// [`Sidecar::stop`] was called.
    Stop,
    /// The waiter of the `spawned`-th child: it has exited and waits to be
    /// reaped, or waiting for it failed.
    Exited {
        spawned: u64,
        result: io::Result<()>,
    },
}

/// The supervisor thread's state.
struct Shell {
    config: SidecarConfig,
    rtr: SocketAddr,
    /// The binary that last passed the version check, if it could be
    /// identified.
    binary: Option<BinaryId>,
    /// What [`Sidecar::version`] reports.
    version: Arc<Mutex<Version>>,
    supervisor: Supervisor,
    /// The child, with its number in [`Shell::spawned`]'s count.
    child: Option<(u64, ChildProc<()>)>,
    /// Children spawned so far. A waiter's message names its child by
    /// this count rather than by process id, which a later child may get.
    spawned: u64,
    rx: Receiver<Msg>,
    /// Given to each waiter. Holding it keeps the channel open, so
    /// receiving cannot fail.
    tx: Sender<Msg>,
    status: Arc<Mutex<SidecarStatus>>,
    options: Options,
    threads: Threads,
}

impl Shell {
    fn run(mut self) {
        self.step(Event::StartRequested);
        let mut stopping = false;
        while !(stopping && self.supervisor.state() == SidecarState::Stopped) {
            match self.wait() {
                Some(Msg::Stop) => {
                    stopping = true;
                    self.step(Event::StopRequested);
                }
                Some(Msg::Exited { spawned, result }) => self.exited(spawned, result),
                None => self.step(Event::Tick),
            }
        }
    }

    /// The next message, or `None` once the supervisor's next deadline
    /// has come.
    fn wait(&self) -> Option<Msg> {
        match self.supervisor.next_deadline() {
            Some(at) => {
                match self
                    .rx
                    .recv_timeout(at.saturating_duration_since(Instant::now()))
                {
                    Ok(msg) => Some(msg),
                    Err(RecvTimeoutError::Timeout) => None,
                    // invariant: `self.tx` keeps the channel open.
                    Err(RecvTimeoutError::Disconnected) => Some(Msg::Stop),
                }
            }
            // invariant: `self.tx` keeps the channel open.
            None => Some(self.rx.recv().unwrap_or(Msg::Stop)),
        }
    }

    /// The waiter of the `spawned`-th child reported.
    fn exited(&mut self, spawned: u64, result: io::Result<()>) {
        let Some((_, child)) = self.child.take_if(|(n, _)| *n == spawned) else {
            // A child that was cleaned up already, as after a failed start
            // of its reader threads.
            return;
        };
        let pid = child.pid();
        if let Err(error) = result {
            // `waitid` fails only for a child that is gone, so its id, and
            // its group's, may name other processes now: `finish` signals
            // neither.
            self.log(
                Level::Error,
                "lost the RPKI sidecar: something else reaped it; not signalling its id or process group",
                &[("pid", &pid), ("error", &error)],
            );
        }
        let (status, _) = child.finish(false);
        let status = status.unwrap_or_else(|error| {
            self.log(
                Level::Error,
                "could not reap the RPKI sidecar; its exit status is unknown",
                &[("pid", &pid), ("error", &error)],
            );
            unknown_status()
        });
        // Reaped: tell the supervisor before anything else can happen.
        self.step(Event::Exited(status));
    }

    /// Feed `event` to the supervisor and carry out what it returns, and
    /// what the spawn results it asks for return in turn.
    fn step(&mut self, event: Event) {
        let mut actions: VecDeque<Action> = self.supervisor.step(event, Instant::now()).into();
        while let Some(action) = actions.pop_front() {
            match action {
                Action::Spawn => {
                    let event = self.spawn();
                    actions.extend(self.supervisor.step(event, Instant::now()));
                }
                Action::SendTerm(_) | Action::Kill(_) => {
                    if let Some((pid, signal)) = action.signal() {
                        self.signal(pid, signal);
                    }
                }
                Action::Log(level, msg, fields) => self.log_fields(level, msg, &fields),
                Action::StatusChanged => *lock(&self.status) = self.supervisor.status(),
            }
        }
    }

    fn signal(&self, pid: u32, signal: ChildSignal) {
        // Only the unreaped child's id is sure to name it.
        if self.child.as_ref().is_none_or(|(_, c)| c.pid() != pid) {
            self.log(
                Level::Error,
                "not signalling a process that is not the RPKI sidecar",
                &[("pid", &pid), ("signal", &signal.number())],
            );
            return;
        }
        if let Err(error) = send_signal(pid, signal) {
            self.log(
                Level::Warn,
                "could not signal the RPKI sidecar",
                &[
                    ("pid", &pid),
                    ("signal", &signal.number()),
                    ("error", &error),
                ],
            );
        }
    }

    fn spawn(&mut self) -> Event {
        self.spawned += 1;
        if let Err(error) = self.recheck_binary() {
            return Event::SpawnFailed(error);
        }
        match self.launch(self.spawned) {
            Ok(child) => {
                let pid = child.pid();
                self.child = Some((self.spawned, child));
                Event::Spawned(pid)
            }
            Err(error) => Event::SpawnFailed(error),
        }
    }

    /// Issue #72: if the binary is no longer the file that last passed the
    /// version check, check it again before running it. The binary is
    /// remembered only once it passes, so a binary that fails is checked
    /// at every attempt until it is replaced again.
    ///
    /// # Errors
    /// The failed check, for [`Event::SpawnFailed`].
    fn recheck_binary(&mut self) -> io::Result<()> {
        let binary = &self.config.binary;
        let Some(id) = BinaryId::of(binary) else {
            // Gone or unreadable: the spawn that follows says why.
            return Ok(());
        };
        if self.binary == Some(id) {
            return Ok(());
        }
        match check_version(&self.config, &self.options, &self.threads) {
            Ok(version) => {
                self.log(
                    Level::Info,
                    "the Routinator binary changed; found a supported Routinator",
                    &[("binary", &binary.display()), ("version", &version)],
                );
                self.binary = Some(id);
                *lock(&self.version) = version;
                Ok(())
            }
            Err(error) => {
                self.log(
                    Level::Error,
                    "the Routinator binary changed and fails the version check; not running it",
                    &[("binary", &binary.display()), ("error", &error)],
                );
                Err(io::Error::other(error))
            }
        }
    }

    /// Spawn the `spawned`-th child with its waiter and readers.
    fn launch(&self, spawned: u64) -> io::Result<ChildProc<()>> {
        let (stdout, child_stdout) = output_pair()?;
        let (stderr, child_stderr) = output_pair()?;
        let mut cmd = command(&self.config);
        cmd.args(routinator_args(&self.config, self.rtr))
            .stdout(stdio(child_stdout))
            .stderr(stdio(child_stderr));
        let tx = self.tx.clone();
        let started = ChildProc::spawn(&mut cmd, &self.threads, move |_, result| {
            // Fails only once the supervisor thread is gone.
            let _ = tx.send(Msg::Exited { spawned, result });
        });
        // Close this process's copies of the child's ends, or the readers
        // would never see the end of the output.
        drop(cmd);
        let mut child = started?;
        let pid = child.pid();
        let readers = [
            ("sidecar-stdout", stdout, Level::Info, "stdout"),
            ("sidecar-stderr", stderr, Level::Warn, "stderr"),
        ];
        for (thread, stream, level, name) in readers {
            let log = Arc::clone(&self.options.log);
            let limit = self.options.line_limit;
            // On an error `child` is dropped, which kills and reaps it.
            child.add_reader(thread, &self.threads, stream, move |stream| {
                log_output(&stream, limit, &log, level, pid, name);
            })?;
        }
        Ok(child)
    }

    fn log(&self, level: Level, msg: &str, fields: &[Field<'_>]) {
        (self.options.log)(level, msg, fields);
    }

    fn log_fields(&self, level: Level, msg: &str, fields: &[LogField]) {
        let fields: Vec<Field<'_>> = fields
            .iter()
            .map(|(key, value)| (*key, value as &dyn Display))
            .collect();
        self.log(level, msg, &fields);
    }
}

/// Log every line read from `stream`, one of the child's output streams
/// called `name`, at `level`.
fn log_output(
    stream: &UnixStream,
    limit: usize,
    log: &Log,
    level: Level,
    pid: u32,
    name: &'static str,
) {
    let result = read_lines(stream, limit, |line| {
        let text = String::from_utf8_lossy(line.text);
        let fields: [Field<'_>; 4] = [
            ("sidecar", &SIDECAR),
            ("pid", &pid),
            ("stream", &name),
            ("truncated", &line.dropped),
        ];
        let used = if line.dropped == 0 { 3 } else { 4 };
        log(level, &text, fields.get(..used).unwrap_or(&fields));
    });
    if let Err(error) = result {
        log(
            Level::Warn,
            "could not read the RPKI sidecar's output",
            &[
                ("sidecar", &SIDECAR),
                ("pid", &pid),
                ("stream", &name),
                ("error", &error),
            ],
        );
    }
}

/// Run `<binary> --version` with the child's environment and check what
/// it prints, killing it after the timeout.
fn check_version(
    config: &SidecarConfig,
    options: &Options,
    threads: &Threads,
) -> Result<Version, SidecarError> {
    let failed = |outcome: ExitReason, output: &str| SidecarError::VersionCheck {
        binary: config.binary.clone(),
        outcome,
        output: excerpt(output),
    };
    // stdout and stderr on one socket: an error message explains a
    // failure, and a warning before the version line is skipped.
    let (ours, theirs) = output_pair()
        .map_err(|e| SidecarError::io("creating a socket pair for `routinator --version`", &e))?;
    let theirs_too = theirs
        .try_clone()
        .map_err(|e| SidecarError::io("creating a socket pair for `routinator --version`", &e))?;
    let mut cmd = command(config);
    cmd.arg("--version")
        .stdout(stdio(theirs))
        .stderr(stdio(theirs_too));
    let (tx, rx) = mpsc::channel();
    let started = ChildProc::spawn(&mut cmd, threads, move |_, result| {
        // Fails only if the check gave up already.
        let _ = tx.send(result);
    });
    drop(cmd);
    let mut child = started.map_err(|e| failed(ExitReason::SpawnFailed(e.to_string()), ""))?;
    child
        .add_reader("sidecar-version", threads, ours, |stream| {
            read_bounded(&stream, VERSION_OUTPUT)
        })
        .map_err(|e| SidecarError::io("starting a thread to read `routinator --version`", &e))?;
    let timed_out = matches!(
        rx.recv_timeout(options.version_timeout),
        Err(RecvTimeoutError::Timeout)
    );
    let (status, outputs) = child.finish(timed_out);
    if timed_out {
        return Err(SidecarError::VersionTimeout {
            binary: config.binary.clone(),
            timeout: options.version_timeout,
        });
    }
    let output = outputs
        .into_iter()
        .next()
        .flatten()
        .and_then(Result::ok)
        .unwrap_or_default();
    let output = String::from_utf8_lossy(&output);
    let status = status.map_err(|e| SidecarError::io("reaping `routinator --version`", &e))?;
    if !status.success() {
        return Err(failed(ExitReason::from(status), &output));
    }
    check_version_output(&output)
}

/// Which file a path names, as far as `stat(2)` tells: a binary replaced
/// by a package upgrade, which renames a new file over it, has another
/// inode; one rewritten in place has another size or other times, at the
/// least a newer change time, which no one can set back. Times are as fine
/// as the file system's clock, a few milliseconds at worst, so a rewrite
/// of the same size within one tick of the last check goes unnoticed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BinaryId {
    dev: u64,
    ino: u64,
    size: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

impl BinaryId {
    /// The file `path` names, following symbolic links as `execve` does;
    /// `None` if it cannot be read.
    fn of(path: &Path) -> Option<BinaryId> {
        let meta = fs::metadata(path).ok()?;
        Some(BinaryId {
            dev: meta.dev(),
            ino: meta.ino(),
            size: meta.size(),
            mtime: (meta.mtime(), meta.mtime_nsec()),
            ctime: (meta.ctime(), meta.ctime_nsec()),
        })
    }
}

/// `listen` with a port 0 replaced by a free port, picked by binding the
/// address with port 0 and closing the socket again (see
/// [`Sidecar::start`] for the race that leaves). The IPv6 scope id and
/// flow label are dropped, as [`routinator_args`] drops them.
fn resolve_rtr(listen: SocketAddr) -> Result<SocketAddr, SidecarError> {
    let addr = SocketAddr::new(listen.ip(), listen.port());
    if addr.port() != 0 {
        return Ok(addr);
    }
    let picked = TcpListener::bind(addr)
        .and_then(|listener| listener.local_addr())
        .map_err(|e| SidecarError::io("picking a free RTR port", &e))?;
    Ok(SocketAddr::new(addr.ip(), picked.port()))
}

/// A seed for the backoff jitter that differs between processes, so
/// validators that failed together do not retry together. std keys each
/// [`RandomState`] from the operating system's random source; the clock is
/// for log timestamps only (AGENTS.md §3). Never zero, which would turn
/// jitter off.
fn jitter_seed() -> u64 {
    RandomState::new().hash_one(std::process::id()).max(1)
}

/// The lock, also after a panic elsewhere: nothing that holds one of
/// these locks can panic halfway through an update.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Live tests: `#!/bin/sh` stubs stand in for Routinator, each written
/// into a fresh temporary directory that is removed afterwards.
#[cfg(all(test, not(miri)))]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::fs;
    use std::net::Ipv4Addr;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::atomic::AtomicUsize;
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::backoff::BackoffConfig;
    use crate::child::CHILD_PATH;
    use crate::version::TESTED_VERSION;

    const FAILED: &str = "RPKI sidecar failed; restarting after a backoff";
    const KEEPS_FAILING: &str =
        "RPKI sidecar keeps failing; the validator is not running, retrying at the backoff cap";
    const STOPPED: &str = "RPKI sidecar stopped";

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    /// A captured log line, with its fields as text.
    #[derive(Clone, Debug)]
    struct Record {
        level: Level,
        msg: String,
        fields: Vec<(String, String)>,
    }

    impl Record {
        fn field(&self, key: &str) -> Option<&str> {
            self.fields
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.as_str())
        }
    }

    fn fields(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|&(k, v)| (k.to_owned(), v.to_owned()))
            .collect()
    }

    /// The log lines of one sidecar.
    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<Record>>>);

    impl Capture {
        /// Shell settings for tests: a 5 s version timeout, lines cut at
        /// 100 bytes, no jitter, and the log captured here.
        fn options(&self) -> Options {
            let records = Arc::clone(&self.0);
            let log: Log = Arc::new(move |level: Level, msg: &str, fields: &[Field<'_>]| {
                let fields = fields
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), v.to_string()))
                    .collect();
                lock(&records).push(Record {
                    level,
                    msg: msg.to_owned(),
                    fields,
                });
            });
            Options {
                version_timeout: Duration::from_secs(5),
                line_limit: 100,
                seed: 0,
                log,
            }
        }

        /// The lines with message `msg`, in order.
        fn find(&self, msg: &str) -> Vec<Record> {
            lock(&self.0)
                .iter()
                .filter(|r| r.msg == msg)
                .cloned()
                .collect()
        }

        /// The first line with message `msg`, once there is one.
        fn wait_for(&self, msg: &str) -> Record {
            wait_until(msg, || self.find(msg).into_iter().next())
        }
    }

    /// Poll `probe` until it returns something; fail after 10 s.
    fn wait_until<T>(what: &str, mut probe: impl FnMut() -> Option<T>) -> T {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(found) = probe() {
                return found;
            }
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            thread::sleep(ms(10));
        }
    }

    /// A fresh directory under the system temp dir, removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> TempDir {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let name = format!("bgpfc-sidecar-{tag}-{}-{nanos}-{n}", std::process::id());
            let path = std::env::temp_dir().join(name);
            fs::create_dir(&path).unwrap();
            TempDir(path)
        }

        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }

        /// An executable `#!/bin/sh` script `name` running `body`.
        ///
        /// Another process writes it. Were this process to hold it open
        /// for writing while a parallel test forks, the forked child would
        /// hold it too until it executes, and running the script meanwhile
        /// would fail with `ETXTBSY`.
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

        /// A stub Routinator that answers `--version` with
        /// [`TESTED_VERSION`] and otherwise runs `body`.
        fn stub(&self, body: &str) -> PathBuf {
            self.versioned_stub("routinator", &TESTED_VERSION.to_string(), body)
        }

        /// A stub `name` that answers `--version` with `Routinator
        /// version` and otherwise runs `body`.
        fn versioned_stub(&self, name: &str, version: &str, body: &str) -> PathBuf {
            let version =
                format!("if [ \"$1\" = --version ]; then echo 'Routinator {version}'; exit 0; fi");
            self.script(name, &format!("{version}\n{body}"))
        }

        /// Replace `binary` with a stub as a package upgrade does: write
        /// the new file beside it and rename it over the old one.
        fn upgrade(&self, binary: &Path, version: &str, body: &str) {
            let new = self.versioned_stub("routinator.new", version, body);
            fs::rename(new, binary).unwrap();
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Settings for a stub: backoff from 50 ms doubling to 1 s, the
    /// shortest settings allowed, stable after 10 s, the alarm after three
    /// failures, a 5 s stop timeout.
    fn config(dir: &TempDir, binary: PathBuf) -> SidecarConfig {
        let mut config = SidecarConfig::new(binary, dir.join("repo"));
        config.backoff = BackoffConfig {
            initial: SidecarConfig::MIN_BACKOFF,
            cap: SidecarConfig::MIN_BACKOFF_CAP,
            stable: Duration::from_secs(10),
        };
        config.stop_timeout = Duration::from_secs(5);
        config.failure_threshold = 3;
        config
    }

    fn running_pid(sidecar: &Sidecar) -> Option<u32> {
        match sidecar.status().state {
            SidecarState::Running { pid, .. } => Some(pid),
            _ => None,
        }
    }

    /// State letter and start time (clock ticks after boot) of `pid` from
    /// `/proc/<pid>/stat` (`proc_pid_stat(5)`, fields 3 and 22), or `None`
    /// if there is no such process, not even a zombie.
    fn proc_stat(pid: u32) -> Option<(char, u64)> {
        let text = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        // The command name (field 2) is parenthesised and may contain
        // spaces or parentheses itself, so split after the last `)`.
        let (_, rest) = text.rsplit_once(')')?;
        let mut fields = rest.split_whitespace();
        let state = fields.next()?.chars().next()?;
        let started = fields.nth(18)?.parse().ok()?;
        Some((state, started))
    }

    fn start_time(pid: u32) -> u64 {
        proc_stat(pid).expect("the process exists").1
    }

    /// Whether the process `pid` that started at `start` is still there,
    /// if only as a zombie. A newer process with the same id is not it.
    fn exists(pid: u32, start: u64) -> bool {
        matches!(proc_stat(pid), Some((_, s)) if s == start)
    }

    /// Whether `pid` is a zombie: exited, and nobody reaped it.
    fn zombie(pid: u32) -> bool {
        matches!(proc_stat(pid), Some(('Z', _)))
    }

    /// (a) The child runs, its output is logged line by line with the
    /// right levels and fields, and a stop leaves nothing behind.
    #[test]
    fn runs_logs_its_output_and_stops() {
        let dir = TempDir::new("run");
        let binary = dir.stub(
            "echo 'hello from stdout'\n\
             echo 'trouble on stderr' >&2\n\
             printf '%0250d\\n' 0\n\
             exec sleep 30",
        );
        let capture = Capture::default();
        let sidecar = Sidecar::start_with(config(&dir, binary), capture.options()).unwrap();
        assert_eq!(sidecar.version(), TESTED_VERSION);
        let rtr = sidecar.rtr_addr();
        assert_eq!(rtr.ip(), Ipv4Addr::LOCALHOST);
        assert_ne!(rtr.port(), 0, "port 0 is replaced at start");

        let pid = wait_until("a running child", || running_pid(&sidecar));
        let start = start_time(pid);
        let pid_text = pid.to_string();
        let lines = [
            ("hello from stdout", Level::Info, "stdout"),
            ("trouble on stderr", Level::Warn, "stderr"),
        ];
        for (msg, level, stream) in lines {
            let line = capture.wait_for(msg);
            assert_eq!(line.level, level, "{msg}");
            let expected = [
                ("sidecar", "routinator"),
                ("pid", &pid_text),
                ("stream", stream),
            ];
            assert_eq!(line.fields, fields(&expected), "{msg}");
        }
        // 250 zeros, cut at the 100-byte line limit.
        let long = capture.wait_for(&"0".repeat(100));
        assert_eq!(long.field("truncated"), Some("150"));
        let status = sidecar.status();
        assert_eq!(status.pid, Some(pid));
        assert_eq!(status.rtr, rtr);
        assert_eq!(status.restarts, 0);
        assert_eq!(status.last_exit, None);
        // The supervisor, the waiter and two readers.
        assert_eq!(sidecar.threads(), 4);

        sidecar.stop();
        let status = sidecar.status();
        assert_eq!(status.state, SidecarState::Stopped);
        assert_eq!(status.pid, None);
        let term = ExitReason::Signal {
            number: 15,
            core_dumped: false,
        };
        assert_eq!(status.last_exit, Some(term));
        assert!(!exists(pid, start), "the child was reaped");
        assert_eq!(sidecar.threads(), 0, "every thread was joined");
        sidecar.stop();
        assert_eq!(capture.find(STOPPED).len(), 1, "a second stop does nothing");
    }

    /// (b) A child that exits at once: the backoff doubles, the alarm is
    /// raised at the threshold, and a stop during the backoff ends it all
    /// without another restart.
    #[test]
    fn a_failing_child_backs_off_then_raises_the_alarm() {
        let dir = TempDir::new("fail");
        let binary = dir.stub("echo 'cannot start' >&2\nexit 1");
        let mut config = config(&dir, binary);
        config.backoff.cap = Duration::from_secs(2);
        config.failure_threshold = 4;
        let capture = Capture::default();
        let sidecar = Sidecar::start_with(config, capture.options()).unwrap();
        let status = wait_until("the alarm", || {
            let status = sidecar.status();
            matches!(status.state, SidecarState::Failed { .. }).then_some(status)
        });

        let backoffs: Vec<_> = capture
            .find(FAILED)
            .iter()
            .map(|r| {
                (
                    r.field("failures").unwrap().to_owned(),
                    r.field("retry_in").unwrap().to_owned(),
                )
            })
            .collect();
        let expected = [("1", "0.050s"), ("2", "0.100s"), ("3", "0.200s")];
        assert_eq!(backoffs, fields(&expected), "the delay doubles");
        let alarm = capture.wait_for(KEEPS_FAILING);
        assert_eq!(alarm.level, Level::Error);
        assert_eq!(alarm.field("failures"), Some("4"));
        assert_eq!(alarm.field("retry_in"), Some("2s"), "retries at the cap");
        assert_eq!(alarm.field("exit"), Some("exited with status 1"));
        assert!(matches!(
            status.state,
            SidecarState::Failed { failures: 4, .. }
        ));
        assert_eq!(status.consecutive_failures, 4);
        assert_eq!(status.restarts, 3);
        assert_eq!(status.last_exit, Some(ExitReason::Code(1)));
        assert_eq!(capture.wait_for("cannot start").level, Level::Warn);

        // The next attempt is 2 s away.
        sidecar.stop();
        let status = sidecar.status();
        assert_eq!(status.state, SidecarState::Stopped);
        assert_eq!(status.last_exit, Some(ExitReason::Code(1)));
        assert_eq!(sidecar.threads(), 0);
        let restarts = capture.find("restarting the RPKI sidecar").len();
        assert_eq!(restarts, 3, "no restart during the stop");
    }

    /// (c) A child that ignores `SIGTERM` gets `SIGKILL` once the stop
    /// timeout has passed.
    #[test]
    fn stop_escalates_to_sigkill_after_the_timeout() {
        let dir = TempDir::new("term");
        let binary = dir.stub("trap '' TERM\necho ready\nexec sleep 30");
        let mut config = config(&dir, binary);
        config.stop_timeout = ms(300);
        let capture = Capture::default();
        let sidecar = Sidecar::start_with(config, capture.options()).unwrap();
        let pid = wait_until("a running child", || running_pid(&sidecar));
        let start = start_time(pid);
        // From here on, `SIGTERM` is ignored.
        capture.wait_for("ready");

        let before = Instant::now();
        sidecar.stop();
        let took = before.elapsed();
        assert!(took >= ms(300), "stopped after {took:?}");
        assert!(took < Duration::from_secs(5), "stopped after {took:?}");
        let kill = capture.wait_for("RPKI sidecar did not stop in time; killing it");
        assert_eq!(kill.level, Level::Warn);
        assert_eq!(kill.field("pid"), Some(pid.to_string().as_str()));
        assert_eq!(kill.field("timeout"), Some("0.300s"));
        let status = sidecar.status();
        assert_eq!(status.state, SidecarState::Stopped);
        let killed = ExitReason::Signal {
            number: 9,
            core_dumped: false,
        };
        assert_eq!(status.last_exit, Some(killed));
        assert!(!exists(pid, start), "the child was reaped");
        assert_eq!(sidecar.threads(), 0);
    }

    /// (d) A binary from another release series is refused at start, and
    /// the version check leaves no process behind.
    #[test]
    fn an_incompatible_version_fails_the_start() {
        let dir = TempDir::new("old");
        let pid_file = dir.join("version.pid");
        let body = format!(
            "echo $$ > '{}'\necho 'Routinator 0.14.2'",
            pid_file.display()
        );
        let binary = dir.script("routinator", &body);
        let capture = Capture::default();
        let err = Sidecar::start_with(config(&dir, binary), capture.options()).unwrap_err();
        let found = Version {
            major: 0,
            minor: 14,
            patch: 2,
            pre: None,
        };
        let expected = SidecarError::IncompatibleVersion {
            found,
            tested: TESTED_VERSION,
        };
        assert_eq!(err, expected);
        assert_eq!(
            err.to_string(),
            "Routinator 0.14.2 is not supported: bgpfcd drives Routinator 0.15.x and was tested with 0.15.2"
        );
        let pid: u32 = fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(!zombie(pid), "the version check was reaped");
        assert!(capture.find("found a supported Routinator").is_empty());
    }

    /// Every way `--version` can go wrong gets an error that says so, and
    /// leaves no thread behind.
    #[test]
    fn the_version_check_explains_failures() {
        let dir = TempDir::new("version");
        let capture = Capture::default();
        let check = |binary: &PathBuf| {
            let threads = Threads::default();
            let result = check_version(&config(&dir, binary.clone()), &capture.options(), &threads);
            assert_eq!(threads.load(Ordering::Acquire), 0, "{}", binary.display());
            result.unwrap_err()
        };
        let version_check = |binary: &PathBuf, outcome, output: &str| SidecarError::VersionCheck {
            binary: binary.clone(),
            outcome,
            output: output.to_owned(),
        };

        let binary = dir.script("garbage", "echo 'hello world'");
        let output = "hello world".to_owned();
        assert_eq!(check(&binary), SidecarError::UnrecognizedVersion { output });

        let binary = dir.script(
            "fails",
            "echo \"error: unexpected argument '$1'\" >&2\nexit 2",
        );
        let expected = version_check(
            &binary,
            ExitReason::Code(2),
            "error: unexpected argument '--version'",
        );
        assert_eq!(check(&binary), expected);
        assert_eq!(
            expected.to_string(),
            format!(
                "`{} --version` exited with status 2: \"error: unexpected argument '--version'\"",
                binary.display()
            )
        );

        let binary = dir.script("killed", "kill -9 $$");
        let killed = ExitReason::Signal {
            number: 9,
            core_dumped: false,
        };
        assert_eq!(check(&binary), version_check(&binary, killed, ""));

        let binary = dir.join("missing");
        let missing = ExitReason::SpawnFailed("No such file or directory (os error 2)".to_owned());
        let expected = version_check(&binary, missing, "");
        assert_eq!(check(&binary), expected);
        assert_eq!(
            expected.to_string(),
            format!(
                "`{} --version` could not be started: No such file or directory (os error 2)",
                binary.display()
            )
        );
    }

    /// A `--version` that hangs is killed after the timeout, together with
    /// what it started in the background, which holds its output open.
    #[test]
    fn a_hung_version_check_is_killed_with_its_group() {
        let dir = TempDir::new("hang");
        let (me, bg) = (dir.join("version.pid"), dir.join("background.pid"));
        let body = format!(
            "echo $$ > '{}'\nsleep 30 &\necho $! > '{}'\nwait",
            me.display(),
            bg.display()
        );
        let binary = dir.script("routinator", &body);
        let capture = Capture::default();
        let mut options = capture.options();
        // Nothing tells the test when the stub has started its background
        // process, so the timeout leaves it ample time to: a few
        // milliseconds of CPU suffice, but a loaded machine may grant
        // that little in a second.
        let timeout = Duration::from_secs(3);
        options.version_timeout = timeout;
        let threads = Threads::default();
        let before = Instant::now();
        let err = check_version(&config(&dir, binary.clone()), &options, &threads).unwrap_err();
        let took = before.elapsed();
        assert!(took >= timeout, "gave up after {took:?}");
        // Not the 30 s the stub would take.
        assert!(took < timeout + Duration::from_secs(10), "took {took:?}");
        assert_eq!(err, SidecarError::VersionTimeout { binary, timeout });
        assert!(
            err.to_string()
                .ends_with("--version` did not finish within 3s and was killed")
        );
        assert_eq!(threads.load(Ordering::Acquire), 0, "the reader was ended");

        let read_pid = |path: &PathBuf| -> u32 {
            let text = fs::read_to_string(path).unwrap_or_else(|e| {
                panic!("the stub did not get to write {}: {e}", path.display())
            });
            text.trim().parse().unwrap()
        };
        assert!(!zombie(read_pid(&me)), "the version check was reaped");
        // Killed with the group; its new parent may not have reaped it yet.
        let bg = read_pid(&bg);
        wait_until("the background process to die", || {
            matches!(proc_stat(bg), None | Some(('Z' | 'X' | 'x', _))).then_some(())
        });
    }

    /// Issue #72: a binary replaced while the sidecar runs is checked
    /// again before the next start. One from another release series is
    /// never run, and every attempt checks it again; a patch release of
    /// the supported series runs, and its version is published.
    #[test]
    fn a_replaced_binary_is_checked_before_a_restart() {
        const REFUSED: &str =
            "the Routinator binary changed and fails the version check; not running it";
        const ACCEPTED: &str = "the Routinator binary changed; found a supported Routinator";
        let dir = TempDir::new("upgrade");
        let binary = dir.stub("echo 'serving 0.15.2'\nexec sleep 30");
        let capture = Capture::default();
        let sidecar = Sidecar::start_with(config(&dir, binary.clone()), capture.options()).unwrap();
        let first = wait_until("a running child", || running_pid(&sidecar));
        capture.wait_for("serving 0.15.2");
        assert_eq!(sidecar.version(), TESTED_VERSION);
        assert!(
            capture.find(REFUSED).is_empty(),
            "an unchanged binary is not checked"
        );

        dir.upgrade(&binary, "0.16.0", "echo 'serving 0.16.0'\nexec sleep 30");
        send_signal(first, ChildSignal::Kill).unwrap();
        let refused = wait_until("two refused attempts", || {
            let found = capture.find(REFUSED);
            (found.len() >= 2).then_some(found)
        });
        let not_supported = "Routinator 0.16.0 is not supported: bgpfcd drives Routinator 0.15.x and was tested with 0.15.2";
        assert_eq!(refused[0].level, Level::Error);
        assert_eq!(refused[0].field("error"), Some(not_supported));
        let failed = wait_until("the refusal as a failure", || {
            let exit = sidecar.status().last_exit;
            matches!(exit, Some(ExitReason::SpawnFailed(_))).then_some(exit)
        });
        assert_eq!(
            failed,
            Some(ExitReason::SpawnFailed(not_supported.to_owned()))
        );
        assert_eq!(sidecar.version(), TESTED_VERSION);

        dir.upgrade(&binary, "0.15.3", "echo 'serving 0.15.3'\nexec sleep 30");
        capture.wait_for("serving 0.15.3");
        let accepted = capture.wait_for(ACCEPTED);
        assert_eq!(accepted.field("version"), Some("0.15.3"));
        let patch = Version {
            major: 0,
            minor: 15,
            patch: 3,
            pre: None,
        };
        assert_eq!(sidecar.version(), patch);
        sidecar.stop();
        assert!(capture.find("serving 0.16.0").is_empty(), "0.16.0 ran");
        assert_eq!(sidecar.threads(), 0);
    }

    /// The identity changes when the file is rewritten in place or another
    /// file is renamed over it, and not otherwise.
    #[test]
    fn a_binary_is_identified_by_its_file() {
        let dir = TempDir::new("identity");
        let path = dir.script("routinator", "exit 0");
        let first = BinaryId::of(&path).expect("the file exists");
        assert_eq!(BinaryId::of(&path), Some(first), "nothing changed");
        // Another size: the times alone may not change within a clock tick.
        dir.script("routinator", "exit 10");
        let rewritten = BinaryId::of(&path).unwrap();
        assert_eq!(rewritten.ino, first.ino, "rewritten in place");
        assert_ne!(rewritten, first);
        let replacement = dir.script("routinator.new", "exit 1");
        fs::rename(replacement, &path).unwrap();
        let replaced = BinaryId::of(&path).unwrap();
        assert_ne!(replaced.ino, rewritten.ino, "a new file");
        assert_ne!(replaced, rewritten);
        assert_eq!(BinaryId::of(&dir.join("missing")), None);
    }

    /// Bad settings are refused before anything runs.
    #[test]
    fn invalid_settings_start_nothing() {
        let dir = TempDir::new("invalid");
        let config = config(&dir, PathBuf::from("routinator"));
        let err = Sidecar::start_with(config, Capture::default().options()).unwrap_err();
        assert_eq!(err, SidecarError::BinaryNotAbsolute("routinator".into()));
    }

    /// (e) A child killed from outside is a failure like any other, and
    /// is restarted after the backoff.
    #[test]
    fn a_child_killed_from_outside_is_restarted() {
        let dir = TempDir::new("kill");
        let binary = dir.stub("exec sleep 30");
        let capture = Capture::default();
        let sidecar = Sidecar::start_with(config(&dir, binary), capture.options()).unwrap();
        let first = wait_until("a running child", || running_pid(&sidecar));
        let first_start = start_time(first);

        // Unreaped until the supervisor thread hears of the exit, so the
        // id is still this child's.
        send_signal(first, ChildSignal::Kill).unwrap();
        let second = wait_until("a new child", || {
            running_pid(&sidecar).filter(|&pid| pid != first)
        });
        let second_start = start_time(second);
        let status = sidecar.status();
        assert_eq!(status.restarts, 1);
        assert_eq!(status.consecutive_failures, 1);
        let killed = ExitReason::Signal {
            number: 9,
            core_dumped: false,
        };
        assert_eq!(status.last_exit, Some(killed));
        let failed = capture.find(FAILED);
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].field("pid"), Some(first.to_string().as_str()));
        assert_eq!(
            failed[0].field("exit"),
            Some("killed by signal 9 (SIGKILL)")
        );
        assert_eq!(failed[0].field("retry_in"), Some("0.050s"));
        assert!(!exists(first, first_start), "the killed child was reaped");

        sidecar.stop();
        assert!(!exists(second, second_start));
        assert_eq!(sidecar.threads(), 0);
    }

    /// (f) The child gets exactly the derived arguments, the environment
    /// of `child_env` and `/` as its working directory.
    #[test]
    fn the_child_gets_the_derived_arguments_and_a_clean_environment() {
        let dir = TempDir::new("argv");
        let (argv, env, pwd) = (dir.join("argv"), dir.join("env"), dir.join("pwd"));
        // The environment the shell was started with, as `execve` passed
        // it: what `env` prints would include what the shell itself
        // exports, which differs between shells (bash adds `SHLVL` and
        // `_`, dash and bash add `PWD`).
        let body = format!(
            "cat /proc/$$/environ > '{env}'\npwd > '{pwd}'\n\
             printf '%s\\0' \"$0\" \"$@\" > '{argv}.tmp'\n\
             mv '{argv}.tmp' '{argv}'\nexec sleep 30",
            env = env.display(),
            pwd = pwd.display(),
            argv = argv.display(),
        );
        let binary = dir.stub(&body);
        let mut config = config(&dir, binary.clone());
        config.config_file = Some(dir.join("routinator.conf"));
        config.accept_arin_rpa = true;
        config.tals.bundled = vec!["ripe-pilot".to_owned()];
        config.tals.extra_dir = Some(dir.join("tals"));
        config.refresh = Duration::from_secs(300);
        config.extra_global_args = vec![
            "--strict".into(),
            "--exceptions=/etc/bgpfc/local exceptions.json".into(),
        ];
        config.extra_server_args = vec!["--http=127.0.0.1:8323".into()];
        let sidecar = Sidecar::start_with(config.clone(), Capture::default().options()).unwrap();
        let written = wait_until("the stub's arguments", || fs::read(&argv).ok());
        sidecar.stop();

        let rtr = sidecar.rtr_addr();
        let mut expected = vec![binary.into_os_string()];
        expected.extend(routinator_args(&config, rtr));
        let got: Vec<OsString> = written
            .strip_suffix(b"\0")
            .unwrap()
            .split(|&b| b == 0)
            .map(|arg| std::ffi::OsStr::from_bytes(arg).to_owned())
            .collect();
        assert_eq!(got, expected);
        let rtr_arg = OsString::from(format!("--rtr=127.0.0.1:{}", rtr.port()));
        assert!(got.contains(&rtr_arg), "{got:?}");

        let env = fs::read_to_string(&env).unwrap();
        let mut vars: Vec<&str> = env.strip_suffix('\0').unwrap().split('\0').collect();
        vars.sort_unstable();
        let home = format!("HOME={}", config.repository_dir.display());
        let path = format!("PATH={CHILD_PATH}");
        // Nothing comes from this process.
        assert_eq!(vars, [home.as_str(), path.as_str()]);
        assert_eq!(fs::read_to_string(&pwd).unwrap(), "/\n");
    }

    /// Dropping the sidecar stops it, and stops from several threads at
    /// once stop it once.
    #[test]
    fn dropping_or_stopping_from_several_threads_stops_once() {
        let dir = TempDir::new("drop");
        let binary = dir.stub("exec sleep 30");
        let capture = Capture::default();
        let sidecar = Sidecar::start_with(config(&dir, binary.clone()), capture.options()).unwrap();
        let pid = wait_until("a running child", || running_pid(&sidecar));
        let start = start_time(pid);
        let threads = Arc::clone(&sidecar.threads);
        drop(sidecar);
        assert!(!exists(pid, start), "dropping reaped the child");
        assert_eq!(threads.load(Ordering::Acquire), 0);
        assert_eq!(capture.find(STOPPED).len(), 1);

        let capture = Capture::default();
        let sidecar = Sidecar::start_with(config(&dir, binary), capture.options()).unwrap();
        wait_until("a running child", || running_pid(&sidecar));
        thread::scope(|s| {
            for _ in 0..3 {
                s.spawn(|| sidecar.stop());
            }
        });
        assert_eq!(sidecar.status().state, SidecarState::Stopped);
        assert_eq!(capture.find(STOPPED).len(), 1);
        assert_eq!(sidecar.threads(), 0);
    }

    /// `request_stop` returns at once and starts the stop; the child's slow
    /// exit is a stop, not a failure, nothing is restarted, and `stop`
    /// then waits for the end. After that both are no-ops.
    #[test]
    fn request_stop_starts_the_stop_and_returns_at_once() {
        let dir = TempDir::new("request");
        let binary = dir.stub("trap 'sleep 1; exit 0' TERM\necho ready\nsleep 30 &\nwait");
        let capture = Capture::default();
        let sidecar = Sidecar::start_with(config(&dir, binary), capture.options()).unwrap();
        let pid = wait_until("a running child", || running_pid(&sidecar));
        let start = start_time(pid);
        capture.wait_for("ready");

        let before = Instant::now();
        sidecar.request_stop();
        let took = before.elapsed();
        assert!(took < ms(500), "request_stop took {took:?}");
        wait_until("the stop to begin", || {
            matches!(
                sidecar.status().state,
                SidecarState::ShuttingDown { pid: Some(p) } if p == pid
            )
            .then_some(())
        });
        assert!(exists(pid, start), "the child takes its time to exit");
        // Twice does no harm.
        sidecar.request_stop();

        sidecar.stop();
        let status = sidecar.status();
        assert_eq!(status.state, SidecarState::Stopped);
        assert_eq!(status.restarts, 0);
        assert_eq!(status.consecutive_failures, 0);
        assert!(capture.find(FAILED).is_empty());
        assert_eq!(capture.find(STOPPED).len(), 1);
        assert!(!exists(pid, start), "the child was reaped");
        assert_eq!(sidecar.threads(), 0);
        // Nothing left to ask.
        sidecar.request_stop();
        sidecar.stop();
    }

    /// `check_binary` runs what the start checks and starts nothing.
    #[test]
    fn check_binary_judges_the_binary_alone() {
        let dir = TempDir::new("check");
        let capture = Capture::default();
        let good = dir.stub("exit 3");
        assert_eq!(
            check_binary_with(&config(&dir, good), &capture.options()),
            Ok(TESTED_VERSION)
        );

        let old = dir.versioned_stub("old", "0.14.2", "exit 3");
        let found = Version {
            major: 0,
            minor: 14,
            patch: 2,
            pre: None,
        };
        assert_eq!(
            check_binary_with(&config(&dir, old), &capture.options()),
            Err(SidecarError::IncompatibleVersion {
                found,
                tested: TESTED_VERSION
            })
        );

        // The settings come first.
        let relative = config(&dir, PathBuf::from("routinator"));
        assert_eq!(
            check_binary_with(&relative, &capture.options()),
            Err(SidecarError::BinaryNotAbsolute(PathBuf::from("routinator")))
        );

        let hung = dir.script("hung", "exec sleep 30");
        let mut options = capture.options();
        options.version_timeout = ms(300);
        let started = Instant::now();
        assert!(matches!(
            check_binary_with(&config(&dir, hung), &options),
            Err(SidecarError::VersionTimeout { .. })
        ));
        assert!(started.elapsed() < Duration::from_secs(5));

        let missing = config(&dir, dir.join("missing"));
        assert!(matches!(
            check_binary(&missing),
            Err(SidecarError::VersionCheck { .. })
        ));
        assert!(capture.find("found a supported Routinator").is_empty());
    }

    /// A process that left the child's process group escapes the group
    /// signal and keeps the child's output socket open; `finish` still
    /// ends and joins the reader, by shutting the socket down.
    #[test]
    fn finish_ends_a_reader_whose_socket_an_escaped_process_holds() {
        let dir = TempDir::new("escape");
        let pid_file = dir.join("escaped.pid");
        let (ours, theirs) = output_pair().unwrap();
        // The escaped process writes its own id once `setsid` has taken
        // it out of the group. `$!` would be known as soon as the shell
        // forked, before `setsid` ran, and a group signal sent in between
        // would still reach it.
        let script = "setsid /bin/sh -c 'echo $$ > \"$1\"; exec sleep 30' sh \"$1\" & wait";
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", script, "sh"])
            .arg(&pid_file)
            .stdout(stdio(theirs))
            .process_group(0);
        let threads = Threads::default();
        let mut child = ChildProc::spawn(&mut cmd, &threads, |_, _| {}).unwrap();
        drop(cmd);
        child
            .add_reader("sidecar-test", &threads, ours, |stream| {
                read_bounded(&stream, 64)
            })
            .unwrap();
        let escaped = wait_until("the escaped process", || {
            fs::read_to_string(&pid_file)
                .ok()?
                .trim()
                .parse::<u32>()
                .ok()
        });
        let start = start_time(escaped);

        let before = Instant::now();
        let (status, outputs) = child.finish(true);
        let took = before.elapsed();
        let survived = matches!(proc_stat(escaped), Some((state, s)) if s == start && state != 'Z');
        // Not this process's child any more, but the same user's.
        let _ = send_signal(escaped, ChildSignal::Kill);
        assert!(survived, "the escaped process was not in the group");
        assert!(took < Duration::from_secs(5), "finished after {took:?}");
        assert_eq!(status.unwrap().signal(), Some(ChildSignal::Kill.number()));
        assert!(matches!(outputs.as_slice(), [Some(Ok(_))]), "{outputs:?}");
        assert_eq!(threads.load(Ordering::Acquire), 0);
    }

    #[test]
    fn port_zero_is_replaced_with_a_free_port() {
        let fixed: SocketAddr = "127.0.0.1:3323".parse().unwrap();
        assert_eq!(resolve_rtr(fixed), Ok(fixed));
        for ip in ["127.0.0.1", "127.0.0.53"] {
            let addr = resolve_rtr(SocketAddr::new(ip.parse().unwrap(), 0)).unwrap();
            assert_eq!(addr.ip().to_string(), ip);
            assert_ne!(addr.port(), 0);
            // The probe socket is closed, so Routinator can bind the port.
            drop(TcpListener::bind(addr).expect("the port is free again"));
        }
    }

    #[test]
    fn jitter_seeds_are_never_zero() {
        assert_ne!(jitter_seed(), 0);
    }
}

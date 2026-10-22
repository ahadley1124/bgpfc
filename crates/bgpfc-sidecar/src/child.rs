//! One child process from spawn to reap: its command line, environment
//! and process group, its output on socket pairs read by threads, and a
//! waiter thread that learns of its exit without reaping it.
//!
//! Implements: no RFC.

use std::ffi::OsString;
use std::io;
use std::net::Shutdown;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};

use bgpfc_sys::{
    ChildSignal, send_signal, send_signal_to_group, set_parent_death_signal, wait_for_exit,
};

use crate::config::SidecarConfig;

/// The signal a child gets when the supervisor thread that spawned it
/// dies (`PR_SET_PDEATHSIG`): `SIGKILL`.
///
/// It fires only when nothing is left to supervise the child: bgpfcd
/// crashed or was killed, or the supervisor thread panicked. A requested
/// stop never relies on it; that sends `SIGTERM` first. When it fires,
/// nobody is left to escalate a `SIGTERM` that the child ignores or is
/// slow to act on, and a validator that outlived its daemon would keep
/// the RTR port, so the next bgpfcd's sidecar could not bind it. `SIGKILL`
/// needs nothing from the child: it cannot be caught, ignored or blocked,
/// so the signal mask the child inherits from the spawning thread does not
/// matter either. Routinator keeps a cache, which it must already
/// rebuild after a power cut or an OOM kill, so dying without cleanup
/// loses nothing it cannot fetch again.
///
/// The kernel clears the setting when the child changes its user or
/// group (`prctl(2)`), and Routinator does that in server mode when its
/// `user` or `group` setting is given. The escape hatch therefore refuses
/// `--user` and `--group`, and a Routinator config file must not set
/// them. When bgpfcd runs unprivileged, as it should once it has dropped
/// root, Routinator cannot switch to another user anyway: it exits with
/// an error, which the supervisor reports.
pub(crate) const DEATH_SIGNAL: ChildSignal = ChildSignal::Kill;

/// `PATH` in the child: systemd's default for services, whatever bgpfcd's
/// own `PATH` is. The binary itself is never looked up (it is absolute),
/// but Routinator runs `rsync` by name (`--rsync-command`, default
/// `rsync`), and that lookup should not depend on how bgpfcd was started.
/// Point `rsync-command` in a Routinator config file at an absolute path
/// to use an `rsync` elsewhere.
pub(crate) const CHILD_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// The child's whole environment: nothing is inherited from bgpfcd.
///
/// - `HOME` is the repository directory. Without `--config`, Routinator
///   reads `$HOME/.routinator.conf` if it exists, and with `HOME` unset it
///   would fall back to the service user's home from the password
///   database. The repository directory is absolute, belongs to the
///   validator and is under bgpfcd's control, so a stray file in a home
///   directory cannot change the validator, and a program that does want
///   to write under `HOME` writes into the cache.
/// - `PATH` is [`CHILD_PATH`].
///
/// Everything else is dropped: `RSYNC_RSH`, which Routinator 0.15.2
/// refuses to start with (`Changelog.md`), locale and proxy settings
/// (Routinator takes RRDP proxies from its config file, `rrdp-proxies`),
/// and whatever bgpfcd was started with. The child's behaviour then
/// depends on bgpfcd's settings alone.
pub(crate) fn child_env(config: &SidecarConfig) -> [(OsString, OsString); 2] {
    [
        (
            "HOME".into(),
            config.repository_dir.clone().into_os_string(),
        ),
        ("PATH".into(), CHILD_PATH.into()),
    ]
}

/// A command for the configured binary, without arguments or output yet:
/// the environment of [`child_env`], `/` as working directory, standard
/// input from `/dev/null`, a process group of its own, and
/// [`DEATH_SIGNAL`] as the parent-death signal.
///
/// Its own process group keeps a terminal's Ctrl-C, which goes to the
/// whole foreground group, from reaching the child at the same moment as
/// bgpfcd (its exit would look like a crash), and lets
/// [`ChildProc::finish`] clean up what the child started.
pub(crate) fn command(config: &SidecarConfig) -> Command {
    let mut cmd = Command::new(&config.binary);
    cmd.env_clear()
        .envs(child_env(config))
        .current_dir("/")
        .stdin(Stdio::null())
        .process_group(0);
    set_parent_death_signal(&mut cmd, DEATH_SIGNAL);
    cmd
}

/// A socket pair for the child's output: the end to read, and the end to
/// give the child as stdout or stderr with [`stdio`].
///
/// A socket rather than a pipe, because shutting down its reading end
/// wakes a thread blocked reading it, with end-of-file once the data
/// already queued has been read. A process that the child started and
/// that escaped its process group can keep a pipe open for ever; with a
/// socket, [`ChildProc::finish`] still ends and joins every reader. Both
/// ends are close-on-exec, so later children do not inherit them.
pub(crate) fn output_pair() -> io::Result<(UnixStream, UnixStream)> {
    UnixStream::pair()
}

/// `end` as a child's standard stream. Spawning duplicates it into the
/// child; drop the [`Command`] afterwards to close this process's copy.
pub(crate) fn stdio(end: UnixStream) -> Stdio {
    Stdio::from(OwnedFd::from(end))
}

/// The wait status to report for a child that [`ChildProc::finish`] could
/// not reap, which only happens if something else in the process reaped
/// it (`ECHILD`), or if `SIGCHLD` is ignored, which makes the kernel reap
/// it. `0xffff` means "continued" (`WIFCONTINUED`), never how a
/// process ends, so it reads as [`ExitReason::Other`](crate::ExitReason)
/// rather than as an exit code or a signal the child never had.
pub(crate) fn unknown_status() -> ExitStatus {
    ExitStatus::from_raw(0xffff)
}

/// Counts the threads [`spawn_thread`] started that have not finished.
pub(crate) type Threads = Arc<AtomicUsize>;

/// Decrements the count when the thread's work ends, even by a panic.
struct Running(Threads);

impl Drop for Running {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Start a named thread running `work`, counted in `threads` until `work`
/// returns.
pub(crate) fn spawn_thread<T: Send + 'static>(
    name: &str,
    threads: &Threads,
    work: impl FnOnce() -> T + Send + 'static,
) -> io::Result<JoinHandle<T>> {
    threads.fetch_add(1, Ordering::AcqRel);
    let running = Running(Arc::clone(threads));
    thread::Builder::new().name(name.to_owned()).spawn(move || {
        let _running = running;
        work()
    })
    // If the thread could not start, the closure is dropped with
    // `running` in it, which takes the count back.
}

/// A thread reading one output stream of the child, and a handle on the
/// stream to end that reading.
struct Reader<T> {
    stream: UnixStream,
    thread: JoinHandle<T>,
}

/// One running child with its waiter and reader threads.
///
/// The thread that holds this is the only one that reaps the child, in
/// [`finish`](Self::finish), so until then [`pid`](Self::pid) names this
/// child and no other process, and signalling it is safe. Dropping it
/// without `finish` kills the child and cleans up as `finish(true)`
/// does, so a panic leaves neither a zombie nor an orphan behind.
///
/// That rests on nothing else in the process reaping the child. If
/// something does, the waiter's [`wait_for_exit`] fails with `ECHILD`,
/// and from then on the id and the process group id may name newer
/// processes: [`finish`](Self::finish) then signals neither.
pub(crate) struct ChildProc<T: Send + 'static> {
    child: Child,
    pid: u32,
    waiter: Option<JoinHandle<()>>,
    /// Set by the waiter, before it calls `notify`, when waiting failed:
    /// the child was reaped elsewhere, so its ids are no longer its own.
    lost: Arc<AtomicBool>,
    readers: Vec<Reader<T>>,
    done: bool,
}

impl<T: Send + 'static> ChildProc<T> {
    /// Spawn `cmd`, whose output is already set up, and start its waiter
    /// thread. Once the child has exited, still unreaped, or waiting for
    /// it failed, the waiter calls `notify` with the child's id and the
    /// result of [`wait_for_exit`]; then call [`finish`](Self::finish).
    ///
    /// # Errors
    /// The spawn failure, or the failure to start the waiter, after
    /// which the child is killed and reaped.
    pub(crate) fn spawn(
        cmd: &mut Command,
        threads: &Threads,
        notify: impl FnOnce(u32, io::Result<()>) + Send + 'static,
    ) -> io::Result<ChildProc<T>> {
        Self::spawn_with(cmd, threads, wait_for_exit, notify)
    }

    /// [`spawn`](Self::spawn), with the waiter calling `wait` instead of
    /// [`wait_for_exit`], so a test can make waiting fail.
    fn spawn_with(
        cmd: &mut Command,
        threads: &Threads,
        wait: fn(u32) -> io::Result<()>,
        notify: impl FnOnce(u32, io::Result<()>) + Send + 'static,
    ) -> io::Result<ChildProc<T>> {
        let child = cmd.spawn()?;
        let pid = child.id();
        let lost = Arc::new(AtomicBool::new(false));
        let mut proc = ChildProc {
            child,
            pid,
            waiter: None,
            lost: Arc::clone(&lost),
            readers: Vec::new(),
            done: false,
        };
        // On an error `proc` is dropped, which kills and reaps the child.
        let waiter = spawn_thread("sidecar-wait", threads, move || {
            let result = wait(pid);
            if result.is_err() {
                lost.store(true, Ordering::Release);
            }
            notify(pid, result);
        })?;
        proc.waiter = Some(waiter);
        Ok(proc)
    }

    /// Start a thread named `name` that runs `read` on `stream`, the
    /// reading end of one of the child's output streams.
    ///
    /// # Errors
    /// The failure to duplicate the stream or start the thread. Drop
    /// `self` then: the child must not run with an unread output.
    pub(crate) fn add_reader(
        &mut self,
        name: &str,
        threads: &Threads,
        stream: UnixStream,
        read: impl FnOnce(UnixStream) -> T + Send + 'static,
    ) -> io::Result<()> {
        let handle = stream.try_clone()?;
        let thread = spawn_thread(name, threads, move || read(stream))?;
        self.readers.push(Reader {
            stream: handle,
            thread,
        });
        Ok(())
    }

    /// The child's process id, which is also its process group's.
    pub(crate) const fn pid(&self) -> u32 {
        self.pid
    }

    /// Whether the waiter found the child reaped by someone else.
    fn lost(&self) -> bool {
        self.lost.load(Ordering::Acquire)
    }

    /// End the child's life: after the waiter has reported its exit, or
    /// with `kill` at any time.
    ///
    /// In order: with `kill`, `SIGKILL` to the child; wait for the waiter,
    /// so the child has exited; `SIGKILL` to its process group, which
    /// removes what it started and left behind while its unreaped id
    /// still names the group; reap it; shut down the reading end of each
    /// output stream, so every reader reads what is queued and then
    /// stops; join the readers.
    ///
    /// If the waiter reported that waiting failed, something else reaped
    /// the child, and its id and its group's may already name newer
    /// processes. Neither signal is sent then, even with `kill`; reaping
    /// fails with `ECHILD`, and whatever the child left in its group runs
    /// on.
    ///
    /// Returns the result of reaping the child, its wait status, and what
    /// each reader returned, `None` for one that panicked.
    pub(crate) fn finish(mut self, kill: bool) -> (io::Result<ExitStatus>, Vec<Option<T>>) {
        self.end(kill)
    }

    fn end(&mut self, kill: bool) -> (io::Result<ExitStatus>, Vec<Option<T>>) {
        self.done = true;
        if kill && !self.lost() {
            // The child is unreaped, so the id is its own; if it has
            // exited already, the zombie takes the signal to no effect.
            let _ = send_signal(self.pid, ChildSignal::Kill);
        }
        if let Some(waiter) = self.waiter.take() {
            // The waiter returns once the child has exited, or once
            // waiting has failed, which `waitid(2)` does only for a child
            // that is gone: reaped elsewhere, or by the kernel while
            // `SIGCHLD` is ignored.
            let _ = waiter.join();
        }
        if !self.lost() {
            // ESRCH: nothing left in the group. Every other error leaves
            // only processes this one may not signal, which it cannot help.
            let _ = send_signal_to_group(self.pid, ChildSignal::Kill);
        }
        // Does not block for a lost child: it is gone, and this fails.
        let status = self.child.wait();
        let outputs = self
            .readers
            .drain(..)
            .map(|reader| {
                // Wakes a reader blocked on an empty socket even when a
                // process outside the group still holds the other end.
                let _ = reader.stream.shutdown(Shutdown::Read);
                reader.thread.join().ok()
            })
            .collect();
        (status, outputs)
    }
}

impl<T: Send + 'static> Drop for ChildProc<T> {
    fn drop(&mut self) {
        if !self.done {
            let _ = self.end(true);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn the_environment_is_home_and_path_only() {
        let config = SidecarConfig::new("/usr/bin/routinator", "/var/lib/bgpfc/rpki");
        let env = child_env(&config);
        assert_eq!(
            env,
            [
                ("HOME".into(), PathBuf::from("/var/lib/bgpfc/rpki").into()),
                ("PATH".into(), CHILD_PATH.into()),
            ]
        );
    }

    #[test]
    fn the_command_starts_clean() {
        let config = SidecarConfig::new("/usr/bin/routinator", "/var/lib/bgpfc/rpki");
        let cmd = command(&config);
        assert_eq!(cmd.get_program(), "/usr/bin/routinator");
        assert_eq!(cmd.get_args().count(), 0);
        assert_eq!(cmd.get_current_dir(), Some("/".as_ref()));
        let envs: Vec<_> = cmd
            .get_envs()
            .map(|(k, v)| (k.to_owned(), v.map(ToOwned::to_owned)))
            .collect();
        assert_eq!(
            envs,
            [
                ("HOME".into(), Some("/var/lib/bgpfc/rpki".into())),
                ("PATH".into(), Some(CHILD_PATH.into())),
            ]
        );
    }

    #[test]
    fn the_unknown_status_is_neither_an_exit_nor_a_signal() {
        let status = unknown_status();
        assert_eq!(status.code(), None);
        assert_eq!(status.signal(), None);
        assert!(!status.success());
    }

    #[test]
    fn thread_counts_go_back_down() {
        let threads = Threads::default();
        let handle = spawn_thread("sidecar-test", &threads, || 7).unwrap();
        assert_eq!(handle.join().unwrap(), 7);
        assert_eq!(threads.load(Ordering::Acquire), 0);
        let handle = spawn_thread("sidecar-test", &threads, || -> u8 { panic!("boom") }).unwrap();
        assert!(handle.join().is_err());
        assert_eq!(threads.load(Ordering::Acquire), 0);
    }

    /// Live tests of what [`ChildProc::finish`] signals.
    #[cfg(not(miri))]
    mod live {
        use super::super::*;
        use std::io::{BufRead, BufReader};
        use std::sync::mpsc;
        use std::time::{Duration, Instant};

        /// `ECHILD`, `<asm-generic/errno-base.h>`.
        const ECHILD: i32 = 10;

        /// Start time (clock ticks after boot, `proc_pid_stat(5)` field
        /// 22) of `pid` while it runs; `None` once it is gone or a zombie.
        fn running_since(pid: u32) -> Option<u64> {
            let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
            // The command name (field 2) may hold spaces and parentheses.
            let (_, rest) = text.rsplit_once(')')?;
            let mut fields = rest.split_whitespace();
            let state = fields.next()?;
            let start = fields.nth(18)?.parse().ok()?;
            (!matches!(state, "Z" | "X" | "x")).then_some(start)
        }

        /// Waits like [`wait_for_exit`], then fails as it does for a child
        /// that something else reaped. The child is in fact a zombie still,
        /// so `finish` can reap it and the test leaks nothing.
        fn wait_then_lose(pid: u32) -> io::Result<()> {
            wait_for_exit(pid)?;
            Err(io::Error::from_raw_os_error(ECHILD))
        }

        /// A child in its own group leaves a `sleep` behind and exits 3,
        /// its waiter calls `wait`, and then `finish(true)` runs. Returns
        /// whether the `sleep` still runs a while later (and kills it if
        /// so), whether the waiter reported success, and how the child
        /// ended.
        fn leftover_after_finish(wait: fn(u32) -> io::Result<()>) -> (bool, bool, ExitStatus) {
            let mut cmd = Command::new("/bin/sh");
            cmd.args(["-c", "sleep 30 > /dev/null 2>&1 & echo $!; exit 3"])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .process_group(0);
            let threads = Threads::default();
            let (tx, rx) = mpsc::channel();
            let mut proc = ChildProc::<()>::spawn_with(&mut cmd, &threads, wait, move |_, r| {
                let _ = tx.send(r.is_ok());
            })
            .unwrap();
            let mut line = String::new();
            let stdout = proc.child.stdout.take().unwrap();
            BufReader::new(stdout).read_line(&mut line).unwrap();
            let leftover: u32 = line.trim().parse().unwrap();
            let start = running_since(leftover).expect("the leftover runs");
            let waited = rx.recv_timeout(Duration::from_secs(10)).unwrap();
            let (status, outputs) = proc.finish(true);
            assert_eq!(outputs, [], "no readers were added");
            assert_eq!(threads.load(Ordering::Acquire), 0);
            // A SIGKILL, if one was sent, has arrived by the deadline.
            let deadline = Instant::now() + Duration::from_millis(500);
            while running_since(leftover) == Some(start) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            let survived = running_since(leftover) == Some(start);
            if survived {
                // Reparented, but still this user's to signal.
                send_signal(leftover, ChildSignal::Kill).unwrap();
            }
            (survived, waited, status.unwrap())
        }

        /// The control: the group signal ends what the child left behind.
        #[test]
        fn finish_ends_what_the_child_left_in_its_group() {
            let (survived, waited, status) = leftover_after_finish(wait_for_exit);
            assert!(waited);
            assert_eq!(status.code(), Some(3));
            assert!(!survived, "the group signal missed the leftover");
        }

        /// Once waiting failed, the child's id and group id may belong to
        /// newer processes, so `finish` signals neither, even with `kill`.
        #[test]
        fn a_child_reaped_elsewhere_is_not_signalled() {
            let (survived, waited, status) = leftover_after_finish(wait_then_lose);
            assert!(!waited);
            assert_eq!(status.code(), Some(3));
            assert!(survived, "the group of a lost child was signalled");
        }
    }
}

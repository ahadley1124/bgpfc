//! Supervising child processes: tie a child's life to the thread that
//! spawned it (`PR_SET_PDEATHSIG`, `prctl(2)`) and send it a chosen signal
//! (`kill(2)`), so a supervisor can ask for a graceful stop; std's
//! [`Child::kill`](std::process::Child::kill) only sends `SIGKILL`.
//!
//! A helper thread can also wait for a child's exit without reaping it
//! (`waitid(2)` with `WNOWAIT`), so the thread that owns the child stays
//! the only one that reaps it and its signals cannot reach a reused id.
//!
//! A signal can also go to a child's whole process group, to reach what
//! it started.
//!
//! Implements the process plumbing of the supervised RPKI relying-party
//! sidecar (GitHub issues #26, #70, #71, #72).

use std::ffi::{c_int, c_ulong};
use std::io;
use std::os::unix::process::CommandExt;
use std::process::Command;

use crate::ffi;

/// A signal a supervisor sends to a child process. The numbers come from
/// `<asm-generic/signal.h>` (`signal(7)`); each one terminates a process
/// that keeps the default disposition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ChildSignal {
    /// `SIGTERM` (15): ask the child to clean up and exit.
    Term,
    /// `SIGKILL` (9): end the child at once. It cannot be caught, blocked
    /// or ignored.
    Kill,
    /// `SIGINT` (2): interrupt, as Ctrl-C does.
    Int,
    /// `SIGHUP` (1): hang-up; many daemons reload their configuration on it.
    Hup,
}

impl ChildSignal {
    /// The signal number, as
    /// [`ExitStatusExt::signal`](std::os::unix::process::ExitStatusExt::signal)
    /// reports it for a child this signal ended.
    #[must_use]
    pub const fn number(self) -> i32 {
        match self {
            ChildSignal::Term => ffi::SIGTERM,
            ChildSignal::Kill => ffi::SIGKILL,
            ChildSignal::Int => ffi::SIGINT,
            ChildSignal::Hup => ffi::SIGHUP,
        }
    }
}

/// Make the child that `cmd` spawns receive `signal` when its parent goes
/// away (`PR_SET_PDEATHSIG`, `prctl(2)`), so a crash of the supervisor
/// cannot leave the child running unsupervised.
///
/// **The trigger is the exit of the spawning *thread*, not of the
/// process.** `prctl(2)`: "the 'parent' in this case is considered to be
/// the thread that created this process". A child spawned from a
/// short-lived thread is signalled as soon as that thread returns, while
/// the process lives on. Spawn from one thread that outlives the child,
/// such as a long-lived supervisor thread, and never from a scoped,
/// per-request or pool thread.
///
/// Call this in the process that calls [`Command::spawn`]: it records
/// this process's id now, and the child compares its parent against it.
/// The hook runs in the child between `fork` and `execve`, in this order:
///
/// 1. For a catchable `signal`, it installs a handler that ends the child
///    with `_exit(128 + signal)`. Until `execve` the child carries the
///    caller's signal handlers, and one of those would otherwise swallow
///    the death signal, after which the program would start with no
///    parent. `execve(2)` resets the handler to the default action, so
///    the program starts with `signal` at its default disposition (which
///    terminates) even if the caller ignores it: an ignored signal would
///    otherwise stay ignored across `execve`.
/// 2. It calls `prctl(PR_SET_PDEATHSIG, signal)`.
/// 3. It checks that `getppid()` still returns the recorded id. If the
///    parent died before step 2 took effect, the race `prctl(2)` warns
///    about, the child has already been reparented; it does not `execve`,
///    and the spawn fails with `ESRCH`.
///
/// The child inherits the spawning thread's signal mask; keep `signal`
/// unblocked there, or the death signal waits until the program unblocks
/// it. [`ChildSignal::Kill`] cannot be blocked, caught or ignored, so it
/// is the choice that does not depend on the child's cooperation;
/// [`ChildSignal::Term`] lets the child clean up first.
///
/// The kernel clears the setting, silently, when the child (`prctl(2)`):
///
/// - executes a set-user-ID or set-group-ID program, or one with file
///   capabilities;
/// - changes its effective or file-system user or group ID, as a program
///   that drops root with `setuid` or `setgid` does, or gains a
///   capability it did not have (`commit_creds` in `kernel/cred.c`).
///
/// So do not rely on it for a program that does either: run it as the
/// user it should end up as instead
/// ([`CommandExt::uid`](std::os::unix::process::CommandExt::uid) and
/// [`gid`](std::os::unix::process::CommandExt::gid) take effect before
/// this hook runs), and keep it from switching users itself. Like any
/// pre-exec hook, this makes std use `fork` and `execve` instead of
/// `posix_spawn`.
#[allow(unsafe_code, reason = "getpid takes no arguments and cannot fail")]
pub fn set_parent_death_signal(cmd: &mut Command, signal: ChildSignal) {
    // SAFETY: `getpid` has no preconditions and always succeeds.
    let parent = unsafe { ffi::getpid() };
    install_hook(cmd, signal, parent);
}

/// [`set_parent_death_signal`] with the parent id as a parameter, so a test
/// can stand in for a parent that died before the child checked.
#[allow(unsafe_code, reason = "a pre-exec hook and the FFI calls inside it")]
fn install_hook(cmd: &mut Command, signal: ChildSignal, parent: ffi::pid_t) {
    // Everything the hook needs is computed here, in the parent: the hook
    // itself must not allocate (signal-safety(7)).
    let number: c_int = signal.number();
    let arg = c_ulong::from(number.unsigned_abs());
    let catchable = signal != ChildSignal::Kill;
    let hook = move || -> io::Result<()> {
        if catchable {
            // SAFETY: `exit_before_exec` is an `extern "C" fn(c_int)` that
            // only calls `_exit`, and `signal` is async-signal-safe
            // (signal-safety(7)). It changes only this child's disposition:
            // after `fork` the child has its own copy.
            if unsafe { ffi::signal(number, exit_before_exec) } == c_ulong::MAX {
                // SIG_ERR is (sighandler_t)-1.
                return Err(io::Error::last_os_error());
            }
        }
        // SAFETY: `prctl` is variadic in `<sys/prctl.h>` and is passed the
        // four `unsigned long` arguments it reads; PR_SET_PDEATHSIG uses
        // only the second, a valid signal number. The C library wrapper is
        // a bare system call: no locks, no allocation.
        if unsafe {
            ffi::prctl(
                ffi::PR_SET_PDEATHSIG,
                arg,
                0 as c_ulong,
                0 as c_ulong,
                0 as c_ulong,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `getppid` has no preconditions, always succeeds and is
        // async-signal-safe (signal-safety(7)).
        if unsafe { ffi::getppid() } != parent {
            // The parent died between `fork` and `prctl`, so the death
            // signal will never come (prctl(2)). Returning an error makes
            // std `_exit` the child without running the program and report
            // the errno to `spawn`. The spawning thread cannot have exited
            // on its own: it is blocked in `spawn` until `execve` succeeds
            // or this error arrives, so a changed parent means the whole
            // process is gone.
            return Err(io::Error::from_raw_os_error(ffi::ESRCH));
        }
        Ok(())
    };
    // SAFETY: `pre_exec` requires the hook to be safe to run in a child of
    // a possibly multi-threaded process between `fork` and `execve`. It
    // calls `signal` and `getppid`, which are async-signal-safe
    // (signal-safety(7)), and `prctl`, a bare system call; it reads
    // `errno` and builds `io::Error`s from an OS error code, which does
    // not allocate. It captures four `Copy` values, takes no locks, does
    // no I/O and touches no memory shared with the parent. Returning `Err`
    // is the documented way to abort: std then `_exit`s the child, never
    // reaching `execve`, and `spawn` returns the error.
    unsafe {
        cmd.pre_exec(hook);
    }
}

/// The death signal's handler between `fork` and `execve`. `execve(2)`
/// replaces it with the default action, which also terminates.
#[allow(unsafe_code, reason = "`_exit(2)` from a signal handler")]
extern "C" fn exit_before_exec(signum: c_int) {
    // SAFETY: `_exit` is async-signal-safe (signal-safety(7)) and takes an
    // integer. It skips atexit handlers and stdio buffers, which are the
    // parent's state copied by `fork`. Signal numbers are at most 64, so
    // the sum cannot overflow; 128 + n is the shell's "killed by n".
    unsafe { ffi::_exit(128 + signum) }
}

/// Send `signal` to the process `pid` (`kill(2)`), for example
/// [`ChildSignal::Term`] to ask a child to stop gracefully.
///
/// `pid` must name one process. `0` and anything above `i32::MAX` are
/// refused before any system call: `kill` reads `0` as the caller's process
/// group, and a value above `i32::MAX` becomes a negative `pid_t`, which
/// means a process group or, for `-1`, every process the caller may signal.
///
/// Pass the id of a child that has not been reaped yet: the
/// [`Child::id`](std::process::Child::id) of a child before
/// [`Child::wait`](std::process::Child::wait) or a successful
/// [`Child::try_wait`](std::process::Child::try_wait). Until then the kernel
/// keeps the pid, at worst as a zombie, so it cannot name another process.
/// Once the child is reaped, the pid may be reused.
///
/// # Errors
/// `InvalidInput` for a `pid` that does not name a single process;
/// otherwise the `kill` failure, such as `ESRCH` when no such process
/// exists or `EPERM` when the caller may not signal it.
#[allow(unsafe_code, reason = "kill(2) with integer arguments")]
pub fn send_signal(pid: u32, signal: ChildSignal) -> io::Result<()> {
    let target = single_process(pid)?;
    // SAFETY: integer arguments only. `target` is positive, so `kill`
    // addresses exactly that process, never a group or every process.
    if unsafe { ffi::kill(target, signal.number()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `pid` as a `pid_t` that `kill(2)` reads as one process: positive.
fn single_process(pid: u32) -> io::Result<ffi::pid_t> {
    match ffi::pid_t::try_from(pid) {
        Ok(p) if p > 0 => Ok(p),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "pid must name one process: 1 to i32::MAX",
        )),
    }
}

/// Block until the child `pid` has terminated, and leave it unreaped
/// (`waitid(2)` with `P_PID` and `WEXITED | WNOWAIT`).
///
/// The child stays a zombie, so the kernel keeps its id, and a later
/// [`Child::wait`](std::process::Child::wait) or
/// [`Child::try_wait`](std::process::Child::try_wait) reaps it at once and
/// returns its status. This lets a helper thread wait for the exit while
/// the thread that owns the [`Child`](std::process::Child) goes on
/// signalling it by id with [`send_signal`]: only the owner reaps, so
/// until the owner has seen the exit, the id names this child and no
/// newer process. Waiting with [`Child::wait`](std::process::Child::wait)
/// on the helper thread instead would reap the child there, and a signal
/// the owner sends before it hears of that could reach a process that
/// reused the id.
///
/// Any thread may wait: by default `waitid` covers the children of every
/// thread in the process. `EINTR` is retried.
///
/// # Errors
/// `InvalidInput` for a `pid` that does not name a single process, before
/// any system call; otherwise the `waitid` failure, such as `ECHILD` when
/// `pid` is not a child of this process or was already reaped.
#[allow(unsafe_code, reason = "waitid(2) with a local siginfo_t")]
pub fn wait_for_exit(pid: u32) -> io::Result<()> {
    let target = single_process(pid)?;
    // `single_process` returned a positive `pid_t`, which fits `id_t`.
    let id = target.unsigned_abs();
    let mut info = ffi::siginfo_t {
        opaque: [0; ffi::SI_MAX_SIZE / size_of::<c_ulong>()],
    };
    loop {
        // SAFETY: `info` is a live, writable `siginfo_t` of the size and
        // alignment `<asm-generic/siginfo.h>` gives it, and `waitid`
        // writes nothing else. `P_PID` with a positive id names exactly
        // one process. `WNOWAIT` leaves the child waitable, so this does
        // not reap it and std's `Child` stays in charge of that.
        let rc = unsafe { ffi::waitid(ffi::P_PID, id, &raw mut info, ffi::WEXITED | ffi::WNOWAIT) };
        if rc == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

/// Send `signal` to every process in the process group `pgid` (`kill(2)`
/// with `-pgid`).
///
/// This is for a child started as the leader of its own group
/// ([`CommandExt::process_group`] with `0`): its group id is its process
/// id, and the processes it starts join the group unless they leave it,
/// so this reaches the helpers [`send_signal`] does not, such as those a
/// child that was killed left behind. Pass the id of a child that has not
/// been reaped yet, say after [`wait_for_exit`]: until then the kernel
/// keeps the id, and with it the group, so it cannot name a newer group.
///
/// `0`, `1` and anything above `i32::MAX` are refused before any system
/// call: `kill` reads a `pid` of `0` as the caller's own group, `-1` as
/// every process the caller may signal, and a value above `i32::MAX`
/// would turn positive.
///
/// # Errors
/// `InvalidInput` for a `pgid` that does not name one process group;
/// otherwise the `kill` failure, such as `ESRCH` when the group is empty
/// or `EPERM` when the caller may signal none of its members.
#[allow(unsafe_code, reason = "kill(2) with integer arguments")]
pub fn send_signal_to_group(pgid: u32, signal: ChildSignal) -> io::Result<()> {
    let group = match ffi::pid_t::try_from(pgid) {
        Ok(g) if g > 1 => g,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "pgid must name one process group: 2 to i32::MAX",
            ));
        }
    };
    // SAFETY: integer arguments only. `group` is 2 to `i32::MAX`, so
    // `-group` cannot overflow and lies in `-i32::MAX..=-2`: one process
    // group, never the caller's own (`0`) or every process (`-1`).
    if unsafe { ffi::kill(-group, signal.number()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The numbers of `<asm-generic/signal.h>` and `signal(7)`.
    #[test]
    fn numbers_match_the_headers() {
        assert_eq!(ChildSignal::Hup.number(), 1);
        assert_eq!(ChildSignal::Int.number(), 2);
        assert_eq!(ChildSignal::Kill.number(), 9);
        assert_eq!(ChildSignal::Term.number(), 15);
    }

    /// `kill(0)`, `kill(-1)` and process groups must be unreachable. These
    /// are refused before the system call, so this runs under Miri too.
    #[test]
    fn send_signal_refuses_anything_but_one_process() {
        let too_big = u32::try_from(i32::MAX).unwrap() + 1;
        for pid in [0, too_big, too_big + 1, u32::MAX - 1, u32::MAX] {
            let err = send_signal(pid, ChildSignal::Kill).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "pid {pid}");
            assert_eq!(err.raw_os_error(), None, "pid {pid}: no syscall made");
        }
        assert_eq!(single_process(1).unwrap(), 1);
        assert_eq!(single_process(too_big - 1).unwrap(), i32::MAX);
    }

    /// `waitid(P_PID, 0)` would wait for any child of the process group;
    /// such ids are refused before the system call, so this runs under
    /// Miri too.
    #[test]
    fn wait_for_exit_refuses_anything_but_one_process() {
        let too_big = u32::try_from(i32::MAX).unwrap() + 1;
        for pid in [0, too_big, u32::MAX] {
            let err = wait_for_exit(pid).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "pid {pid}");
            assert_eq!(err.raw_os_error(), None, "pid {pid}: no syscall made");
        }
    }

    /// `kill(0)` and `kill(-1)` must be unreachable through the group
    /// signal, as must a group id that would turn the `pid` positive.
    /// Refused before the system call, so this runs under Miri too.
    #[test]
    fn send_signal_to_group_refuses_own_group_and_everyone() {
        let too_big = u32::try_from(i32::MAX).unwrap() + 1;
        for pgid in [0, 1, too_big, u32::MAX] {
            let err = send_signal_to_group(pgid, ChildSignal::Kill).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "pgid {pgid}");
            assert_eq!(err.raw_os_error(), None, "pgid {pgid}: no syscall made");
        }
    }

    #[cfg(not(miri))]
    mod live {
        use super::super::*;
        use std::os::unix::process::ExitStatusExt;
        use std::path::{Path, PathBuf};
        use std::process::{Child, Stdio};
        use std::time::{Duration, Instant};

        /// A fresh directory under the system temp dir, removed on drop.
        struct TempDir(PathBuf);

        impl TempDir {
            fn new(tag: &str) -> TempDir {
                let nanos = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos();
                let path = std::env::temp_dir()
                    .join(format!("bgpfc-sys-{tag}-{}-{nanos}", std::process::id()));
                std::fs::create_dir(&path).unwrap();
                TempDir(path)
            }
        }

        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        /// State letter and start time (clock ticks after boot) of `pid`
        /// from `/proc/<pid>/stat` (`proc_pid_stat(5)`, fields 3 and 22),
        /// or `None` if there is no such process.
        fn proc_stat(pid: u32) -> Option<(char, u64)> {
            let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
            // The command name (field 2) is parenthesised and may contain
            // spaces or parentheses itself, so split after the last `)`.
            let (_, rest) = text.rsplit_once(')')?;
            let mut fields = rest.split_whitespace();
            let state = fields.next()?.chars().next()?;
            // Fields 4 to 21 lie between the state and the start time.
            let started = fields.nth(18)?.parse().ok()?;
            Some((state, started))
        }

        /// Whether the process that had `pid` and `start` still runs: not
        /// gone, not a zombie, and not a newer process reusing the pid.
        fn running(pid: u32, start: u64) -> bool {
            matches!(proc_stat(pid), Some((state, s)) if s == start && !matches!(state, 'Z' | 'X' | 'x'))
        }

        fn sleep_30() -> Command {
            let mut cmd = Command::new("/bin/sleep");
            cmd.arg("30")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            cmd
        }

        fn wait_with_deadline(child: &mut Child, limit: Duration) -> std::process::ExitStatus {
            let deadline = Instant::now() + limit;
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    return status;
                }
                assert!(Instant::now() < deadline, "child did not exit in time");
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        /// The hook lets the program run, and `send_signal(Term)` stops it
        /// with `SIGTERM`, which `Child::kill` cannot send.
        #[test]
        fn hooked_child_runs_and_term_stops_it() {
            let mut cmd = sleep_30();
            set_parent_death_signal(&mut cmd, ChildSignal::Term);
            let mut child = cmd.spawn().expect("spawn /bin/sleep with the hook");
            // `spawn` returns once `execve` closes the close-on-exec pipe,
            // which can be just before the kernel fills in the new argument
            // area, so the command line may need a moment to appear.
            let path = format!("/proc/{}/cmdline", child.id());
            let deadline = Instant::now() + Duration::from_secs(5);
            while std::fs::read(&path).unwrap() != b"/bin/sleep\x0030\x00" {
                assert!(Instant::now() < deadline, "the program was not executed");
                std::thread::sleep(Duration::from_millis(10));
            }
            assert!(child.try_wait().unwrap().is_none(), "still running");

            send_signal(child.id(), ChildSignal::Term).unwrap();
            let status = wait_with_deadline(&mut child, Duration::from_secs(5));
            assert_eq!(status.signal(), Some(ChildSignal::Term.number()));
        }

        /// Every signal is accepted by `prctl` and does not stop the
        /// program from running.
        #[test]
        fn every_signal_can_be_the_death_signal() {
            for signal in [
                ChildSignal::Term,
                ChildSignal::Kill,
                ChildSignal::Int,
                ChildSignal::Hup,
            ] {
                let mut cmd = Command::new("/bin/true");
                set_parent_death_signal(&mut cmd, signal);
                let status = cmd.status().expect("spawn /bin/true with the hook");
                assert!(status.success(), "{signal:?}: {status}");
            }
        }

        /// The branch for a parent that died before `prctl` took effect:
        /// with a recorded parent that is not the child's parent, the
        /// spawn fails with `ESRCH` and the program never runs.
        #[test]
        fn a_child_whose_parent_changed_never_executes() {
            let dir = TempDir::new("pdeath-race");
            let marker = dir.0.join("ran");
            let mut cmd = Command::new("/bin/sh");
            cmd.args(["-c", ": > \"$1\"", "sh"]).arg(&marker);
            // pid_max is at most 2^22 (proc(5)), so no process has this id.
            install_hook(&mut cmd, ChildSignal::Term, i32::MAX);
            let err = cmd.spawn().expect_err("the hook must refuse to exec");
            assert_eq!(err.raw_os_error(), Some(ffi::ESRCH));
            assert!(!marker.exists(), "the program ran");
        }

        /// Set by [`parent_death_case`] for the copy of this test binary
        /// that plays the intermediate process.
        const INTERMEDIATE_ENV: &str = "BGPFC_SYS_TEST_PDEATH_DIR";

        /// Not a test on its own: [`parent_death_case`] runs this test
        /// binary again with [`INTERMEDIATE_ENV`] set, and this function
        /// then spawns the grandchildren. Without the variable it returns
        /// at once.
        #[test]
        fn pdeath_intermediate() {
            let Some(dir) = std::env::var_os(INTERMEDIATE_ENV) else {
                return;
            };
            let dir = PathBuf::from(dir);
            let mut hooked = sleep_30();
            set_parent_death_signal(&mut hooked, ChildSignal::Term);
            let mut hooked = hooked.spawn().unwrap();
            let mut bare = sleep_30().spawn().unwrap();
            let tmp = dir.join("pids.tmp");
            std::fs::write(&tmp, format!("{} {}\n", hooked.id(), bare.id())).unwrap();
            std::fs::rename(&tmp, dir.join("pids")).unwrap();
            // The outer test SIGKILLs this process now. If it does not,
            // clean up instead of leaving the grandchildren behind.
            std::thread::sleep(Duration::from_secs(30));
            for child in [&mut hooked, &mut bare] {
                let _ = child.kill();
                let _ = child.wait();
            }
        }

        fn wait_for_pids(path: &Path, intermediate: &mut Child) -> (u32, u32) {
            let deadline = Instant::now() + Duration::from_secs(20);
            loop {
                if let Ok(text) = std::fs::read_to_string(path) {
                    let mut it = text.split_whitespace().map(|p| p.parse::<u32>().unwrap());
                    return (it.next().unwrap(), it.next().unwrap());
                }
                if let Some(status) = intermediate.try_wait().unwrap() {
                    let mut err = String::new();
                    if let Some(mut stderr) = intermediate.stderr.take() {
                        let _ = std::io::Read::read_to_string(&mut stderr, &mut err);
                    }
                    panic!("intermediate exited ({status}) before spawning: {err}");
                }
                if Instant::now() >= deadline {
                    let _ = intermediate.kill();
                    let _ = intermediate.wait();
                    panic!("intermediate never wrote the pids");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        /// Whether `pid` ignores `signal`: the `SigIgn` mask of
        /// `/proc/<pid>/status` (`proc_pid_status(5)`), bit `signal - 1`.
        fn ignores(pid: u32, signal: ChildSignal) -> bool {
            let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
            let mask = status
                .lines()
                .find_map(|l| l.strip_prefix("SigIgn:"))
                .map(|v| u64::from_str_radix(v.trim(), 16).unwrap())
                .unwrap();
            mask & (1 << (signal.number() - 1)) != 0
        }

        /// End to end: an intermediate process spawns one grandchild with
        /// the hook (death signal `SIGTERM`) and one without, then is
        /// killed with `SIGKILL`. The hooked grandchild must die promptly;
        /// the bare one, the control, must survive, which shows the death
        /// came from the hook. With `ignore_term`, the intermediate starts
        /// with `SIGTERM` ignored, which `execve` would pass on to both
        /// grandchildren if the hook did not reset it.
        fn parent_death_case(ignore_term: bool) {
            let dir = TempDir::new("pdeath");
            let exe = std::env::current_exe().unwrap();
            let mut cmd = if ignore_term {
                // `trap "" TERM` sets SIGTERM to SIG_IGN, and an ignored
                // signal stays ignored across `exec` (execve(2)).
                let mut sh = Command::new("/bin/sh");
                sh.args(["-c", "trap '' TERM; exec \"$0\" \"$@\""]).arg(exe);
                sh
            } else {
                Command::new(exe)
            };
            let mut intermediate = cmd
                .args([
                    "--exact",
                    "process::tests::live::pdeath_intermediate",
                    "--test-threads=1",
                ])
                .env(INTERMEDIATE_ENV, &dir.0)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let (hooked, bare) = wait_for_pids(&dir.0.join("pids"), &mut intermediate);
            let (_, hooked_start) = proc_stat(hooked).expect("hooked grandchild exists");
            let (_, bare_start) = proc_stat(bare).expect("bare grandchild exists");
            assert!(running(hooked, hooked_start));
            assert!(running(bare, bare_start));
            let hooked_ignores = ignores(hooked, ChildSignal::Term);
            let bare_ignores = ignores(bare, ChildSignal::Term);

            send_signal(intermediate.id(), ChildSignal::Kill).unwrap();
            let status = intermediate.wait().unwrap();
            assert_eq!(status.signal(), Some(ChildSignal::Kill.number()));

            let deadline = Instant::now() + Duration::from_secs(5);
            while running(hooked, hooked_start) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            let hooked_survived = running(hooked, hooked_start);
            let bare_survived = running(bare, bare_start);
            // Clean up before asserting, so a failure leaks nothing. The
            // orphans now belong to init or a subreaper, but the same user
            // may still signal them.
            for (pid, survived) in [(hooked, hooked_survived), (bare, bare_survived)] {
                if survived {
                    send_signal(pid, ChildSignal::Kill).unwrap();
                }
            }
            assert!(!hooked_ignores, "the hook left SIGTERM ignored");
            assert_eq!(bare_ignores, ignore_term, "the control inherits SIG_IGN");
            assert!(
                !hooked_survived,
                "the hooked grandchild outlived its parent"
            );
            assert!(
                bare_survived,
                "the grandchild without the hook died as well"
            );
        }

        #[test]
        fn parent_death_signals_the_grandchild() {
            parent_death_case(false);
        }

        #[test]
        fn parent_death_signal_overrides_an_ignored_signal() {
            parent_death_case(true);
        }

        /// `ECHILD` from `waitid(2)`, `<asm-generic/errno-base.h>`.
        const ECHILD: i32 = 10;

        /// The child is left a zombie: still there under its id, and
        /// `Child::try_wait` then reaps it and gets its status.
        #[test]
        fn wait_for_exit_leaves_the_child_to_reap() {
            let mut child = Command::new("/bin/sh")
                .args(["-c", "exit 7"])
                .spawn()
                .expect("spawn /bin/sh");
            wait_for_exit(child.id()).unwrap();
            let (state, _) = proc_stat(child.id()).expect("the zombie keeps its id");
            assert_eq!(state, 'Z', "exited but not reaped");
            // Waiting again sees the same unreaped exit.
            wait_for_exit(child.id()).unwrap();
            let status = child.try_wait().unwrap().expect("reaped at once");
            assert_eq!(status.code(), Some(7));
            let err = wait_for_exit(child.id()).unwrap_err();
            assert_eq!(err.raw_os_error(), Some(ECHILD), "already reaped");
        }

        /// A thread blocks until the child ends, while the thread that
        /// owns the `Child` signals it by id.
        #[test]
        fn wait_for_exit_blocks_until_the_child_ends() {
            let mut child = sleep_30().spawn().expect("spawn /bin/sleep");
            let pid = child.id();
            let (tx, rx) = std::sync::mpsc::channel();
            let waiter = std::thread::spawn(move || tx.send(wait_for_exit(pid)).unwrap());
            let early = rx.recv_timeout(Duration::from_millis(200));
            send_signal(pid, ChildSignal::Term).unwrap();
            let result = rx.recv_timeout(Duration::from_secs(5));
            waiter.join().unwrap();
            let status = wait_with_deadline(&mut child, Duration::from_secs(5));
            assert!(early.is_err(), "returned while the child ran: {early:?}");
            result
                .expect("the waiter returns once the child ends")
                .unwrap();
            assert_eq!(status.signal(), Some(ChildSignal::Term.number()));
        }

        /// A process that is not a child of this one cannot be waited for.
        #[test]
        fn wait_for_exit_needs_a_child() {
            let err = wait_for_exit(1).unwrap_err();
            assert_eq!(err.raw_os_error(), Some(ECHILD));
        }

        /// The group signal reaches what a group leader started and left
        /// behind, and nothing outside the group: a shell in its own group
        /// starts `sleep` in the background, the group gets `SIGKILL`, and
        /// a `sleep` outside the group, the control, survives.
        #[test]
        fn group_signal_reaches_the_grandchildren() {
            use std::io::BufRead;

            let mut leader = Command::new("/bin/sh")
                .args(["-c", "/bin/sleep 30 & echo $!; wait"])
                .process_group(0)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .spawn()
                .expect("spawn /bin/sh");
            let mut line = String::new();
            std::io::BufReader::new(leader.stdout.take().unwrap())
                .read_line(&mut line)
                .unwrap();
            let grandchild: u32 = line.trim().parse().unwrap();
            let mut control = sleep_30().spawn().expect("spawn /bin/sleep");
            let (_, grandchild_start) = proc_stat(grandchild).expect("grandchild exists");
            let (_, control_start) = proc_stat(control.id()).expect("control exists");

            // The leader is unreaped, so its id still names this group.
            send_signal_to_group(leader.id(), ChildSignal::Kill).unwrap();
            let status = wait_with_deadline(&mut leader, Duration::from_secs(5));
            let deadline = Instant::now() + Duration::from_secs(5);
            while running(grandchild, grandchild_start) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            let grandchild_survived = running(grandchild, grandchild_start);
            let control_survived = running(control.id(), control_start);
            if grandchild_survived {
                send_signal(grandchild, ChildSignal::Kill).unwrap();
            }
            let _ = control.kill();
            let _ = control.wait();
            assert_eq!(status.signal(), Some(ChildSignal::Kill.number()));
            assert!(
                !grandchild_survived,
                "the group signal missed the grandchild"
            );
            assert!(control_survived, "the group signal reached another group");
        }
    }
}

//! `SIGTERM`, `SIGINT` and `SIGHUP` delivered to a thread that can act on
//! them (AGENTS.md §3, "Signals"): the handler only writes one byte to a
//! pipe, which is async-signal-safe (`signal-safety(7)`).

use std::ffi::{c_int, c_void};
use std::io::{self, Read};
use std::os::fd::{FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicI32, Ordering};

use crate::ffi;

/// A signal the daemon reacts to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signal {
    /// `SIGTERM`: shut down.
    Term,
    /// `SIGINT`: shut down.
    Int,
    /// `SIGHUP`: reload the configuration.
    Hup,
}

impl Signal {
    const fn from_number(n: c_int) -> Option<Signal> {
        match n {
            ffi::SIGTERM => Some(Signal::Term),
            ffi::SIGINT => Some(Signal::Int),
            ffi::SIGHUP => Some(Signal::Hup),
            _ => None,
        }
    }
}

/// The write end of the self-pipe, for the handler. `-1` until installed.
static PIPE_WRITER: AtomicI32 = AtomicI32::new(-1);

#[allow(unsafe_code, reason = "a `write(2)` from a signal handler")]
extern "C" fn handler(signum: c_int) {
    let fd = PIPE_WRITER.load(Ordering::Relaxed);
    if fd < 0 {
        return;
    }
    // Signal numbers fit a byte (they are at most 64).
    let byte = u8::try_from(signum).unwrap_or(0);
    // SAFETY: `byte` is a live local for the duration of the call and the
    // length is 1; `write` is async-signal-safe. A failure (a full pipe
    // after thousands of unread signals) loses nothing worth keeping.
    let _ = unsafe { ffi::write(fd, (&raw const byte).cast::<c_void>(), 1) };
}

/// Installed handlers and the pipe they write to.
#[derive(Debug)]
pub struct Signals {
    reader: std::fs::File,
    _writer: OwnedFd,
}

impl Signals {
    /// Install handlers for `SIGTERM`, `SIGINT` and `SIGHUP`. Call once,
    /// before spawning threads, so every thread inherits the disposition.
    ///
    /// # Errors
    /// The `pipe` or `signal` failure, or if already installed.
    #[allow(unsafe_code, reason = "pipe and signal FFI")]
    pub fn install() -> io::Result<Signals> {
        if PIPE_WRITER.load(Ordering::Relaxed) >= 0 {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "signal handlers already installed",
            ));
        }
        let mut fds: [c_int; 2] = [-1, -1];
        // SAFETY: `fds` is a writable array of two ints, as `pipe(2)` wants.
        if unsafe { ffi::pipe(fds.as_mut_ptr()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: both descriptors were just created by `pipe` and are
        // owned by nobody else; wrapping them now closes them on drop.
        let (reader, writer) =
            unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        PIPE_WRITER.store(fds[1], Ordering::SeqCst);
        for sig in [ffi::SIGTERM, ffi::SIGINT, ffi::SIGHUP] {
            // SAFETY: `handler` is an `extern "C" fn(c_int)` that only
            // touches a static atomic and calls `write`. glibc's `signal`
            // gives BSD semantics (the handler stays installed, syscalls
            // restart), which is what the daemon wants.
            let previous = unsafe { ffi::signal(sig, handler) };
            // SIG_ERR is (sighandler_t)-1.
            if previous == u64::MAX as _ {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(Signals {
            reader: std::fs::File::from(reader),
            _writer: writer,
        })
    }

    /// Block until a signal arrives.
    ///
    /// # Errors
    /// A read failure on the pipe (never, in practice).
    pub fn wait(&mut self) -> io::Result<Signal> {
        loop {
            let mut byte = [0u8; 1];
            self.reader.read_exact(&mut byte)?;
            if let Some(s) = Signal::from_number(c_int::from(byte[0])) {
                return Ok(s);
            }
        }
    }
}

//! Joining a network namespace (`network_namespaces(7)`, `setns(2)`), so
//! that a daemon started in one namespace runs in another, as
//! `ip netns exec` would start it there.
//!
//! A namespace is named by a file: `/run/netns/NAME`, which `ip netns add`
//! creates (iproute2's convention), or `/proc/PID/ns/net`, the namespace a
//! process is in. Opening one needs no privilege; joining it needs
//! `CAP_SYS_ADMIN` (`setns(2)`), which the caller should give up once it
//! has joined ([`drop_capability`](crate::drop_capability)).
//!
//! `setns(2)` moves the calling *thread* only. A thread starts in the
//! namespace of the thread that creates it, and a socket stays in the
//! namespace of the thread that opened it, so join on the main thread
//! while it is the only one ([`threads`]), before any socket is opened:
//! then every thread and every socket of the process is in the namespace.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use crate::ffi;

/// Where the calling thread's network namespace shows (`proc(5)`):
/// `/proc/self/ns/net` would be the main thread's.
const THREAD_NAMESPACE: &str = "/proc/thread-self/ns/net";

/// A namespace's identity: the device and inode of its file in the `nsfs`
/// file system, the same for every path that names it
/// (`namespaces(7)`, "The /proc/pid/ns/ directory"). Shown as `dev:ino`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NsId {
    /// `st_dev`.
    pub dev: u64,
    /// `st_ino`.
    pub ino: u64,
}

impl NsId {
    fn of(metadata: &std::fs::Metadata) -> NsId {
        NsId {
            dev: metadata.dev(),
            ino: metadata.ino(),
        }
    }
}

impl fmt::Display for NsId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.dev, self.ino)
    }
}

/// Why a network namespace could not be opened or joined.
#[derive(Debug)]
pub enum NetNsError {
    /// The path could not be opened, or asked what it is.
    Open(io::Error),
    /// The path opened, but it is not a network namespace: another kind
    /// of namespace, or not one at all.
    NotNetwork,
    /// `setns(2)` failed: `EPERM` without `CAP_SYS_ADMIN`.
    Join(io::Error),
    /// `setns(2)` succeeded but the thread is not in the namespace after
    /// it.
    NotEntered {
        /// The namespace the thread is in.
        now: NsId,
        /// The namespace it was to join.
        want: NsId,
    },
}

impl fmt::Display for NetNsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetNsError::Open(e) => write!(f, "cannot open: {e}"),
            NetNsError::NotNetwork => f.write_str("not a network namespace"),
            NetNsError::Join(e) if e.raw_os_error() == Some(ffi::EPERM) => {
                write!(f, "setns(2) needs CAP_SYS_ADMIN: {e}")
            }
            NetNsError::Join(e) => write!(f, "setns(2): {e}"),
            NetNsError::NotEntered { now, want } => write!(
                f,
                "the thread is in namespace {now} after setns(2), not in {want}"
            ),
        }
    }
}

impl std::error::Error for NetNsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            NetNsError::Open(e) | NetNsError::Join(e) => Some(e),
            NetNsError::NotNetwork | NetNsError::NotEntered { .. } => None,
        }
    }
}

/// An open network namespace, ready to be joined.
#[derive(Debug)]
pub struct NetNs {
    /// The namespace's file, read-only and close-on-exec, so no child
    /// inherits it.
    file: File,
    id: NsId,
}

impl NetNs {
    /// Open `path` and check that it is a network namespace
    /// (`ioctl(NS_GET_NSTYPE)`, `ioctl_nsfs(2)`). Needs no privilege, and
    /// joins nothing.
    ///
    /// # Errors
    /// [`NetNsError::Open`] if the path cannot be opened;
    /// [`NetNsError::NotNetwork`] if it is not a network namespace.
    #[allow(unsafe_code, reason = "ioctl(2) on a borrowed descriptor")]
    pub fn open(path: &Path) -> Result<NetNs, NetNsError> {
        // O_NONBLOCK: a FIFO at the path must not block the open; it
        // changes nothing for a namespace file.
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(ffi::O_NONBLOCK)
            .open(path)
            .map_err(NetNsError::Open)?;
        // SAFETY: the descriptor belongs to `file`, which stays open for
        // the call. NS_GET_NSTYPE takes no argument and returns the
        // namespace's CLONE_NEW* type; the kernel writes no memory.
        let kind = unsafe { ffi::ioctl(file.as_raw_fd(), ffi::NS_GET_NSTYPE) };
        if kind < 0 {
            let e = io::Error::last_os_error();
            // ENOTTY: not a file of the nsfs file system at all.
            return Err(if e.raw_os_error() == Some(ffi::ENOTTY) {
                NetNsError::NotNetwork
            } else {
                NetNsError::Open(e)
            });
        }
        if kind != ffi::CLONE_NEWNET {
            return Err(NetNsError::NotNetwork);
        }
        let id = NsId::of(&file.metadata().map_err(NetNsError::Open)?);
        Ok(NetNs { file, id })
    }

    /// The namespace's identity.
    #[must_use]
    pub fn id(&self) -> NsId {
        self.id
    }

    /// The network namespace of the calling thread.
    ///
    /// # Errors
    /// If `/proc/thread-self/ns/net` cannot be read: no `/proc`.
    pub fn current() -> io::Result<NsId> {
        std::fs::metadata(THREAD_NAMESPACE).map(|m| NsId::of(&m))
    }

    /// Move the calling thread into the namespace (`setns(2)`), then check
    /// that it is there. Only the calling thread moves: threads it creates
    /// afterwards start there, others stay where they are. Sockets opened
    /// before stay in the namespace they were opened in.
    ///
    /// # Errors
    /// [`NetNsError::Join`] if `setns(2)` fails, with `EPERM` without
    /// `CAP_SYS_ADMIN`; [`NetNsError::NotEntered`] if the thread is not in
    /// the namespace afterwards.
    #[allow(unsafe_code, reason = "setns(2) on a borrowed descriptor")]
    pub fn enter(&self) -> Result<(), NetNsError> {
        // SAFETY: the descriptor belongs to `self.file`, which stays open
        // for the call; the type is an integer constant. setns(2) touches
        // no memory of ours.
        if unsafe { ffi::setns(self.file.as_raw_fd(), ffi::CLONE_NEWNET) } < 0 {
            return Err(NetNsError::Join(io::Error::last_os_error()));
        }
        let now = NetNs::current().map_err(NetNsError::Join)?;
        if now != self.id {
            return Err(NetNsError::NotEntered { now, want: self.id });
        }
        Ok(())
    }
}

/// How many threads this process has (`Threads:` in `/proc/self/status`,
/// `proc(5)`).
///
/// # Errors
/// If the file cannot be read or has no such line.
pub fn threads() -> io::Result<usize> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    parse_threads(&status).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "no Threads in /proc/self/status",
        )
    })
}

/// The `Threads:` count of `/proc/PID/status` text.
fn parse_threads(status: &str) -> Option<usize> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("Threads:"))
        .and_then(|v| v.trim().parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_show_as_dev_and_inode() {
        let id = NsId {
            dev: 4,
            ino: 4_026_531_840,
        };
        assert_eq!(id.to_string(), "4:4026531840");
    }

    #[test]
    fn parses_the_thread_count() {
        assert_eq!(
            parse_threads("Name:\tx\nThreads:\t1\nSigQ:\t0/1\n"),
            Some(1)
        );
        assert_eq!(parse_threads("Threads: 12\n"), Some(12));
        assert_eq!(parse_threads("Name:\tx\n"), None);
        assert_eq!(parse_threads("Threads:\tmany\n"), None);
    }

    /// The messages name what is wrong, and `CAP_SYS_ADMIN` when that is
    /// why `setns(2)` failed.
    #[test]
    fn errors_say_why() {
        let eperm = NetNsError::Join(io::Error::from_raw_os_error(ffi::EPERM));
        assert!(
            eperm
                .to_string()
                .starts_with("setns(2) needs CAP_SYS_ADMIN: "),
            "{eperm}"
        );
        let einval = NetNsError::Join(io::Error::from_raw_os_error(ffi::EINVAL));
        assert!(!einval.to_string().contains("CAP_SYS_ADMIN"), "{einval}");
        assert_eq!(
            NetNsError::NotNetwork.to_string(),
            "not a network namespace"
        );
        let missing = NetNsError::Open(io::Error::from(io::ErrorKind::NotFound));
        assert!(
            missing.to_string().starts_with("cannot open: "),
            "{missing}"
        );
        let (now, want) = (NsId { dev: 4, ino: 1 }, NsId { dev: 4, ino: 2 });
        assert_eq!(
            NetNsError::NotEntered { now, want }.to_string(),
            "the thread is in namespace 4:1 after setns(2), not in 4:2"
        );
    }
}

/// Real files of `/proc`, as any user: opening needs no privilege.
#[cfg(all(test, not(miri)))]
mod proc_tests {
    use super::*;

    /// A path to the namespace the thread is in opens, with the identity
    /// the thread reads for its own.
    #[test]
    fn the_own_namespace_opens_with_its_identity() {
        let ns = NetNs::open(Path::new("/proc/thread-self/ns/net")).unwrap();
        assert_eq!(ns.id(), NetNs::current().unwrap());
        let by_process = NetNs::open(Path::new("/proc/self/ns/net")).unwrap();
        assert_eq!(by_process.id(), ns.id());
    }

    /// Another kind of namespace, a regular file and a directory are not
    /// network namespaces; a missing path does not open.
    #[test]
    fn other_files_are_refused() {
        for path in [
            "/proc/self/ns/uts",
            "/proc/self/ns/mnt",
            concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"),
            "/proc/self/status",
            "/",
        ] {
            let err = NetNs::open(Path::new(path)).unwrap_err();
            assert!(matches!(err, NetNsError::NotNetwork), "{path}: {err:?}");
        }
        let err = NetNs::open(Path::new("/nonexistent/netns")).unwrap_err();
        assert!(
            matches!(&err, NetNsError::Open(e) if e.kind() == io::ErrorKind::NotFound),
            "{err:?}"
        );
    }

    #[test]
    fn this_process_has_threads() {
        assert!(threads().unwrap() >= 1);
    }

    /// Without `CAP_SYS_ADMIN` a thread cannot join a network namespace,
    /// not even its own, and the error says what it needs. Run as root, the
    /// thread drops the capability first, so this runs for every user.
    #[test]
    fn joining_without_cap_sys_admin_names_it() {
        let ns = NetNs::open(Path::new("/proc/self/ns/net")).unwrap();
        let err = std::thread::spawn(move || {
            crate::drop_capability(crate::Capability::SysAdmin).unwrap();
            ns.enter().unwrap_err()
        })
        .join()
        .unwrap();
        assert!(
            matches!(&err, NetNsError::Join(e) if e.raw_os_error() == Some(ffi::EPERM)),
            "{err:?}"
        );
        assert!(err.to_string().contains("CAP_SYS_ADMIN"), "{err}");
    }
}

/// Joining a namespace of its own needs `CAP_SYS_ADMIN`. Run as root:
///
/// ```sh
/// sudo -E "$(command -v cargo)" test -p bgpfc-sys -- --ignored netns
/// ```
#[cfg(all(test, not(miri)))]
pub(crate) mod root_tests {
    use super::*;

    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    /// `unshare --net sleep 30`, killed on drop: a process in a network
    /// namespace of its own with nothing but `lo` in it. The netlink
    /// tests join it too.
    pub(crate) struct Sleeper(Child);

    impl Sleeper {
        pub(crate) fn start() -> Sleeper {
            let child = Command::new("unshare")
                .args(["--net", "sleep", "30"])
                .stdin(Stdio::null())
                .spawn()
                .expect("unshare(1)");
            let sleeper = Sleeper(child);
            // unshare(1) moves itself, then executes sleep(1) in its place:
            // the namespace is the new one once the process is `sleep`.
            let comm = format!("/proc/{}/comm", sleeper.0.id());
            let deadline = Instant::now() + Duration::from_secs(10);
            while std::fs::read_to_string(&comm).unwrap_or_default().trim() != "sleep" {
                assert!(Instant::now() < deadline, "unshare --net did not start");
                std::thread::sleep(Duration::from_millis(10));
            }
            sleeper
        }

        /// Its namespace, opened.
        pub(crate) fn namespace(&self) -> NetNs {
            NetNs::open(Path::new(&format!("/proc/{}/ns/net", self.0.id()))).unwrap()
        }
    }

    impl Drop for Sleeper {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// A thread joins the namespace of another process by its
    /// `/proc/PID/ns/net` path, the absolute-path form of `netns`, and is
    /// in it afterwards, with that namespace's interfaces; the thread that
    /// spawned it stays where it was.
    #[test]
    #[ignore = "needs CAP_SYS_ADMIN: joins a network namespace"]
    fn netns_a_thread_joins_another_processes_namespace() {
        let sleeper = Sleeper::start();
        let path = format!("/proc/{}/ns/net", sleeper.0.id());
        let ns = NetNs::open(Path::new(&path)).unwrap();
        let here = NetNs::current().unwrap();
        assert_ne!(ns.id(), here, "unshare --net made no namespace");
        let want = ns.id();
        let (there, devices) = std::thread::spawn(move || {
            ns.enter().unwrap();
            let devices = std::fs::read_to_string("/proc/thread-self/net/dev").unwrap();
            (NetNs::current().unwrap(), devices)
        })
        .join()
        .unwrap();
        assert_eq!(there, want);
        assert_eq!(NetNs::current().unwrap(), here, "only the thread moved");
        // Two header lines, then one per interface: `lo` alone.
        let names: Vec<&str> = devices
            .lines()
            .skip(2)
            .filter_map(|l| l.split(':').next())
            .map(str::trim)
            .collect();
        assert_eq!(names, ["lo"], "{devices}");
    }

    /// A thread that joins a namespace and then starts another: the new
    /// thread is in the namespace too, as every thread bgpfcd starts after
    /// the join is.
    #[test]
    #[ignore = "needs CAP_SYS_ADMIN: joins a network namespace"]
    fn netns_threads_started_after_the_join_are_in_it() {
        let sleeper = Sleeper::start();
        let ns = NetNs::open(Path::new(&format!("/proc/{}/ns/net", sleeper.0.id()))).unwrap();
        let want = ns.id();
        let child = std::thread::spawn(move || {
            ns.enter().unwrap();
            std::thread::spawn(|| NetNs::current().unwrap())
                .join()
                .unwrap()
        })
        .join()
        .unwrap();
        assert_eq!(child, want);
    }
}

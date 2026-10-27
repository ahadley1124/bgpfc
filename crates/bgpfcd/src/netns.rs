//! Joining the network namespace that `netns` or `--netns` names
//! (docs/config.md, "Network namespace"), so that bgpfcd need not be
//! started inside it with `ip netns exec`.
//!
//! `setns(2)` moves the calling thread alone, a new thread starts in the
//! namespace of the thread that creates it, and a socket stays in the
//! namespace it was opened in. So the main thread joins while it is the
//! only thread and before anything opens a socket: every thread bgpfcd
//! starts, every socket it opens, and Routinator, a child of one of those
//! threads, are then in the namespace. The join needs `CAP_SYS_ADMIN`,
//! which nothing after it needs, so it is dropped at once, before the
//! privilege drop of `--user` and in capability mode alike.

use std::path::Path;

use bgpfc_sys::{Capability, Effective, NetNs, NsId};

/// What the main thread does about the namespace it is to run in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Join {
    /// Already there, as when started with `ip netns exec` into it: no
    /// `setns(2)`, and no capability needed for it.
    AlreadyThere,
    /// `setns(2)` into it.
    Enter,
}

/// Decide, from what the process is: `threads` running, the namespace the
/// thread is in (`here`), the one asked for (`target`) and whether
/// `CAP_SYS_ADMIN` is effective. Pure, for the tests.
///
/// # Errors
/// Why the join cannot happen.
fn plan(threads: usize, here: NsId, target: NsId, sys_admin: bool) -> Result<Join, String> {
    // setns(2) moves the calling thread alone: with another thread running,
    // some of bgpfcd would stay behind, and `/proc/self/net`, the main
    // thread's, could disagree with where the sockets are.
    if threads != 1 {
        return Err(format!(
            "cannot join a network namespace with {threads} threads running"
        ));
    }
    if here == target {
        return Ok(Join::AlreadyThere);
    }
    if !sys_admin {
        return Err("setns(2) needs CAP_SYS_ADMIN".to_owned());
    }
    Ok(Join::Enter)
}

/// Join the network namespace at `path` on the calling thread, which must
/// be the process's only one, and drop `CAP_SYS_ADMIN`; exits with the
/// reason if either fails, so that bgpfcd never runs in another namespace
/// than the one it was told.
pub(crate) fn join(path: &Path) {
    if let Err(e) = try_join(path) {
        bgpfc_log::error!(
            "cannot join network namespace",
            netns = path.display(),
            error = e
        );
        std::process::exit(1);
    }
}

fn try_join(path: &Path) -> Result<(), String> {
    let threads = bgpfc_sys::threads().map_err(|e| format!("cannot count threads: {e}"))?;
    let ns = NetNs::open(path).map_err(|e| e.to_string())?;
    let here = NetNs::current().map_err(|e| format!("cannot read the current namespace: {e}"))?;
    let have = effective()?;
    match plan(threads, here, ns.id(), have.has(Capability::SysAdmin))? {
        Join::AlreadyThere => bgpfc_log::info!(
            "network namespace already in use",
            netns = path.display(),
            id = ns.id()
        ),
        Join::Enter => {
            ns.enter().map_err(|e| e.to_string())?;
            bgpfc_log::info!(
                "network namespace joined",
                netns = path.display(),
                id = ns.id()
            );
        }
    }
    // Nothing after the join needs it: not the listeners, the netlink
    // socket nor Routinator. As root it would survive until `--user`, and in
    // capability mode for good.
    bgpfc_sys::drop_capability(Capability::SysAdmin)
        .map_err(|e| format!("cannot drop CAP_SYS_ADMIN: {e}"))?;
    if effective()?.has(Capability::SysAdmin) {
        return Err("CAP_SYS_ADMIN is still effective after it was dropped".to_owned());
    }
    bgpfc_log::info!("capability dropped", capability = Capability::SysAdmin);
    Ok(())
}

/// The effective capabilities of the main thread, the one that joins.
fn effective() -> Result<Effective, String> {
    Effective::current().map_err(|e| format!("cannot read capabilities: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const HERE: NsId = NsId { dev: 4, ino: 1 };
    const THERE: NsId = NsId { dev: 4, ino: 2 };

    /// The main thread joins only while it is alone, with
    /// `CAP_SYS_ADMIN`, unless it is there already.
    #[test]
    fn the_join_needs_one_thread_and_cap_sys_admin() {
        assert_eq!(plan(1, HERE, THERE, true), Ok(Join::Enter));
        assert_eq!(plan(1, THERE, THERE, false), Ok(Join::AlreadyThere));
        assert_eq!(plan(1, THERE, THERE, true), Ok(Join::AlreadyThere));
        assert_eq!(
            plan(1, HERE, THERE, false),
            Err("setns(2) needs CAP_SYS_ADMIN".to_owned())
        );
        for threads in [0, 2, 9] {
            for (here, sys_admin) in [(HERE, true), (THERE, true), (HERE, false)] {
                assert_eq!(
                    plan(threads, here, THERE, sys_admin),
                    Err(format!(
                        "cannot join a network namespace with {threads} threads running"
                    ))
                );
            }
        }
    }

    /// The real count: a process with a second thread refuses, before it
    /// asks for any privilege, even to join the namespace it is in.
    #[test]
    fn a_process_with_threads_refuses_to_join() {
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let other = std::thread::spawn(move || rx.recv());
        let err = try_join(Path::new("/proc/self/ns/net")).unwrap_err();
        drop(tx);
        let _ = other.join();
        assert!(
            err.starts_with("cannot join a network namespace with ")
                && err.ends_with(" threads running"),
            "{err}"
        );
    }
}

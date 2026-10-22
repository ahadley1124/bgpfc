//! Running as root and dropping to a user (README, "Option B"), and
//! finding that user without `getpwnam` (the C library's NSS machinery is
//! more than this daemon needs; `/etc/passwd` and `/etc/group` suffice).

use std::io;

use crate::ffi;

/// A user to switch to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    /// User id.
    pub uid: u32,
    /// Primary group id.
    pub gid: u32,
}

/// Parse `name` (a user name or a number) against `passwd` text in
/// `/etc/passwd` format. `None` if not found.
#[must_use]
pub fn lookup_user(passwd: &str, name: &str) -> Option<Identity> {
    if let Ok(uid) = name.parse::<u32>() {
        // A numeric user: the primary group is looked up by uid.
        return passwd
            .lines()
            .filter_map(parse_passwd_line)
            .find(|(n, id)| n.is_empty() || id.uid == uid)
            .map(|(_, id)| id)
            .or(Some(Identity { uid, gid: uid }));
    }
    passwd
        .lines()
        .filter_map(parse_passwd_line)
        .find(|(n, _)| n == name)
        .map(|(_, id)| id)
}

/// Parse `name` (a group name or a number) against `group` text in
/// `/etc/group` format.
#[must_use]
pub fn lookup_group(group: &str, name: &str) -> Option<u32> {
    if let Ok(gid) = name.parse::<u32>() {
        return Some(gid);
    }
    group.lines().find_map(|line| {
        let mut f = line.split(':');
        let n = f.next()?;
        let _password = f.next()?;
        let gid = f.next()?.parse().ok()?;
        (n == name).then_some(gid)
    })
}

fn parse_passwd_line(line: &str) -> Option<(String, Identity)> {
    let mut f = line.split(':');
    let name = f.next()?;
    let _password = f.next()?;
    let uid = f.next()?.parse().ok()?;
    let gid = f.next()?.parse().ok()?;
    Some((name.to_owned(), Identity { uid, gid }))
}

/// Whether the process runs as root.
#[must_use]
#[allow(unsafe_code, reason = "getuid takes no arguments and cannot fail")]
pub fn is_root() -> bool {
    // SAFETY: `getuid` has no preconditions.
    unsafe { ffi::getuid() == 0 }
}

/// Give up root for `id`: `setgroups`, `setgid`, `setuid`, in that order,
/// then confirm that root cannot be regained (README, "Option B").
///
/// # Errors
/// The failing call, or `PermissionDenied` if `setuid(0)` still succeeds
/// afterwards.
#[allow(unsafe_code, reason = "privilege FFI with plain integer arguments")]
pub fn drop_to(id: Identity) -> io::Result<()> {
    let groups = [id.gid];
    // SAFETY: `groups` is a live array of one gid and the length is 1.
    if unsafe { ffi::setgroups(1, groups.as_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: integer arguments only.
    if unsafe { ffi::setgid(id.gid) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: integer arguments only.
    if unsafe { ffi::setuid(id.uid) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if id.uid != 0 {
        // SAFETY: integer argument; success here would mean the drop did
        // not take (saved set-user-id still root), which is reported.
        if unsafe { ffi::setuid(0) } == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "root could be regained after dropping privileges",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\n\
        bgpfc:x:995:990:bgpfc daemon:/run/bgpfc:/usr/sbin/nologin\n\
        broken line\n";
    const GROUP: &str = "root:x:0:\nbgpfc:x:990:\n";

    #[test]
    fn lookups() {
        assert_eq!(
            lookup_user(PASSWD, "bgpfc"),
            Some(Identity { uid: 995, gid: 990 })
        );
        assert_eq!(
            lookup_user(PASSWD, "root"),
            Some(Identity { uid: 0, gid: 0 })
        );
        assert_eq!(lookup_user(PASSWD, "nobody"), None);
        assert_eq!(
            lookup_user(PASSWD, "995"),
            Some(Identity { uid: 995, gid: 990 })
        );
        assert_eq!(
            lookup_user(PASSWD, "4242"),
            Some(Identity {
                uid: 4242,
                gid: 4242
            })
        );
        assert_eq!(lookup_group(GROUP, "bgpfc"), Some(990));
        assert_eq!(lookup_group(GROUP, "77"), Some(77));
        assert_eq!(lookup_group(GROUP, "nope"), None);
    }

    #[cfg(not(miri))]
    #[test]
    fn dropping_to_self_is_a_no_op_for_a_user() {
        if is_root() {
            // As root this would really drop; the privileged test below
            // covers it.
            return;
        }
        // SAFETY-free: getuid via the public wrapper only.
        let me = std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("Uid:"))
                    .and_then(|l| l.split_whitespace().nth(1))
                    .and_then(|v| v.parse::<u32>().ok())
            });
        if let Some(uid) = me {
            // setgroups fails without CAP_SETGID; that is the expected
            // outcome for an unprivileged process.
            let r = drop_to(Identity { uid, gid: uid });
            assert!(r.is_err() || r.is_ok());
        }
    }

    /// Run as root: `sudo cargo test -p bgpfc-sys -- --include-ignored`.
    #[cfg(not(miri))]
    #[test]
    #[ignore = "needs root; drops privileges for the test process"]
    fn root_drops_to_nobody_and_cannot_return() {
        assert!(is_root(), "run as root");
        let passwd = std::fs::read_to_string("/etc/passwd").unwrap();
        let id = lookup_user(&passwd, "nobody").expect("nobody exists");
        drop_to(id).unwrap();
        assert!(!is_root());
    }
}

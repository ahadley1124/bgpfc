//! The two ways to run with the privileges the configuration needs
//! (README, "Run"): capabilities on an unprivileged user, or root that
//! drops to a user once the privileged sockets are open. Routinator, run
//! with `rpki { mode sidecar; }`, gets neither: it runs as the user bgpfcd
//! runs as, with no capabilities (issue #70; m14 design §4.2).

use bgpfc_config::Config;
use bgpfc_config::ast::{FibMode, RpkiMode};
use bgpfc_sys::{Capability, Effective, Identity};

/// What to do instead of running Routinator as root.
pub(crate) const SIDECAR_AS_ROOT_HINT: &str = "start bgpfcd with --user (README, Option B) or as an unprivileged user with capabilities (Option A)";

/// Why `mode` must not run as `root` (bgpfcd's identity) without `user`
/// (`--user`, which drops root before the sidecar starts), or `None` if it
/// may.
///
/// Routinator fetches and parses data from the internet, so it never runs
/// as root. bgpfcd starts it after the privilege drop, and clears its own
/// ambient capabilities from the child, but a child of root gets every
/// capability when it executes, whatever the ambient set
/// (`capabilities(7)`; bgpfc-sidecar, `Sidecar`). So with `mode sidecar`,
/// root without `--user` is refused rather than warned about.
pub(crate) fn sidecar_as_root(
    root: bool,
    user: Option<&str>,
    mode: RpkiMode,
) -> Option<&'static str> {
    (root && user.is_none() && mode == RpkiMode::Sidecar)
        .then_some("mode sidecar would run Routinator as root")
}

/// Verify the process can do what `config` asks, or exit with a message
/// naming what is missing. Root needs nothing, but must drop to `user` to
/// run the Routinator sidecar ([`sidecar_as_root`]); a user needs
/// `CAP_NET_BIND_SERVICE` for a privileged port and `CAP_NET_ADMIN` for
/// install mode.
pub(crate) fn check(config: &Config, user: Option<&str>) {
    if bgpfc_sys::is_root() {
        if let Some(refused) = sidecar_as_root(true, user, config.rpki.mode) {
            bgpfc_log::error!(refused, hint = SIDECAR_AS_ROOT_HINT);
            std::process::exit(1);
        }
        if user.is_none() {
            bgpfc_log::warn!("running as root; consider --user or capabilities (README, Run)");
        }
        return;
    }
    if user.is_some() {
        bgpfc_log::error!("--user needs root to start with");
        std::process::exit(1);
    }
    let mut needed = Vec::new();
    if config.listen.iter().any(|a| a.port() < 1024) {
        needed.push(Capability::NetBindService);
    }
    if config.fib.mode == FibMode::Install {
        needed.push(Capability::NetAdmin);
    }
    let have = match Effective::current() {
        Ok(e) => e,
        Err(e) => {
            bgpfc_log::error!("cannot read capabilities", error = e);
            std::process::exit(1);
        }
    };
    let missing = have.missing(&needed);
    if !missing.is_empty() {
        let names: Vec<String> = missing.iter().map(ToString::to_string).collect();
        bgpfc_log::error!(
            "missing capabilities",
            missing = names.join(","),
            hint = "see README, Run: setcap, setpriv or a systemd unit with AmbientCapabilities"
        );
        std::process::exit(1);
    }
}

/// Drop from root to `user` (and `group`, else the user's primary group).
/// Exits on failure: running on as root was not asked for.
pub(crate) fn drop(user: &str, group: Option<&str>) {
    let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    let Some(mut id) = bgpfc_sys::lookup_user(&passwd, user) else {
        bgpfc_log::error!("unknown user", user = user);
        std::process::exit(1);
    };
    if let Some(g) = group {
        let groups = std::fs::read_to_string("/etc/group").unwrap_or_default();
        let Some(gid) = bgpfc_sys::lookup_group(&groups, g) else {
            bgpfc_log::error!("unknown group", group = g);
            std::process::exit(1);
        };
        id = Identity { uid: id.uid, gid };
    }
    if id.uid == 0 {
        bgpfc_log::error!("--user names root; nothing to drop to", user = user);
        std::process::exit(1);
    }
    match bgpfc_sys::drop_to(id) {
        Ok(()) => bgpfc_log::info!("privileges dropped", uid = id.uid, gid = id.gid),
        Err(e) => {
            bgpfc_log::error!("cannot drop privileges", error = e);
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// m14 design §4.2: Routinator runs as root only if bgpfcd is root
    /// and nothing drops that first; that, and only that, is refused.
    #[test]
    fn routinator_never_runs_as_root() {
        let modes = [RpkiMode::Disabled, RpkiMode::External, RpkiMode::Sidecar];
        for root in [false, true] {
            for user in [None, Some("bgpfc")] {
                for mode in modes {
                    let refused = sidecar_as_root(root, user, mode);
                    let expected = root && user.is_none() && mode == RpkiMode::Sidecar;
                    assert_eq!(refused.is_some(), expected, "{root} {user:?} {mode}");
                }
            }
        }
        assert_eq!(
            sidecar_as_root(true, None, RpkiMode::Sidecar),
            Some("mode sidecar would run Routinator as root")
        );
    }
}

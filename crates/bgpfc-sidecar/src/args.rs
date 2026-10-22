//! Routinator's command line, written for
//! [`TESTED_VERSION`](crate::TESTED_VERSION) from its manual page
//! (<https://routinator.docs.nlnetlabs.nl/en/stable/manual-page.html>, the
//! documentation of 0.15.2) and from its source at tag v0.15.2
//! (`src/config.rs` for how command-line options and a config file
//! combine, `src/tals.rs` for the bundled TALs).
//!
//! The shape is `routinator [options] server [server-options]` (manual
//! page, "Synopsis"): global options before the command, server options
//! after it.
//!
//! Implements: no RFC.

use std::ffi::{OsStr, OsString};
use std::net::SocketAddr;

use crate::config::SidecarConfig;
use crate::error::SidecarError;

/// The production TALs of the five Regional Internet Registries, as
/// Routinator 0.15 names them (`BUNDLED_TALS` in `src/tals.rs`).
const RIR_TALS: [&str; 5] = ["afrinic", "apnic", "arin", "lacnic", "ripe"];

/// ARIN's production TAL, used only when its Relying Party Agreement is
/// accepted.
pub(crate) const ARIN_TAL: &str = "arin";

/// Every TAL Routinator 0.15 bundles (`BUNDLED_TALS` in `src/tals.rs`):
/// the RIR TALs, the RIR test beds and one third-party test bed.
pub(crate) const BUNDLED_TALS: [&str; 9] = [
    "afrinic",
    "apnic",
    "arin",
    "lacnic",
    "ripe",
    "apnic-testbed",
    "arin-ote",
    "ripe-pilot",
    "nlnetlabs-testbed",
];

const TALS: &str = "bgpfcd derives the TAL options from the TAL settings";
const FOREIGN_RTR: &str = "it would serve RTR on a listener bgpfcd does not control";
const EXITS: &str = "Routinator would print and exit instead of serving";
/// Routinator 0.15 spells the option `--systemd-listen` (`ServerArgs` in
/// `src/config.rs` at v0.15.2); its manual page says `--listen-systemd`,
/// which clap rejects.
const SYSTEMD: &str = "Routinator would take its RTR listener from systemd, and bgpfcd passes it none, so it would fail at every start";
/// Routinator applies `--user` and `--group` in server mode, detached or
/// not: `Server::run` calls `drop_privileges` (`src/process.rs` at
/// v0.15.2) once it has bound its listeners.
const CREDENTIALS: &str = "Routinator would switch to it by itself, which clears the parent-death signal that ends it when bgpfcd dies";

/// Long options the escape hatch may not carry, because bgpfcd sets them
/// itself or because they defeat supervision or the loopback-only RTR
/// listener (issue #71), with the reason given to the operator.
const RESERVED_LONG: [(&str, &str); 14] = [
    (
        "config",
        "bgpfcd passes --config from the config file setting",
    ),
    (
        "repository-dir",
        "bgpfcd passes --repository-dir from the repository directory setting",
    ),
    ("no-rir-tals", TALS),
    ("tal", TALS),
    ("extra-tals-dir", TALS),
    (
        "rtr",
        "bgpfcd passes --rtr; RTR is served on the configured loopback address only",
    ),
    ("rtr-tls", FOREIGN_RTR),
    ("systemd-listen", SYSTEMD),
    (
        "refresh",
        "bgpfcd passes --refresh from the refresh setting",
    ),
    (
        "detach",
        "a detached Routinator leaves bgpfcd's supervision",
    ),
    ("user", CREDENTIALS),
    ("group", CREDENTIALS),
    ("help", EXITS),
    ("version", EXITS),
];

/// Short forms of reserved options, with their long names: `-c`, `-r`,
/// `-d` (`server`), `-h` and `-V`.
const RESERVED_SHORT: [(u8, &str); 5] = [
    (b'c', "config"),
    (b'r', "repository-dir"),
    (b'd', "detach"),
    (b'h', "help"),
    (b'V', "version"),
];

/// Unreserved short options that take a value; the rest of their cluster
/// is that value (`-xFILE`). `-x` is `--exceptions`.
const SHORT_WITH_VALUE: &[u8] = b"x";

/// The arguments, after the program name, that run Routinator as the
/// sidecar described by a validated `config`, serving RTR on `rtr`:
///
/// ```text
/// [--config=FILE] --repository-dir=DIR
/// --no-rir-tals --tal=NAME... [--extra-tals-dir=DIR]
/// EXTRA-GLOBAL-ARGS...
/// server --rtr=ADDR:PORT --refresh=SECONDS
/// EXTRA-SERVER-ARGS...
/// ```
///
/// - Values are attached with `=`, so a path that starts with `-` cannot
///   be taken for an option, and non-UTF-8 paths are passed unchanged.
/// - The TAL set is spelled out: `--no-rir-tals`, then one `--tal` for
///   each RIR TAL in use (ARIN's only with
///   [`accept_arin_rpa`](SidecarConfig::accept_arin_rpa)) and for each
///   further bundled TAL, without duplicates. Command-line `--tal`
///   replaces a config file's `tals` list, so a config file cannot change
///   which bundled TALs are used. Its `extra-tals-dir` still applies when
///   [`extra_dir`](crate::TalConfig::extra_dir) is unset: the command line
///   cannot remove it.
/// - Command-line `--rtr` replaces a config file's `rtr-listen` list, so
///   RTR is served on `rtr` only (issue #71).
/// - No `--detach`: Routinator stays in the foreground and logs to stderr
///   (manual page, config file option `log`), and its exit is what the
///   supervisor watches.
/// - The escape hatch (issue #72): the extra global arguments come just
///   before `server` and the extra server arguments last, both verbatim
///   and after bgpfcd's own. [`SidecarConfig::validate`] refuses the ones
///   that would repeat or contradict an option above.
///
/// `rtr` is where to serve, with a configured port 0 already replaced by
/// the port bgpfcd picked; `--rtr` would otherwise bind an ephemeral port
/// nobody knows. The scope id and flow label of an IPv6 address are
/// dropped: Routinator parses `--rtr` as `[addr]:port`.
///
/// Notes for the code that spawns the child:
/// - Without `--config`, Routinator reads `$HOME/.routinator.conf` when it
///   exists (manual page, `-c`). Point `HOME` at a directory bgpfcd
///   controls, so a stray file in the service user's home cannot change
///   the validator.
/// - Routinator 0.15.2 refuses to start while `RSYNC_RSH` is set
///   (`Changelog.md`); remove it from the child's environment.
/// - Routinator opens its RTR listener only after its first validation
///   run (manual page, `server`), which can take minutes with a cold
///   cache.
#[must_use]
pub fn routinator_args(config: &SidecarConfig, rtr: SocketAddr) -> Vec<OsString> {
    let mut args = Vec::new();
    if let Some(file) = &config.config_file {
        args.push(with_value("--config=", file.as_os_str()));
    }
    args.push(with_value(
        "--repository-dir=",
        config.repository_dir.as_os_str(),
    ));
    args.push("--no-rir-tals".into());
    for name in tal_names(config) {
        args.push(format!("--tal={name}").into());
    }
    if let Some(dir) = &config.tals.extra_dir {
        args.push(with_value("--extra-tals-dir=", dir.as_os_str()));
    }
    args.extend(config.extra_global_args.iter().cloned());
    args.push("server".into());
    args.push(format!("--rtr={}", SocketAddr::new(rtr.ip(), rtr.port())).into());
    args.push(format!("--refresh={}", config.refresh.as_secs()).into());
    args.extend(config.extra_server_args.iter().cloned());
    args
}

/// The bundled TALs in use: the RIR TALs (ARIN's only when its agreement
/// is accepted), then the further bundled TALs in configured order, each
/// once.
fn tal_names(config: &SidecarConfig) -> Vec<&str> {
    let mut names = Vec::new();
    if config.tals.rir_tals {
        names.extend(
            RIR_TALS
                .into_iter()
                .filter(|&name| name != ARIN_TAL || config.accept_arin_rpa),
        );
    }
    for name in &config.tals.bundled {
        if !names.contains(&name.as_str()) {
            names.push(name);
        }
    }
    names
}

fn with_value(flag: &str, value: &OsStr) -> OsString {
    let mut arg = OsString::from(flag);
    arg.push(value);
    arg
}

/// Refuse NUL bytes and reserved options in escape-hatch arguments.
///
/// Every argument is checked as clap would read it as an option: a
/// separate value such as `/path` in `--logfile /path` cannot look like
/// one, because clap does not take a value that starts with `-` either.
pub(crate) fn check_extra_args(args: &[OsString]) -> Result<(), SidecarError> {
    for arg in args {
        let bytes = arg.as_encoded_bytes();
        if bytes.contains(&0) {
            return Err(SidecarError::NulByte {
                setting: "extra argument",
            });
        }
        if let Some(reason) = reserved(bytes) {
            return Err(SidecarError::ReservedArg {
                arg: arg.to_string_lossy().into_owned(),
                reason,
            });
        }
    }
    Ok(())
}

/// Why `arg` is reserved, if it is: `--name` or `--name=value` with a
/// reserved name, or a short-option cluster such as `-vd` that holds a
/// reserved letter before any option that takes the rest as its value.
/// Long names are matched exactly; Routinator's clap setup does not accept
/// abbreviations.
fn reserved(arg: &[u8]) -> Option<&'static str> {
    if let Some(rest) = arg.strip_prefix(b"--") {
        let name = rest.split(|&b| b == b'=').next().unwrap_or(rest);
        return long_reason(name);
    }
    for &letter in arg.strip_prefix(b"-")? {
        if let Some(&(_, long)) = RESERVED_SHORT.iter().find(|(s, _)| *s == letter) {
            return long_reason(long.as_bytes());
        }
        if SHORT_WITH_VALUE.contains(&letter) {
            break;
        }
    }
    None
}

fn long_reason(name: &[u8]) -> Option<&'static str> {
    RESERVED_LONG
        .iter()
        .find(|(long, _)| long.as_bytes() == name)
        .map(|&(_, reason)| reason)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TalConfig;
    use std::net::{Ipv6Addr, SocketAddrV6};
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;
    use std::time::Duration;

    fn base() -> SidecarConfig {
        SidecarConfig::new("/usr/bin/routinator", "/var/lib/bgpfc/rpki")
    }

    fn lossy(args: &[OsString]) -> Vec<String> {
        args.iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    const RTR: &str = "127.0.0.1:3323";

    /// The options before `server` for the default TALs: the RIR TALs
    /// without ARIN's.
    const DEFAULT_GLOBAL: [&str; 6] = [
        "--repository-dir=/var/lib/bgpfc/rpki",
        "--no-rir-tals",
        "--tal=afrinic",
        "--tal=apnic",
        "--tal=lacnic",
        "--tal=ripe",
    ];

    /// Check one golden command line. The config must also pass
    /// validation: `routinator_args` is only defined for those.
    fn golden(shape: fn(&mut SidecarConfig), rtr: &str, expected: &[&str]) {
        let mut c = base();
        shape(&mut c);
        assert_eq!(c.validate(), Ok(()));
        let got = routinator_args(&c, rtr.parse().unwrap());
        assert_eq!(lossy(&got), expected);
    }

    #[test]
    fn golden_defaults() {
        let tail = ["server", "--rtr=127.0.0.1:3323", "--refresh=600"];
        golden(|_| {}, RTR, &[&DEFAULT_GLOBAL[..], &tail[..]].concat());
    }

    #[test]
    fn golden_arin_accepted_on_ipv6() {
        golden(
            |c| {
                c.accept_arin_rpa = true;
                c.refresh = Duration::from_secs(300);
            },
            "[::1]:3323",
            &[
                "--repository-dir=/var/lib/bgpfc/rpki",
                "--no-rir-tals",
                "--tal=afrinic",
                "--tal=apnic",
                "--tal=arin",
                "--tal=lacnic",
                "--tal=ripe",
                "server",
                "--rtr=[::1]:3323",
                "--refresh=300",
            ],
        );
    }

    #[test]
    fn golden_config_file_test_beds_and_tal_directory() {
        golden(
            |c| {
                c.config_file = Some("/etc/bgpfc/routinator.conf".into());
                c.tals.bundled = vec!["ripe-pilot".into(), "ripe".into(), "arin-ote".into()];
                c.tals.extra_dir = Some("/etc/bgpfc/tals".into());
            },
            RTR,
            &[
                "--config=/etc/bgpfc/routinator.conf",
                "--repository-dir=/var/lib/bgpfc/rpki",
                "--no-rir-tals",
                "--tal=afrinic",
                "--tal=apnic",
                "--tal=lacnic",
                "--tal=ripe",
                "--tal=ripe-pilot",
                "--tal=arin-ote",
                "--extra-tals-dir=/etc/bgpfc/tals",
                "server",
                "--rtr=127.0.0.1:3323",
                "--refresh=600",
            ],
        );
    }

    #[test]
    fn golden_rir_subset() {
        golden(
            |c| {
                c.tals = TalConfig {
                    rir_tals: false,
                    bundled: vec!["ripe".into(), "apnic".into(), "ripe".into()],
                    extra_dir: None,
                };
            },
            RTR,
            &[
                "--repository-dir=/var/lib/bgpfc/rpki",
                "--no-rir-tals",
                "--tal=ripe",
                "--tal=apnic",
                "server",
                "--rtr=127.0.0.1:3323",
                "--refresh=600",
            ],
        );
    }

    #[test]
    fn golden_tal_directory_only() {
        golden(
            |c| {
                c.tals.rir_tals = false;
                c.tals.extra_dir = Some("/etc/bgpfc/tals".into());
            },
            "127.0.0.1:40000",
            &[
                "--repository-dir=/var/lib/bgpfc/rpki",
                "--no-rir-tals",
                "--extra-tals-dir=/etc/bgpfc/tals",
                "server",
                "--rtr=127.0.0.1:40000",
                "--refresh=600",
            ],
        );
    }

    /// Issue #72: extra global arguments just before `server`, extra
    /// server arguments last, both verbatim.
    #[test]
    fn golden_escape_hatch() {
        let tail = [
            "--strict",
            "--stale=reject",
            "-v",
            "server",
            "--rtr=127.0.0.1:3323",
            "--refresh=600",
            "--http=127.0.0.1:8323",
            "--retry=300",
        ];
        golden(
            |c| {
                c.extra_global_args = vec!["--strict".into(), "--stale=reject".into(), "-v".into()];
                c.extra_server_args = vec!["--http=127.0.0.1:8323".into(), "--retry=300".into()];
            },
            RTR,
            &[&DEFAULT_GLOBAL[..], &tail[..]].concat(),
        );
    }

    #[test]
    fn ipv6_scope_and_flow_label_are_dropped() {
        let rtr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 3323, 5, 7));
        let args = routinator_args(&base(), rtr);
        assert!(
            args.contains(&OsString::from("--rtr=[::1]:3323")),
            "{args:?}"
        );
    }

    #[test]
    fn paths_are_passed_as_bytes() {
        let mut c = base();
        c.repository_dir = PathBuf::from(OsStr::from_bytes(b"/var/lib/\xffrpki"));
        c.config_file = Some("/etc/-odd/r.conf".into());
        let args = routinator_args(&c, RTR.parse().unwrap());
        assert_eq!(args[0], OsString::from("--config=/etc/-odd/r.conf"));
        assert_eq!(args[1].as_bytes(), b"--repository-dir=/var/lib/\xffrpki");
    }

    #[test]
    fn rir_tals_are_bundled_tals() {
        for name in RIR_TALS {
            assert!(BUNDLED_TALS.contains(&name), "{name}");
        }
        assert!(RIR_TALS.contains(&ARIN_TAL));
    }

    #[test]
    fn reserved_options_as_clap_reads_them() {
        let cases: &[(&[u8], bool)] = &[
            (b"--rtr", true),
            (b"--rtr=127.0.0.1:1", true),
            (b"--rtr=", true),
            (b"--detach", true),
            (b"--version", true),
            (b"--rtr-tcp-keepalive=60", false),
            (b"--rtr-client-metrics", false),
            (b"--systemd-listen", true),
            (b"--user=routinator", true),
            (b"--group", true),
            (b"--users", false),
            // The manual page's spelling, which clap refuses by itself.
            (b"--listen-systemd", false),
            (b"--tals", false),
            (b"--rt", false),
            (b"--", false),
            (b"-", false),
            (b"", false),
            (b"rtr", false),
            (b"server", false),
            (b"-d", true),
            (b"-V", true),
            (b"-vqd", true),
            (b"-cfile", true),
            (b"-v", false),
            (b"-qq", false),
            (b"-x/srv/rd/exceptions.json", false),
            (b"-vx/dir", false),
            (b"--\xffrtr", false),
            (b"--rtr=\xff", true),
        ];
        for (arg, expected) in cases {
            assert_eq!(
                reserved(arg).is_some(),
                *expected,
                "{}",
                String::from_utf8_lossy(arg)
            );
        }
    }
}

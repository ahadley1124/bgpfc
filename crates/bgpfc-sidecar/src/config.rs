//! The sidecar's settings and their validation. This is the plain struct
//! the config language (milestone 14) will lower to.
//!
//! Implements: RFC 8210 §6 (the range of the Refresh Interval, which
//! Routinator announces to RTR clients from its refresh setting).

use std::ffi::OsString;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::args::{ARIN_TAL, BUNDLED_TALS, check_extra_args};
use crate::backoff::BackoffConfig;
use crate::error::SidecarError;

/// Which trust anchors Routinator validates from (manual page, options
/// `--no-rir-tals`, `--tal` and `--extra-tals-dir`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TalConfig {
    /// Use the production TALs of the five Regional Internet Registries
    /// that Routinator bundles. ARIN's is among them only when
    /// [`SidecarConfig::accept_arin_rpa`] is true.
    pub rir_tals: bool,
    /// More TALs bundled with Routinator, by name: the RIR test beds
    /// `apnic-testbed`, `arin-ote` and `ripe-pilot`, say. With `rir_tals`
    /// off, naming RIR TALs here selects a subset of them.
    pub bundled: Vec<String>,
    /// A directory whose `*.tal` files (RFC 8630) are used as well.
    /// Absolute. bgpfcd does not read it, so it is up to the operator
    /// what it holds, the ARIN TAL included.
    pub extra_dir: Option<PathBuf>,
}

impl Default for TalConfig {
    /// The RIR TALs only.
    fn default() -> TalConfig {
        TalConfig {
            rir_tals: true,
            bundled: Vec::new(),
            extra_dir: None,
        }
    }
}

/// Everything bgpfcd needs to run and supervise Routinator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SidecarConfig {
    /// The Routinator binary: an absolute path, never looked up on `PATH`,
    /// because a BGP daemon must not run whatever happens to be called
    /// `routinator` (issue #70).
    pub binary: PathBuf,
    /// Where Routinator serves RTR: a loopback address only (issue #71).
    /// Port 0 asks bgpfcd to pick a free ephemeral port when it starts the
    /// sidecar.
    pub rtr_listen: SocketAddr,
    /// Routinator's repository directory, its cache of RPKI data
    /// (`--repository-dir`). Absolute.
    pub repository_dir: PathBuf,
    /// The trust anchors.
    pub tals: TalConfig,
    /// Whether the operator accepts ARIN's Relying Party Agreement, the
    /// terms under which ARIN publishes its TAL. Routinator stopped asking
    /// for an explicit opt-in in 0.12.0 and uses the ARIN TAL by default,
    /// but accepting an agreement is the operator's decision, so bgpfcd
    /// leaves the ARIN TAL out unless this is true. Without it, routes in
    /// ARIN's address space validate as `NotFound`.
    pub accept_arin_rpa: bool,
    /// How long Routinator waits after a validation run before the next
    /// (`server --refresh`). Routinator also announces it to RTR clients
    /// as the Refresh Interval. A whole number of seconds from 1 to 7199:
    /// RFC 8210 §6 allows at least 1 s and requires the Expire Interval to
    /// be larger, and Routinator's default `--expire` is 7200 s.
    pub refresh: Duration,
    /// A Routinator config file (`--config`), for settings bgpfcd does not
    /// model. Absolute. Routinator 0.15 requires such a file to set
    /// `repository-dir` even though bgpfcd passes `--repository-dir`,
    /// which takes precedence. The command line also overrides its TALs
    /// and RTR listeners; see [`routinator_args`](crate::routinator_args).
    pub config_file: Option<PathBuf>,
    /// Escape hatch (issue #72): options passed to Routinator verbatim
    /// just before the `server` command, such as `--strict` or
    /// `--stale=reject`.
    pub extra_global_args: Vec<OsString>,
    /// Escape hatch (issue #72): `server` options passed to Routinator
    /// verbatim at the end of the command line, such as
    /// `--http=127.0.0.1:8323`.
    pub extra_server_args: Vec<OsString>,
    /// Restart delays after a failure.
    pub backoff: BackoffConfig,
    /// How long a graceful stop (`SIGTERM`) may take before the child is
    /// killed (`SIGKILL`).
    pub stop_timeout: Duration,
    /// After this many consecutive failures, the sidecar is reported as
    /// failed: an alarm that stays raised while it keeps retrying at the
    /// backoff cap.
    pub failure_threshold: u32,
}

impl SidecarConfig {
    /// Routinator's own default refresh interval (manual page, `server
    /// --refresh`).
    pub const DEFAULT_REFRESH: Duration = Duration::from_secs(600);

    /// Default graceful-stop timeout.
    pub const DEFAULT_STOP_TIMEOUT: Duration = Duration::from_secs(10);

    /// Default consecutive-failure threshold.
    pub const DEFAULT_FAILURE_THRESHOLD: u32 = 5;

    /// Settings with defaults: RTR on `127.0.0.1` with a port picked at
    /// start, the RIR TALs without ARIN's, Routinator's default refresh,
    /// no config file or extra arguments, [`BackoffConfig::default`], and
    /// the `DEFAULT_*` constants.
    #[must_use]
    pub fn new(binary: impl Into<PathBuf>, repository_dir: impl Into<PathBuf>) -> SidecarConfig {
        SidecarConfig {
            binary: binary.into(),
            rtr_listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            repository_dir: repository_dir.into(),
            tals: TalConfig::default(),
            accept_arin_rpa: false,
            refresh: Self::DEFAULT_REFRESH,
            config_file: None,
            extra_global_args: Vec::new(),
            extra_server_args: Vec::new(),
            backoff: BackoffConfig::default(),
            stop_timeout: Self::DEFAULT_STOP_TIMEOUT,
            failure_threshold: Self::DEFAULT_FAILURE_THRESHOLD,
        }
    }

    /// Check the settings. Returns the first problem found.
    ///
    /// # Errors
    /// The [`SidecarError`] variant that names the problem: a relative
    /// path, a NUL byte, a non-loopback RTR address, an unusable TAL
    /// choice, an extra argument bgpfcd reserves, or a value out of range.
    pub fn validate(&self) -> Result<(), SidecarError> {
        if !self.binary.is_absolute() {
            return Err(SidecarError::BinaryNotAbsolute(self.binary.clone()));
        }
        no_nul("binary", &self.binary)?;
        // Issue #71. `Ipv6Addr::is_loopback` is true for `::1` only, so an
        // IPv4-mapped `::ffff:127.0.0.1` is refused too: write 127.0.0.1.
        if !self.rtr_listen.ip().is_loopback() {
            return Err(SidecarError::RtrNotLoopback(self.rtr_listen));
        }
        absolute("repository directory", &self.repository_dir)?;
        if let Some(file) = &self.config_file {
            absolute("config file", file)?;
        }
        self.validate_tals()?;
        let refresh = self.refresh.as_secs();
        if self.refresh.subsec_nanos() != 0 || !(1..7200).contains(&refresh) {
            // RFC 8210 §6: Refresh Interval 1..=86400 s, and the cache MUST
            // set the Expire Interval larger; Routinator's is 7200 s.
            return Err(SidecarError::OutOfRange {
                setting: "refresh",
                expected: "a whole number of seconds from 1 to 7199",
            });
        }
        check_extra_args(&self.extra_global_args)?;
        check_extra_args(&self.extra_server_args)?;
        self.validate_supervision()
    }

    fn validate_tals(&self) -> Result<(), SidecarError> {
        let tals = &self.tals;
        for name in &tals.bundled {
            if !BUNDLED_TALS.contains(&name.as_str()) {
                return Err(SidecarError::UnknownTal(name.clone()));
            }
            if name == ARIN_TAL && !self.accept_arin_rpa {
                return Err(SidecarError::ArinRpaNotAccepted);
            }
        }
        if let Some(dir) = &tals.extra_dir {
            absolute("extra TAL directory", dir)?;
        }
        if !tals.rir_tals && tals.bundled.is_empty() && tals.extra_dir.is_none() {
            return Err(SidecarError::NoTrustAnchors);
        }
        Ok(())
    }

    fn validate_supervision(&self) -> Result<(), SidecarError> {
        let b = &self.backoff;
        if b.initial.is_zero() {
            return Err(SidecarError::OutOfRange {
                setting: "initial backoff",
                expected: "longer than zero",
            });
        }
        if b.cap < b.initial {
            return Err(SidecarError::OutOfRange {
                setting: "backoff cap",
                expected: "at least the initial backoff",
            });
        }
        if b.stable.is_zero() {
            return Err(SidecarError::OutOfRange {
                setting: "stable period",
                expected: "longer than zero",
            });
        }
        if self.stop_timeout.is_zero() {
            return Err(SidecarError::OutOfRange {
                setting: "stop timeout",
                expected: "longer than zero",
            });
        }
        if self.failure_threshold == 0 {
            return Err(SidecarError::OutOfRange {
                setting: "failure threshold",
                expected: "at least 1",
            });
        }
        Ok(())
    }
}

/// `path` must be absolute and free of NUL bytes.
fn absolute(setting: &'static str, path: &Path) -> Result<(), SidecarError> {
    if !path.is_absolute() {
        return Err(SidecarError::NotAbsolute {
            setting,
            path: path.to_path_buf(),
        });
    }
    no_nul(setting, path)
}

fn no_nul(setting: &'static str, path: &Path) -> Result<(), SidecarError> {
    if path.as_os_str().as_encoded_bytes().contains(&0) {
        return Err(SidecarError::NulByte { setting });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    type Mutate = fn(&mut SidecarConfig);

    fn base() -> SidecarConfig {
        SidecarConfig::new("/usr/bin/routinator", "/var/lib/bgpfc/rpki")
    }

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    fn out_of_range(setting: &'static str, expected: &'static str) -> SidecarError {
        SidecarError::OutOfRange { setting, expected }
    }

    fn reserved(arg: &str, reason: &'static str) -> SidecarError {
        SidecarError::ReservedArg {
            arg: arg.to_owned(),
            reason,
        }
    }

    fn assert_accepts(cases: &[(&str, Mutate)]) {
        for (name, mutate) in cases {
            let mut c = base();
            mutate(&mut c);
            assert_eq!(c.validate(), Ok(()), "{name}");
        }
    }

    fn assert_rejects(cases: &[(&str, Mutate, SidecarError)]) {
        for (name, mutate, expected) in cases {
            let mut c = base();
            mutate(&mut c);
            assert_eq!(c.validate().as_ref(), Err(expected), "{name}");
        }
    }

    #[test]
    fn defaults_are_valid() {
        let c = base();
        assert_eq!(c.validate(), Ok(()));
        assert_eq!(c.rtr_listen, addr("127.0.0.1:0"));
        assert!(c.tals.rir_tals);
        assert!(!c.accept_arin_rpa);
        assert_eq!(c.refresh, Duration::from_secs(600));
    }

    #[test]
    fn accepts_good_settings() {
        assert_accepts(&[
            ("IPv6 loopback", |c| c.rtr_listen = addr("[::1]:3323")),
            ("rest of 127/8", |c| c.rtr_listen = addr("127.0.0.53:3323")),
            ("fixed port", |c| c.rtr_listen = addr("127.0.0.1:323")),
            ("ARIN accepted and named", |c| {
                c.accept_arin_rpa = true;
                c.tals.bundled = vec!["arin".into(), "arin-ote".into()];
            }),
            ("RIR subset", |c| {
                c.tals.rir_tals = false;
                c.tals.bundled = vec!["ripe".into(), "apnic".into()];
            }),
            ("extra directory only", |c| {
                c.tals.rir_tals = false;
                c.tals.extra_dir = Some("/etc/bgpfc/tals".into());
            }),
            ("config file", |c| {
                c.config_file = Some("/etc/bgpfc/routinator.conf".into());
            }),
            ("shortest refresh", |c| c.refresh = Duration::from_secs(1)),
            ("longest refresh", |c| c.refresh = Duration::from_secs(7199)),
            ("backoff at its cap from the start", |c| {
                c.backoff.cap = c.backoff.initial;
            }),
            ("threshold of one", |c| c.failure_threshold = 1),
        ]);
    }

    #[test]
    fn accepts_unreserved_extra_args() {
        assert_accepts(&[("escape hatch", |c| {
            c.extra_global_args = args(&[
                "-v",
                "-qq",
                "--strict",
                "--stale=reject",
                // -x takes a value: the r and d after it are not options.
                "-x/srv/rpki/exceptions.json",
                "--exceptions=/srv/rpki/local.json",
                "--rrdp-proxy=http://192.0.2.1:3128",
                "--log-repository-issues",
            ]);
            c.extra_server_args = args(&[
                "--http=127.0.0.1:8323",
                "--retry=300",
                "--rtr-tcp-keepalive=30",
                "--rtr-client-metrics",
                "--history=4",
            ]);
        })]);
    }

    #[test]
    fn rejects_relative_paths_and_nul_bytes() {
        assert_rejects(&[
            (
                "binary found on PATH",
                |c| c.binary = "routinator".into(),
                SidecarError::BinaryNotAbsolute("routinator".into()),
            ),
            (
                "binary relative to the working directory",
                |c| c.binary = "./bin/routinator".into(),
                SidecarError::BinaryNotAbsolute("./bin/routinator".into()),
            ),
            (
                "empty binary",
                |c| c.binary = PathBuf::new(),
                SidecarError::BinaryNotAbsolute(PathBuf::new()),
            ),
            (
                "NUL in the binary",
                |c| c.binary = PathBuf::from(OsStr::from_bytes(b"/usr/bin/rout\0inator")),
                SidecarError::NulByte { setting: "binary" },
            ),
            (
                "relative repository directory",
                |c| c.repository_dir = "rpki-cache".into(),
                SidecarError::NotAbsolute {
                    setting: "repository directory",
                    path: "rpki-cache".into(),
                },
            ),
            (
                "NUL in the repository directory",
                |c| c.repository_dir = PathBuf::from(OsStr::from_bytes(b"/var/\0")),
                SidecarError::NulByte {
                    setting: "repository directory",
                },
            ),
            (
                "relative config file",
                |c| c.config_file = Some("routinator.conf".into()),
                SidecarError::NotAbsolute {
                    setting: "config file",
                    path: "routinator.conf".into(),
                },
            ),
            (
                "relative extra TAL directory",
                |c| c.tals.extra_dir = Some("tals".into()),
                SidecarError::NotAbsolute {
                    setting: "extra TAL directory",
                    path: "tals".into(),
                },
            ),
        ]);
    }

    #[test]
    fn rejects_rtr_addresses_off_loopback() {
        let cases: &[(&str, Mutate)] = &[
            ("documentation address", |c| {
                c.rtr_listen = addr("192.0.2.1:3323");
            }),
            ("IPv4 unspecified", |c| c.rtr_listen = addr("0.0.0.0:3323")),
            ("IPv6 unspecified", |c| c.rtr_listen = addr("[::]:323")),
            ("IPv6 global", |c| c.rtr_listen = addr("[2001:db8::1]:3323")),
            ("IPv4-mapped loopback", |c| {
                c.rtr_listen = addr("[::ffff:127.0.0.1]:3323");
            }),
        ];
        for (name, mutate) in cases {
            let mut c = base();
            mutate(&mut c);
            let expected = SidecarError::RtrNotLoopback(c.rtr_listen);
            assert_eq!(c.validate(), Err(expected), "{name}");
        }
    }

    #[test]
    fn rejects_bad_tal_choices() {
        assert_rejects(&[
            (
                "unknown TAL",
                |c| c.tals.bundled = vec!["ripe-ncc".into()],
                SidecarError::UnknownTal("ripe-ncc".into()),
            ),
            (
                // `--tal=list` makes Routinator print its TALs and exit 0.
                "the list pseudo-TAL",
                |c| c.tals.bundled = vec!["list".into()],
                SidecarError::UnknownTal("list".into()),
            ),
            (
                "ARIN named without accepting the RPA",
                |c| c.tals.bundled = vec!["arin".into()],
                SidecarError::ArinRpaNotAccepted,
            ),
            (
                "no trust anchor at all",
                |c| c.tals.rir_tals = false,
                SidecarError::NoTrustAnchors,
            ),
        ]);
    }

    #[test]
    fn rejects_out_of_range_numbers() {
        let refresh = out_of_range("refresh", "a whole number of seconds from 1 to 7199");
        assert_rejects(&[
            (
                "zero refresh",
                |c| c.refresh = Duration::ZERO,
                refresh.clone(),
            ),
            (
                "fractional refresh",
                |c| c.refresh = Duration::from_millis(600_500),
                refresh.clone(),
            ),
            (
                "refresh not below the expire interval",
                |c| c.refresh = Duration::from_secs(7200),
                refresh,
            ),
            (
                "zero initial backoff",
                |c| c.backoff.initial = Duration::ZERO,
                out_of_range("initial backoff", "longer than zero"),
            ),
            (
                "cap below the initial backoff",
                |c| c.backoff.cap = Duration::from_millis(500),
                out_of_range("backoff cap", "at least the initial backoff"),
            ),
            (
                "zero stable period",
                |c| c.backoff.stable = Duration::ZERO,
                out_of_range("stable period", "longer than zero"),
            ),
            (
                "zero stop timeout",
                |c| c.stop_timeout = Duration::ZERO,
                out_of_range("stop timeout", "longer than zero"),
            ),
            (
                "zero failure threshold",
                |c| c.failure_threshold = 0,
                out_of_range("failure threshold", "at least 1"),
            ),
        ]);
    }

    #[test]
    fn rejects_reserved_extra_args() {
        let rtr = "bgpfcd passes --rtr; RTR is served on the configured loopback address only";
        assert_rejects(&[
            (
                "second RTR listener",
                |c| c.extra_server_args = args(&["--rtr=0.0.0.0:323"]),
                reserved("--rtr=0.0.0.0:323", rtr),
            ),
            (
                "second RTR listener, separate value",
                |c| c.extra_server_args = args(&["--retry=60", "--rtr", "0.0.0.0:323"]),
                reserved("--rtr", rtr),
            ),
            (
                "RTR over TLS",
                |c| c.extra_server_args = args(&["--rtr-tls=192.0.2.1:324"]),
                reserved(
                    "--rtr-tls=192.0.2.1:324",
                    "it would serve RTR on a listener bgpfcd does not control",
                ),
            ),
            (
                "detach",
                |c| c.extra_server_args = args(&["-d"]),
                reserved("-d", "a detached Routinator leaves bgpfcd's supervision"),
            ),
            (
                "reserved short option inside a cluster",
                |c| c.extra_global_args = args(&["-vr/tmp/cache"]),
                reserved(
                    "-vr/tmp/cache",
                    "bgpfcd passes --repository-dir from the repository directory setting",
                ),
            ),
            (
                "config file through the escape hatch",
                |c| c.extra_global_args = args(&["--config=/tmp/x.conf"]),
                reserved(
                    "--config=/tmp/x.conf",
                    "bgpfcd passes --config from the config file setting",
                ),
            ),
            (
                "TAL list through the escape hatch",
                |c| c.extra_global_args = args(&["--tal=list"]),
                reserved(
                    "--tal=list",
                    "bgpfcd derives the TAL options from the TAL settings",
                ),
            ),
            (
                "refresh through the escape hatch",
                |c| c.extra_server_args = args(&["--refresh=60"]),
                reserved(
                    "--refresh=60",
                    "bgpfcd passes --refresh from the refresh setting",
                ),
            ),
            (
                "help",
                |c| c.extra_global_args = args(&["-h"]),
                reserved("-h", "Routinator would print and exit instead of serving"),
            ),
            (
                "NUL in an extra argument",
                |c| c.extra_global_args = vec![OsStr::from_bytes(b"--strict\0").into()],
                SidecarError::NulByte {
                    setting: "extra argument",
                },
            ),
        ]);
    }

    #[test]
    fn messages_name_the_problem() {
        let cases: &[(SidecarError, &str)] = &[
            (
                SidecarError::BinaryNotAbsolute("routinator".into()),
                "the Routinator binary must be an absolute path, not \"routinator\": bgpfcd never searches PATH for it",
            ),
            (
                SidecarError::RtrNotLoopback(addr("192.0.2.1:3323")),
                "RTR listen address 192.0.2.1:3323 is not a loopback address; the sidecar serves this host only",
            ),
            (
                SidecarError::UnknownTal("ripe-ncc".into()),
                "Routinator 0.15 bundles no TAL named \"ripe-ncc\"; it knows afrinic, apnic, arin, lacnic, ripe, apnic-testbed, arin-ote, ripe-pilot, nlnetlabs-testbed",
            ),
            (
                out_of_range("refresh", "a whole number of seconds from 1 to 7199"),
                "refresh must be a whole number of seconds from 1 to 7199",
            ),
            (
                reserved("-d", "a detached Routinator leaves bgpfcd's supervision"),
                "extra Routinator argument \"-d\" is not allowed: a detached Routinator leaves bgpfcd's supervision",
            ),
        ];
        for (err, text) in cases {
            assert_eq!(err.to_string(), *text);
        }
    }
}

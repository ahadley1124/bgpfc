//! The daemon as a process, where no privilege is needed: a cache of an
//! external `rpki` block that has no address stops the start, naming the
//! cache, before anything is opened (issue #60), while `--check` judges
//! the file alone and looks nothing up (`docs/config.md`, "RPKI"); the
//! start line names the `rpki` block's enforcement; `--check` reports
//! what Routinator's rules refuse in a `sidecar` block at its position,
//! without running the binary (issue #72); a Routinator that cannot run
//! stops the start (issue #60); and, with `mode sidecar`, `--check` and
//! the start warn when the owner check of Routinator's port is weaker,
//! as for `nobody` or in a user namespace, and go on (COMPLIANCE.md, RFC
//! 8210 §9, §13).

use std::fs;
use std::net::TcpListener;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Command;

/// A directory of its own for one test, under the system's temporary
/// directory.
fn scratch(name: &str) -> PathBuf {
    scratch_in(&std::env::temp_dir(), name)
}

/// A directory of its own for one test under `base`.
fn scratch_in(base: &Path, name: &str) -> PathBuf {
    let dir = base.join(format!("bgpfcd-test-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Whether every directory from `/` down to `dir` lets others through
/// (their mode has `o+x`), as a process that dropped to `nobody` needs to
/// reach anything below it.
fn others_can_reach(dir: &Path) -> bool {
    dir.canonicalize().is_ok_and(|dir| {
        dir.ancestors().all(|d| {
            fs::metadata(d).is_ok_and(|m| m.is_dir() && m.permissions().mode() & 0o001 != 0)
        })
    })
}

/// A directory of its own for one test that a bgpfcd run as root with
/// `--user nobody` can work in: mode 0777, under the system's temporary
/// directory if `nobody` can reach it, and otherwise under `/tmp`, as when
/// `TMPDIR` names a directory only root may enter.
fn scratch_for_nobody(name: &str) -> PathBuf {
    let base = [std::env::temp_dir(), PathBuf::from("/tmp")]
        .into_iter()
        .find(|base| others_can_reach(base))
        .unwrap_or_else(|| {
            panic!(
                "neither TMPDIR nor /tmp lets nobody through; set TMPDIR to a directory \
                 every user can reach"
            )
        });
    let dir = scratch_in(&base, name);
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();
    dir
}

#[test]
fn a_cache_that_cannot_be_found_stops_the_start() {
    let dir = scratch("unresolvable");
    let config = dir.join("bgpfcd.conf");
    let socket = dir.join("ctl.sock");
    // RFC 2606 §2: a name under `.invalid` never resolves.
    fs::write(
        &config,
        format!(
            "router-id 192.0.2.1;\nlocal-as 65000;\ncontrol {{ socket {}; }}\n\
             rpki {{ mode external; cache 127.0.0.1 port 3323;\n\
             cache rtr.invalid preference 1; }}\n",
            socket.display()
        ),
    )
    .unwrap();
    let bgpfcd = || {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_bgpfcd"));
        cmd.arg("-c").arg(&config);
        cmd
    };

    let out = bgpfcd().output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("msg=\"cannot start\" error=\"cannot resolve rpki cache rtr.invalid: "),
        "{stderr}"
    );
    // Only the cache at fault is named.
    assert!(!stderr.contains("cache 127.0.0.1"), "{stderr}");
    // Nothing was opened: not even the control socket.
    assert!(!socket.exists());

    // `--check` looks nothing up: the file itself is fine.
    let out = bgpfcd().arg("--check").output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn the_start_line_names_the_rpki_enforcement_and_startup() {
    // Design §D1.3: the operator sees the configured action next to the
    // mode, `drop-invalid` unless another is written (issue #61), and
    // what becomes of the routes until the first data, `accept` unless
    // another is written (RFC 6811 §2). The cache that cannot be found
    // ends the start right after the line.
    let dir = scratch("enforcement");
    let config = dir.join("bgpfcd.conf");
    for (statement, shown) in [
        ("", "drop-invalid startup=accept"),
        ("enforcement prefer-valid;", "prefer-valid startup=accept"),
        ("enforcement off; startup hold;", "off startup=hold"),
    ] {
        fs::write(
            &config,
            format!(
                "router-id 192.0.2.1;\nlocal-as 65000;\n\
                 rpki {{ mode external; {statement} cache rtr.invalid; }}\n"
            ),
        )
        .unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_bgpfcd"))
            .arg("-c")
            .arg(&config)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{stderr}");
        let start = stderr
            .lines()
            .find(|l| l.contains("msg=\"bgpfcd starting\""))
            .unwrap_or_else(|| panic!("{stderr}"));
        assert!(
            start.ends_with(&format!(" rpki=external enforcement={shown}")),
            "{start}"
        );
    }
    let _ = fs::remove_dir_all(&dir);
}

/// Run `bgpfcd --check` on `text`, written to `name` in `dir`.
fn check(dir: &std::path::Path, name: &str, text: &str) -> std::process::Output {
    let config = dir.join(name);
    fs::write(&config, text).unwrap();
    Command::new(env!("CARGO_BIN_EXE_bgpfcd"))
        .arg("-c")
        .arg(&config)
        .arg("--check")
        .output()
        .unwrap()
}

#[test]
fn check_reports_a_reserved_routinator_option_at_its_block() {
    let dir = scratch("reserved");
    let out = check(
        &dir,
        "bgpfcd.conf",
        "router-id 192.0.2.1;\nlocal-as 65000;\nrpki {\n    mode sidecar;\n    \
         sidecar { global-args --strict \"-d\"; }\n}\n",
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    let file = dir.join("bgpfcd.conf");
    let expected = format!(
        "{}:5:5: rpki sidecar: extra Routinator argument \"-d\" is not allowed: \
         a detached Routinator leaves bgpfcd's supervision\n      \
         sidecar {{ global-args --strict \"-d\"; }}\n      ^\n",
        file.display()
    );
    assert_eq!(stderr, expected);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn check_does_not_run_routinator() {
    // `--check` judges the file alone, wherever it runs: a binary that is
    // not there, and a repository directory that is not either, are the
    // start's business (m14 design §1.5).
    let dir = scratch("unrun");
    let repository = dir.join("repo");
    let out = check(
        &dir,
        "bgpfcd.conf",
        &format!(
            "router-id 192.0.2.1;\nlocal-as 65000;\n\
             rpki {{ mode sidecar; sidecar {{ binary /nonexistent/routinator; \
             repository-dir {}; }} }}\n",
            repository.display()
        ),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(
        String::from_utf8_lossy(&out.stdout).ends_with(": ok (0 neighbors, 0 policies)\n"),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        !repository.exists(),
        "--check created the repository directory"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_missing_routinator_stops_the_start() {
    let root = fs::metadata("/proc/self").unwrap().uid() == 0;
    let dir = if root {
        scratch_for_nobody("missing-routinator")
    } else {
        scratch("missing-routinator")
    };
    let binary = dir.join("routinator");
    let config = dir.join("bgpfcd.conf");
    // A free high port, so that no privilege is needed to listen.
    let port = TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .unwrap()
        .port();
    fs::write(
        &config,
        format!(
            "router-id 192.0.2.1;\nlocal-as 65000;\n\
             listen {{ address 127.0.0.1; port {port}; }}\nfib {{ mode dry-run; }}\n\
             rpki {{ mode sidecar; sidecar {{ binary \"{}\"; repository-dir \"{}\"; }} }}\n",
            binary.display(),
            dir.join("repo").display()
        ),
    )
    .unwrap();
    let mut bgpfcd = Command::new(env!("CARGO_BIN_EXE_bgpfcd"));
    bgpfcd.arg("-c").arg(&config);
    // As root, bgpfcd refuses to run Routinator without --user (m14 design
    // §4.2). So the test drops to nobody, as an operator would, in a
    // scratch directory that nobody can reach and write, where it creates
    // the repository directory: the start then fails where it fails for an
    // unprivileged run, at the binary.
    if root {
        bgpfcd.args(["--user", "nobody"]);
    }
    let out = bgpfcd.output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    let line = stderr
        .lines()
        .find(|l| l.contains("msg=\"cannot start rpki\""))
        .unwrap_or_else(|| panic!("{stderr}"));
    assert!(
        line.contains(&format!(
            "{} --version` could not be started",
            binary.display()
        )),
        "{line}"
    );
    // The neighbors would start after it; none is configured, but the
    // repository directory shows how far the start got.
    assert!(dir.join("repo").is_dir(), "{stderr}");
    // As nobody, the owner check of Routinator's port is weaker, which
    // the start says before it goes on.
    if root {
        let warning = stderr
            .lines()
            .position(|l| l.contains(WEAKER_AT_START))
            .unwrap_or_else(|| panic!("{stderr}"));
        assert!(
            stderr
                .lines()
                .nth(warning)
                .unwrap()
                .contains(" is nobody's, ")
        );
        let failed = stderr
            .lines()
            .position(|l| l.contains("msg=\"cannot start rpki\""));
        assert!(failed > Some(warning), "{stderr}");
    }
    let _ = fs::remove_dir_all(&dir);
}

/// The start's warning that the owner check of Routinator's port is
/// weaker.
const WEAKER_AT_START: &str =
    "msg=\"rpki sidecar: the owner check of Routinator's port is weaker here; starting anyway\"";

/// `--check`'s.
const WEAKER_AT_CHECK: &str =
    ": warning: rpki sidecar: the owner check of Routinator's port is weaker for bgpfcd as uid";

/// With `mode sidecar`, `--check` warns, at the `mode sidecar` statement,
/// when bgpfcd would run as `nobody` (`--user nobody`), and the file is
/// still ok; with another mode, or as a user of its own, it says nothing.
#[test]
fn check_warns_when_the_owner_check_is_weaker_as_nobody() {
    let passwd = fs::read_to_string("/etc/passwd").unwrap_or_default();
    if !passwd.lines().any(|l| l.starts_with("nobody:")) {
        eprintln!("skipped: no user nobody here");
        return;
    }
    let dir = scratch("weaker-nobody");
    let config = dir.join("bgpfcd.conf");
    let run = |text: &str, user: Option<&str>| {
        fs::write(&config, text).unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_bgpfcd"));
        cmd.arg("-c").arg(&config).arg("--check");
        if let Some(user) = user {
            cmd.args(["--user", user]);
        }
        let out = cmd.output().unwrap();
        assert!(out.status.success(), "{out:?}");
        assert!(String::from_utf8_lossy(&out.stdout).ends_with(": ok (0 neighbors, 0 policies)\n"));
        String::from_utf8_lossy(&out.stderr).into_owned()
    };
    let sidecar = "router-id 192.0.2.1;\nlocal-as 65000;\nrpki {\n    mode sidecar;\n}\n";
    let stderr = run(sidecar, Some("nobody"));
    assert!(
        stderr.starts_with(&format!("{}:4:5{WEAKER_AT_CHECK}", config.display())),
        "{stderr}"
    );
    assert!(stderr.contains(" is nobody's, "), "{stderr}");
    assert_eq!(stderr.lines().count(), 1, "{stderr}");
    // Only `mode sidecar` has the check.
    let external = "router-id 192.0.2.1;\nlocal-as 65000;\n\
                    rpki { mode external; cache 127.0.0.1; }\n";
    assert_eq!(run(external, Some("nobody")), "");
    // Root, as `--user root` would judge, in the initial namespace, is a
    // user of its own.
    let initial = fs::read_to_string("/proc/self/uid_map")
        .is_ok_and(|m| m.split_whitespace().collect::<Vec<_>>() == ["0", "0", "4294967295"]);
    if initial {
        assert_eq!(run(sidecar, Some("root")), "");
    }
    let _ = fs::remove_dir_all(&dir);
}

/// Whether this process may make a user namespace (`unshare -U`).
fn user_namespaces_allowed() -> bool {
    Command::new("unshare")
        .args(["-U", "true"])
        .output()
        .is_ok_and(|o| o.status.success())
}

/// In a new user namespace with no map, `unshare -U`, bgpfcd is the
/// overflow user itself, and every user outside reads as that user: both
/// `--check` and the start say why the owner check is weaker there, and
/// the start goes on to Routinator, which is missing here.
#[test]
fn a_user_namespace_weakens_the_owner_check() {
    if !user_namespaces_allowed() {
        eprintln!("skipped: unshare -U is not allowed here");
        return;
    }
    let dir = scratch_for_nobody("weaker-userns");
    let config = dir.join("bgpfcd.conf");
    let port = TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .unwrap()
        .port();
    fs::write(
        &config,
        format!(
            "router-id 192.0.2.1;\nlocal-as 65000;\n\
             listen {{ address 127.0.0.1; port {port}; }}\nfib {{ mode dry-run; }}\n\
             rpki {{ mode sidecar; sidecar {{ binary \"{}\"; repository-dir \"{}\"; }} }}\n",
            dir.join("routinator").display(),
            dir.join("repo").display()
        ),
    )
    .unwrap();
    let bgpfcd = |check: bool| {
        let mut cmd = Command::new("unshare");
        cmd.args(["-U", env!("CARGO_BIN_EXE_bgpfcd"), "-c"])
            .arg(&config);
        if check {
            cmd.arg("--check");
        }
        cmd.output().unwrap()
    };
    let reasons = [
        "uid 65534 is the overflow uid, ",
        "bgpfcd runs in a user namespace whose uid_map is not the identity, ",
    ];
    let out = bgpfcd(true);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    // At the `sidecar` block.
    assert!(
        stderr.starts_with(&format!(
            "{}:5:22{WEAKER_AT_CHECK} 65534: ",
            config.display()
        )),
        "{stderr}"
    );
    for reason in reasons {
        assert!(stderr.contains(reason), "{reason}: {stderr}");
    }
    let out = bgpfcd(false);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    let warning = stderr
        .lines()
        .find(|l| l.contains(WEAKER_AT_START))
        .unwrap_or_else(|| panic!("{stderr}"));
    assert!(warning.contains(" uid=65534 "), "{warning}");
    for reason in reasons {
        assert!(warning.contains(reason), "{reason}: {warning}");
    }
    assert!(
        stderr.contains("msg=\"cannot start rpki\""),
        "started on to Routinator: {stderr}"
    );
    let _ = fs::remove_dir_all(&dir);
}

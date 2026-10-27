//! The daemon as a process, where no privilege is needed: a cache of an
//! external `rpki` block that has no address stops the start, naming the
//! cache, before anything is opened (issue #60), while `--check` judges
//! the file alone and looks nothing up (`docs/config.md`, "RPKI"); the
//! start line names the `rpki` block's enforcement; `--check` reports
//! what Routinator's rules refuse in a `sidecar` block at its position,
//! without running the binary (issue #72); and a Routinator that cannot
//! run stops the start (issue #60).

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
    let _ = fs::remove_dir_all(&dir);
}

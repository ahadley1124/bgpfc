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
use std::path::PathBuf;
use std::process::Command;

/// A directory of its own for one test, under the system's temporary
/// directory.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("bgpfcd-test-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
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
fn the_start_line_names_the_rpki_enforcement() {
    // Design §D1.3: the operator sees the configured action next to the
    // mode, `drop-invalid` unless another is written (issue #61). The
    // cache that cannot be found ends the start right after the line.
    let dir = scratch("enforcement");
    let config = dir.join("bgpfcd.conf");
    for (statement, shown) in [
        ("", "drop-invalid"),
        ("enforcement prefer-valid;", "prefer-valid"),
        ("enforcement off;", "off"),
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
    let dir = scratch("missing-routinator");
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
    // §4.2). So the test drops to nobody, as an operator would, and opens
    // its scratch directory to nobody, who creates the repository
    // directory there: the start then fails where it fails for an
    // unprivileged run, at the binary.
    if fs::metadata("/proc/self").unwrap().uid() == 0 {
        bgpfcd.args(["--user", "nobody"]);
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();
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

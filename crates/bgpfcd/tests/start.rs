//! The daemon as a process, where no privilege is needed: a cache of an
//! external `rpki` block that has no address stops the start, naming the
//! cache, before anything is opened (issue #60), while `--check` judges
//! the file alone and looks nothing up (`docs/config.md`, "RPKI").

use std::fs;
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

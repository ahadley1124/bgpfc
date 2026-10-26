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
             rpki {{ mode external; invalid policy; cache 127.0.0.1 port 3323;\n\
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

/// RFC 8481 §5: "Absent specific operator configuration, policy MUST NOT
/// be applied", so an external `rpki` block has to say what becomes of
/// Invalid routes, and `--check` refuses one that does not, naming the
/// choices.
#[test]
fn an_external_block_must_say_what_to_do_with_invalid_routes() {
    let dir = scratch("invalid-statement");
    let config = dir.join("bgpfcd.conf");
    let check = |block: &str| {
        fs::write(
            &config,
            format!("router-id 192.0.2.1;\nlocal-as 65000;\n{block}\n"),
        )
        .unwrap();
        Command::new(env!("CARGO_BIN_EXE_bgpfcd"))
            .arg("-c")
            .arg(&config)
            .arg("--check")
            .output()
            .unwrap()
    };

    let out = check("rpki { mode external; cache 127.0.0.1; }");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains(
            "`mode external` needs an `invalid` statement: `drop`, `prefer-valid` or `policy`"
        ),
        "{stderr}"
    );
    for action in ["drop", "prefer-valid", "policy"] {
        let out = check(&format!(
            "rpki {{ mode external; invalid {action}; cache 127.0.0.1; }}"
        ));
        assert!(
            out.status.success(),
            "{action}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    // Without a lookup there is nothing to act on, so a block that does
    // not validate need not say.
    assert!(check("rpki { mode disabled; }").status.success());
    assert!(check("").status.success());
    let _ = fs::remove_dir_all(&dir);
}

//! Golden tests (AGENTS.md §5, `bgpfc-config` row): every `tests/golden/*.conf`
//! has a `.out` next to it holding either the debug rendering of the
//! parsed configuration or the error report. Run with `UPDATE_GOLDEN=1` to
//! rewrite the expectations after an intended change, then review the diff.

use std::fs;
use std::path::{Path, PathBuf};

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden")
}

fn render(name: &str, text: &str) -> String {
    match bgpfc_config::parse_str(name, text) {
        Ok(cfg) => format!("{cfg:#?}\n"),
        Err(e) => format!("{e}\n"),
    }
}

#[test]
fn golden_files() {
    let dir = golden_dir();
    let mut confs: Vec<PathBuf> = fs::read_dir(&dir)
        .expect("golden dir")
        .map(|e| e.expect("entry").path())
        .filter(|p| p.extension().is_some_and(|x| x == "conf"))
        .collect();
    confs.sort();
    assert_ne!(confs.len(), 0);
    let update = std::env::var_os("UPDATE_GOLDEN").is_some();
    let mut failures = Vec::new();
    for conf in confs {
        let name = conf.file_name().unwrap().to_str().unwrap().to_owned();
        let text = fs::read_to_string(&conf).unwrap();
        let actual = render(&name, &text);
        let out = conf.with_extension("out");
        if update {
            fs::write(&out, &actual).unwrap();
            continue;
        }
        let expected = fs::read_to_string(&out).unwrap_or_default();
        if expected != actual {
            failures.push(format!(
                "{name}: output differs from {}\n--- expected\n{expected}\n--- actual\n{actual}",
                out.display()
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The shipped example and the README's sketch of it stay parseable.
#[test]
fn shipped_example_parses() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let example = fs::read_to_string(root.join("contrib/bgpfc.conf")).unwrap();
    let cfg = bgpfc_config::parse_str("contrib/bgpfc.conf", &example).unwrap();
    assert_eq!(cfg.neighbors.len(), 1);
    let readme = fs::read_to_string(root.join("README.md")).unwrap();
    let start = readme
        .find("\n```\nrouter-id")
        .expect("README config example");
    let body = &readme[start + 5..];
    let end = body.find("\n```").unwrap();
    let readme_cfg = bgpfc_config::parse_str("README.md", &body[..end]).unwrap();
    // Same content; only the positions differ.
    let diff = bgpfc_config::ConfigDiff::between(&cfg, &readme_cfg);
    assert!(diff.is_empty(), "{diff:?}");
    assert_eq!(readme_cfg.neighbors.len(), cfg.neighbors.len());
}

//! Configuration language: lexer, parser, typed configuration, validation
//! and reload diffing (AGENTS.md §3, "Config"). The grammar is documented
//! in `docs/config.md`.
//!
//! Implements: RFC 4271 §4.2 and §10 (Hold Time and timer defaults per
//! neighbor), §9.2.1.1 (`advertisement-interval`); RFC 7607 §2 (AS 0 is
//! rejected); RFC 9687 §4.4 (`send-hold-time`); RFC 9774 §3
//! (`allow-as-set`); RFC 8950 §4 (`extended-next-hop`); RFC 4486 §4
//! (`restart-limit`); RFC 4271 §6.7 (`maximum-prefix`); RFC 8210 §6, §7,
//! §9 and §10 (the `rpki` block: the Expire Interval cap and the
//! back-off within their ranges, the protocol version, the rpki-rtr port,
//! the cache list with preferences, the sidecar's RTR on loopback only);
//! RFC 6811 §2 and §5 (the `rpki` block's `enforcement` and `startup`:
//! acting on the validation state, and holding routes not validated yet,
//! only as configured). Issues #26 and #70-#72: the
//! `sidecar` block, Routinator's settings within the bounds of
//! `bgpfc-sidecar`. The `netns` statement: the network namespace bgpfcd
//! joins, named as iproute2 names them ([`netns_path`]).
//!
//! ```
//! let text = "router-id 192.0.2.1; local-as 65000;
//!     policy ANY { term all { action accept; } }
//!     neighbor 192.0.2.2 { remote-as 65001; import ANY; export ANY; }";
//! let cfg = bgpfc_config::parse_str("example.conf", text).unwrap();
//! assert_eq!(cfg.neighbors[0].hold_time.secs(), 90);
//! ```
#![forbid(unsafe_code)]

pub mod ast;
pub mod diff;
pub mod error;
pub mod lexer;
mod lower;
pub mod parser;
mod validate;

use std::path::{Path, PathBuf};

pub use ast::Config;
pub use diff::ConfigDiff;
pub use error::{ConfigError, ConfigErrors, Pos};

/// Parse and validate configuration text. `file` names it in errors.
///
/// # Errors
/// Every problem found, in source order. Lexical and syntax errors stop
/// the pass before lowering; otherwise lowering and validation errors are
/// reported together.
pub fn parse_str(file: &str, text: &str) -> Result<Config, ConfigErrors> {
    parse_str_with(file, text, &no_check)
}

/// [`parse_str`], plus `check`: the caller's own checks of the lowered
/// configuration, for rules this crate cannot judge, such as those of a
/// program the caller runs from it. Each error `check` returns carries a
/// position in `text`, as validation's do (a position the configuration
/// keeps, such as a [`Neighbor`](ast::Neighbor)'s), and is reported with
/// them, in source order, as `file:line:col` with the line and a caret.
///
/// `check` runs only on a file that lowers: after a lexical, syntax or
/// lowering error the pass stops, as in [`parse_str`], without it. It runs
/// whether or not validation finds problems, so that one pass reports
/// them all.
///
/// # Errors
/// As [`parse_str`], with the errors of `check` among the validation
/// errors.
pub fn parse_str_with(
    file: &str,
    text: &str,
    check: &dyn Fn(&Config) -> Vec<ConfigError>,
) -> Result<Config, ConfigErrors> {
    let (tokens, mut errors) = lexer::lex(text);
    let (statements, parse_errors) = parser::parse(&tokens);
    errors.extend(parse_errors);
    if !errors.is_empty() {
        return Err(ConfigErrors::new(file, text, errors));
    }
    let cfg = match lower::lower(&statements) {
        Ok(cfg) => cfg,
        Err(errors) => return Err(ConfigErrors::new(file, text, errors)),
    };
    let mut errors = validate::validate(&cfg);
    errors.extend(check(&cfg));
    if errors.is_empty() {
        Ok(cfg)
    } else {
        Err(ConfigErrors::new(file, text, errors))
    }
}

/// Read and parse a configuration file.
///
/// # Errors
/// [`LoadError::Io`] when the file cannot be read, else as [`parse_str`].
pub fn parse_file(path: &Path) -> Result<Config, LoadError> {
    parse_file_with(path, &no_check)
}

/// Read and parse a configuration file, with the caller's `check` as in
/// [`parse_str_with`].
///
/// # Errors
/// [`LoadError::Io`] when the file cannot be read, else as
/// [`parse_str_with`].
pub fn parse_file_with(
    path: &Path,
    check: &dyn Fn(&Config) -> Vec<ConfigError>,
) -> Result<Config, LoadError> {
    let text =
        std::fs::read_to_string(path).map_err(|e| LoadError::Io(path.display().to_string(), e))?;
    parse_str_with(&path.display().to_string(), &text, check).map_err(LoadError::Config)
}

/// Where iproute2 keeps the network namespaces `ip netns add` names
/// (`ip-netns(8)`).
pub const NETNS_DIR: &str = "/run/netns";

/// The longest name of a file, `NAME_MAX` (`<linux/limits.h>`).
const NAME_MAX: usize = 255;

/// The file that names a network namespace, from the value of `netns` or
/// of `bgpfcd --netns`: a NAME means `/run/netns/NAME`, the file
/// `ip netns add NAME` creates; a value that starts with `/` is a path used
/// as it is, such as `/proc/PID/ns/net`. A NAME is what iproute2 accepts
/// as one (`invalid_name()` in `ip/ipnetns.c`): one path component, not
/// empty, without `/`, not `.` or `..`, at most `NAME_MAX` octets; and,
/// as in any path, without a NUL character. Nothing is opened here.
///
/// ```
/// use std::path::Path;
/// assert_eq!(bgpfc_config::netns_path("blue").unwrap(), Path::new("/run/netns/blue"));
/// assert_eq!(
///     bgpfc_config::netns_path("/proc/1/ns/net").unwrap(),
///     Path::new("/proc/1/ns/net")
/// );
/// assert!(bgpfc_config::netns_path("a/b").is_err());
/// ```
///
/// # Errors
/// What is wrong with the value, to follow `netns` or `--netns`.
pub fn netns_path(value: &str) -> Result<PathBuf, String> {
    const WANT: &str = "takes a name in /run/netns or an absolute path";
    if value.contains('\0') {
        return Err(format!("{WANT}, not one with a NUL character"));
    }
    if value.starts_with('/') {
        return Ok(PathBuf::from(value));
    }
    if value.is_empty() {
        return Err(format!("{WANT}, not an empty string"));
    }
    if value == "." || value == ".." {
        return Err(format!("{WANT}, not `{value}`"));
    }
    if value.contains('/') {
        return Err(format!("{WANT}, not the relative path `{value}`"));
    }
    if value.len() > NAME_MAX {
        return Err(format!(
            "{WANT}: a name is at most {NAME_MAX} octets, not {}",
            value.len()
        ));
    }
    Ok(Path::new(NETNS_DIR).join(value))
}

/// The check of [`parse_str`] and [`parse_file`]: none.
fn no_check(_: &Config) -> Vec<ConfigError> {
    Vec::new()
}

/// Why a file could not be loaded.
#[derive(Debug)]
pub enum LoadError {
    /// The file could not be read.
    Io(String, std::io::Error),
    /// The file does not parse or validate.
    Config(ConfigErrors),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::Io(path, e) => write!(f, "{path}: {e}"),
            LoadError::Config(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for LoadError {}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    const TEXT: &str = "router-id 192.0.2.1;
local-as 65000;
policy ANY { term all { action accept; } }
neighbor 192.0.2.2 { remote-as 65001; import NONE; export ANY; }
neighbor 192.0.2.3 { remote-as 65002; import ANY; export ANY; }
";

    /// The caller's error at the second neighbor, rendered like the
    /// validation error at the first, and after it.
    #[test]
    fn parse_str_with_reports_the_callers_errors_with_positions() {
        let check = |cfg: &Config| {
            vec![ConfigError::new(
                cfg.neighbors[1].pos,
                "the caller's rule is broken",
            )]
        };
        let errors = parse_str_with("t.conf", TEXT, &check).unwrap_err();
        assert_eq!(errors.len(), 2, "{errors}");
        let text = errors.to_string();
        let (validation, caller) = text.split_once("\nt.conf:5:").expect("two errors");
        assert!(
            validation.starts_with("t.conf:4:1: ") && validation.contains("`NONE`"),
            "{validation}"
        );
        assert_eq!(
            caller,
            "1: the caller's rule is broken\n  \
             neighbor 192.0.2.3 { remote-as 65002; import ANY; export ANY; }\n  ^"
        );
        // Without the caller's check, the file has the validation error
        // alone.
        assert_eq!(parse_str("t.conf", TEXT).unwrap_err().len(), 1);
    }

    /// A check that finds nothing leaves a good file alone.
    #[test]
    fn a_check_that_finds_nothing_accepts_the_file() {
        let text = TEXT.replace("import NONE", "import ANY");
        let checked = Cell::new(0);
        let check = |_: &Config| {
            checked.set(checked.get() + 1);
            Vec::new()
        };
        let cfg = parse_str_with("t.conf", &text, &check).unwrap();
        assert_eq!(checked.get(), 1);
        assert_eq!(cfg, parse_str("t.conf", &text).unwrap());
    }

    /// The caller's check sees only a lowered configuration: a syntax
    /// error or a lowering error stops the pass first.
    #[test]
    fn the_callers_check_runs_only_on_a_lowered_file() {
        let checked = Cell::new(false);
        let check = |_: &Config| {
            checked.set(true);
            vec![ConfigError::new(Pos { line: 1, col: 1 }, "never")]
        };
        let syntax = TEXT.replace("local-as 65000;", "local-as 65000");
        let errors = parse_str_with("t.conf", &syntax, &check).unwrap_err();
        assert!(!errors.to_string().contains("never"), "{errors}");
        let lowering = TEXT.replace("local-as 65000;", "local-as 0;");
        let errors = parse_str_with("t.conf", &lowering, &check).unwrap_err();
        assert!(!errors.to_string().contains("never"), "{errors}");
        assert!(!checked.get(), "the check ran on a file that did not lower");
    }

    /// iproute2's names, and absolute paths as they are; nothing else.
    #[test]
    fn netns_names_and_paths() {
        for (value, path) in [
            ("blue", "/run/netns/blue"),
            ("ns-1.lab_2", "/run/netns/ns-1.lab_2"),
            ("...", "/run/netns/..."),
            ("/proc/42/ns/net", "/proc/42/ns/net"),
            ("/var/run/netns/x", "/var/run/netns/x"),
            ("/", "/"),
        ] {
            assert_eq!(netns_path(value).unwrap(), Path::new(path), "{value}");
        }
        let longest = "n".repeat(NAME_MAX);
        assert_eq!(
            netns_path(&longest).unwrap(),
            Path::new(NETNS_DIR).join(&longest)
        );
        for (value, why) in [
            ("", "not an empty string"),
            (".", "not `.`"),
            ("..", "not `..`"),
            ("a/b", "not the relative path `a/b`"),
            ("./x", "not the relative path `./x`"),
            ("x/", "not the relative path `x/`"),
            ("a\0b", "not one with a NUL character"),
            ("/run/netns/a\0", "not one with a NUL character"),
        ] {
            let err = netns_path(value).unwrap_err();
            assert_eq!(
                err,
                format!("takes a name in /run/netns or an absolute path, {why}"),
                "{value:?}"
            );
        }
        let err = netns_path(&format!("{longest}n")).unwrap_err();
        assert!(
            err.ends_with("a name is at most 255 octets, not 256"),
            "{err}"
        );
    }

    /// A file that cannot be read is an I/O error; one that can is
    /// checked by the caller as text is.
    #[test]
    fn parse_file_with_checks_what_it_reads() {
        let missing = Path::new("/nonexistent/bgpfc.conf");
        let err = parse_file_with(missing, &no_check).unwrap_err();
        assert!(matches!(err, LoadError::Io(..)), "{err}");
        let dir = std::env::temp_dir().join(format!("bgpfc-config-lib-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.conf");
        std::fs::write(&path, TEXT.replace("import NONE", "import ANY")).unwrap();
        let check = |cfg: &Config| vec![ConfigError::new(cfg.neighbors[0].pos, "caller")];
        let err = parse_file_with(&path, &check).unwrap_err();
        std::fs::remove_dir_all(&dir).unwrap();
        let LoadError::Config(errors) = err else {
            panic!("expected config errors, got {err}");
        };
        assert_eq!(
            errors.to_string(),
            format!(
                "{}:4:1: caller\n  \
                 neighbor 192.0.2.2 {{ remote-as 65001; import ANY; export ANY; }}\n  ^",
                path.display()
            )
        );
    }
}

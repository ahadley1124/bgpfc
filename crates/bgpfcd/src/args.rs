//! Command-line arguments: the configuration file and a few overrides
//! (docs/config.md, "Command line").

use std::path::PathBuf;

use bgpfc_config::ast::FibMode;

/// Usage text, also printed on a bad argument.
pub(crate) const USAGE: &str = "\
usage: bgpfcd -c FILE [--check] [--log-level LEVEL] [--fib dry-run|install]
              [--user USER [--group GROUP]]

  -c, --config FILE       configuration file (docs/config.md)
  --check                 parse and validate FILE, then exit
  --log-level LEVEL       override log { level }: error | warn | info | debug | trace
  --fib MODE              override fib { mode }: dry-run | install
  --user USER             when started as root: drop to this user after
                          opening the listeners and the netlink socket
  --group GROUP           the group to drop to (default: USER's primary group)
";

/// Parsed arguments.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Args {
    /// The configuration file.
    pub(crate) config: PathBuf,
    /// Validate and exit.
    pub(crate) check: bool,
    /// Log level override.
    pub(crate) log_level: Option<bgpfc_log::Level>,
    /// FIB mode override.
    pub(crate) fib: Option<FibMode>,
    /// User to drop to (README, "Option B").
    pub(crate) user: Option<String>,
    /// Group to drop to.
    pub(crate) group: Option<String>,
}

/// Parse `argv[1..]`.
///
/// # Errors
/// A message to print, followed by [`USAGE`]; an empty message for
/// `--help`.
pub(crate) fn parse(args: &[String]) -> Result<Args, String> {
    let mut config = None;
    let mut check = false;
    let mut log_level = None;
    let mut fib = None;
    let mut user = None;
    let mut group = None;
    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        let value = || {
            args.get(i + 1)
                .cloned()
                .ok_or_else(|| format!("{flag} needs a value"))
        };
        let mut used_value = true;
        match flag {
            "-c" | "--config" => config = Some(PathBuf::from(value()?)),
            "--check" => {
                check = true;
                used_value = false;
            }
            "--log-level" => {
                log_level = Some(bgpfc_log::Level::parse(&value()?).ok_or("bad --log-level")?);
            }
            "--fib" => {
                fib = Some(match value()?.as_str() {
                    "dry-run" => FibMode::DryRun,
                    "install" => FibMode::Install,
                    _ => return Err("--fib takes dry-run or install".to_owned()),
                });
            }
            "--user" => user = Some(value()?),
            "--group" => group = Some(value()?),
            "-h" | "--help" => return Err(String::new()),
            other => return Err(format!("unknown argument {other}")),
        }
        i += if used_value { 2 } else { 1 };
    }
    if group.is_some() && user.is_none() {
        return Err("--group needs --user".to_owned());
    }
    Ok(Args {
        config: config.ok_or("-c FILE is required")?,
        check,
        log_level,
        fib,
        user,
        group,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn parses_flags() {
        let a = parse(&argv(
            "-c /etc/bgpfc/bgpfc.conf --check --log-level debug --fib install",
        ))
        .unwrap();
        assert_eq!(
            a,
            Args {
                config: PathBuf::from("/etc/bgpfc/bgpfc.conf"),
                check: true,
                log_level: Some(bgpfc_log::Level::Debug),
                fib: Some(FibMode::Install),
                user: None,
                group: None,
            }
        );
        let a = parse(&argv("-c x --user bgpfc --group net")).unwrap();
        assert_eq!(a.user.as_deref(), Some("bgpfc"));
        assert_eq!(a.group.as_deref(), Some("net"));
        let a = parse(&argv("--config x.conf")).unwrap();
        assert_eq!(a.config, PathBuf::from("x.conf"));
        assert!(!a.check);
        assert_eq!(a.log_level, None);
        assert_eq!(a.fib, None);
    }

    #[test]
    fn errors() {
        for bad in [
            "",
            "--check",
            "-c",
            "-c x --log-level loud",
            "-c x --fib maybe",
            "-c x --bogus",
            "-c x --group g",
        ] {
            assert!(parse(&argv(bad)).is_err(), "{bad}");
        }
        assert_eq!(parse(&argv("--help")), Err(String::new()));
    }
}

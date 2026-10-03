//! Command-line arguments: the configuration file and a few overrides
//! (docs/config.md, "Command line").

use std::path::PathBuf;

use bgpfc_config::ast::FibMode;

/// Usage text, also printed on a bad argument.
pub(crate) const USAGE: &str = "\
usage: bgpfcd -c FILE [--check] [--log-level LEVEL] [--fib dry-run|install]

  -c, --config FILE       configuration file (docs/config.md)
  --check                 parse and validate FILE, then exit
  --log-level LEVEL       override log { level }: error | warn | info | debug | trace
  --fib MODE              override fib { mode }: dry-run | install
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
            "-h" | "--help" => return Err(String::new()),
            other => return Err(format!("unknown argument {other}")),
        }
        i += if used_value { 2 } else { 1 };
    }
    Ok(Args {
        config: config.ok_or("-c FILE is required")?,
        check,
        log_level,
        fib,
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
            }
        );
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
        ] {
            assert!(parse(&argv(bad)).is_err(), "{bad}");
        }
        assert_eq!(parse(&argv("--help")), Err(String::new()));
    }
}

//! Routinator's version: parse what `routinator --version` prints and check
//! that it is the release series the command line was written for, so a
//! mismatch is reported clearly at startup (issue #72) instead of showing
//! up as a child that exits on an unknown option.
//!
//! Implements: no RFC. Routinator builds its command line with clap as
//! `Command::new("Routinator").version(crate_version!())` (`src/main.rs`
//! at v0.15.2), so `--version` prints `Routinator 0.15.2`.

use std::fmt;

use crate::error::SidecarError;

/// A Routinator release number: `major.minor.patch`, with an optional
/// pre-release tag such as `rc1`. Semantic-versioning build metadata
/// (`+...`) is accepted when parsing and dropped.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Version {
    /// Major version.
    pub major: u64,
    /// Minor version. While the major version is 0, a new minor version
    /// may change the command line.
    pub minor: u64,
    /// Patch version.
    pub patch: u64,
    /// Pre-release tag, without the leading `-`.
    pub pre: Option<String>,
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if let Some(pre) = &self.pre {
            write!(f, "-{pre}")?;
        }
        Ok(())
    }
}

/// The newest stable Routinator release whose documentation the command
/// line follows: 0.15.2, released 2026-06-08 (`Changelog.md`). Its manual
/// page is <https://routinator.docs.nlnetlabs.nl/en/stable/manual-page.html>,
/// built from
/// <https://github.com/NLnetLabs/routinator/blob/v0.15.2/doc/manual/source/manual-page.rst>.
pub const TESTED_VERSION: Version = Version {
    major: 0,
    minor: 15,
    patch: 2,
    pre: None,
};

/// How much of an unrecognised `--version` output an error repeats.
const EXCERPT_CHARS: usize = 120;

/// The version in the output of `routinator --version`, or `None` if the
/// output names another program or no well-formed version.
///
/// The first line whose first word is `Routinator` (in any case) and whose
/// second word is `major.minor.patch`, optionally prefixed with `v` and
/// followed by a pre-release tag or build metadata, wins. Other lines,
/// such as warnings, and words after the version are ignored.
#[must_use]
pub fn parse_version(stdout: &str) -> Option<Version> {
    stdout.lines().find_map(|line| {
        let mut words = line.split_whitespace();
        if !words.next()?.eq_ignore_ascii_case("routinator") {
            return None;
        }
        parse_number(words.next()?)
    })
}

/// `major.minor.patch[-pre][+build]`, optionally prefixed with `v`.
fn parse_number(text: &str) -> Option<Version> {
    let text = text.strip_prefix(['v', 'V']).unwrap_or(text);
    let (text, build) = match text.split_once('+') {
        Some((text, build)) => (text, Some(build)),
        None => (text, None),
    };
    let (core, pre) = match text.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (text, None),
    };
    if !pre.is_none_or(is_tag) || !build.is_none_or(is_tag) {
        return None;
    }
    let mut parts = core.split('.');
    let major = component(parts.next()?)?;
    let minor = component(parts.next()?)?;
    let patch = component(parts.next()?)?;
    if parts.next().is_some() {
        return None;
    }
    Some(Version {
        major,
        minor,
        patch,
        pre: pre.map(str::to_owned),
    })
}

/// A numeric component: ASCII digits only (`u64::from_str` would also take
/// a leading `+`), and small enough for a `u64`.
fn component(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// A pre-release tag or build metadata: dot-separated, non-empty
/// identifiers of ASCII letters, digits and `-` (Semantic Versioning 2.0.0,
/// items 9 and 10).
fn is_tag(text: &str) -> bool {
    text.split('.')
        .all(|id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
}

/// Whether `found` is from the same release series as [`TESTED_VERSION`]:
/// the same major and minor version. The patch level and pre-release tag
/// do not matter.
///
/// # Errors
/// [`SidecarError::IncompatibleVersion`], naming both versions.
pub fn check_compatible(found: &Version) -> Result<(), SidecarError> {
    if found.major == TESTED_VERSION.major && found.minor == TESTED_VERSION.minor {
        Ok(())
    } else {
        Err(SidecarError::IncompatibleVersion {
            found: found.clone(),
            tested: TESTED_VERSION,
        })
    }
}

/// [`parse_version`] and then [`check_compatible`]: the startup check on
/// the output of `routinator --version`.
///
/// # Errors
/// [`SidecarError::UnrecognizedVersion`] with the start of the output when
/// it holds no version, or [`SidecarError::IncompatibleVersion`].
pub fn check_version_output(stdout: &str) -> Result<Version, SidecarError> {
    let Some(version) = parse_version(stdout) else {
        return Err(SidecarError::UnrecognizedVersion {
            output: excerpt(stdout),
        });
    };
    check_compatible(&version)?;
    Ok(version)
}

/// The start of what a program printed, for an error message: trimmed,
/// at most [`EXCERPT_CHARS`] characters, and `...` if there was more.
pub(crate) fn excerpt(output: &str) -> String {
    let trimmed = output.trim();
    let mut excerpt: String = trimmed.chars().take(EXCERPT_CHARS).collect();
    if excerpt.len() < trimmed.len() {
        excerpt.push_str("...");
    }
    excerpt
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(major: u64, minor: u64, patch: u64, pre: Option<&str>) -> Version {
        Version {
            major,
            minor,
            patch,
            pre: pre.map(str::to_owned),
        }
    }

    #[test]
    fn parses_good_and_odd_outputs() {
        let cases: &[(&str, Version)] = &[
            // What clap prints for the release this crate targets.
            ("Routinator 0.15.2\n", v(0, 15, 2, None)),
            ("Routinator 0.14.2", v(0, 14, 2, None)),
            ("Routinator 0.15.0-rc1\n", v(0, 15, 0, Some("rc1"))),
            ("Routinator 0.16.0-dev", v(0, 16, 0, Some("dev"))),
            ("Routinator 1.2.3-rc.1-x", v(1, 2, 3, Some("rc.1-x"))),
            // Odd but unambiguous.
            ("routinator 0.15.2", v(0, 15, 2, None)),
            ("ROUTINATOR v0.15.2", v(0, 15, 2, None)),
            ("  Routinator\t0.15.2  \r\n", v(0, 15, 2, None)),
            ("Routinator 0.15.2+deb12u1", v(0, 15, 2, None)),
            ("Routinator 0.15.0-rc1+build.7", v(0, 15, 0, Some("rc1"))),
            (
                "Routinator 0.15.2 (built from git abc123)",
                v(0, 15, 2, None),
            ),
            ("warning: something\nRoutinator 0.15.2\n", v(0, 15, 2, None)),
            ("Routinator\nRoutinator 0.15.1", v(0, 15, 1, None)),
            ("Routinator 0.015.2", v(0, 15, 2, None)),
        ];
        for (output, expected) in cases {
            assert_eq!(parse_version(output).as_ref(), Some(expected), "{output:?}");
        }
    }

    #[test]
    fn rejects_garbage() {
        let cases = [
            "",
            "\n\n",
            "Routinator",
            "Routinator ",
            "Routinator 0.15",
            "Routinator 0.15.",
            "Routinator 0.15.2.1",
            "Routinator .15.2",
            "Routinator 0..2",
            "Routinator 0.x.2",
            "Routinator 0.15.+2",
            "Routinator -0.15.2",
            "Routinator 0.15.2-",
            "Routinator 0.15.2-rc..1",
            "Routinator 0.15.2-rc_1",
            "Routinator 0.15.2+",
            "Routinator vv0.15.2",
            "Routinator 0.15.2\u{feff}",
            "Routinator 18446744073709551616.0.0",
            "Routinator: 0.15.2",
            "routinator-ng 0.15.2",
            "rpki-client 9.5",
            "0.15.2",
            "error: unexpected argument '--version' found",
            "\u{0}\u{1}\u{fffd}garbage",
        ];
        for output in cases {
            assert_eq!(parse_version(output), None, "{output:?}");
        }
    }

    #[test]
    fn display_round_trips() {
        for text in ["0.15.2", "0.15.0-rc1", "1.0.0-alpha.1"] {
            let parsed = parse_version(&format!("Routinator {text}")).unwrap();
            assert_eq!(parsed.to_string(), text);
        }
        assert_eq!(TESTED_VERSION.to_string(), "0.15.2");
    }

    #[test]
    fn same_major_minor_is_compatible() {
        let cases: &[(Version, bool)] = &[
            (TESTED_VERSION, true),
            (v(0, 15, 0, None), true),
            (v(0, 15, 9, None), true),
            (v(0, 15, 0, Some("rc1")), true),
            (v(0, 14, 2, None), false),
            (v(0, 16, 0, None), false),
            (v(0, 16, 0, Some("rc1")), false),
            (v(1, 15, 2, None), false),
            (v(0, 1, 15, None), false),
        ];
        for (found, ok) in cases {
            let result = check_compatible(found);
            assert_eq!(result.is_ok(), *ok, "{found}");
            if let Err(e) = result {
                assert_eq!(
                    e,
                    SidecarError::IncompatibleVersion {
                        found: found.clone(),
                        tested: TESTED_VERSION,
                    }
                );
            }
        }
    }

    #[test]
    fn mismatch_message_names_both_versions() {
        let err = check_version_output("Routinator 0.14.2\n").unwrap_err();
        assert_eq!(
            err.to_string(),
            "Routinator 0.14.2 is not supported: bgpfcd drives Routinator 0.15.x and was tested with 0.15.2"
        );
    }

    #[test]
    fn startup_check() {
        assert_eq!(
            check_version_output("Routinator 0.15.1\n"),
            Ok(v(0, 15, 1, None))
        );
        assert_eq!(
            check_version_output("  bash: routinator: command not found \n"),
            Err(SidecarError::UnrecognizedVersion {
                output: "bash: routinator: command not found".to_owned()
            })
        );
        // Long output is cut, on a character boundary.
        let long = "é".repeat(500);
        let Err(SidecarError::UnrecognizedVersion { output }) = check_version_output(&long) else {
            panic!("expected UnrecognizedVersion");
        };
        assert_eq!(output, format!("{}...", "é".repeat(EXCERPT_CHARS)));
        let err = check_version_output("").unwrap_err();
        assert_eq!(
            err.to_string(),
            "`routinator --version` printed \"\", which is not a Routinator version"
        );
    }
}

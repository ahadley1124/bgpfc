//! Configuration errors with a position and a caret snippet (AGENTS.md §3,
//! "Config": every error carries `file:line:col`).

use std::fmt;

/// A position in a configuration file: 1-based line and column.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Pos {
    /// Line, starting at 1.
    pub line: u32,
    /// Column in characters, starting at 1.
    pub col: u32,
}

impl fmt::Display for Pos {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.line, self.col)
    }
}

/// One problem with the configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigError {
    /// Where it is.
    pub pos: Pos,
    /// What is wrong.
    pub message: String,
}

impl ConfigError {
    /// Build an error.
    #[must_use]
    pub fn new(pos: Pos, message: impl Into<String>) -> ConfigError {
        ConfigError {
            pos,
            message: message.into(),
        }
    }
}

/// Every problem found in one file, in source order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigErrors {
    /// File name as given to the parser.
    pub file: String,
    /// The problems; never empty.
    pub errors: Vec<ConfigError>,
    /// The source, for snippets.
    source: String,
}

impl ConfigErrors {
    pub(crate) fn new(file: &str, source: &str, mut errors: Vec<ConfigError>) -> ConfigErrors {
        errors.sort_by_key(|e| e.pos);
        ConfigErrors {
            file: file.to_owned(),
            errors,
            source: source.to_owned(),
        }
    }

    /// Number of problems.
    #[must_use]
    pub fn len(&self) -> usize {
        self.errors.len()
    }

    /// Never true for a value the parser returned, but required for `len`.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.errors.is_empty()
    }

    /// `file:line:col: message`, the offending line, and a caret under the
    /// column, for each error.
    fn render(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, e) in self.errors.iter().enumerate() {
            if i > 0 {
                writeln!(f)?;
            }
            writeln!(f, "{}:{}: {}", self.file, e.pos, e.message)?;
            if let Some(line) = self
                .source
                .lines()
                .nth(e.pos.line.saturating_sub(1) as usize)
            {
                let line = line.trim_end();
                writeln!(f, "  {line}")?;
                let pad = line
                    .chars()
                    .take(e.pos.col.saturating_sub(1) as usize)
                    .map(|c| if c == '\t' { '\t' } else { ' ' })
                    .collect::<String>();
                write!(f, "  {pad}^")?;
            }
        }
        Ok(())
    }
}

impl fmt::Display for ConfigErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.render(f)
    }
}

impl std::error::Error for ConfigErrors {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_position_line_and_caret() {
        let src = "router-id 192.0.2.1;\nlocal-as zero;\n";
        let errs = ConfigErrors::new(
            "t.conf",
            src,
            vec![
                ConfigError::new(Pos { line: 2, col: 10 }, "bad AS number"),
                ConfigError::new(Pos { line: 1, col: 1 }, "first"),
            ],
        );
        assert_eq!(errs.len(), 2);
        assert!(!errs.is_empty());
        let text = errs.to_string();
        assert_eq!(
            text,
            "t.conf:1:1: first\n  router-id 192.0.2.1;\n  ^\n\
             t.conf:2:10: bad AS number\n  local-as zero;\n           ^"
        );
    }
}

//! Configuration language: lexer, parser, typed configuration and
//! validation (AGENTS.md §3, "Config"). The grammar is documented
//! in `docs/config.md`.
//!
//! Implements: RFC 4271 §4.2 and §10 (Hold Time and timer defaults per
//! neighbor); RFC 7607 §2 (AS 0 is rejected); RFC 9687 §4.4
//! (`send-hold-time`); RFC 9774 §3 (`allow-as-set`).
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
pub mod error;
pub mod lexer;
mod lower;
pub mod parser;
mod validate;

use std::path::Path;

pub use ast::Config;
pub use error::{ConfigError, ConfigErrors, Pos};

/// Parse and validate configuration text. `file` names it in errors.
///
/// # Errors
/// Every problem found, in source order. Lexical and syntax errors stop
/// the pass before lowering; otherwise lowering and validation errors are
/// reported together.
pub fn parse_str(file: &str, text: &str) -> Result<Config, ConfigErrors> {
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
    let errors = validate::validate(&cfg);
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
    let text =
        std::fs::read_to_string(path).map_err(|e| LoadError::Io(path.display().to_string(), e))?;
    parse_str(&path.display().to_string(), &text).map_err(LoadError::Config)
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

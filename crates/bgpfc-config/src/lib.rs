//! Configuration language: lexer, parser, typed configuration, validation
//! and reload diffing (AGENTS.md §3, "Config"). The grammar is documented
//! in `docs/config.md`.
//!
//! Implements: nothing protocol-level yet; the typed configuration follows.
#![forbid(unsafe_code)]

pub mod error;
pub mod lexer;
pub mod parser;

pub use error::{ConfigError, ConfigErrors, Pos};

/// Parse text into generic statements, reporting every lexical and syntax
/// error. `file` names the text in errors.
///
/// # Errors
/// Every problem found, in source order.
pub fn parse_statements(file: &str, text: &str) -> Result<Vec<parser::Statement>, ConfigErrors> {
    let (tokens, mut errors) = lexer::lex(text);
    let (statements, parse_errors) = parser::parse(&tokens);
    errors.extend(parse_errors);
    if errors.is_empty() {
        Ok(statements)
    } else {
        Err(ConfigErrors::new(file, text, errors))
    }
}

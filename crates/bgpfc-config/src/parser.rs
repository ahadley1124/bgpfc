//! The generic block grammar, before any keyword has meaning:
//!
//! ```text
//! file      = { statement } ;
//! statement = word { argument } ( ";" | block ) ;
//! block     = "{" { statement } "}" ;
//! argument  = word | string ;
//! ```
//!
//! Errors are collected, not fatal: after one, parsing resumes at the next
//! `;` or `}` at the same depth so that one file reports several problems
//! (AGENTS.md §3, "Config").

use crate::error::{ConfigError, Pos};
use crate::lexer::{Token, TokenKind};

/// A statement: a keyword, its arguments, and either a terminating `;` or
/// a block of nested statements.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    /// Where the keyword starts.
    pub pos: Pos,
    /// The keyword.
    pub keyword: String,
    /// Arguments in order.
    pub args: Vec<Arg>,
    /// Nested statements, when the statement ends in a block.
    pub block: Option<Vec<Statement>>,
}

impl Statement {
    /// The argument values as strings, for simple statements.
    #[must_use]
    pub fn arg_strs(&self) -> Vec<&str> {
        self.args.iter().map(|a| a.value.as_str()).collect()
    }
}

/// One argument: a word or a quoted string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Arg {
    /// Where it starts.
    pub pos: Pos,
    /// Its text (string escapes already resolved).
    pub value: String,
    /// Whether it was quoted.
    pub quoted: bool,
}

struct Parser<'a> {
    tokens: &'a [Token],
    i: usize,
    errors: Vec<ConfigError>,
}

/// Parse a token stream into top-level statements, collecting errors.
#[must_use]
pub fn parse(tokens: &[Token]) -> (Vec<Statement>, Vec<ConfigError>) {
    let mut p = Parser {
        tokens,
        i: 0,
        errors: Vec::new(),
    };
    let statements = p.statements(None);
    (statements, p.errors)
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.i)
    }

    fn end_pos(&self) -> Pos {
        self.tokens
            .last()
            .map_or(Pos { line: 1, col: 1 }, |t| t.pos)
    }

    /// Statements until the end of input, or until the `}` closing the
    /// block that `opened_by` (a keyword and its position) started.
    fn statements(&mut self, opened_by: Option<(&str, Pos)>) -> Vec<Statement> {
        let mut out = Vec::new();
        loop {
            match self.peek() {
                None => {
                    if let Some((keyword, pos)) = opened_by {
                        self.errors.push(ConfigError::new(
                            self.end_pos(),
                            format!("missing `}}` for the `{keyword}` block opened at {pos}"),
                        ));
                    }
                    return out;
                }
                Some(t) if t.kind == TokenKind::Close => {
                    if opened_by.is_some() {
                        self.i += 1;
                    } else {
                        self.errors
                            .push(ConfigError::new(t.pos, "unexpected `}` outside any block"));
                        self.i += 1;
                        continue;
                    }
                    return out;
                }
                Some(_) => {
                    if let Some(s) = self.statement() {
                        out.push(s);
                    }
                }
            }
        }
    }

    fn statement(&mut self) -> Option<Statement> {
        let first = self.peek().cloned()?;
        let keyword = match first.kind {
            TokenKind::Word(w) => w,
            other => {
                self.errors.push(ConfigError::new(
                    first.pos,
                    format!("expected a keyword, found {}", other.describe()),
                ));
                self.recover();
                return None;
            }
        };
        self.i += 1;
        let mut args = Vec::new();
        loop {
            let Some(t) = self.peek().cloned() else {
                self.errors.push(ConfigError::new(
                    self.end_pos(),
                    format!("`{keyword}` is not terminated by `;` or a block"),
                ));
                return None;
            };
            match t.kind {
                TokenKind::Word(w) => {
                    args.push(Arg {
                        pos: t.pos,
                        value: w,
                        quoted: false,
                    });
                    self.i += 1;
                }
                TokenKind::Str(s) => {
                    args.push(Arg {
                        pos: t.pos,
                        value: s,
                        quoted: true,
                    });
                    self.i += 1;
                }
                TokenKind::Semi => {
                    self.i += 1;
                    return Some(Statement {
                        pos: first.pos,
                        keyword,
                        args,
                        block: None,
                    });
                }
                TokenKind::Open => {
                    self.i += 1;
                    let block = self.statements(Some((&keyword, first.pos)));
                    return Some(Statement {
                        pos: first.pos,
                        keyword,
                        args,
                        block: Some(block),
                    });
                }
                TokenKind::Close => {
                    self.errors.push(ConfigError::new(
                        t.pos,
                        format!("`{keyword}` is missing its `;`"),
                    ));
                    // Leave the `}` for the enclosing block.
                    return Some(Statement {
                        pos: first.pos,
                        keyword,
                        args,
                        block: None,
                    });
                }
            }
        }
    }

    /// Skip to just after the next `;` at this depth or after a whole
    /// stray block, or to the `}` that closes the current block (left for
    /// the caller).
    fn recover(&mut self) {
        let mut depth = 0usize;
        while let Some(t) = self.peek() {
            match t.kind {
                TokenKind::Open => depth += 1,
                TokenKind::Close => {
                    if depth == 0 {
                        return;
                    }
                    depth -= 1;
                    if depth == 0 {
                        self.i += 1;
                        return;
                    }
                }
                TokenKind::Semi if depth == 0 => {
                    self.i += 1;
                    return;
                }
                _ => {}
            }
            self.i += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::lex;

    fn parse_src(src: &str) -> (Vec<Statement>, Vec<ConfigError>) {
        let (tokens, lex_errors) = lex(src);
        assert_eq!(lex_errors, vec![]);
        parse(&tokens)
    }

    #[test]
    fn statements_and_blocks() {
        let (s, e) = parse_src("a 1 \"two\"; b { c; d x { e; } }");
        assert!(e.is_empty(), "{e:?}");
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].keyword, "a");
        assert_eq!(s[0].arg_strs(), ["1", "two"]);
        assert!(s[0].args[1].quoted);
        assert!(s[0].block.is_none());
        let b = s[1].block.as_ref().unwrap();
        assert_eq!(b.len(), 2);
        assert_eq!(b[1].keyword, "d");
        assert_eq!(b[1].arg_strs(), ["x"]);
        assert_eq!(b[1].block.as_ref().unwrap()[0].keyword, "e");
        assert_eq!(s[1].pos, Pos { line: 1, col: 12 });
    }

    #[test]
    fn errors_are_reported_and_parsing_continues() {
        let (s, e) = parse_src("a; ; b { c } d; }\ne");
        let msgs: Vec<&str> = e.iter().map(|e| e.message.as_str()).collect();
        assert_eq!(
            msgs,
            [
                "expected a keyword, found `;`",
                "`c` is missing its `;`",
                "unexpected `}` outside any block",
                "`e` is not terminated by `;` or a block",
            ]
        );
        // What could be parsed survives: a, b (with c), d.
        let kws: Vec<&str> = s.iter().map(|s| s.keyword.as_str()).collect();
        assert_eq!(kws, ["a", "b", "d"]);
        let (s, e) = parse_src("x { y; ");
        assert_eq!(e[0].message, "missing `}` for the `x` block opened at 1:1");
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn recovery_skips_a_whole_bad_statement() {
        let (s, e) = parse_src("\"str\" first; { skipped { inner; } } second;");
        assert_eq!(e.len(), 2);
        let kws: Vec<&str> = s.iter().map(|s| s.keyword.as_str()).collect();
        assert_eq!(kws, ["second"]);
    }
}

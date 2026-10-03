//! Tokens: words, quoted strings, `{`, `}`, `;`. Comments run from `#` to
//! the end of the line.
//!
//! A word is any run of characters that are not whitespace, a quote, a
//! brace, a semicolon or `#`; that lets addresses (`2001:db8::1`),
//! prefixes (`10.0.0.0/8`), communities (`65000:100`) and keywords
//! (`ipv4-unicast`) share one token kind. The parser gives words meaning.

use crate::error::{ConfigError, Pos};

/// One token with its position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token {
    /// Where it starts.
    pub pos: Pos,
    /// What it is.
    pub kind: TokenKind,
}

/// Token kinds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TokenKind {
    /// A bare word.
    Word(String),
    /// A double-quoted string, escapes resolved.
    Str(String),
    /// `{`
    Open,
    /// `}`
    Close,
    /// `;`
    Semi,
}

impl TokenKind {
    /// How the token reads in an error message.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            TokenKind::Word(w) => format!("`{w}`"),
            TokenKind::Str(s) => format!("\"{s}\""),
            TokenKind::Open => "`{`".to_owned(),
            TokenKind::Close => "`}`".to_owned(),
            TokenKind::Semi => "`;`".to_owned(),
        }
    }
}

/// Tokenise `src`. Lexical errors (an unterminated string, a bad escape)
/// are collected; lexing continues after them so the parser can report
/// more.
#[must_use]
pub fn lex(src: &str) -> (Vec<Token>, Vec<ConfigError>) {
    let mut tokens = Vec::new();
    let mut errors = Vec::new();
    let mut line = 1u32;
    let mut col = 1u32;
    let mut chars = src.chars().peekable();
    while let Some(c) = chars.next() {
        let pos = Pos { line, col };
        match c {
            '\n' => {
                line += 1;
                col = 1;
                continue;
            }
            c if c.is_whitespace() => {}
            '#' => {
                // Comment to end of line; the newline itself is handled
                // on the next iteration.
                while let Some(&n) = chars.peek() {
                    if n == '\n' {
                        break;
                    }
                    chars.next();
                    col += 1;
                }
            }
            '{' => tokens.push(Token {
                pos,
                kind: TokenKind::Open,
            }),
            '}' => tokens.push(Token {
                pos,
                kind: TokenKind::Close,
            }),
            ';' => tokens.push(Token {
                pos,
                kind: TokenKind::Semi,
            }),
            '"' => {
                let mut s = String::new();
                let mut closed = false;
                while let Some(n) = chars.next() {
                    col += 1;
                    match n {
                        '"' => {
                            closed = true;
                            break;
                        }
                        '\\' => match chars.next() {
                            Some(e) => {
                                col += 1;
                                match e {
                                    '"' => s.push('"'),
                                    '\\' => s.push('\\'),
                                    'n' => s.push('\n'),
                                    't' => s.push('\t'),
                                    other => {
                                        errors.push(ConfigError::new(
                                            Pos { line, col },
                                            format!("unknown escape `\\{other}` in string"),
                                        ));
                                        s.push(other);
                                    }
                                }
                            }
                            None => break,
                        },
                        '\n' => {
                            line += 1;
                            col = 0;
                            s.push('\n');
                        }
                        other => s.push(other),
                    }
                }
                if !closed {
                    errors.push(ConfigError::new(pos, "unterminated string"));
                }
                tokens.push(Token {
                    pos,
                    kind: TokenKind::Str(s),
                });
            }
            _ => {
                let mut w = String::new();
                w.push(c);
                while let Some(&n) = chars.peek() {
                    if n.is_whitespace() || matches!(n, '{' | '}' | ';' | '"' | '#') {
                        break;
                    }
                    w.push(n);
                    chars.next();
                    col += 1;
                }
                tokens.push(Token {
                    pos,
                    kind: TokenKind::Word(w),
                });
            }
        }
        col += 1;
    }
    (tokens, errors)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(src: &str) -> Vec<TokenKind> {
        let (t, e) = lex(src);
        assert!(e.is_empty(), "{e:?}");
        t.into_iter().map(|t| t.kind).collect()
    }

    #[test]
    fn words_punctuation_strings_and_comments() {
        use TokenKind::{Close, Open, Semi, Str, Word};
        assert_eq!(
            kinds("neighbor 2001:db8::1 { description \"a \\\"b\\\"\"; } # c\nx;"),
            vec![
                Word("neighbor".into()),
                Word("2001:db8::1".into()),
                Open,
                Word("description".into()),
                Str("a \"b\"".into()),
                Semi,
                Close,
                Word("x".into()),
                Semi,
            ]
        );
        assert_eq!(
            kinds("a{b}c;"),
            vec![
                Word("a".into()),
                Open,
                Word("b".into()),
                Close,
                Word("c".into()),
                Semi
            ]
        );
        assert_eq!(kinds("10.0.0.0/8 le 32;")[0], Word("10.0.0.0/8".into()));
    }

    #[test]
    fn positions_are_line_and_column() {
        let (t, _) = lex("ab cd\n  ef \"g\" {");
        let pos: Vec<(u32, u32)> = t.iter().map(|t| (t.pos.line, t.pos.col)).collect();
        assert_eq!(pos, vec![(1, 1), (1, 4), (2, 3), (2, 6), (2, 10)]);
    }

    #[test]
    fn lexical_errors_are_collected() {
        let (t, e) = lex("a \"x\\q\"; b \"open\n");
        assert_eq!(e.len(), 2);
        assert!(e[0].message.contains("escape"));
        assert!(e[1].message.contains("unterminated"));
        assert_eq!(t.len(), 5);
        assert_eq!(TokenKind::Open.describe(), "`{`");
        assert_eq!(TokenKind::Word("w".into()).describe(), "`w`");
    }
}

//! Regular expressions over AS numbers, for `match as-path` (AGENTS.md §3,
//! "Policy": operators act on ASN tokens, not characters).
//!
//! Syntax, in the spirit of the Cisco and FRR AS-path regexes:
//!
//! ```text
//! pattern  = alt ;
//! alt      = seq { "|" seq } ;
//! seq      = { repeat } ;
//! repeat   = atom [ "*" | "+" | "?" ] ;
//! atom     = ASN | "." | "^" | "$" | "[" ["^"] { ASN | ASN "-" ASN } "]" | "(" alt ")" ;
//! ```
//!
//! Tokens may be separated by whitespace or `_`, which carry no meaning
//! themselves: `^65001 .* 7$` and `^65001_.*_7$` are the same. `^` and `$`
//! anchor to the start and end of the path; a pattern without anchors
//! matches anywhere. `.` matches any one ASN. The pattern is compiled to a
//! Thompson NFA and run as a state-set simulation, so matching takes time
//! proportional to the pattern size times the path length whatever the
//! pattern looks like.

use std::fmt;

use bgpfc_wire::types::Asn;

/// Why a pattern did not compile. `pos` is the character offset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegexError {
    /// Offset into the pattern.
    pub pos: usize,
    /// What is wrong.
    pub message: String,
}

impl fmt::Display for RegexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "at offset {}: {}", self.pos, self.message)
    }
}

impl std::error::Error for RegexError {}

/// Largest number of NFA instructions one pattern may compile to; keeps a
/// configuration from costing unbounded memory or time per route.
pub const MAX_INSTRUCTIONS: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Inst {
    Asn(u32),
    Any,
    Class {
        negated: bool,
        ranges: Vec<(u32, u32)>,
    },
    Start,
    End,
    /// Try `a` first, then `b` (order is irrelevant without captures).
    Split(usize, usize),
    Jmp(usize),
    Match,
}

/// A compiled AS-path regular expression.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AsPathRegex {
    insts: Vec<Inst>,
    anchored_start: bool,
    source: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    Asn(u32),
    Dot,
    Caret,
    Dollar,
    Class {
        negated: bool,
        ranges: Vec<(u32, u32)>,
    },
    Open,
    Close,
    Bar,
    Star,
    Plus,
    Question,
}

fn tokenize(src: &str) -> Result<Vec<(usize, Token)>, RegexError> {
    let bytes = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    let err = |pos: usize, m: &str| RegexError {
        pos,
        message: m.to_owned(),
    };
    while i < bytes.len() {
        let c = bytes[i];
        let start = i;
        let tok = match c {
            b' ' | b'\t' | b'_' => {
                i += 1;
                continue;
            }
            b'.' => Token::Dot,
            b'^' => Token::Caret,
            b'$' => Token::Dollar,
            b'(' => Token::Open,
            b')' => Token::Close,
            b'|' => Token::Bar,
            b'*' => Token::Star,
            b'+' => Token::Plus,
            b'?' => Token::Question,
            b'0'..=b'9' => {
                let (n, next) = number(bytes, i)?;
                i = next;
                out.push((start, Token::Asn(n)));
                continue;
            }
            b'[' => {
                i += 1;
                let negated = bytes.get(i) == Some(&b'^');
                if negated {
                    i += 1;
                }
                let mut ranges = Vec::new();
                loop {
                    while matches!(bytes.get(i), Some(b' ' | b'\t' | b'_' | b',')) {
                        i += 1;
                    }
                    match bytes.get(i) {
                        None => return Err(err(start, "unterminated `[`")),
                        Some(b']') => {
                            i += 1;
                            break;
                        }
                        Some(b'0'..=b'9') => {
                            let (lo, next) = number(bytes, i)?;
                            i = next;
                            let hi = if bytes.get(i) == Some(&b'-') {
                                let (hi, next) = number(bytes, i + 1)?;
                                i = next;
                                hi
                            } else {
                                lo
                            };
                            if hi < lo {
                                return Err(err(start, "range bounds are reversed"));
                            }
                            ranges.push((lo, hi));
                        }
                        Some(_) => return Err(err(i, "expected an AS number or `]`")),
                    }
                }
                if ranges.is_empty() {
                    return Err(err(start, "empty `[]`"));
                }
                out.push((start, Token::Class { negated, ranges }));
                continue;
            }
            _ => {
                return Err(err(
                    i,
                    "expected an AS number, `.`, `^`, `$`, `[`, `(`, `)`, `|`, `*`, `+` or `?`",
                ));
            }
        };
        out.push((start, tok));
        i += 1;
    }
    Ok(out)
}

fn number(bytes: &[u8], mut i: usize) -> Result<(u32, usize), RegexError> {
    let start = i;
    let mut n: u32 = 0;
    while let Some(d) = bytes.get(i).filter(|b| b.is_ascii_digit()) {
        n = n
            .checked_mul(10)
            .and_then(|n| n.checked_add(u32::from(d - b'0')))
            .ok_or_else(|| RegexError {
                pos: start,
                message: "AS number does not fit in 32 bits".to_owned(),
            })?;
        i += 1;
    }
    if i == start {
        return Err(RegexError {
            pos: start,
            message: "expected an AS number".to_owned(),
        });
    }
    Ok((n, i))
}

/// A partial program: instruction indices are relative until linked.
struct Frag {
    insts: Vec<Inst>,
}

struct Parser {
    tokens: Vec<(usize, Token)>,
    i: usize,
    end: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.i).map(|(_, t)| t)
    }

    fn pos(&self) -> usize {
        self.tokens.get(self.i).map_or(self.end, |(p, _)| *p)
    }

    fn alt(&mut self) -> Result<Frag, RegexError> {
        let mut branches = vec![self.seq()?];
        while self.peek() == Some(&Token::Bar) {
            self.i += 1;
            branches.push(self.seq()?);
        }
        if branches.len() == 1 {
            return Ok(branches.pop().expect("one branch"));
        }
        // split L1, L2; L1: a; jmp end; L2: split ...
        let mut insts: Vec<Inst> = Vec::new();
        let total: usize = branches.iter().map(|b| b.insts.len()).sum();
        // Each branch but the last costs one Split before it and one Jmp
        // after it.
        let n = branches.len();
        let end = total + 2 * (n - 1);
        for (k, b) in branches.into_iter().enumerate() {
            if k + 1 < n {
                let here = insts.len();
                let after = here + 1 + b.insts.len() + 1;
                insts.push(Inst::Split(here + 1, after));
                let base = insts.len();
                insts.extend(b.insts.into_iter().map(|i| shift(i, base)));
                insts.push(Inst::Jmp(end));
            } else {
                let base = insts.len();
                insts.extend(b.insts.into_iter().map(|i| shift(i, base)));
            }
        }
        debug_assert_eq!(insts.len(), end);
        Ok(Frag { insts })
    }

    fn seq(&mut self) -> Result<Frag, RegexError> {
        let mut insts = Vec::new();
        while let Some(t) = self.peek() {
            if matches!(t, Token::Bar | Token::Close) {
                break;
            }
            let f = self.repeat()?;
            let base = insts.len();
            insts.extend(f.insts.into_iter().map(|i| shift(i, base)));
            if insts.len() > MAX_INSTRUCTIONS {
                return Err(RegexError {
                    pos: self.pos(),
                    message: format!("pattern exceeds {MAX_INSTRUCTIONS} instructions"),
                });
            }
        }
        Ok(Frag { insts })
    }

    fn repeat(&mut self) -> Result<Frag, RegexError> {
        let atom = self.atom()?;
        let n = atom.insts.len();
        let frag = match self.peek() {
            Some(Token::Star) => {
                self.i += 1;
                // L0: split L1, L2; L1: atom; jmp L0; L2:
                let mut insts = vec![Inst::Split(1, n + 2)];
                insts.extend(atom.insts.into_iter().map(|i| shift(i, 1)));
                insts.push(Inst::Jmp(0));
                Frag { insts }
            }
            Some(Token::Plus) => {
                self.i += 1;
                // L0: atom; split L0, L1; L1:
                let mut insts = atom.insts;
                insts.push(Inst::Split(0, n + 1));
                Frag { insts }
            }
            Some(Token::Question) => {
                self.i += 1;
                // split L1, L2; L1: atom; L2:
                let mut insts = vec![Inst::Split(1, n + 1)];
                insts.extend(atom.insts.into_iter().map(|i| shift(i, 1)));
                Frag { insts }
            }
            _ => atom,
        };
        if matches!(
            self.peek(),
            Some(Token::Star | Token::Plus | Token::Question)
        ) {
            return Err(RegexError {
                pos: self.pos(),
                message: "nested repetition".to_owned(),
            });
        }
        Ok(frag)
    }

    fn atom(&mut self) -> Result<Frag, RegexError> {
        let pos = self.pos();
        let Some(t) = self.peek().cloned() else {
            return Err(RegexError {
                pos,
                message: "unexpected end of pattern".to_owned(),
            });
        };
        self.i += 1;
        let inst = match t {
            Token::Asn(n) => Inst::Asn(n),
            Token::Dot => Inst::Any,
            Token::Caret => Inst::Start,
            Token::Dollar => Inst::End,
            Token::Class { negated, ranges } => Inst::Class { negated, ranges },
            Token::Open => {
                let inner = self.alt()?;
                if self.peek() != Some(&Token::Close) {
                    return Err(RegexError {
                        pos,
                        message: "unclosed `(`".to_owned(),
                    });
                }
                self.i += 1;
                return Ok(inner);
            }
            Token::Close => {
                return Err(RegexError {
                    pos,
                    message: "unmatched `)`".to_owned(),
                });
            }
            Token::Bar => {
                return Err(RegexError {
                    pos,
                    message: "empty alternative".to_owned(),
                });
            }
            Token::Star | Token::Plus | Token::Question => {
                return Err(RegexError {
                    pos,
                    message: "nothing to repeat".to_owned(),
                });
            }
        };
        Ok(Frag { insts: vec![inst] })
    }
}

fn shift(inst: Inst, base: usize) -> Inst {
    match inst {
        Inst::Split(a, b) => Inst::Split(a + base, b + base),
        Inst::Jmp(a) => Inst::Jmp(a + base),
        other => other,
    }
}

impl AsPathRegex {
    /// Compile `pattern`.
    ///
    /// # Errors
    /// [`RegexError`] with the offset of the problem.
    pub fn new(pattern: &str) -> Result<AsPathRegex, RegexError> {
        let tokens = tokenize(pattern)?;
        let anchored_start = matches!(tokens.first(), Some((_, Token::Caret)));
        let mut p = Parser {
            tokens,
            i: 0,
            end: pattern.len(),
        };
        let frag = p.alt()?;
        if let Some((pos, t)) = p.tokens.get(p.i) {
            return Err(RegexError {
                pos: *pos,
                message: if *t == Token::Close {
                    "unmatched `)`".to_owned()
                } else {
                    "unexpected token".to_owned()
                },
            });
        }
        let mut insts = frag.insts;
        insts.push(Inst::Match);
        if insts.len() > MAX_INSTRUCTIONS {
            return Err(RegexError {
                pos: 0,
                message: format!("pattern exceeds {MAX_INSTRUCTIONS} instructions"),
            });
        }
        Ok(AsPathRegex {
            insts,
            anchored_start,
            source: pattern.to_owned(),
        })
    }

    /// The pattern as written.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Whether the regex matches somewhere in `path` (anywhere unless
    /// anchored).
    #[must_use]
    pub fn is_match(&self, path: &[Asn]) -> bool {
        let n = self.insts.len();
        let mut current: Vec<usize> = Vec::with_capacity(n);
        let mut next: Vec<usize> = Vec::with_capacity(n);
        let mut mark = vec![usize::MAX; n];
        let mut generation = 0usize;
        for pos in 0..=path.len() {
            if pos == 0 || !self.anchored_start {
                // A fresh thread may start at any position for an
                // unanchored search (and only at 0 otherwise).
                generation += 1;
                let mut stack = vec![0usize];
                if self.add_threads(
                    &mut current,
                    &mut mark,
                    generation,
                    &mut stack,
                    pos,
                    path.len(),
                ) {
                    return true;
                }
            }
            if current.is_empty() {
                if self.anchored_start {
                    return false;
                }
                continue;
            }
            let Some(&asn) = path.get(pos) else {
                break;
            };
            generation += 1;
            next.clear();
            for &pc in &current {
                let step = match &self.insts[pc] {
                    Inst::Asn(a) => *a == asn.0,
                    Inst::Any => true,
                    Inst::Class { negated, ranges } => {
                        ranges.iter().any(|(lo, hi)| (*lo..=*hi).contains(&asn.0)) != *negated
                    }
                    _ => false,
                };
                if step {
                    let mut stack = vec![pc + 1];
                    if self.add_threads(
                        &mut next,
                        &mut mark,
                        generation,
                        &mut stack,
                        pos + 1,
                        path.len(),
                    ) {
                        return true;
                    }
                }
            }
            std::mem::swap(&mut current, &mut next);
            // Threads that started earlier survive in `current`; new ones
            // join on the next iteration, so this stays a plain union.
        }
        false
    }

    /// Follow the epsilon edges from the program counters on `stack`,
    /// adding consuming instructions to `set`. Returns true on `Match`.
    fn add_threads(
        &self,
        set: &mut Vec<usize>,
        mark: &mut [usize],
        generation: usize,
        stack: &mut Vec<usize>,
        pos: usize,
        len: usize,
    ) -> bool {
        while let Some(pc) = stack.pop() {
            if mark[pc] == generation {
                continue;
            }
            mark[pc] = generation;
            match &self.insts[pc] {
                Inst::Match => return true,
                Inst::Jmp(a) => stack.push(*a),
                Inst::Split(a, b) => {
                    stack.push(*b);
                    stack.push(*a);
                }
                Inst::Start => {
                    if pos == 0 {
                        stack.push(pc + 1);
                    }
                }
                Inst::End => {
                    if pos == len {
                        stack.push(pc + 1);
                    }
                }
                Inst::Asn(_) | Inst::Any | Inst::Class { .. } => set.push(pc),
            }
        }
        false
    }
}

impl fmt::Display for AsPathRegex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(asns: &[u32]) -> Vec<Asn> {
        asns.iter().map(|a| Asn(*a)).collect()
    }

    fn m(pattern: &str, asns: &[u32]) -> bool {
        AsPathRegex::new(pattern).unwrap().is_match(&path(asns))
    }

    #[test]
    fn literals_anchors_and_any() {
        assert!(m("65001", &[1, 65001, 2]));
        assert!(!m("65001", &[1, 2]));
        assert!(m("^65001", &[65001, 2]));
        assert!(!m("^65001", &[2, 65001]));
        assert!(m("65001$", &[2, 65001]));
        assert!(!m("65001$", &[65001, 2]));
        assert!(m("^65001 . 7$", &[65001, 9, 7]));
        assert!(!m("^65001 . 7$", &[65001, 9, 9, 7]));
        assert!(m("^$", &[]));
        assert!(!m("^$", &[1]));
        assert!(m("^.*$", &[]));
        assert!(m("_65001_7_", &[1, 65001, 7, 2]));
        assert!(m("", &[1, 2]));
    }

    #[test]
    fn repetition_alternation_groups_and_classes() {
        assert!(m("^65001 .* 7$", &[65001, 7]));
        assert!(m("^65001 .* 7$", &[65001, 1, 2, 3, 7]));
        assert!(m("^65001 .+ 7$", &[65001, 1, 7]));
        assert!(!m("^65001 .+ 7$", &[65001, 7]));
        assert!(m("^(1 2)+$", &[1, 2, 1, 2]));
        assert!(!m("^(1 2)+$", &[1, 2, 1]));
        assert!(m("^1 (2|3) 4$", &[1, 3, 4]));
        assert!(!m("^1 (2|3) 4$", &[1, 5, 4]));
        assert!(m("^1 2? 3$", &[1, 3]));
        assert!(m("^1 2? 3$", &[1, 2, 3]));
        assert!(m("^[64512-65534]", &[65000]));
        assert!(!m("^[64512-65534]", &[65535]));
        assert!(m("^[^64512-65534]", &[65535]));
        assert!(m("[1 2 3]$", &[9, 2]));
        assert!(m("^(1|2|3)$", &[3]));
        assert!(m("^4200000000$", &[4_200_000_000]));
        assert!(m("1 (2 3)* 4", &[1, 4]));
        assert!(m("1 (2 3)* 4", &[0, 1, 2, 3, 2, 3, 4, 9]));
        assert!(!m("1 (2 3)* 4", &[1, 2, 4]));
    }

    #[test]
    fn errors_carry_offsets() {
        for (pat, pos) in [
            ("(1", 0),
            ("1)", 1),
            ("*", 0),
            ("1**", 2),
            ("[", 0),
            ("[]", 0),
            ("[5-1]", 0),
            ("[a]", 1),
            ("x", 0),
            ("99999999999", 0),
        ] {
            let e = AsPathRegex::new(pat).unwrap_err();
            assert_eq!(e.pos, pos, "{pat}: {e}");
        }
        assert_eq!(AsPathRegex::new("1").unwrap().to_string(), "1");
        // An empty alternative matches the empty path.
        assert!(m("^(1|)$", &[]));
    }

    #[test]
    fn pathological_patterns_stay_linear() {
        // A backtracker explodes on these; the state-set simulation does
        // not (AGENTS.md §3, "Policy").
        let input: Vec<Asn> = vec![Asn(1); 5_000];
        let t = std::time::Instant::now();
        let re = AsPathRegex::new("^(1*)* 2$").unwrap();
        assert!(!re.is_match(&input));
        let re = AsPathRegex::new("^(1|1)+ (1|1)+ (1|1)+ 2$").unwrap();
        assert!(!re.is_match(&input));
        let re = AsPathRegex::new("(1?)* (1?)* (1?)* 1 1 1 1 1 1 1 1 1 1 2").unwrap();
        assert!(!re.is_match(&input));
        assert!(
            t.elapsed() < std::time::Duration::from_secs(5),
            "{:?}",
            t.elapsed()
        );
        // Size limit.
        let huge = "(1|2)".repeat(2000);
        let e = AsPathRegex::new(&huge).unwrap_err();
        assert!(e.message.contains("instructions"), "{e}");
    }
}

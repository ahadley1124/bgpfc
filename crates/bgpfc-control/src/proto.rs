//! The line protocol between `bgpfcctl` and `bgpfcd` (`docs/control.md`):
//! one request line of words, one response of a status line, body lines
//! and a terminating `.` line.
//!
//! ```text
//! request  = word { " " word } "\n" ;
//! response = ( "+ok" | "-error: " message ) "\n" { line "\n" } ".\n" ;
//! ```
//!
//! Words may be double-quoted to contain spaces (`"a b"`); a body line
//! that would start with `.` is sent as `..` (dot-stuffing, as in SMTP).

use std::fmt;
use std::io::{self, BufRead, Write};

/// Longest request line accepted.
pub const MAX_REQUEST_LEN: usize = 4096;

/// A parsed request: the words of the line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// The words, quotes removed.
    pub words: Vec<String>,
}

/// A malformed request line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequestError {
    /// Nothing on the line.
    Empty,
    /// A quote was not closed.
    UnterminatedQuote,
    /// Longer than [`MAX_REQUEST_LEN`].
    TooLong,
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            RequestError::Empty => "empty request",
            RequestError::UnterminatedQuote => "unterminated quote",
            RequestError::TooLong => "request too long",
        })
    }
}

impl std::error::Error for RequestError {}

impl Request {
    /// Parse one line (without its newline).
    ///
    /// # Errors
    /// [`RequestError`] for an empty, over-long or badly quoted line.
    pub fn parse(line: &str) -> Result<Request, RequestError> {
        if line.len() > MAX_REQUEST_LEN {
            return Err(RequestError::TooLong);
        }
        let mut words = Vec::new();
        let mut chars = line.trim().chars().peekable();
        while let Some(&c) = chars.peek() {
            if c.is_whitespace() {
                chars.next();
                continue;
            }
            let mut word = String::new();
            if c == '"' {
                chars.next();
                let mut closed = false;
                for c in chars.by_ref() {
                    if c == '"' {
                        closed = true;
                        break;
                    }
                    word.push(c);
                }
                if !closed {
                    return Err(RequestError::UnterminatedQuote);
                }
            } else {
                while let Some(&c) = chars.peek() {
                    if c.is_whitespace() {
                        break;
                    }
                    word.push(c);
                    chars.next();
                }
            }
            words.push(word);
        }
        if words.is_empty() {
            return Err(RequestError::Empty);
        }
        Ok(Request { words })
    }

    /// Quote the words back into a line, for the client.
    #[must_use]
    pub fn format(words: &[String]) -> String {
        let mut out = String::new();
        for (i, w) in words.iter().enumerate() {
            if i > 0 {
                out.push(' ');
            }
            if w.is_empty() || w.chars().any(|c| c.is_whitespace() || c == '"') {
                out.push('"');
                out.push_str(&w.replace('"', ""));
                out.push('"');
            } else {
                out.push_str(w);
            }
        }
        out.push('\n');
        out
    }
}

/// What the server answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    /// `Ok(())` or the error message.
    pub status: Result<(), String>,
    /// Body lines, without newlines.
    pub lines: Vec<String>,
}

impl Response {
    /// A successful response with these lines.
    #[must_use]
    pub fn ok(lines: Vec<String>) -> Response {
        Response {
            status: Ok(()),
            lines,
        }
    }

    /// An error response.
    #[must_use]
    pub fn error(message: impl Into<String>) -> Response {
        Response {
            status: Err(message.into()),
            lines: Vec::new(),
        }
    }

    /// Write the response in wire form.
    ///
    /// # Errors
    /// The write failure.
    pub fn write_to(&self, w: &mut impl Write) -> io::Result<()> {
        match &self.status {
            Ok(()) => w.write_all(b"+ok\n")?,
            Err(m) => {
                w.write_all(b"-error: ")?;
                w.write_all(m.replace('\n', " ").as_bytes())?;
                w.write_all(b"\n")?;
            }
        }
        for l in &self.lines {
            if l.starts_with('.') {
                w.write_all(b".")?;
            }
            w.write_all(l.as_bytes())?;
            w.write_all(b"\n")?;
        }
        w.write_all(b".\n")?;
        w.flush()
    }

    /// Read a response in wire form, for the client.
    ///
    /// # Errors
    /// An I/O error, or `InvalidData` for a malformed status line or a
    /// stream that ends before the `.` line.
    pub fn read_from(r: &mut impl BufRead) -> io::Result<Response> {
        let mut status = String::new();
        if r.read_line(&mut status)? == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "no response"));
        }
        let status = status.trim_end_matches(['\r', '\n']);
        let status = if status == "+ok" {
            Ok(())
        } else if let Some(m) = status.strip_prefix("-error: ") {
            Err(m.to_owned())
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bad status line",
            ));
        };
        let mut lines = Vec::new();
        loop {
            let mut line = String::new();
            if r.read_line(&mut line)? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "response not terminated",
                ));
            }
            let line = line.trim_end_matches(['\r', '\n']);
            if line == "." {
                break;
            }
            lines.push(line.strip_prefix('.').unwrap_or(line).to_owned());
        }
        Ok(Response { status, lines })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_parse_and_format() {
        let r = Request::parse("show  neighbor 10.0.0.1 \"a b\"").unwrap();
        assert_eq!(r.words, ["show", "neighbor", "10.0.0.1", "a b"]);
        assert_eq!(Request::parse("  "), Err(RequestError::Empty));
        assert_eq!(
            Request::parse("x \"open"),
            Err(RequestError::UnterminatedQuote)
        );
        assert_eq!(
            Request::parse(&"x".repeat(5000)),
            Err(RequestError::TooLong)
        );
        let line = Request::format(&["clear".into(), "a b".into(), String::new(), "q\"".into()]);
        assert_eq!(line, "clear \"a b\" \"\" \"q\"\n");
        let back = Request::parse(line.trim_end()).unwrap();
        assert_eq!(back.words, ["clear", "a b", "", "q"]);
        assert_eq!(RequestError::Empty.to_string(), "empty request");
    }

    #[test]
    fn responses_round_trip_with_dot_stuffing() {
        let r = Response::ok(vec!["line".into(), ".dot".into(), String::new()]);
        let mut buf = Vec::new();
        r.write_to(&mut buf).unwrap();
        assert_eq!(buf, b"+ok\nline\n..dot\n\n.\n");
        let back = Response::read_from(&mut &buf[..]).unwrap();
        assert_eq!(back, r);
        let e = Response::error("no such\nneighbor");
        let mut buf = Vec::new();
        e.write_to(&mut buf).unwrap();
        assert_eq!(buf, b"-error: no such neighbor\n.\n");
        let back = Response::read_from(&mut &buf[..]).unwrap();
        assert_eq!(back.status, Err("no such neighbor".to_owned()));
        assert!(Response::read_from(&mut &b""[..]).is_err());
        assert!(Response::read_from(&mut &b"?\n.\n"[..]).is_err());
        assert!(Response::read_from(&mut &b"+ok\nx\n"[..]).is_err());
    }
}

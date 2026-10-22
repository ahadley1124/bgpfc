//! A minimal HTTP/1.1 request parser and response writer for the JSON API
//! (AGENTS.md §3, "Control plane"): request line, headers, an optional
//! body bounded by `Content-Length`; every size is capped. One request
//! per connection (`Connection: close`).
//!
//! Implements: RFC 9112 §2.1 (message format), §3 (request line), §5
//! (field lines), §6.2 (`Content-Length`); RFC 6750 §2.1 (bearer token
//! in `Authorization`).

use std::fmt;
use std::io::{self, BufRead, Write};

/// Longest request (line, headers and body) accepted.
pub const MAX_REQUEST: usize = 16 * 1024;
/// Most header lines accepted.
pub const MAX_HEADERS: usize = 64;
/// Longest body accepted.
pub const MAX_BODY: usize = 4096;

/// A parsed request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// `GET`, `POST`, ...
    pub method: String,
    /// The path without the query.
    pub path: String,
    /// `key=value` pairs of the query string, percent-decoded.
    pub query: Vec<(String, String)>,
    /// Header names lower-cased, values trimmed.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
}

/// Why a request was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HttpError {
    /// Not an HTTP/1.x request line, or a bad header line.
    Malformed,
    /// Over one of the caps: 413.
    TooLarge,
    /// The connection ended early.
    Incomplete,
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            HttpError::Malformed => "malformed request",
            HttpError::TooLarge => "request too large",
            HttpError::Incomplete => "incomplete request",
        })
    }
}

impl std::error::Error for HttpError {}

impl Request {
    /// Read one request from `r`.
    ///
    /// # Errors
    /// [`HttpError`] for a bad or over-size request; an I/O error is
    /// reported as [`HttpError::Incomplete`].
    pub fn read_from(r: &mut impl BufRead) -> Result<Request, HttpError> {
        let mut total = 0usize;
        let mut line = String::new();
        read_line(r, &mut line, &mut total)?;
        let mut parts = line.split(' ');
        let method = parts.next().unwrap_or("").to_owned();
        let target = parts.next().ok_or(HttpError::Malformed)?;
        let version = parts.next().ok_or(HttpError::Malformed)?;
        if method.is_empty() || parts.next().is_some() || !version.starts_with("HTTP/1.") {
            return Err(HttpError::Malformed);
        }
        let (path, query) = match target.split_once('?') {
            Some((p, q)) => (p.to_owned(), parse_query(q)),
            None => (target.to_owned(), Vec::new()),
        };
        if !path.starts_with('/') {
            return Err(HttpError::Malformed);
        }
        let mut headers = Vec::new();
        loop {
            line.clear();
            read_line(r, &mut line, &mut total)?;
            if line.is_empty() {
                break;
            }
            if headers.len() >= MAX_HEADERS {
                return Err(HttpError::TooLarge);
            }
            let (name, value) = line.split_once(':').ok_or(HttpError::Malformed)?;
            if name.is_empty() || name.contains(' ') {
                return Err(HttpError::Malformed);
            }
            headers.push((name.to_ascii_lowercase(), value.trim().to_owned()));
        }
        let length = headers
            .iter()
            .find(|(n, _)| n == "content-length")
            .map(|(_, v)| v.parse::<usize>().map_err(|_| HttpError::Malformed))
            .transpose()?
            .unwrap_or(0);
        if length > MAX_BODY || total + length > MAX_REQUEST {
            return Err(HttpError::TooLarge);
        }
        let mut body = vec![0u8; length];
        r.read_exact(&mut body).map_err(|_| HttpError::Incomplete)?;
        Ok(Request {
            method,
            path,
            query,
            headers,
            body,
        })
    }

    /// The value of header `name` (lower case).
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    /// The bearer token of the `Authorization` header, if any (RFC 6750
    /// §2.1; the scheme is compared case-insensitively).
    #[must_use]
    pub fn bearer_token(&self) -> Option<&str> {
        let v = self.header("authorization")?;
        let (scheme, token) = v.split_once(' ')?;
        scheme.eq_ignore_ascii_case("bearer").then(|| token.trim())
    }

    /// The first query parameter called `name`.
    #[must_use]
    pub fn param(&self, name: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

fn read_line(r: &mut impl BufRead, line: &mut String, total: &mut usize) -> Result<(), HttpError> {
    let mut raw = Vec::new();
    loop {
        let buf = r.fill_buf().map_err(|_| HttpError::Incomplete)?;
        if buf.is_empty() {
            return Err(HttpError::Incomplete);
        }
        let (chunk, done) = match buf.iter().position(|&b| b == b'\n') {
            Some(i) => (&buf[..=i], true),
            None => (buf, false),
        };
        let n = chunk.len();
        raw.extend_from_slice(chunk);
        r.consume(n);
        *total += n;
        if *total > MAX_REQUEST {
            return Err(HttpError::TooLarge);
        }
        if done {
            break;
        }
    }
    let text = std::str::from_utf8(&raw).map_err(|_| HttpError::Malformed)?;
    line.push_str(text.trim_end_matches(['\r', '\n']));
    Ok(())
}

/// Parse `a=b&c=d`, percent-decoding both sides.
#[must_use]
pub fn parse_query(q: &str) -> Vec<(String, String)> {
    q.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (percent_decode(k), percent_decode(v))
        })
        .collect()
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = &s[i + 1..i + 3];
                if let Ok(b) = u8::from_str_radix(hex, 16) {
                    out.push(b);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A response to write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    /// Status code.
    pub status: u16,
    /// Body, with `Content-Type: application/json` unless `text` is set.
    pub body: String,
    /// Send as `text/plain` instead of JSON.
    pub text: bool,
    /// Extra headers (for example `WWW-Authenticate`).
    pub extra: Vec<(String, String)>,
}

impl Response {
    /// A JSON response.
    #[must_use]
    pub fn json(status: u16, body: String) -> Response {
        Response {
            status,
            body,
            text: false,
            extra: Vec::new(),
        }
    }

    /// A JSON error object `{"error": message}`.
    #[must_use]
    pub fn error(status: u16, message: &str) -> Response {
        let mut j = crate::json::Json::new();
        j.begin_object().field_str("error", message).end_object();
        Response::json(status, j.finish())
    }

    /// Write the response, closing the connection afterwards.
    ///
    /// # Errors
    /// The write failure.
    pub fn write_to(&self, w: &mut impl Write) -> io::Result<()> {
        let reason = match self.status {
            200 => "OK",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            413 => "Content Too Large",
            500 => "Internal Server Error",
            503 => "Service Unavailable",
            _ => "Unknown",
        };
        write!(w, "HTTP/1.1 {} {reason}\r\n", self.status)?;
        write!(
            w,
            "Content-Type: {}\r\n",
            if self.text {
                "text/plain; charset=utf-8"
            } else {
                "application/json"
            }
        )?;
        write!(w, "Content-Length: {}\r\n", self.body.len())?;
        w.write_all(b"Connection: close\r\nCache-Control: no-store\r\n")?;
        for (k, v) in &self.extra {
            write!(w, "{k}: {v}\r\n")?;
        }
        w.write_all(b"\r\n")?;
        w.write_all(self.body.as_bytes())?;
        w.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<Request, HttpError> {
        Request::read_from(&mut s.as_bytes())
    }

    #[test]
    fn parses_requests() {
        let r = parse("GET /v1/routes?family=ipv6&prefix=2001%3Adb8%3A%3A%2F32&x HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer  s3cret \r\n\r\n")
            .unwrap();
        assert_eq!(r.method, "GET");
        assert_eq!(r.path, "/v1/routes");
        assert_eq!(r.param("family"), Some("ipv6"));
        assert_eq!(r.param("prefix"), Some("2001:db8::/32"));
        assert_eq!(r.param("x"), Some(""));
        assert_eq!(r.header("host"), Some("localhost"));
        assert_eq!(r.bearer_token(), Some("s3cret"));
        assert_eq!(r.body.len(), 0);
        let p = parse("POST /v1/reload HTTP/1.0\r\nContent-Length: 5\r\n\r\nhello").unwrap();
        assert_eq!(p.body, b"hello");
        assert_eq!(p.bearer_token(), None);
        let b = parse("GET / HTTP/1.1\r\nAuthorization: Basic xx\r\n\r\n").unwrap();
        assert_eq!(b.bearer_token(), None);
        assert_eq!(
            parse_query("a+b=c%20d"),
            vec![("a b".to_owned(), "c d".to_owned())]
        );
        assert_eq!(
            parse_query("bad=%zz%4"),
            vec![("bad".to_owned(), "%zz%4".to_owned())]
        );
    }

    #[test]
    fn refuses_bad_and_large_requests() {
        assert_eq!(parse("GET\r\n\r\n"), Err(HttpError::Malformed));
        assert_eq!(
            parse("GET / HTTP/1.1 extra\r\n\r\n"),
            Err(HttpError::Malformed)
        );
        assert_eq!(parse("GET / SPDY/3\r\n\r\n"), Err(HttpError::Malformed));
        assert_eq!(parse("GET x HTTP/1.1\r\n\r\n"), Err(HttpError::Malformed));
        assert_eq!(
            parse("GET / HTTP/1.1\r\nNoColon\r\n\r\n"),
            Err(HttpError::Malformed)
        );
        assert_eq!(
            parse("GET / HTTP/1.1\r\nContent-Length: x\r\n\r\n"),
            Err(HttpError::Malformed)
        );
        assert_eq!(parse("GET / HTTP/1.1\r\n"), Err(HttpError::Incomplete));
        assert_eq!(
            parse("GET / HTTP/1.1\r\nContent-Length: 3\r\n\r\nab"),
            Err(HttpError::Incomplete)
        );
        assert_eq!(parse(""), Err(HttpError::Incomplete));
        let many = format!(
            "GET / HTTP/1.1\r\n{}\r\n",
            "X: y\r\n".repeat(MAX_HEADERS + 1)
        );
        assert_eq!(parse(&many), Err(HttpError::TooLarge));
        let long = format!("GET /{} HTTP/1.1\r\n\r\n", "a".repeat(MAX_REQUEST));
        assert_eq!(parse(&long), Err(HttpError::TooLarge));
        let body = format!(
            "POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY + 1
        );
        assert_eq!(parse(&body), Err(HttpError::TooLarge));
        assert_eq!(HttpError::TooLarge.to_string(), "request too large");
    }

    #[test]
    fn writes_responses() {
        let mut out = Vec::new();
        Response::json(200, "{}".into()).write_to(&mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text}");
        assert!(text.contains("Content-Type: application/json\r\n"));
        assert!(text.contains("Content-Length: 2\r\n"));
        assert!(text.contains("Connection: close\r\n"));
        assert!(text.ends_with("\r\n\r\n{}"));
        let mut out = Vec::new();
        let mut r = Response::error(401, "token");
        r.extra.push(("WWW-Authenticate".into(), "Bearer".into()));
        r.write_to(&mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("HTTP/1.1 401 Unauthorized\r\n"));
        assert!(text.contains("WWW-Authenticate: Bearer\r\n"));
        assert!(text.ends_with(r#"{"error":"token"}"#));
    }
}

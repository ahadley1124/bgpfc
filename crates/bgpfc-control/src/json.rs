//! A small JSON writer (AGENTS.md §3, "Control plane"): correct escaping,
//! no allocation beyond the output string, no serialisation framework.
//!
//! Implements: RFC 8259 §7 (string escapes), §6 (numbers as integers only).

use std::fmt::Write as _;

/// Builds one JSON document.
#[derive(Debug, Default)]
pub struct Json {
    out: String,
    /// Whether the next value is the first in its container.
    first: Vec<bool>,
    /// A key was just written: the value that follows takes no comma.
    after_key: bool,
}

impl Json {
    /// An empty writer.
    #[must_use]
    pub fn new() -> Json {
        Json::default()
    }

    /// The document so far.
    #[must_use]
    pub fn finish(self) -> String {
        self.out
    }

    fn separate(&mut self) {
        if self.after_key {
            self.after_key = false;
            return;
        }
        if let Some(first) = self.first.last_mut() {
            if *first {
                *first = false;
            } else {
                self.out.push(',');
            }
        }
    }

    /// Start an object (`{`).
    pub fn begin_object(&mut self) -> &mut Self {
        self.separate();
        self.out.push('{');
        self.first.push(true);
        self
    }

    /// End an object (`}`).
    pub fn end_object(&mut self) -> &mut Self {
        self.first.pop();
        self.out.push('}');
        self
    }

    /// Start an array (`[`).
    pub fn begin_array(&mut self) -> &mut Self {
        self.separate();
        self.out.push('[');
        self.first.push(true);
        self
    }

    /// End an array (`]`).
    pub fn end_array(&mut self) -> &mut Self {
        self.first.pop();
        self.out.push(']');
        self
    }

    /// A member name inside an object; the value follows.
    pub fn key(&mut self, name: &str) -> &mut Self {
        self.separate();
        write_string(&mut self.out, name);
        self.out.push(':');
        self.after_key = true;
        self
    }

    /// A string value.
    pub fn string(&mut self, s: &str) -> &mut Self {
        self.separate();
        write_string(&mut self.out, s);
        self
    }

    /// Anything with a `Display`, as a string value.
    pub fn display(&mut self, v: impl std::fmt::Display) -> &mut Self {
        self.string(&v.to_string())
    }

    /// An integer value.
    pub fn number(&mut self, n: impl Into<i128>) -> &mut Self {
        self.separate();
        let _ = write!(self.out, "{}", n.into());
        self
    }

    /// A boolean value.
    pub fn boolean(&mut self, b: bool) -> &mut Self {
        self.separate();
        self.out.push_str(if b { "true" } else { "false" });
        self
    }

    /// `null`.
    pub fn null(&mut self) -> &mut Self {
        self.separate();
        self.out.push_str("null");
        self
    }

    /// `key: string` in one call.
    pub fn field_str(&mut self, name: &str, v: &str) -> &mut Self {
        self.key(name).string(v)
    }

    /// `key: display` in one call.
    pub fn field_display(&mut self, name: &str, v: impl std::fmt::Display) -> &mut Self {
        self.key(name).display(v)
    }

    /// `key: number` in one call.
    pub fn field_num(&mut self, name: &str, n: impl Into<i128>) -> &mut Self {
        self.key(name).number(n)
    }

    /// `key: bool` in one call.
    pub fn field_bool(&mut self, name: &str, b: bool) -> &mut Self {
        self.key(name).boolean(b)
    }

    /// `key: string | null` in one call.
    pub fn field_opt(&mut self, name: &str, v: Option<impl std::fmt::Display>) -> &mut Self {
        self.key(name);
        match v {
            Some(v) => self.display(v),
            None => self.null(),
        }
    }
}

/// Write `s` as a JSON string with the escapes RFC 8259 §7 requires:
/// `"`, `\`, and control characters; everything else as UTF-8.
pub fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || c == '\u{7f}' => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reference reader for strings, enough to check the escapes.
    fn read_string(s: &str) -> Option<String> {
        let mut chars = s.strip_prefix('"')?.strip_suffix('"')?.chars();
        let mut out = String::new();
        while let Some(c) = chars.next() {
            if c != '\\' {
                if (c as u32) < 0x20 {
                    return None;
                }
                out.push(c);
                continue;
            }
            match chars.next()? {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                'b' => out.push('\u{08}'),
                'f' => out.push('\u{0c}'),
                'u' => {
                    let hex: String = chars.by_ref().take(4).collect();
                    out.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
                }
                _ => return None,
            }
        }
        Some(out)
    }

    #[test]
    fn documents_are_well_formed() {
        let mut j = Json::new();
        j.begin_object()
            .field_str("name", "a\"b\\c\n")
            .field_num("n", 42u32)
            .field_bool("ok", true)
            .field_opt("none", None::<u8>)
            .key("list")
            .begin_array()
            .number(1u8)
            .string("x")
            .begin_object()
            .field_display("ip", std::net::Ipv4Addr::LOCALHOST)
            .end_object()
            .end_array()
            .key("empty")
            .begin_object()
            .end_object()
            .end_object();
        assert_eq!(
            j.finish(),
            r#"{"name":"a\"b\\c\n","n":42,"ok":true,"none":null,"list":[1,"x",{"ip":"127.0.0.1"}],"empty":{}}"#
        );
        let mut a = Json::new();
        a.begin_array().end_array();
        assert_eq!(a.finish(), "[]");
        let mut n = Json::new();
        n.number(-5i64);
        assert_eq!(n.finish(), "-5");
    }

    #[test]
    fn escapes_round_trip() {
        for s in [
            "",
            "plain",
            "tab\there",
            "quote\"and\\slash",
            "ctrl\u{01}\u{1f}\u{7f}",
            "unicode ☃ 😀",
            "\r\n\u{08}\u{0c}",
        ] {
            let mut out = String::new();
            write_string(&mut out, s);
            assert_eq!(read_string(&out).as_deref(), Some(s), "{out}");
            assert!(out.is_ascii() || !s.is_ascii());
        }
    }
}

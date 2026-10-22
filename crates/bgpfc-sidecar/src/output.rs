//! The child's output, read in bounded memory: split into lines of at
//! most a fixed length for the log, or collected up to a limit. Whatever a
//! chatty or broken child prints, bgpfcd holds at most one line and one
//! read buffer per stream.
//!
//! Implements: no RFC.

use std::io::{self, Read};

/// The longest line logged, in bytes. Routinator's lines are far shorter;
/// what a longer line has beyond this is dropped and counted.
pub(crate) const MAX_LINE: usize = 4096;

/// How much is read at a time.
const CHUNK: usize = 8192;

/// A line of output: at most the limit's bytes of it, without the line
/// end, and how many more bytes it had.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Line<'a> {
    /// The start of the line, without `\n` or `\r\n`.
    pub(crate) text: &'a [u8],
    /// Bytes past the limit, dropped.
    pub(crate) dropped: usize,
}

/// Splits a byte stream into [`Line`]s, keeping at most `limit` bytes of
/// each. Pure: bytes go in with [`push`](Self::push), lines come out
/// through a callback. Empty lines are skipped.
#[derive(Debug)]
pub(crate) struct LineBuffer {
    line: Vec<u8>,
    dropped: usize,
    limit: usize,
}

impl LineBuffer {
    pub(crate) fn new(limit: usize) -> LineBuffer {
        LineBuffer {
            line: Vec::new(),
            dropped: 0,
            limit,
        }
    }

    /// Take `chunk` and call `emit` for every line it completes.
    pub(crate) fn push(&mut self, mut chunk: &[u8], emit: &mut impl FnMut(Line<'_>)) {
        while let Some(end) = chunk.iter().position(|&b| b == b'\n') {
            let (line, rest) = chunk.split_at(end);
            self.append(line);
            self.flush(emit);
            // `rest` starts with the `\n` that `position` found.
            chunk = rest.get(1..).unwrap_or_default();
        }
        self.append(chunk);
    }

    /// The input ended: emit a last line that had no line end.
    pub(crate) fn finish(&mut self, emit: &mut impl FnMut(Line<'_>)) {
        self.flush(emit);
    }

    fn append(&mut self, part: &[u8]) {
        let room = self.limit.saturating_sub(self.line.len());
        let (kept, rest) = part.split_at(room.min(part.len()));
        self.line.extend_from_slice(kept);
        self.dropped = self.dropped.saturating_add(rest.len());
    }

    fn flush(&mut self, emit: &mut impl FnMut(Line<'_>)) {
        let text = self.line.strip_suffix(b"\r").unwrap_or(&self.line);
        if !text.is_empty() || self.dropped > 0 {
            emit(Line {
                text,
                dropped: self.dropped,
            });
        }
        self.line.clear();
        self.dropped = 0;
    }
}

/// Read `input` to its end, calling `emit` for every line of at most
/// `limit` bytes, including an unterminated last one.
///
/// # Errors
/// A read failure other than `EINTR`, after the lines read before it.
pub(crate) fn read_lines(
    mut input: impl Read,
    limit: usize,
    mut emit: impl FnMut(Line<'_>),
) -> io::Result<()> {
    let mut lines = LineBuffer::new(limit);
    let mut buf = [0u8; CHUNK];
    loop {
        match input.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => lines.push(buf.get(..n).unwrap_or(&buf), &mut emit),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => {
                lines.finish(&mut emit);
                return Err(e);
            }
        }
    }
    lines.finish(&mut emit);
    Ok(())
}

/// Read `input` to its end and return its first `limit` bytes. The rest
/// is read and dropped, so the writer never blocks on a full pipe.
///
/// # Errors
/// A read failure other than `EINTR`.
pub(crate) fn read_bounded(mut input: impl Read, limit: usize) -> io::Result<Vec<u8>> {
    let mut kept = Vec::new();
    let mut buf = [0u8; CHUNK];
    loop {
        match input.read(&mut buf) {
            Ok(0) => return Ok(kept),
            Ok(n) => {
                let room = limit.saturating_sub(kept.len());
                kept.extend_from_slice(buf.get(..n.min(room)).unwrap_or_default());
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The lines of `chunks`, fed in that split, as `(text, dropped)`.
    fn split(limit: usize, chunks: &[&[u8]]) -> Vec<(String, usize)> {
        let mut got = Vec::new();
        let mut emit = |line: Line<'_>| {
            got.push((String::from_utf8(line.text.to_vec()).unwrap(), line.dropped));
        };
        let mut lines = LineBuffer::new(limit);
        for chunk in chunks {
            lines.push(chunk, &mut emit);
        }
        lines.finish(&mut emit);
        got
    }

    /// Chunks fed in, and the lines expected as `(text, dropped)`.
    type Case<'a> = (&'a [&'a [u8]], &'a [(&'a str, usize)]);

    fn owned(lines: &[(&str, usize)]) -> Vec<(String, usize)> {
        lines.iter().map(|&(t, d)| (t.to_owned(), d)).collect()
    }

    #[test]
    fn splits_lines_across_chunks() {
        let cases: &[Case<'_>] = &[
            (&[b"one\ntwo\n"], &[("one", 0), ("two", 0)]),
            (&[b"o", b"ne\nt", b"wo", b"\n"], &[("one", 0), ("two", 0)]),
            (&[b"one\r\ntwo\r", b"\n"], &[("one", 0), ("two", 0)]),
            // An unterminated last line still comes out.
            (&[b"one\ntwo"], &[("one", 0), ("two", 0)]),
            // Empty lines are skipped, a lone `\r` too.
            (&[b"\n\none\n\r\n\n"], &[("one", 0)]),
            (&[], &[]),
            (&[b""], &[]),
            // Only the line end is stripped, not other whitespace.
            (&[b"  a b \t\n"], &[("  a b \t", 0)]),
        ];
        for (chunks, lines) in cases {
            assert_eq!(split(16, chunks), owned(lines), "{chunks:?}");
        }
    }

    #[test]
    fn long_lines_are_cut_and_counted() {
        let cases: &[Case<'_>] = &[
            (&[b"abcd\n"], &[("abcd", 0)]),
            (&[b"abcde\n"], &[("abcd", 1)]),
            (&[b"abcdefghij\nxy\n"], &[("abcd", 6), ("xy", 0)]),
            // The count spans chunks, and resets for the next line.
            (
                &[b"abc", b"def", b"ghi\nab", b"cdef"],
                &[("abcd", 5), ("abcd", 2)],
            ),
            // A `\r` past the limit is dropped with the rest.
            (&[b"abcdef\r\n"], &[("abcd", 3)]),
        ];
        for (chunks, lines) in cases {
            assert_eq!(split(4, chunks), owned(lines), "{chunks:?}");
        }
    }

    #[test]
    fn memory_stays_bounded() {
        let mut lines = LineBuffer::new(64);
        let chunk = [b'x'; 1000];
        let mut seen = 0;
        for _ in 0..1000 {
            lines.push(&chunk, &mut |_| seen += 1);
            assert!(lines.line.capacity() <= 128, "{}", lines.line.capacity());
        }
        let mut last = None;
        lines.finish(&mut |line| last = Some(line.dropped));
        assert_eq!(seen, 0);
        assert_eq!(last, Some(1_000_000 - 64));
    }

    #[test]
    fn reads_lines_to_the_end() {
        let input: &[u8] = b"one\ntwo three\nfour";
        let mut got = Vec::new();
        read_lines(input, 8, |line| {
            got.push((
                String::from_utf8_lossy(line.text).into_owned(),
                line.dropped,
            ));
        })
        .unwrap();
        assert_eq!(got, owned(&[("one", 0), ("two thre", 1), ("four", 0)]));
    }

    /// A reader that returns `EINTR` once, then some bytes, then fails.
    struct Flaky(u8);

    impl Read for Flaky {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0 += 1;
            match self.0 {
                1 => Err(io::ErrorKind::Interrupted.into()),
                2 => {
                    buf[..4].copy_from_slice(b"a\nbc");
                    Ok(4)
                }
                _ => Err(io::ErrorKind::ConnectionReset.into()),
            }
        }
    }

    #[test]
    fn read_errors_end_reading_after_the_lines_so_far() {
        let mut got = Vec::new();
        let err = read_lines(Flaky(0), 8, |line| got.push(line.text.to_vec())).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(got, [b"a".to_vec(), b"bc".to_vec()]);
        let err = read_bounded(Flaky(0), 8).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
    }

    #[test]
    fn bounded_reads_keep_the_start() {
        let input = vec![b'v'; 3 * CHUNK + 5];
        assert_eq!(read_bounded(&input[..], 10).unwrap(), vec![b'v'; 10]);
        assert_eq!(read_bounded(&input[..], usize::MAX).unwrap(), input);
        assert_eq!(read_bounded(&b""[..], 10).unwrap(), Vec::<u8>::new());
    }
}

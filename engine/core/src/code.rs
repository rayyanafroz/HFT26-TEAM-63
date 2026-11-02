//! Source code and confidentiality markers (`code.py`). At most one finding per rule, per text.

use crate::patterns as p;
use crate::pyre::{Re, RegexError};
use crate::uni;
use crate::{Candidate, DetectError, Settings};

pub struct Code {
    marker: Re,
    copyright: Re,
    fence: Re,
    token: Re,
    line: Re,
}

/// `str.splitlines()`: every line boundary Python knows, without the boundaries.
fn splitlines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        let boundary = matches!(c, '\n' | '\r' | '\x0b' | '\x0c' | '\x1c' | '\x1d' | '\x1e' | '\u{85}' | '\u{2028}' | '\u{2029}');
        if !boundary {
            continue;
        }
        lines.push(&text[start..i]);
        let mut next = i + c.len_utf8();
        if c == '\r' && chars.peek().is_some_and(|&(_, d)| d == '\n') {
            chars.next();
            next += 1;
        }
        start = next;
    }
    if start < text.len() {
        lines.push(&text[start..]);
    }
    lines
}

impl Code {
    pub fn new() -> Result<Self, RegexError> {
        let re = |def: (&str, crate::pyre::Flags)| Re::new(def.0, def.1);
        Ok(Code {
            marker: re(p::MARKER_RE)?,
            copyright: re(p::COPYRIGHT_RE)?,
            fence: re(p::FENCE_RE)?,
            token: re(p::CODE_TOKEN_RE)?,
            line: re(p::CODE_LINE_RE)?,
        })
    }

    fn confidential_marker(&self, text: &str, s: &Settings) -> Result<Option<Candidate>, DetectError> {
        for (a, b) in self.marker.find_all(text)? {
            let from = uni::back_chars(text, a, s.marker_window);
            let to = uni::forward_chars(text, b, s.marker_window);
            if self.copyright.is_match(&text[from..to])? {
                return Ok(Some(Candidate::new("CODE_CONFIDENTIAL_MARKER", a, b, &text[a..b].to_lowercase())));
            }
        }
        Ok(None)
    }

    fn distinct_tokens(&self, text: &str) -> Result<usize, DetectError> {
        let mut seen: Vec<&str> = Vec::new();
        for c in self.token.captures_all(text)? {
            let token = c.text(text, 1).or_else(|| c.text(text, 2)).unwrap_or("");
            if !seen.contains(&token) {
                seen.push(token);
            }
        }
        Ok(seen.len())
    }

    fn shaped_lines(&self, text: &str, enough: usize) -> Result<usize, DetectError> {
        let mut count = 0;
        for line in splitlines(text) {
            if self.line.is_match(line)? {
                count += 1;
                if count >= enough {
                    break;
                }
            }
        }
        Ok(count)
    }

    fn possible_source(&self, text: &str, s: &Settings) -> Result<Option<Candidate>, DetectError> {
        let fences = self.fence.find_all(text)?;
        let (start, end) = if let (Some(first), Some(last)) = (fences.first(), fences.last()) {
            (first.0, last.1)
        } else if text.matches('\n').count() + 1 >= s.code_min_lines {
            if self.shaped_lines(text, s.code_min_shaped_lines)? < s.code_min_shaped_lines {
                return Ok(None);
            }
            (0, text.len())
        } else {
            return Ok(None);
        };
        let region = &text[start..end];
        if self.distinct_tokens(region)? < s.code_min_distinct_tokens {
            return Ok(None);
        }
        if !s.internal_markers.is_empty() {
            let lowered = text.to_lowercase();
            if !s.internal_markers.iter().any(|m| lowered.contains(&m.to_lowercase())) {
                return Ok(None);
            }
        }
        Ok(Some(Candidate::new("CODE_POSSIBLE_SOURCE", start, end, region)))
    }

    pub fn find(&self, text: &str, s: &Settings) -> Result<Vec<Candidate>, DetectError> {
        let mut found = Vec::new();
        found.extend(self.confidential_marker(text, s)?);
        found.extend(self.possible_source(text, s)?);
        Ok(found)
    }
}

#[cfg(test)]
mod tests {
    use super::splitlines;

    #[test]
    fn splitlines_matches_python() {
        assert_eq!(splitlines("a\r\nb\rc\n"), vec!["a", "b", "c"]);
        assert_eq!(splitlines("a\u{2028}b"), vec!["a", "b"]);
        assert_eq!(splitlines(""), Vec::<&str>::new());
        assert_eq!(splitlines("a\n\nb"), vec!["a", "", "b"]);
    }
}

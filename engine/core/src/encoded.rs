//! Secrets that are broken up or encoded, found without guessing (`encoded.py`).

use crate::patterns as p;
use crate::pii::Pii;
use crate::pydecode::{a2b_base64, unhexlify};
use crate::pyre::{Re, RegexError};

use crate::secrets::{shannon_entropy, Secrets};
use crate::uni;
use crate::{Candidate, DetectError, Settings};

pub struct Encoded {
    key_start: Re,
    next_piece: Re,
}

impl Encoded {
    pub fn new() -> Result<Self, RegexError> {
        Ok(Encoded {
            key_start: Re::new(p::KEY_START.0, p::KEY_START.1)?,
            next_piece: Re::new(p::NEXT_PIECE.0, p::NEXT_PIECE.1)?,
        })
    }

    /// Named secrets cut by spaces, line breaks, quotes or `+` (`find_split_secrets`).
    pub fn find_split(&self, text: &str, secrets: &Secrets) -> Result<Vec<Candidate>, DetectError> {
        let mut found = Vec::new();
        for (first_start, first_end) in self.key_start.find_all(text)? {
            let mut pieces = vec![(first_start, first_end)];
            let mut cursor = first_end;
            while pieces.len() < p::MAX_PIECES {
                let Some(next) = self.next_piece.match_at(text, cursor)? else { break };
                let (a, b) = next.get(1).expect("group 1 always takes part");
                if !looks_random(&text[a..b]) {
                    break;
                }
                pieces.push((a, b));
                cursor = next.end();
            }
            if pieces.len() == 1 {
                continue; // nothing was split: the plain pass has it
            }
            // Every piece is ASCII ([A-Za-z0-9_\-]), so byte and character counts agree here.
            let compact: String = pieces.iter().map(|&(a, b)| &text[a..b]).collect();
            let first_len = first_end - first_start;
            for (rule, pattern) in secrets.named() {
                let Some(hit) = pattern.match_at(&compact, 0)? else { continue };
                if hit.end() <= first_len {
                    continue;
                }
                let mut used = hit.end();
                let mut end = first_end;
                for &(a, b) in &pieces {
                    if used <= b - a {
                        end = a + used;
                        break;
                    }
                    used -= b - a;
                }
                found.push(Candidate::new(rule, first_start, end, &compact[..hit.end()]));
                break;
            }
        }
        Ok(found)
    }

    /// Secrets and personal data inside base64 or hex tokens (`find_encoded_secrets`).
    pub fn find_encoded(&self, text: &str, s: &Settings, secrets: &Secrets, pii: &Pii) -> Result<Vec<Candidate>, DetectError> {
        let mut found = Vec::new();
        let mut tokens = 0;
        for (spans, base64) in [(base64_tokens(text), true), (hex_tokens(text), false)] {
            for (a, b) in spans {
                tokens += 1;
                if tokens > p::MAX_TOKENS {
                    return Ok(found);
                }
                let token = &text[a..b];
                let decoded = if base64 { from_base64(token) } else { from_hex(token) };
                let Some(decoded) = decoded else { continue };
                let mut inner = secrets.find_named(&decoded)?;
                inner.extend(secrets.find_generic(&decoded, s)?);
                inner.extend(pii.find(&decoded, s)?);
                for hit in inner {
                    found.push(Candidate::new(hit.rule, a, b, &hit.value));
                }
            }
        }
        Ok(found)
    }
}

fn is_b64_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'_' | b'-')
}

/// Maximal runs of bytes accepted by `class`, as (start, end).
fn runs(text: &str, class: fn(u8) -> bool) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if !class(bytes[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && class(bytes[i]) {
            i += 1;
        }
        out.push((start, i));
    }
    out
}

/// Spans `_B64` matches: `(?<![A-Za-z0-9+/_\-=])[A-Za-z0-9+/_\-]{24,4096}={0,2}(?![A-Za-z0-9+/_\-])`.
///
/// Worked out from how the pattern backtracks: a start inside a run fails the lookbehind, and a run longer
/// than 4096 can never reach the lookahead, so only a whole run of 24 to 4096 characters, not preceded by
/// "=", matches. Of the "=" after it, up to two are taken, but one fewer when taking them all would leave a
/// base64 character next to the end. As a regex this cost quadratic time on one long run.
fn base64_tokens(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    for (start, end) in runs(text, is_b64_char) {
        if (start > 0 && bytes[start - 1] == b'=') || !(24..=p::MAX_TOKEN_CHARS).contains(&(end - start)) {
            continue;
        }
        let pads = bytes[end..].iter().take_while(|&&b| b == b'=').count();
        let after = bytes.get(end + pads).copied();
        let taken = if pads >= 3 {
            2
        } else if after.is_some_and(is_b64_char) {
            pads - 1 // pads >= 1 here: the run is maximal, so a base64 character cannot follow it directly
        } else {
            pads
        };
        out.push((start, end + taken));
    }
    out
}

/// Spans `_HEX` matches: `(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){12,2048}(?![0-9A-Fa-f])`, which is a whole run
/// of hex digits of even length from 24 to 4096 (an odd run leaves a digit next to the end and fails).
fn hex_tokens(text: &str) -> Vec<(usize, usize)> {
    runs(text, |b| b.is_ascii_hexdigit())
        .into_iter()
        .filter(|&(a, b)| (b - a) % 2 == 0 && (24..=p::MAX_TOKEN_CHARS).contains(&(b - a)))
        .collect()
}

/// A later piece of a key has a digit, or is a long, varied string. A plain word is not part of it.
fn looks_random(piece: &str) -> bool {
    if piece.chars().any(uni::is_digit) {
        return true;
    }
    let n = uni::len(piece);
    let tail_upper = piece.chars().skip(1).any(char::is_uppercase);
    if n >= 6 && piece.chars().any(char::is_lowercase) && tail_upper {
        return true;
    }
    n >= 8 && shannon_entropy(piece) >= p::MIN_PIECE_ENTROPY
}

fn decoded_text(raw: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(raw).ok()?;
    let n = uni::len(text);
    if n < p::MIN_DECODED_CHARS {
        return None;
    }
    let printable = text.chars().filter(|&c| uni::is_printable(c) || matches!(c, '\r' | '\n' | '\t')).count();
    (printable as f64 >= p::PRINTABLE_RATIO * n as f64).then(|| text.to_string())
}

fn from_base64(token: &str) -> Option<String> {
    let cleaned: String = token.chars().map(|c| match c {
        '-' => '+',
        '_' => '/',
        c => c,
    }).collect();
    let cleaned = cleaned.trim_end_matches('=');
    let mut padded = cleaned.to_string();
    padded.extend(std::iter::repeat_n('=', (4 - uni::len(cleaned) % 4) % 4));
    decoded_text(&a2b_base64(padded.as_bytes(), true).ok()?)
}

fn from_hex(token: &str) -> Option<String> {
    decoded_text(&unhexlify(token).ok()?)
}

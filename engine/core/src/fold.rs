//! A plain view of text for detection, with an exact way back to the original (`normalize.fold`).
//!
//! Fullwidth letters, zero-width characters, look-alike letters and `s`, `%73`, `&#115;` escapes are
//! written the way a reader sees them. Every view character remembers which original characters it came
//! from, so a match in the view is redacted in the original, character for character.

use crate::uni;

/// The view, and for every view character its `[start, end)` in the original (character indices).
/// `maps` is `None` when the view is the original unchanged.
pub struct View {
    pub text: String,
    pub maps: Option<(Vec<usize>, Vec<usize>)>,
}

fn is_interesting_ascii(c: char) -> bool {
    matches!(c as u32, 0x00..=0x08 | 0x0b | 0x0c | 0x0e..=0x1f | 0x7f)
}

fn hex_value(chars: &[char]) -> Option<u32> {
    let s: String = chars.iter().collect();
    u32::from_str_radix(&s, 16).ok()
}

/// The escape that starts at `chars[i]`, as (length in characters, decoded text); `None` if there is none.
/// Mirrors `_INTERESTING`'s escape alternatives and `_decode`.
fn escape_at(chars: &[char], i: usize) -> Option<(usize, String)> {
    let is_hex = |c: &char| c.is_ascii_hexdigit();
    match chars[i] {
        '\\' => {
            let body = chars.get(i + 1..i + 6)?;
            if body[0] != 'u' || !body[1..].iter().all(is_hex) {
                return None;
            }
            let code = hex_value(&body[1..])?;
            Some((6, decoded(code)))
        }
        '%' => {
            let body = chars.get(i + 1..i + 3)?;
            if !body.iter().all(is_hex) {
                return None;
            }
            let code = hex_value(body)?;
            let raw: String = chars[i..i + 3].iter().collect();
            // A %XX byte that is not plain text stays as written.
            Some((3, if (0x20..0x7f).contains(&code) { decoded(code) } else { raw }))
        }
        '&' => {
            if chars.get(i + 1) != Some(&'#') {
                return None;
            }
            let mut j = i + 2;
            let hexadecimal = matches!(chars.get(j), Some('x' | 'X'));
            if hexadecimal {
                j += 1;
            }
            let digits_start = j;
            let max = if hexadecimal { 6 } else { 7 };
            // Python's \d: any decimal digit, which int() also reads ("&#١٠٠;" is "d").
            while j < chars.len() && j - digits_start < max && (if hexadecimal { chars[j].is_ascii_hexdigit() } else { uni::is_nd(chars[j]) }) {
                j += 1;
            }
            if j == digits_start || chars.get(j) != Some(&';') {
                return None;
            }
            let digits = &chars[digits_start..j];
            let code = if hexadecimal {
                hex_value(digits)?
            } else {
                u32::try_from(uni::py_int(&digits.iter().collect::<String>())?).unwrap_or(u32::MAX)
            };
            Some((j + 1 - i, decoded(code)))
        }
        _ => None,
    }
}

fn decoded(code: u32) -> String {
    if (0xD800..=0xDFFF).contains(&code) || code > 0x10FFFF {
        return String::new();
    }
    char::from_u32(code).map(String::from).unwrap_or_default()
}

fn clean_into(out: &mut String, c: char) -> usize {
    if matches!(c, '\t' | '\n' | '\r') {
        out.push(c);
        return 1;
    }
    match uni::clean_char(c) {
        Some(s) => {
            out.push_str(s);
            s.chars().count()
        }
        None => {
            out.push(c);
            1
        }
    }
}

/// `normalize.fold`.
pub fn fold(text: &str) -> View {
    let chars: Vec<char> = text.chars().collect();
    let interesting = |i: usize| -> bool {
        let c = chars[i];
        !c.is_ascii() || is_interesting_ascii(c) || (matches!(c, '\\' | '%' | '&') && escape_at(&chars, i).is_some())
    };
    if !(0..chars.len()).any(interesting) {
        return View { text: text.to_string(), maps: None };
    }
    let mut view = String::with_capacity(text.len());
    let mut starts = Vec::with_capacity(chars.len());
    let mut ends = Vec::with_capacity(chars.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        // _INTERESTING tries the escapes first, then a single non-ASCII or control character.
        if matches!(c, '\\' | '%' | '&') {
            if let Some((length, decoded)) = escape_at(&chars, i) {
                let mut n = 0;
                for d in decoded.chars() {
                    n += clean_into(&mut view, d);
                }
                starts.extend(std::iter::repeat_n(i, n));
                ends.extend(std::iter::repeat_n(i + length, n));
                i += length;
                continue;
            }
        }
        if !c.is_ascii() || is_interesting_ascii(c) {
            let n = clean_into(&mut view, c);
            starts.extend(std::iter::repeat_n(i, n));
            ends.extend(std::iter::repeat_n(i + 1, n));
        } else {
            view.push(c);
            starts.push(i);
            ends.push(i + 1);
        }
        i += 1;
    }
    View { text: view, maps: Some((starts, ends)) }
}

impl View {
    /// A span of view characters as a span of original characters (`to_original`).
    pub fn to_original(&self, start: usize, end: usize) -> (usize, usize) {
        match &self.maps {
            Some((starts, ends)) if end > start => (starts[start], ends[end - 1]),
            _ => (start, end),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_is_unchanged() {
        let v = fold("hello world");
        assert!(v.maps.is_none() && v.text == "hello world");
    }

    #[test]
    fn escapes_and_invisible_characters_fold() {
        let v = fold("a\\u0073b%41c&#100;d&#x65;e\u{200b}f");
        assert_eq!(v.text, "asbAcddeef");
        assert_eq!(fold("&#\u{661}\u{660}\u{660};").text, "d");
        let v = fold("x\u{200b}y");
        assert_eq!(v.text, "xy");
        assert_eq!(v.to_original(0, 2), (0, 3));
    }

    #[test]
    fn a_control_percent_escape_stays() {
        assert_eq!(fold("%0Aé").text, "%0Aé");
    }
}

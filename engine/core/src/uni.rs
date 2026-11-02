//! Python's character predicates, from tables generated out of Python's own Unicode database.

use crate::tables;

fn in_ranges(table: &[(u32, u32)], c: char) -> bool {
    let cp = c as u32;
    table
        .binary_search_by(|&(lo, hi)| {
            if hi < cp {
                std::cmp::Ordering::Less
            } else if lo > cp {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// `str.isalpha()` for one character.
pub fn is_alpha(c: char) -> bool {
    in_ranges(tables::ALPHA, c)
}

/// `str.isdigit()` for one character (wider than Nd: superscripts, circled digits).
pub fn is_digit(c: char) -> bool {
    in_ranges(tables::ISDIGIT, c)
}

/// `str.isupper()` for one character.
pub fn is_upper(c: char) -> bool {
    in_ranges(tables::UPPER, c)
}

/// `str.isprintable()` for one character.
pub fn is_printable(c: char) -> bool {
    in_ranges(tables::PRINTABLE, c)
}

/// Python regex `\w`.
pub fn is_word(c: char) -> bool {
    in_ranges(tables::WORD, c)
}

/// Python regex `\d` (category Nd).
pub fn is_nd(c: char) -> bool {
    in_ranges(tables::DIGIT_ND, c)
}

/// The decimal value of an Nd character, as `int()` reads it.
pub fn nd_value(c: char) -> Option<u32> {
    let cp = c as u32;
    let at = tables::DIGIT_RUNS.partition_point(|&(lo, _, _)| lo <= cp);
    if at == 0 {
        return None;
    }
    let (lo, hi, first) = tables::DIGIT_RUNS[at - 1];
    (cp <= hi).then(|| first + (cp - lo))
}

/// `int(text)` for a string of Nd digits (no sign, no spaces); `None` if any character is not one.
pub fn py_int(text: &str) -> Option<u64> {
    if text.is_empty() {
        return None;
    }
    let mut value: u64 = 0;
    for c in text.chars() {
        value = value.checked_mul(10)?.checked_add(u64::from(nd_value(c)?))?;
    }
    Some(value)
}

/// `str.isalpha()`: non-empty and every character is a letter.
pub fn str_is_alpha(s: &str) -> bool {
    !s.is_empty() && s.chars().all(is_alpha)
}

/// `str.isdigit()`: non-empty and every character has a digit value.
pub fn str_is_digit(s: &str) -> bool {
    !s.is_empty() && s.chars().all(is_digit)
}

/// What `normalize._clean_char` gives for one character: `None` when it is unchanged.
pub fn clean_char(c: char) -> Option<&'static str> {
    if in_ranges(tables::CLEAN_DROP, c) {
        return Some("");
    }
    let cp = c as u32;
    tables::CLEAN_MAP.binary_search_by_key(&cp, |&(k, _)| k).ok().map(|i| tables::CLEAN_MAP[i].1)
}

/// The number of characters (code points), as Python's `len()` counts them.
pub fn len(s: &str) -> usize {
    s.chars().count()
}

/// Byte offset of the character `n` places before byte offset `at` (or 0).
pub fn back_chars(s: &str, at: usize, n: usize) -> usize {
    let mut pos = at;
    for _ in 0..n {
        match s[..pos].chars().next_back() {
            Some(c) => pos -= c.len_utf8(),
            None => break,
        }
    }
    pos
}

/// Byte offset of the character `n` places after byte offset `at` (or the end).
pub fn forward_chars(s: &str, at: usize, n: usize) -> usize {
    let mut pos = at;
    for c in s[at..].chars().take(n) {
        pos += c.len_utf8();
    }
    pos
}

/// The first `n` characters of `s`.
pub fn prefix_chars(s: &str, n: usize) -> &str {
    &s[..forward_chars(s, 0, n)]
}

/// The last `n` characters of `s`.
pub fn suffix_chars(s: &str, n: usize) -> &str {
    &s[back_chars(s, s.len(), n)..]
}

/// For every byte offset that starts a character, its character index; the end maps to the length.
pub struct CharIndex {
    starts: Vec<usize>,
}

impl CharIndex {
    pub fn new(s: &str) -> Self {
        let mut starts: Vec<usize> = s.char_indices().map(|(b, _)| b).collect();
        starts.push(s.len());
        CharIndex { starts }
    }

    /// Character index of byte offset `byte` (which must be a character boundary).
    pub fn char_at(&self, byte: usize) -> usize {
        self.starts.partition_point(|&b| b < byte)
    }

    /// Byte offset of character index `index`.
    pub fn byte_at(&self, index: usize) -> usize {
        self.starts[index.min(self.starts.len() - 1)]
    }

    pub fn char_len(&self) -> usize {
        self.starts.len() - 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn predicates_follow_python() {
        assert!(is_alpha('é') && !is_alpha('1'));
        assert!(is_digit('²') && !is_nd('²'));
        assert!(is_nd('٣') && nd_value('٣') == Some(3));
        assert_eq!(py_int("١٠"), Some(10));
        assert!(!is_printable('\u{200b}') && is_printable(' '));
        assert_eq!(clean_char('\u{200b}'), Some(""));
        assert_eq!(clean_char('ａ'), Some("a"));
        assert_eq!(clean_char('a'), None);
    }

    #[test]
    fn char_index_maps_both_ways() {
        let s = "a😀b";
        let ix = CharIndex::new(s);
        assert_eq!(ix.char_at(5), 2);
        assert_eq!(ix.byte_at(2), 5);
        assert_eq!(ix.char_len(), 3);
        assert_eq!(back_chars(s, 5, 1), 1);
        assert_eq!(suffix_chars("abcdef", 4), "cdef");
    }
}

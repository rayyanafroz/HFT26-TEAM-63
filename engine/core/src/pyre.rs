//! Python regular expressions, run with the same meaning in Rust.
//!
//! The detector patterns are copied from the Python reference as written. `translate` rewrites the parts
//! whose meaning differs between Python's `re` and Rust's `fancy-regex`:
//!
//! * `\w`, `\d`, `\s` and `\b` use Python's definitions (`\s` also covers `\x1c`-`\x1f`);
//! * `$` matches at the end or before a final newline, `^` only at the start (MULTILINE changes both);
//! * `\Z` is the very end;
//! * under IGNORECASE, Python also lets `i` match the dotless `ı` and the dotted `İ`;
//! * escaped punctuation becomes a `\x{..}` escape, which both regex dialects read the same way.
//!
//! Positions are byte offsets into the searched `&str`.

use std::sync::OnceLock;

use fancy_regex::{Regex, RegexBuilder, RegexInput};

const WORD: &str = r"\p{L}\p{N}_";
const ND: &str = r"\p{Nd}";
const SPACE: &str = r"\x{9}\x{A}\x{B}\x{C}\x{D}\x{1C}-\x{1F}\x{20}\x{85}\x{A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}";
const LETTER_NOT_DIGIT: &str = r"\p{L}\p{Nl}\p{No}";
const I_FOLD: &str = r"\x{131}\x{130}";

/// Pattern flags that change how the pattern text is read.
#[derive(Clone, Copy, Default)]
pub struct Flags {
    pub multiline: bool,
    pub dotall: bool,
}

pub const PLAIN: Flags = Flags { multiline: false, dotall: false };

#[derive(Debug)]
pub struct RegexError(pub String);

fn boundary() -> String {
    format!("(?:(?<=[{WORD}])(?![{WORD}])|(?<![{WORD}])(?=[{WORD}]))")
}

fn hex(c: char) -> String {
    format!("\\x{{{:X}}}", c as u32)
}

/// One item of a character class: a single character, a range, or a whole class escape such as `\w`.
enum ClassItem {
    Char(char),
    Range(char, char),
    Set(&'static str),
}

fn covers_i(items: &[ClassItem]) -> bool {
    items.iter().any(|item| match item {
        ClassItem::Char(c) => *c == 'i' || *c == 'I',
        ClassItem::Range(a, b) => (*a..=*b).contains(&'i') || (*a..=*b).contains(&'I'),
        ClassItem::Set(_) => false,
    })
}

/// The character a simple escape stands for, after the backslash at `chars[*i]`; advances `*i` past it.
fn escaped_char(chars: &[char], i: &mut usize) -> Result<char, RegexError> {
    let d = chars[*i];
    let take_hex = |i: &mut usize, n: usize| -> Result<char, RegexError> {
        let digits: String = chars.get(*i + 1..*i + 1 + n).ok_or_else(|| RegexError("short escape".into()))?.iter().collect();
        let code = u32::from_str_radix(&digits, 16).map_err(|_| RegexError(format!("bad escape \\{d}{digits}")))?;
        *i += n;
        char::from_u32(code).ok_or_else(|| RegexError("bad code point".into()))
    };
    let c = match d {
        'n' => '\n',
        'r' => '\r',
        't' => '\t',
        'f' => '\x0c',
        'v' => '\x0b',
        'a' => '\x07',
        '0' => '\0',
        'x' => take_hex(i, 2)?,
        'u' => take_hex(i, 4)?,
        'U' => take_hex(i, 8)?,
        c if !c.is_ascii_alphanumeric() => c,
        c => return Err(RegexError(format!("unsupported escape \\{c}"))),
    };
    *i += 1;
    Ok(c)
}

/// Where translated pattern text goes: the exact pattern, and a relaxed copy without lookarounds.
///
/// The relaxed copy matches wherever the exact one does (it only drops constraints), so a fast DFA can
/// run it to find where a real match could start. Text inside a lookaround is left out of it.
struct Out {
    strict: String,
    relaxed: String,
    suppress: usize,
}

impl Out {
    fn both(&mut self, s: &str) {
        self.strict.push_str(s);
        if self.suppress == 0 {
            self.relaxed.push_str(s);
        }
    }
    fn split(&mut self, strict: &str, relaxed: &str) {
        self.strict.push_str(strict);
        if self.suppress == 0 {
            self.relaxed.push_str(relaxed);
        }
    }
}

/// Translate a Python pattern. See the module documentation for what changes.
pub fn translate(pattern: &str, flags: Flags) -> Result<String, RegexError> {
    translate_pair(pattern, flags).map(|(strict, _, _)| strict)
}

/// The translated pattern and its relaxed copy (no lookarounds, no `\b`, backreferences as `.*?`).
///
/// A one-character lookbehind at the very start is kept in the relaxed copy as a consumed character,
/// `(?:\A|[^class])`: the third value is then true, and a relaxed match starting at `r` means a real
/// match can start one character later (or at 0). Without it the DFA would propose every position inside
/// a run, and long runs would cost quadratic time.
pub fn translate_pair(pattern: &str, flags: Flags) -> Result<(String, String, bool), RegexError> {
    let chars: Vec<char> = pattern.chars().collect();
    let mut out = Out { strict: String::with_capacity(pattern.len() * 2), relaxed: String::new(), suppress: 0 };
    let mut ci = false;
    let mut stack: Vec<(bool, bool)> = Vec::new(); // (case-insensitive before the group, is a lookaround)
    let mut i = 0;
    if pattern.starts_with("(?i)") {
        ci = true;
        out.both("(?i)");
        i = 4;
    }
    let body_start = i;
    let mut lead = false;
    let mut lead_open: Option<(usize, bool)> = None; // (where its text starts in `strict`, is negative)
    while i < chars.len() {
        let c = chars[i];
        match c {
            '\\' => {
                i += 1;
                let d = *chars.get(i).ok_or_else(|| RegexError("trailing backslash".into()))?;
                match d {
                    'b' => out.split(&boundary(), ""),
                    'w' => out.both(&format!("[{WORD}]")),
                    'W' => out.both(&format!("[^{WORD}]")),
                    'd' => out.both(&format!("[{ND}]")),
                    'D' => out.both(&format!("[^{ND}]")),
                    's' => out.both(&format!("[{SPACE}]")),
                    'S' => out.both(&format!("[^{SPACE}]")),
                    'A' => out.both(r"\A"),
                    'Z' => out.both(r"\z"),
                    '1'..='9' => out.split(&format!("\\{d}"), "(?s:.*?)"),
                    _ => {
                        let literal = escaped_char(&chars, &mut i)?;
                        let mut s = String::new();
                        push_literal(&mut s, literal, ci);
                        out.both(&s);
                        continue;
                    }
                }
                i += 1;
            }
            '[' => {
                let mut s = String::new();
                i = translate_class(&chars, i, ci, &mut s)?;
                out.both(&s);
            }
            '(' => {
                let ahead: String = chars[i + 1..chars.len().min(i + 4)].iter().collect();
                if ahead.starts_with("?i:") {
                    stack.push((ci, false));
                    ci = true;
                    out.both("(?i:");
                    i += 4;
                } else if ahead.starts_with("?=") || ahead.starts_with("?!") {
                    stack.push((ci, true));
                    out.split(&format!("({}", &ahead[..2]), "");
                    out.suppress += 1;
                    i += 3;
                } else if ahead.starts_with("?<=") || ahead.starts_with("?<!") {
                    stack.push((ci, true));
                    out.split(&format!("({}", &ahead[..3]), "");
                    if i == body_start && stack.len() == 1 {
                        lead_open = Some((out.strict.len(), ahead.starts_with("?<!")));
                    }
                    out.suppress += 1;
                    i += 4;
                } else {
                    stack.push((ci, false));
                    out.both("(");
                    i += 1;
                }
            }
            ')' => {
                let (before, lookaround) = stack.pop().ok_or_else(|| RegexError("unbalanced ')'".into()))?;
                ci = before;
                if lookaround {
                    out.suppress -= 1;
                    if let (Some((at, negative)), true) = (lead_open.take(), stack.is_empty()) {
                        let inner = out.strict[at..].to_string();
                        if inner.starts_with('[') && inner.ends_with(']') && inner.matches('[').count() == 1 {
                            let class = if negative {
                                match inner.strip_prefix("[^") {
                                    Some(rest) => format!("[{rest}"),
                                    None => format!("[^{}", &inner[1..]),
                                }
                            } else {
                                inner.clone()
                            };
                            out.relaxed.push_str(&format!("(?:{}{class})", if negative { r"\A|" } else { "" }));
                            lead = true;
                        }
                    }
                    out.strict.push(')');
                } else {
                    out.both(")");
                }
                i += 1;
            }
            '$' => {
                out.split(if flags.multiline { r"(?=\n|\z)" } else { r"(?=\n?\z)" }, "");
                i += 1;
            }
            '^' => {
                if flags.multiline {
                    out.split(r"(?:\A|(?<=\n))", "");
                } else {
                    out.both(r"\A");
                }
                i += 1;
            }
            '.' => {
                out.both(if flags.dotall { "(?s:.)" } else { "." });
                i += 1;
            }
            'i' | 'I' if ci => {
                out.both(&format!("[iI{I_FOLD}]"));
                i += 1;
            }
            _ => {
                let mut s = [0u8; 4];
                out.both(c.encode_utf8(&mut s));
                i += 1;
            }
        }
    }
    if !stack.is_empty() {
        return Err(RegexError("unbalanced '('".into()));
    }
    Ok((out.strict, out.relaxed, lead))
}

fn push_literal(out: &mut String, c: char, ci: bool) {
    if ci && (c == 'i' || c == 'I') {
        out.push_str(&format!("[iI{I_FOLD}]"));
    } else if c.is_ascii_alphanumeric() {
        out.push(c);
    } else {
        out.push_str(&hex(c));
    }
}

/// Translate the class that starts at `chars[start] == '['`; returns the index after its `]`.
fn translate_class(chars: &[char], start: usize, ci: bool, out: &mut String) -> Result<usize, RegexError> {
    let mut i = start + 1;
    let negated = chars.get(i) == Some(&'^');
    if negated {
        i += 1;
    }
    // [^\W\d_]: a letter that is not a digit or "_". The only use of an inverted escape inside a class.
    let rest: String = chars[i..chars.len().min(i + 6)].iter().collect();
    if negated && rest == r"\W\d_]" {
        out.push_str(&format!("[{LETTER_NOT_DIGIT}]"));
        return Ok(i + 6);
    }
    let mut items: Vec<ClassItem> = Vec::new();
    let mut first = true;
    loop {
        let c = *chars.get(i).ok_or_else(|| RegexError("unterminated class".into()))?;
        if c == ']' && !first {
            i += 1;
            break;
        }
        first = false;
        let atom = if c == '\\' {
            i += 1;
            match chars.get(i) {
                Some('w') => {
                    i += 1;
                    ClassItem::Set(WORD)
                }
                Some('d') => {
                    i += 1;
                    ClassItem::Set(ND)
                }
                Some('s') => {
                    i += 1;
                    ClassItem::Set(SPACE)
                }
                Some('W' | 'D' | 'S') => return Err(RegexError("inverted escape inside a class".into())),
                Some(_) => ClassItem::Char(escaped_char(chars, &mut i)?),
                None => return Err(RegexError("trailing backslash".into())),
            }
        } else {
            i += 1;
            ClassItem::Char(c)
        };
        // A range: atom '-' atom, unless the '-' is the last character of the class.
        if let ClassItem::Char(lo) = atom {
            if chars.get(i) == Some(&'-') && chars.get(i + 1).is_some_and(|&n| n != ']') {
                i += 1;
                let hi_raw = chars[i];
                let hi = if hi_raw == '\\' {
                    i += 1;
                    escaped_char(chars, &mut i)?
                } else {
                    i += 1;
                    hi_raw
                };
                items.push(ClassItem::Range(lo, hi));
                continue;
            }
        }
        items.push(atom);
    }
    out.push('[');
    if negated {
        out.push('^');
    }
    for item in &items {
        match item {
            ClassItem::Char(c) => out.push_str(&hex(*c)),
            ClassItem::Range(a, b) => {
                out.push_str(&hex(*a));
                out.push('-');
                out.push_str(&hex(*b));
            }
            ClassItem::Set(s) => out.push_str(s),
        }
    }
    if ci && covers_i(&items) {
        out.push_str(I_FOLD);
    }
    out.push(']');
    Ok(i)
}

/// Positions of one match and its groups.
#[derive(Clone, Debug)]
pub struct Caps {
    groups: Vec<Option<(usize, usize)>>,
}

impl Caps {
    pub fn get(&self, group: usize) -> Option<(usize, usize)> {
        self.groups.get(group).copied().flatten()
    }
    pub fn start(&self) -> usize {
        self.groups[0].unwrap().0
    }
    pub fn end(&self) -> usize {
        self.groups[0].unwrap().1
    }
    /// The text of a group, if it took part in the match.
    pub fn text<'t>(&self, text: &'t str, group: usize) -> Option<&'t str> {
        self.get(group).map(|(a, b)| &text[a..b])
    }
}

/// A compiled Python pattern.
///
/// Patterns with lookarounds run on fancy-regex's backtracking VM, which tries every start position. To
/// keep that fast, the relaxed copy (see `translate_pair`) runs first on the `regex` crate's DFA and
/// names the next position where a match could start; the exact pattern is then tried, anchored, only
/// there. Every exact match is also a relaxed match at the same start, so no match is skipped. Patterns
/// without lookarounds go straight to the DFA.
pub struct Re {
    source: String,
    strict: String,
    relaxed_source: Option<String>,
    lead: bool,
    exact: OnceLock<Result<Regex, String>>,
    relaxed: OnceLock<Result<regex::Regex, String>>,
    names: OnceLock<Vec<(String, usize)>>,
}

fn build(pattern: &str) -> Result<Regex, String> {
    RegexBuilder::new(pattern)
        .backtrack_limit(50_000_000)
        .delegate_size_limit(256 << 20)
        .delegate_dfa_size_limit(64 << 20)
        .build()
        .map_err(|e| format!("{e}"))
}

fn runtime(e: fancy_regex::Error) -> RegexError {
    RegexError(format!("{e}"))
}

fn char_len_at(text: &str, at: usize) -> usize {
    text[at..].chars().next().map_or(1, char::len_utf8)
}

impl Re {
    /// Translates now (so a bad pattern fails at once); compiles on first use, since some patterns are
    /// only needed for some texts and compiling all of them up front costs hundreds of milliseconds.
    pub fn new(pattern: &str, flags: Flags) -> Result<Re, RegexError> {
        let (strict, relaxed, lead) = translate_pair(pattern, flags)?;
        Ok(Re {
            source: pattern.to_string(),
            relaxed_source: (relaxed != strict).then_some(relaxed),
            strict,
            lead,
            exact: OnceLock::new(),
            relaxed: OnceLock::new(),
            names: OnceLock::new(),
        })
    }

    /// Compile now. Used by tests and by callers that want every pattern checked up front.
    pub fn compile(&self) -> Result<(), RegexError> {
        self.exact()?;
        self.relaxed()?;
        Ok(())
    }

    fn exact(&self) -> Result<&Regex, RegexError> {
        self.exact.get_or_init(|| build(&self.strict)).as_ref().map_err(|e| RegexError(format!("{}: {e}", self.source)))
    }

    fn relaxed(&self) -> Result<Option<&regex::Regex>, RegexError> {
        let Some(source) = &self.relaxed_source else { return Ok(None) };
        let built = self.relaxed.get_or_init(|| {
            regex::RegexBuilder::new(source).size_limit(256 << 20).dfa_size_limit(64 << 20).build().map_err(|e| format!("{e}"))
        });
        built.as_ref().map(Some).map_err(|e| RegexError(format!("relaxed form of {}: {e}", self.source)))
    }

    /// The group number of a named group.
    pub fn group(&self, name: &str) -> usize {
        let names = self.names.get_or_init(|| match self.exact() {
            Ok(re) => re.capture_names().enumerate().filter_map(|(i, n)| n.map(|n| (n.to_string(), i))).collect(),
            Err(_) => Vec::new(),
        });
        names.iter().find(|(n, _)| n == name).map(|(_, i)| *i).unwrap_or_else(|| panic!("no group {name} in {}", self.source))
    }

    fn caps(c: &fancy_regex::Captures<'_, str>) -> Caps {
        Caps { groups: (0..c.len()).map(|g| c.get(g).map(|m| (m.start(), m.end()))).collect() }
    }

    /// `pattern.match(text, pos)`: a match that starts exactly at `pos`. Lookbehinds see the text before it.
    pub fn match_at(&self, text: &str, pos: usize) -> Result<Option<Caps>, RegexError> {
        let input = RegexInput::new(text).from_pos(pos).anchored(true);
        Ok(self.exact()?.captures_input(input).map_err(runtime)?.as_ref().map(Self::caps))
    }

    fn try_at(&self, text: &str, pos: usize, groups: bool) -> Result<Option<Caps>, RegexError> {
        if groups {
            return self.match_at(text, pos);
        }
        let input = RegexInput::new(text).from_pos(pos).anchored(true);
        Ok(self.exact()?.find_input(input).map_err(runtime)?.map(|m| Caps { groups: vec![Some((m.start(), m.end()))] }))
    }

    /// The leftmost match that starts at or after `pos`, with its groups when `groups` is set.
    fn next(&self, text: &str, mut pos: usize, groups: bool) -> Result<Option<Caps>, RegexError> {
        let Some(relaxed) = self.relaxed()? else {
            let exact = self.exact()?;
            return Ok(if groups {
                exact.captures_from_pos(text, pos).map_err(runtime)?.as_ref().map(Self::caps)
            } else {
                exact.find_from_pos(text, pos).map_err(runtime)?.map(|m| Caps { groups: vec![Some((m.start(), m.end()))] })
            });
        };
        while pos <= text.len() {
            if !self.lead {
                let Some(candidate) = relaxed.find_at(text, pos) else { return Ok(None) };
                let at = candidate.start();
                if let Some(found) = self.try_at(text, at, groups)? {
                    return Ok(Some(found));
                }
                pos = at + char_len_at(text, at);
                continue;
            }
            // The relaxed match includes the character before the real start, so search from there.
            let from = if pos == 0 { 0 } else { pos - text[..pos].chars().next_back().map_or(1, char::len_utf8) };
            let Some(candidate) = relaxed.find_at(text, from) else { return Ok(None) };
            let r = candidate.start();
            let after = if r < text.len() { r + char_len_at(text, r) } else { r + 1 };
            // At 0 the leading part may have matched the start of the text (nothing consumed).
            for at in [r, after] {
                if (at == r && r != 0) || at < pos || at > text.len() {
                    continue;
                }
                if let Some(found) = self.try_at(text, at, groups)? {
                    return Ok(Some(found));
                }
            }
            // Every start up to `after` has been tried; the next one is a character further on.
            pos = if after >= text.len() { text.len() + 1 } else { after + char_len_at(text, after) };
        }
        Ok(None)
    }

    fn all(&self, text: &str, groups: bool) -> Result<Vec<Caps>, RegexError> {
        let mut out = Vec::new();
        let mut pos = 0;
        while pos <= text.len() {
            let Some(c) = self.next(text, pos, groups)? else { break };
            let (start, end) = (c.start(), c.end());
            out.push(c);
            // As re.finditer: continue at the end; after an empty match, one character further.
            pos = if end > start { end } else { end + char_len_at(text, end) };
        }
        Ok(out)
    }

    /// Every match with its groups, as `re.finditer` reports them.
    pub fn captures_all(&self, text: &str) -> Result<Vec<Caps>, RegexError> {
        self.all(text, true)
    }

    /// The spans of every match.
    pub fn find_all(&self, text: &str) -> Result<Vec<(usize, usize)>, RegexError> {
        Ok(self.all(text, false)?.into_iter().map(|c| (c.start(), c.end())).collect())
    }

    /// `pattern.search(text) is not None`.
    pub fn is_match(&self, text: &str) -> Result<bool, RegexError> {
        if let Some(relaxed) = self.relaxed()? {
            if !relaxed.is_match(text) {
                return Ok(false);
            }
        }
        Ok(self.next(text, 0, false)?.is_some())
    }

    /// True when the first match at the start covers the whole text (used by tests).
    pub fn matches_whole(&self, text: &str) -> Result<bool, RegexError> {
        Ok(self.try_at(text, 0, false)?.is_some_and(|c| c.end() == text.len()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn re(p: &str) -> Re {
        Re::new(p, PLAIN).unwrap()
    }

    #[test]
    fn word_boundary_is_python_s() {
        let r = re(r"\bkey\b");
        assert!(r.is_match("a key here").unwrap());
        assert!(!r.is_match("keyé").unwrap());
        assert!(r.is_match("key\u{0903}").unwrap()); // a spacing mark is not \w in Python
    }

    #[test]
    fn dollar_allows_a_final_newline() {
        assert!(re(r"ab$").is_match("ab\n").unwrap());
        assert!(!re(r"ab$").is_match("ab\n\n").unwrap());
        let m = Re::new(r"x$", Flags { multiline: true, dotall: false }).unwrap();
        assert!(m.is_match("x\ny").unwrap());
    }

    #[test]
    fn ignorecase_i_matches_turkish_forms() {
        assert!(re(r"(?i)pin").is_match("PİN").unwrap());
        assert!(re(r"(?i)[a-z]+x").matches_whole("ıx").unwrap());
        assert!(!re(r"[a-z]x").is_match("ıx").unwrap());
        assert!(re(r"(?i:sec)ret").is_match("SECret").unwrap());
    }

    #[test]
    fn classes_and_escapes_translate() {
        assert!(re(r#"[^\s\"'`,;&<>{}()\[\]\\]+"#).matches_whole("abc").unwrap());
        assert!(re(r"[^\W\d_]{2}").matches_whole("ab").unwrap());
        assert!(!re(r"[^\W\d_]{2}").matches_whole("a1").unwrap());
        assert!(re(r"\s").is_match("\u{1c}").unwrap());
        assert!(re(r"(['])x\1").is_match("'x'").unwrap());
        assert!(re(r"[\x00-\x08]").is_match("\u{7}").unwrap());
    }

    #[test]
    fn named_groups_and_anchored_match() {
        let r = re(r"(?P<a>x+)(?P<b>y)?");
        let c = r.match_at("zxxy", 1).unwrap().unwrap();
        assert_eq!(c.get(r.group("a")), Some((1, 3)));
        assert_eq!(c.get(r.group("b")), Some((3, 4)));
        assert!(r.match_at("zxxy", 0).unwrap().is_none());
    }
}

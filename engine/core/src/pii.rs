//! Personal data detectors (`pii.py`). Checksums reject random numbers.

use crate::checksums::{iban_valid, luhn_valid, verhoeff_valid};
use crate::patterns as p;
use crate::pyre::{Re, RegexError, PLAIN};
use crate::uni;
use crate::{Candidate, DetectError, Settings};

pub struct Pii {
    digit_run: Re,
    single_digits: Re,
    digit_group: Re,
    aadhaar_body: Re,
    iban_group: Re,
    ssn: Re,
    ssn_worded: Re,
    pan: Re,
    email: Re,
    email_spelled: Re,
    example_word: Re,
    phones: Vec<Re>,
    hostname: Re,
    private_ip: Re,
}

fn re(def: (&str, crate::pyre::Flags)) -> Result<Re, RegexError> {
    Re::new(def.0, def.1)
}

impl Pii {
    pub fn new() -> Result<Self, RegexError> {
        Ok(Pii {
            digit_run: re(p::DIGIT_RUN_RE)?,
            single_digits: re(p::SINGLE_DIGITS_RE)?,
            digit_group: re(p::DIGIT_GROUP_RE)?,
            // _AADHAAR_RE without its zero-width wrapper: (?<!\d)(?=(BODY)) is walked by hand below.
            aadhaar_body: Re::new(r"[2-9]\d{3}[\s\-.]?\d{4}[\s\-.]?\d{4}(?!\d)", PLAIN)?,
            iban_group: re(p::IBAN_GROUP_RE)?,
            ssn: re(p::SSN_RE)?,
            ssn_worded: re(p::SSN_WORDED_RE)?,
            pan: re(p::PAN_RE)?,
            email: re(p::EMAIL_RE)?,
            email_spelled: re(p::EMAIL_SPELLED_RE)?,
            example_word: Re::new(r"(?i)\b(?:example|test)\b", PLAIN)?,
            phones: p::PHONE_PATTERNS.iter().map(|def| re(*def)).collect::<Result<_, _>>()?,
            hostname: re(p::HOSTNAME_RE)?,
            private_ip: re(p::PRIVATE_IP_RE)?,
        })
    }

    fn cards(&self, text: &str, found: &mut Vec<Candidate>) -> Result<(), DetectError> {
        for (run_start, run_end) in self.digit_run.find_all(text)? {
            let run = &text[run_start..run_end];
            let groups = self.digit_group.find_all(run)?;
            let lens: Vec<usize> = groups.iter().map(|&(a, b)| uni::len(&run[a..b])).collect();
            let mut first = 0;
            while first < groups.len() {
                let mut windows: Vec<(usize, usize)> = Vec::new(); // (digit count, last group)
                let mut digits = 0;
                for last in first..(first + p::CARD_MAX_GROUPS).min(groups.len()) {
                    digits += lens[last];
                    if digits > p::CARD_MAX_DIGITS || lens[last] < p::CARD_MIN_GROUP_DIGITS {
                        break;
                    }
                    if digits >= p::CARD_MIN_DIGITS {
                        windows.push((digits, last));
                    }
                }
                let mut matched = None;
                for &length in p::CARD_LENGTHS {
                    if let Some(&(_, last)) = windows.iter().find(|(d, _)| *d == length) {
                        let number: String = groups[first..=last].iter().map(|&(a, b)| &run[a..b]).collect();
                        if is_card(&number) {
                            matched = Some(last);
                            break;
                        }
                    }
                }
                let Some(last) = matched else {
                    first += 1;
                    continue;
                };
                let start = run_start + groups[first].0;
                let end = run_start + groups[last].1;
                found.push(Candidate::new("PII_CREDIT_CARD", start, end, &text[start..end]));
                first = last + 1;
            }
        }
        for (a, b) in self.single_digits.find_all(text)? {
            let digits = digits_only(&text[a..b]);
            let n = uni::len(&digits);
            if (p::CARD_MIN_DIGITS..=p::CARD_MAX_DIGITS).contains(&n) && is_card(&digits) {
                found.push(Candidate::new("PII_CREDIT_CARD", a, b, &text[a..b]));
            }
        }
        Ok(())
    }

    fn aadhaar(&self, text: &str, found: &mut Vec<Candidate>) -> Result<(), DetectError> {
        let mut prev: Option<char> = None;
        for (at, c) in text.char_indices() {
            let after_digit = prev.is_some_and(uni::is_nd);
            prev = Some(c);
            if after_digit || !('2'..='9').contains(&c) {
                continue;
            }
            let Some(m) = self.aadhaar_body.match_at(text, at)? else { continue };
            if ends_a_uuid(text, at) {
                continue;
            }
            let value = &text[m.start()..m.end()];
            if verhoeff_valid(&digits_only(value)) {
                found.push(Candidate::new("PII_AADHAAR", m.start(), m.end(), value));
            }
        }
        Ok(())
    }

    /// IBANs (`_ibans`). `(?i)\b(?=[A-Z]{2}\d{2})` and `_IBAN_RUN_RE` are walked by hand: see `iban_run_at`.
    fn ibans(&self, text: &str, found: &mut Vec<Candidate>) -> Result<(), DetectError> {
        let mut covered_until = 0;
        let mut prev: Option<char> = None;
        for (at, c) in text.char_indices() {
            let boundary = !prev.is_some_and(uni::is_word) && uni::is_word(c);
            prev = Some(c);
            if !boundary || at < covered_until {
                continue;
            }
            let Some(run_end) = iban_run_at(text, at) else { continue };
            let run_text = &text[at..run_end];
            let groups = self.iban_group.find_all(run_text)?;
            for &(_, group_end) in groups.iter().rev() {
                let end = at + group_end;
                let value = &text[at..end];
                if iban_valid(&value.replace(' ', "").to_uppercase()) {
                    found.push(Candidate::new("PII_IBAN", at, end, value));
                    covered_until = end;
                    break;
                }
            }
        }
        Ok(())
    }

    /// `find_pii`, in the same order as the reference (the order decides overlaps).
    pub fn find(&self, text: &str, s: &Settings) -> Result<Vec<Candidate>, DetectError> {
        let mut found = Vec::new();
        self.cards(text, &mut found)?;
        self.aadhaar(text, &mut found)?;
        self.ibans(text, &mut found)?;
        let collect = |found: &mut Vec<Candidate>, rule: &'static str, pattern: &Re, accept: &dyn Fn(&str) -> Result<bool, DetectError>| -> Result<(), DetectError> {
            for (a, b) in pattern.find_all(text)? {
                if accept(&text[a..b])? {
                    found.push(Candidate::new(rule, a, b, &text[a..b]));
                }
            }
            Ok(())
        };
        let always = |_: &str| Ok(true);
        collect(&mut found, "PII_SSN", &self.ssn, &always)?;
        let v = self.ssn_worded.group("v");
        for c in self.ssn_worded.captures_all(text)? {
            let (a, b) = c.get(v).expect("v always takes part");
            found.push(Candidate::new("PII_SSN", a, b, &text[a..b]));
        }
        collect(&mut found, "PII_PAN", &self.pan, &|v: &str| {
            let fourth = v.chars().nth(3).map(|c| c.to_uppercase().collect::<String>()).unwrap_or_default();
            Ok(fourth.chars().count() == 1 && p::PAN_FOURTH_LETTERS.contains(fourth.as_str()))
        })?;
        if text.contains('@') {
            let skip: Vec<String> = s.email_skip_domains.iter().map(|d| d.to_lowercase()).collect();
            collect(&mut found, "PII_EMAIL", &self.email, &|v: &str| {
                let domain = v.rsplit_once('@').map(|(_, d)| d).unwrap_or("").to_lowercase();
                Ok(!skip.contains(&domain))
            })?;
        }
        if text.contains('[') || text.contains('(') || text.contains('{') {
            collect(&mut found, "PII_EMAIL", &self.email_spelled, &|v: &str| Ok(!self.example_word.is_match(v)?))?;
        }
        for pattern in &self.phones {
            collect(&mut found, "PII_PHONE", pattern, &always)?;
        }
        let lowered = text.to_lowercase();
        if p::HOST_SUFFIXES.iter().any(|suffix| lowered.contains(suffix)) {
            collect(&mut found, "PII_INTERNAL_HOST", &self.hostname, &always)?;
        }
        collect(&mut found, "PII_INTERNAL_HOST", &self.private_ip, &|v: &str| {
            Ok(v.split('.').all(|part| uni::py_int(part).is_some_and(|n| n <= 255)))
        })?;
        Ok(found)
    }
}

impl From<RegexError> for DetectError {
    fn from(e: RegexError) -> Self {
        DetectError::Regex(e.0)
    }
}

/// `(?i)[A-Z]` in Python: ASCII letters, plus the four characters that ignore-case folds onto them.
fn iban_letter(c: char) -> bool {
    c.is_ascii_alphabetic() || matches!(c, '\u{130}' | '\u{131}' | '\u{17f}' | '\u{212a}')
}

/// The end of `_IBAN_RUN_RE.match(text, start)`: `(?i)[A-Z]{2}\d{2}(?: ?[A-Z0-9]{1,4}){3,9}\b`.
///
/// The regex form backtracks through every way of cutting a long run of letters and digits into groups
/// whenever the final `\b` fails, which took seconds on text full of API keys. This explores the same
/// choices in the same order (one more group first, a space first, the longest piece first) and so finds
/// the same match, but remembers which (position, group count) pairs already failed.
fn iban_run_at(text: &str, start: usize) -> Option<usize> {
    let chars: Vec<(usize, char)> = text[start..].char_indices().map(|(i, c)| (start + i, c)).take(4 + 9 * 5 + 1).collect();
    if chars.len() < 4 || !iban_letter(chars[0].1) || !iban_letter(chars[1].1) || !uni::is_nd(chars[2].1) || !uni::is_nd(chars[3].1) {
        return None;
    }
    let byte_at = |i: usize| chars.get(i).map_or(text.len(), |&(b, _)| b);
    let ch = |i: usize| chars.get(i).map(|&(_, c)| c);
    let piece = |c: char| iban_letter(c) || c.is_ascii_digit();
    let mut failed = std::collections::HashSet::new();
    fn walk(i: usize, count: usize, ch: &dyn Fn(usize) -> Option<char>, piece: &dyn Fn(char) -> bool,
            failed: &mut std::collections::HashSet<(usize, usize)>) -> Option<usize> {
        if failed.contains(&(i, count)) {
            return None;
        }
        if count < 9 {
            let spaces: &[usize] = if ch(i) == Some(' ') { &[1, 0] } else { &[0] };
            for &space in spaces {
                let q = i + space;
                let available = (0..4).take_while(|&k| ch(q + k).is_some_and(piece)).count();
                for n in (1..=available).rev() {
                    if let Some(end) = walk(q + n, count + 1, ch, piece, failed) {
                        return Some(end);
                    }
                }
            }
        }
        // \b after the last piece (a word character): the next character must not be one.
        if count >= 3 && !ch(i).is_some_and(uni::is_word) {
            return Some(i);
        }
        failed.insert((i, count));
        None
    }
    walk(4, 0, &ch, &piece, &mut failed).map(byte_at)
}

/// `re.sub(r"\D", "", value)`: the Nd digits only.
fn digits_only(value: &str) -> String {
    value.chars().filter(|&c| uni::is_nd(c)).collect()
}

fn is_card(digits: &str) -> bool {
    digits.chars().next().is_some_and(|c| p::CARD_FIRST_DIGITS.contains(c)) && luhn_valid(digits)
}

/// True when the characters ending at byte `start` are a UUID's first four groups and their dashes.
fn ends_a_uuid(text: &str, start: usize) -> bool {
    let from = uni::back_chars(text, start, 24);
    let window: Vec<char> = text[from..start].chars().collect();
    if window.len() != 24 {
        return false;
    }
    let shape = [8usize, 4, 4, 4];
    let mut i = 0;
    for n in shape {
        if !window[i..i + n].iter().all(|c| c.is_ascii_hexdigit()) || window[i + n] != '-' {
            return false;
        }
        i += n + 1;
    }
    true
}

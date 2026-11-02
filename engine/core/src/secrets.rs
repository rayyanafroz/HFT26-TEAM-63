//! Secret detectors: named patterns, assignments and entropy (`secrets.py`).

use crate::patterns as p;
use crate::pydecode::{a2b_base64, json_object_has_key, JsonError};
use crate::pyre::{Re, RegexError, PLAIN};
use crate::uni;
use crate::{Candidate, DetectError, Settings};

pub struct Secrets {
    named: Vec<(&'static str, Re)>,
    vendor: Vec<Re>,
    aws_secret: Re,
    jwt: Re,
    prefilter: Re,
    generic: Re,
    plain: Re,
    quoted: Re,
    pair: Re,
    bearer: Re,
    cli: Re,
    url: Re,
    camel: Re,
    reference: Re,
    uuid: Re,
    hex: Re,
    model_before: Re,
    integrity: Re,
    word_part: Re,
    separators: Re,
    entropy_token: Re,
}

fn re(def: (&str, crate::pyre::Flags)) -> Result<Re, RegexError> {
    Re::new(def.0, def.1)
}

impl Secrets {
    pub fn new(settings: &Settings) -> Result<Self, RegexError> {
        let token = p::ENTROPY_TOKEN.replace("{{{min},}}", &format!("{{{},}}", settings.entropy_min_len));
        Ok(Secrets {
            named: p::NAMED_PATTERNS.iter().map(|(rule, def)| Ok((*rule, re(*def)?))).collect::<Result<_, RegexError>>()?,
            vendor: p::VENDOR_PATTERNS.iter().map(|def| re(*def)).collect::<Result<_, _>>()?,
            aws_secret: re(p::AWS_SECRET_RE)?,
            jwt: re(p::JWT_RE)?,
            prefilter: re(p::NAMED_PREFILTER_RE)?,
            generic: re(p::GENERIC_RE)?,
            plain: re(p::GENERIC_PLAIN_RE)?,
            quoted: re(p::GENERIC_QUOTED_RE)?,
            pair: re(p::PAIR_RE)?,
            bearer: re(p::BEARER_RE)?,
            cli: re(p::CLI_PASSWORD_RE)?,
            url: re(p::URL_CREDENTIALS_RE)?,
            camel: re(p::GENERIC_CAMEL_RE)?,
            reference: re(p::REFERENCE_RE)?,
            uuid: re(p::UUID_RE)?,
            hex: re(p::HEX_RE)?,
            model_before: re(p::MODEL_FIELD_BEFORE_RE)?,
            integrity: re(p::INTEGRITY_HASH_RE)?,
            word_part: re(p::WORD_PART_RE)?,
            separators: re(p::SEPARATORS_RE)?,
            entropy_token: Re::new(&token, PLAIN)?,
        })
    }

    /// The named patterns, in catalog order, for the split-secret pass.
    pub fn named(&self) -> &[(&'static str, Re)] {
        &self.named
    }

    /// Patterns with a recognizable shape (`find_named_secrets`).
    pub fn find_named(&self, text: &str) -> Result<Vec<Candidate>, DetectError> {
        let mut found = Vec::new();
        if !self.prefilter.is_match(text)? {
            return Ok(found);
        }
        for (rule, pattern) in &self.named {
            for (a, b) in pattern.find_all(text)? {
                found.push(Candidate::new(rule, a, b, &text[a..b]));
            }
        }
        for c in self.aws_secret.captures_all(text)? {
            let (a, b) = c.get(1).expect("group 1 always takes part");
            found.push(Candidate::new("SEC_AWS_SECRET_KEY", a, b, &text[a..b]));
        }
        for (a, b) in self.jwt.find_all(text)? {
            if jwt_header_has_alg(&text[a..b])? {
                found.push(Candidate::new("SEC_JWT", a, b, &text[a..b]));
            }
        }
        for pattern in &self.vendor {
            for (a, b) in pattern.find_all(text)? {
                found.push(Candidate::new("SEC_GENERIC_ASSIGNMENT", a, b, &text[a..b]));
            }
        }
        Ok(found)
    }

    fn is_real_value(&self, value: &str, is_password: bool, s: &Settings) -> Result<bool, DetectError> {
        let min = if is_password { s.generic_password_min_len } else { s.generic_min_len };
        if uni::len(value) < min {
            return Ok(false);
        }
        let lowered = value.to_lowercase();
        if s.generic_placeholder_words.iter().any(|w| lowered.contains(w.as_str())) {
            return Ok(false);
        }
        if p::NOT_A_VALUE_PREFIXES.iter().any(|prefix| value.starts_with(prefix)) || value.contains("://") || uni::str_is_digit(value) {
            return Ok(false);
        }
        if self.reference.match_at(value, 0)?.is_some() {
            return Ok(false);
        }
        if shannon_entropy(value) < s.generic_min_entropy {
            return Ok(false);
        }
        Ok(!reads_as_a_name(value))
    }

    /// Assignments, bearer tokens, CLI and URL passwords (`find_generic_assignments`).
    pub fn find_generic(&self, text: &str, s: &Settings) -> Result<Vec<Candidate>, DetectError> {
        let mut found = Vec::new();
        let add = |found: &mut Vec<Candidate>, span: Option<(usize, usize)>, is_password: bool, extra: &dyn Fn(&str) -> bool| -> Result<(), DetectError> {
            if let Some((a, b)) = span {
                let value = &text[a..b];
                if !value.is_empty() && self.is_real_value(value, is_password, s)? && extra(value) {
                    found.push(Candidate::new("SEC_GENERIC_ASSIGNMENT", a, b, value));
                }
            }
            Ok(())
        };
        let any = |_: &str| true;
        for pattern in [&self.generic, &self.camel] {
            let (pw, v) = (pattern.group("pw"), pattern.group("v"));
            for c in pattern.captures_all(text)? {
                add(&mut found, c.get(v), c.get(pw).is_some(), &any)?;
            }
        }
        let v = self.plain.group("v");
        for c in self.plain.captures_all(text)? {
            add(&mut found, c.get(v), true, &looks_chosen)?;
        }
        let (pw, v) = (self.quoted.group("pw"), self.quoted.group("v"));
        for c in self.quoted.captures_all(text)? {
            add(&mut found, c.get(v), c.get(pw).is_some(), &|value: &str| value.contains(' ') && looks_chosen(value))?;
        }
        let v = self.bearer.group("v");
        for c in self.bearer.captures_all(text)? {
            add(&mut found, c.get(v), false, &any)?;
        }
        let v = self.pair.group("v");
        for c in self.pair.captures_all(text)? {
            add(&mut found, c.get(v), true, &looks_chosen)?;
        }
        let (v, v2) = (self.cli.group("v"), self.cli.group("v2"));
        for c in self.cli.captures_all(text)? {
            // match.group("v") is truthy only when it took part and is not empty.
            let span = if c.get(v).is_some_and(|(a, b)| b > a) { c.get(v) } else { c.get(v2) };
            add(&mut found, span, true, &any)?;
        }
        let v = self.url.group("v");
        for c in self.url.captures_all(text)? {
            add(&mut found, c.get(v), true, &any)?;
        }
        Ok(found)
    }

    fn is_made_of_words(&self, token: &str) -> Result<bool, DetectError> {
        let parts = split(&self.separators, token)?;
        let parts: Vec<&str> = parts.into_iter().filter(|part| !part.is_empty()).collect();
        if parts.len() < 3 {
            return Ok(false);
        }
        let mut words = 0;
        for part in &parts {
            if self.word_part.match_at(part, 0)?.is_some() {
                words += 1;
            }
        }
        Ok(words * 2 >= parts.len())
    }

    fn entropy_score(&self, token: &str, before: &str, s: &Settings) -> Result<Option<f64>, DetectError> {
        if self.uuid.match_at(token, 0)?.is_some() {
            return Ok(None);
        }
        if !token.chars().any(uni::is_digit) {
            return Ok(None);
        }
        if self.model_before.is_match(before)? {
            return Ok(None);
        }
        if before.ends_with("base64,") || before.ends_with("://") || self.integrity.match_at(token, 0)?.is_some() {
            return Ok(None);
        }
        if self.is_made_of_words(token)? || is_a_sequence(token) {
            return Ok(None);
        }
        if decodes_to_json_object(token) {
            return Ok(None);
        }
        let entropy = shannon_entropy(token);
        let length = uni::len(token);
        if self.hex.match_at(token, 0)?.is_some() {
            if length < 32 || s.entropy_digest_lengths.contains(&length) {
                return Ok(None);
            }
            return Ok((entropy >= s.entropy_hex).then_some(entropy));
        }
        let needed = s.entropy_alnum.min(s.entropy_length_ratio * (length as f64).log2());
        Ok((entropy >= needed).then_some(entropy))
    }

    /// Every entropy hit with its score; the cap is applied later (`find_high_entropy`).
    pub fn find_entropy(&self, text: &str, s: &Settings) -> Result<Vec<(f64, Candidate)>, DetectError> {
        let mut found = Vec::new();
        for (a, b) in self.entropy_token.find_all(text)? {
            let token = &text[a..b];
            let before = &text[uni::back_chars(text, a, 20)..a];
            if let Some(score) = self.entropy_score(token, before, s)? {
                found.push((score, Candidate::new("SEC_HIGH_ENTROPY", a, b, token)));
            }
        }
        Ok(found)
    }
}

/// `re.split(pattern, text)` for a pattern without groups.
fn split<'t>(pattern: &Re, text: &'t str) -> Result<Vec<&'t str>, RegexError> {
    let mut parts = Vec::new();
    let mut last = 0;
    for (a, b) in pattern.find_all(text)? {
        parts.push(&text[last..a]);
        last = b;
    }
    parts.push(&text[last..]);
    Ok(parts)
}

/// Shannon entropy in bits per character, summed in the order `collections.Counter` keeps.
pub fn shannon_entropy(value: &str) -> f64 {
    if value.is_empty() {
        return 0.0;
    }
    let mut counts: Vec<(char, usize)> = Vec::new();
    let mut total = 0usize;
    for c in value.chars() {
        total += 1;
        match counts.iter_mut().find(|(k, _)| *k == c) {
            Some((_, n)) => *n += 1,
            None => counts.push((c, 1)),
        }
    }
    let total = total as f64;
    let mut sum = 0.0;
    for (_, n) in counts {
        let share = n as f64 / total;
        sum += share * share.log2();
    }
    -sum
}

/// password = getPassword, token: Optional: letters only, and the capitals follow word starts.
fn reads_as_a_name(value: &str) -> bool {
    let letters: String = value.chars().filter(|&c| c != '_' && c != '-').collect();
    if !uni::str_is_alpha(&letters) {
        return false;
    }
    let capitals = letters.chars().filter(|&c| uni::is_upper(c)).count();
    let n = uni::len(&letters);
    capitals == n || capitals * 4 <= n
}

/// A password nobody labelled needs a letter and a digit or symbol, so prose does not count.
pub fn looks_chosen(value: &str) -> bool {
    value.chars().any(uni::is_alpha) && value.chars().any(|c| !uni::is_alpha(c))
}

fn is_a_sequence(token: &str) -> bool {
    let chars: Vec<char> = token.chars().collect();
    let steps = chars.windows(2).filter(|w| (w[1] as i64) - (w[0] as i64) == 1).count();
    steps * 2 > chars.len()
}

/// `base64.b64decode` (lenient) of the token as URL-safe text, and whether it starts with "{".
fn decodes_to_json_object(token: &str) -> bool {
    let mut s: String = token.chars().map(|c| match c {
        '-' => '+',
        '_' => '/',
        c => c,
    }).collect();
    let pad = (4 - uni::len(token) % 4) % 4;
    s.extend(std::iter::repeat_n('=', pad));
    match a2b_base64(s.as_bytes(), false) {
        Ok(raw) => raw.iter().find(|b| !matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)) == Some(&b'{'),
        Err(()) => false,
    }
}

/// The JWT header (before the first ".") decodes to a JSON object with "alg".
fn jwt_header_has_alg(token: &str) -> Result<bool, DetectError> {
    let header = token.split('.').next().unwrap_or("");
    let mut s: String = header.chars().map(|c| match c {
        '-' => '+',
        '_' => '/',
        c => c,
    }).collect();
    let pad = (4 - uni::len(header) % 4) % 4;
    s.extend(std::iter::repeat_n('=', pad));
    let Ok(raw) = a2b_base64(s.as_bytes(), false) else { return Ok(false) };
    match json_object_has_key(&raw, "alg") {
        Ok(found) => Ok(found),
        Err(JsonError::Invalid) => Ok(false),
        Err(JsonError::TooDeep) => Err(DetectError::Recursion),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_matches_python() {
        // python: secrets.shannon_entropy("aab") == 0.9182958340544896
        assert_eq!(shannon_entropy("aab"), 0.9182958340544896);
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn names_and_chosen_values() {
        assert!(reads_as_a_name("getPassword"));
        assert!(!reads_as_a_name("Xk39aQ2zLm7pR"));
        assert!(looks_chosen("abc1") && !looks_chosen("abc"));
        assert!(is_a_sequence("abcdefghijklmnop"));
    }
}

//! The Shadow Lens text detection engine.
//!
//! `Engine::analyze(text)` finds secrets, personal data and source code in text and returns the text with
//! them replaced by placeholders. It is a port of the Python reference (`src/shadowlens/analysis`), held
//! to it by the conformance suite in `conformance/`: same findings, same spans, same masks, same hashes.
//!
//! Spans are Unicode code point indices into the original text. No raw value is ever returned: a finding
//! carries a mask (at most 4 characters of the value) and a keyed hash.

pub mod checksums;
pub mod code;
pub mod encoded;
pub mod fold;
pub mod masking;
pub mod patterns;
pub mod pii;
pub mod pydecode;
pub mod pyre;
pub mod secrets;
pub mod tables;
pub mod uni;

use serde::{Deserialize, Serialize};

use crate::pyre::{Re, RegexError};

/// Tunable thresholds; the defaults match `config/rules.yaml`.
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct Settings {
    #[serde(skip)]
    pub salt: Vec<u8>,
    pub salt_hex: Option<String>,
    pub internal_markers: Vec<String>,
    pub entropy_alnum: f64,
    pub entropy_hex: f64,
    pub entropy_min_len: usize,
    pub entropy_length_ratio: f64,
    pub max_entropy_findings_per_event: usize,
    pub entropy_digest_lengths: Vec<usize>,
    pub generic_min_entropy: f64,
    pub generic_min_len: usize,
    pub generic_password_min_len: usize,
    pub generic_placeholder_words: Vec<String>,
    pub email_skip_domains: Vec<String>,
    pub marker_window: usize,
    pub code_min_lines: usize,
    pub code_min_distinct_tokens: usize,
    pub code_min_shaped_lines: usize,
}

impl Default for Settings {
    fn default() -> Self {
        let words = |list: &[&str]| list.iter().map(|s| s.to_string()).collect();
        Settings {
            salt: vec![b's'; 32],
            salt_hex: None,
            internal_markers: Vec::new(),
            entropy_alnum: 4.2,
            entropy_hex: 3.3,
            entropy_min_len: 24,
            entropy_length_ratio: 0.88,
            max_entropy_findings_per_event: 3,
            entropy_digest_lengths: vec![32, 40, 64],
            generic_min_entropy: 3.0,
            generic_min_len: 12,
            generic_password_min_len: 8,
            generic_placeholder_words: words(&["your_", "xxx", "changeme", "example", "<", "${", "{{"]),
            email_skip_domains: words(&["example.com", "example.org", "test.com", "localhost"]),
            marker_window: 200,
            code_min_lines: 20,
            code_min_distinct_tokens: 3,
            code_min_shaped_lines: 3,
        }
    }
}

impl Settings {
    /// Settings from JSON (the shape of `conformance/build/settings.json`); missing fields keep defaults.
    pub fn from_json(json: &str) -> Result<Settings, String> {
        let mut settings: Settings = serde_json::from_str(json).map_err(|e| e.to_string())?;
        if let Some(hex) = settings.salt_hex.take() {
            settings.salt = (0..hex.len())
                .step_by(2)
                .map(|i| hex.get(i..i + 2).and_then(|pair| u8::from_str_radix(pair, 16).ok()))
                .collect::<Option<Vec<u8>>>()
                .ok_or("salt_hex is not hex")?;
        }
        Ok(settings)
    }
}

/// One raw detector match, before overlaps are resolved. Positions are byte offsets in the text searched.
#[derive(Clone, Debug)]
pub struct Candidate {
    pub rule: &'static str,
    pub start: usize,
    pub end: usize,
    pub value: String,
}

impl Candidate {
    pub fn new(rule: &'static str, start: usize, end: usize, value: &str) -> Self {
        Candidate { rule, start, end, value: value.to_string() }
    }
}

/// Why a detector could not finish. Anything that decides whether text is safe treats it as unsafe.
#[derive(Debug)]
pub enum DetectError {
    Regex(String),
    Recursion,
}

/// A finding: no raw value, only a mask and a keyed hash.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct Finding {
    pub rule_id: &'static str,
    pub masked_preview: String,
    pub hash12: String,
    pub spans: Vec<(usize, usize)>,
    pub count: Option<u32>,
    pub truncated: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct Analysis {
    pub findings: Vec<Finding>,
    pub redacted_text: String,
    pub safe_to_send: bool,
    pub failed: Vec<String>,
}

/// The rule catalog entry for `rule_id`: (severity, confidence, overlap priority).
pub fn rule(rule_id: &str) -> Option<(&'static str, f64, u32)> {
    patterns::RULES.iter().find(|r| r.0 == rule_id).map(|r| (r.1, r.2, r.3))
}

fn priority(rule_id: &str) -> u32 {
    rule(rule_id).map(|r| r.2).unwrap_or(9)
}

/// Compiled detectors for one set of settings. Build once, analyze many times.
pub struct Engine {
    settings: Settings,
    secrets: secrets::Secrets,
    pii: pii::Pii,
    encoded: encoded::Encoded,
    code: code::Code,
    placeholder: Re,
}

fn guarded<T>(name: &str, failed: &mut Vec<String>, run: impl FnOnce() -> Result<Vec<T>, DetectError>) -> Vec<T> {
    match run() {
        Ok(found) => found,
        Err(_) => {
            failed.push(name.to_string());
            Vec::new()
        }
    }
}

/// A candidate tagged with where it came from: its index in the candidate list and its entropy score.
#[derive(Clone)]
struct Tagged {
    index: usize,
    score: Option<f64>,
    c: Candidate,
}

impl Engine {
    pub fn new(settings: Settings) -> Result<Engine, RegexError> {
        Ok(Engine {
            secrets: secrets::Secrets::new(&settings)?,
            pii: pii::Pii::new()?,
            encoded: encoded::Encoded::new()?,
            code: code::Code::new()?,
            placeholder: Re::new(patterns::PLACEHOLDER_RE.0, patterns::PLACEHOLDER_RE.1)?,
            settings,
        })
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// Text that is already a placeholder is not a new hit (`drop_already_redacted`).
    fn drop_already_redacted(&self, text: &str, candidates: Vec<Tagged>) -> Result<Vec<Tagged>, DetectError> {
        let spans = self.placeholder.find_all(text)?;
        if spans.is_empty() {
            return Ok(candidates);
        }
        Ok(candidates
            .into_iter()
            .filter(|t| {
                let at = spans.partition_point(|&(start, _)| start < t.c.end);
                !(at > 0 && spans[at - 1].1 > t.c.start)
            })
            .collect())
    }

    /// Everything in `text`, and the text with it hidden (`analyze_text`).
    pub fn analyze(&self, text: &str) -> Analysis {
        let s = &self.settings;
        if text.is_empty() {
            return Analysis { findings: Vec::new(), redacted_text: String::new(), safe_to_send: true, failed: Vec::new() };
        }
        let mut failed: Vec<String> = Vec::new();
        let view = fold::fold(text);
        let v = view.text.as_str();

        // Order matters inside a priority: an earlier detector wins a tie.
        let mut spans: Vec<Candidate> = Vec::new();
        spans.extend(guarded("named_secrets", &mut failed, || self.secrets.find_named(v)));
        spans.extend(guarded("pii", &mut failed, || self.pii.find(v, s)));
        spans.extend(guarded("generic_assignments", &mut failed, || self.secrets.find_generic(v, s)));
        spans.extend(guarded("split_secrets", &mut failed, || self.encoded.find_split(v, &self.secrets)));
        spans.extend(guarded("encoded_secrets", &mut failed, || self.encoded.find_encoded(v, s, &self.secrets, &self.pii)));
        let entropy = guarded("high_entropy", &mut failed, || self.secrets.find_entropy(v, s));

        let mut tagged: Vec<Tagged> = spans.into_iter().map(|c| Tagged { index: 0, score: None, c }).collect();
        tagged.extend(entropy.into_iter().map(|(score, c)| Tagged { index: 0, score: Some(score), c }));
        for (i, t) in tagged.iter_mut().enumerate() {
            t.index = i;
        }
        let tagged = match self.drop_already_redacted(v, tagged) {
            Ok(kept) => kept,
            Err(_) => {
                failed.push("redaction".into());
                Vec::new()
            }
        };
        let resolved = resolve_overlaps(tagged);

        // The entropy cap applies only to what survived the stronger detectors.
        let mut surviving: Vec<&Tagged> = resolved.iter().filter(|t| t.score.is_some()).collect();
        surviving.sort_by(|a, b| b.score.unwrap().partial_cmp(&a.score.unwrap()).unwrap_or(std::cmp::Ordering::Equal));
        let allowed: Vec<usize> = surviving.iter().take(s.max_entropy_findings_per_event).map(|t| t.index).collect();
        let truncated = surviving.len() > allowed.len();
        // Redaction still covers tokens over the cap: the cap limits findings, not what gets hidden.
        let kept: Vec<Candidate> = resolved.iter().filter(|t| t.score.is_none() || allowed.contains(&t.index)).map(|t| t.c.clone()).collect();
        let capped: Vec<Candidate> = resolved.iter().filter(|t| t.score.is_some() && !allowed.contains(&t.index)).map(|t| t.c.clone()).collect();

        // Code findings sit on top: they may contain other findings and never suppress them.
        let code = guarded("code", &mut failed, || {
            let found: Vec<Tagged> = self.code.find(v, s)?.into_iter().map(|c| Tagged { index: 0, score: None, c }).collect();
            Ok(self.drop_already_redacted(v, found)?.into_iter().map(|t| t.c).collect::<Vec<_>>())
        });

        let index = uni::CharIndex::new(v);
        let to_original = |list: Vec<Candidate>| -> Vec<Candidate> {
            list.into_iter()
                .map(|mut c| {
                    let (a, b) = view.to_original(index.char_at(c.start), index.char_at(c.end));
                    c.start = a;
                    c.end = b;
                    c
                })
                .collect()
        };
        let (kept, code, capped) = (to_original(kept), to_original(code), to_original(capped));
        let mut ordered = kept;
        ordered.extend(code);
        ordered.sort_by_key(|c| (c.start, c.end));
        let mut findings = build_findings(&ordered, &s.salt);
        if truncated {
            for f in findings.iter_mut().filter(|f| f.rule_id == "SEC_HIGH_ENTROPY") {
                f.truncated = true;
            }
        }
        let over_cap = build_findings(&capped, &s.salt);
        let mut all = findings.clone();
        all.extend(over_cap);
        let redacted_text = redact(text, &all);
        let safe_to_send = findings.is_empty() && failed.is_empty();
        Analysis { findings, redacted_text, safe_to_send, failed }
    }
}

/// Keep the higher-priority match wherever spans overlap, so one secret gives one finding.
fn resolve_overlaps(candidates: Vec<Tagged>) -> Vec<Tagged> {
    let mut indexed: Vec<(usize, Tagged)> = candidates.into_iter().enumerate().collect();
    indexed.sort_by_key(|(i, t)| (priority(t.c.rule), *i, t.c.start as i64 - t.c.end as i64));
    let mut kept: Vec<Tagged> = Vec::new();
    for (_, t) in indexed {
        let at = kept.partition_point(|k| k.c.start < t.c.start);
        if at > 0 && kept[at - 1].c.end > t.c.start {
            continue;
        }
        if at < kept.len() && kept[at].c.start < t.c.end {
            continue;
        }
        if at < kept.len() && kept[at].c.start == t.c.start {
            continue; // an empty span at the same place
        }
        kept.insert(at, t);
    }
    kept.sort_by_key(|t| (t.c.start, t.c.end));
    kept
}

/// One finding per distinct value; email and phone collapse into one per text.
fn build_findings(candidates: &[Candidate], salt: &[u8]) -> Vec<Finding> {
    let mut findings: Vec<Finding> = Vec::new();
    let mut by_key: Vec<(&'static str, String, usize)> = Vec::new();
    let mut grouped: Vec<(&'static str, usize)> = Vec::new();
    for c in candidates {
        let digest = masking::hash12(&c.value, salt);
        let span = (c.start, c.end);
        let existing = grouped
            .iter()
            .find(|(r, _)| *r == c.rule)
            .map(|(_, i)| *i)
            .or_else(|| by_key.iter().find(|(r, d, _)| *r == c.rule && *d == digest).map(|(_, _, i)| *i));
        if let Some(i) = existing {
            findings[i].spans.push(span);
            if let Some(n) = findings[i].count.as_mut() {
                *n += 1;
            }
            continue;
        }
        let is_grouped = patterns::GROUPED_RULES.contains(&c.rule);
        findings.push(Finding {
            rule_id: c.rule,
            masked_preview: masking::mask_for(c.rule, &c.value),
            hash12: digest.clone(),
            spans: vec![span],
            count: is_grouped.then_some(1),
            truncated: false,
        });
        by_key.push((c.rule, digest, findings.len() - 1));
        if is_grouped {
            grouped.push((c.rule, findings.len() - 1));
        }
    }
    findings
}

/// Replace every span with its placeholder. A span inside a larger one disappears with it, and a span
/// that only partly overlaps the previous one is removed in full, so its tail never stays visible.
fn redact(text: &str, findings: &[Finding]) -> String {
    let index = uni::CharIndex::new(text);
    let mut items: Vec<(usize, usize, &Finding)> = findings.iter().flat_map(|f| f.spans.iter().map(move |&(a, b)| (a, b, f))).collect();
    items.sort_by_key(|&(a, b, _)| (a, a as i64 - b as i64));
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    for (start, end, f) in items {
        if start < cursor {
            cursor = cursor.max(end);
            continue;
        }
        out.push_str(&text[index.byte_at(cursor)..index.byte_at(start)]);
        out.push_str(&masking::placeholder_for(f.rule_id, &f.hash12));
        cursor = end;
    }
    out.push_str(&text[index.byte_at(cursor.min(index.char_len()))..]);
    out
}

/// `is_safe_to_send`: no findings and every detector ran.
pub fn is_safe_to_send(engine: &Engine, text: &str) -> bool {
    engine.analyze(text).safe_to_send
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patterns as p;
    use crate::pyre::Flags;

    /// Patterns compile lazily, so a broken one would only show on some texts. Compile them all here.
    #[test]
    fn every_pattern_compiles() {
        let mut all: Vec<(&str, Flags)> = Vec::new();
        all.extend(p::NAMED_PATTERNS.iter().map(|(_, def)| *def));
        all.extend(p::VENDOR_PATTERNS.iter().copied());
        all.extend(p::PHONE_PATTERNS.iter().copied());
        all.extend([
            p::AWS_SECRET_RE, p::JWT_RE, p::NAMED_PREFILTER_RE, p::GENERIC_RE, p::GENERIC_PLAIN_RE, p::GENERIC_QUOTED_RE,
            p::PAIR_RE, p::BEARER_RE, p::CLI_PASSWORD_RE, p::URL_CREDENTIALS_RE, p::GENERIC_CAMEL_RE, p::REFERENCE_RE,
            p::UUID_RE, p::HEX_RE, p::MODEL_FIELD_BEFORE_RE, p::INTEGRITY_HASH_RE, p::WORD_PART_RE, p::SEPARATORS_RE,
            p::DIGIT_RUN_RE, p::SINGLE_DIGITS_RE, p::DIGIT_GROUP_RE, p::IBAN_GROUP_RE, p::SSN_RE, p::SSN_WORDED_RE,
            p::PAN_RE, p::EMAIL_RE, p::EMAIL_SPELLED_RE, p::HOSTNAME_RE, p::PRIVATE_IP_RE, p::KEY_START, p::NEXT_PIECE,
            p::MARKER_RE, p::COPYRIGHT_RE, p::FENCE_RE, p::CODE_TOKEN_RE, p::CODE_LINE_RE, p::PLACEHOLDER_RE,
        ]);
        for (pattern, flags) in all {
            Re::new(pattern, flags).and_then(|re| re.compile()).unwrap_or_else(|e| panic!("{pattern}: {}", e.0));
        }
    }

    #[test]
    fn analyze_finds_and_hides_a_key() {
        let engine = Engine::new(Settings::default()).unwrap();
        let key = format!("sk-{}{}", "proj-", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v");
        let result = engine.analyze(&format!("my key {key} ok"));
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].rule_id, "SEC_OPENAI_KEY");
        assert_eq!(result.findings[0].spans, vec![(7, 7 + key.len())]);
        assert!(!result.redacted_text.contains(&key) && !result.safe_to_send);
    }

    #[test]
    fn empty_and_clean_text_are_safe() {
        let engine = Engine::new(Settings::default()).unwrap();
        assert!(engine.analyze("").safe_to_send);
        assert!(engine.analyze("nothing to see here").safe_to_send);
    }
}

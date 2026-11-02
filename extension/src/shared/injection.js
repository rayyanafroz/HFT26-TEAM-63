// Hidden characters and instructions in pasted text: the way prompt-injection attacks travel.
//
// Text copied from a web page, a PDF or an email can carry characters nobody sees (Unicode "tag"
// characters that spell out a hidden message, direction overrides, runs of zero-width characters) and
// sentences written for the AI rather than for the person ("ignore previous instructions").

const TAG = /[\u{E0000}-\u{E007F}]/u;
const TAG_RUN = /[\u{E0000}-\u{E007F}]+/gu;
const BIDI = /[\u202A-\u202E\u2066-\u2069]/g;
const ZERO_WIDTH_RUN = /[\u200B\u200C\u200D\u2060\uFEFF\u00AD]{2,}/g;
const STRIP = /[\u{E0000}-\u{E007F}\u202A-\u202E\u2066-\u2069\u200B\u200C\u2060\uFEFF\u00AD]/gu;
const PICTOGRAPHIC = /\p{Extended_Pictographic}/u;

const PHRASES = [
  /\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+|the\s+|your\s+)?(?:previous|prior|above|earlier|preceding|original)\s+(?:instructions?|prompts?|messages?|rules|directions)\b/gi,
  /\byou\s+are\s+now\s+(?:in\s+)?(?:developer|dan|jailbreak|unrestricted|admin)\b/gi,
  /\b(?:reveal|print|show|repeat|leak)\s+(?:your|the)\s+(?:system\s+prompt|hidden\s+instructions|instructions\s+above)\b/gi,
  /\bdo\s+not\s+(?:tell|inform|alert)\s+the\s+user\b/gi,
  /\b(?:send|post|upload|exfiltrate)\s+(?:the|all|any)\s+(?:files?|data|credentials|secrets|keys|conversation)\s+to\s+(?:https?:\/\/|\S+@)/gi,
];

/** A tag-character run spells ASCII: U+E0041 is "A". */
export function decodeTags(run) {
  return [...run].map((c) => String.fromCodePoint(c.codePointAt(0) - 0xe0000)).join("").replace(/[^\x20-\x7e]/g, "");
}

/**
 * Findings for hidden text, in the same shape as engine findings (`rule_id`, `ranges` in UTF-16).
 * HIDDEN_TEXT: invisible characters; INJECTION_PHRASE: an instruction aimed at the AI.
 */
export function inspect(text) {
  const findings = [];
  const hidden = [];
  for (const m of text.matchAll(TAG_RUN)) hidden.push({ range: [m.index, m.index + m[0].length], what: `hidden message "${decodeTags(m[0]).slice(0, 80)}"` });
  for (const m of text.matchAll(BIDI)) hidden.push({ range: [m.index, m.index + m[0].length], what: "text-direction override" });
  for (const m of text.matchAll(ZERO_WIDTH_RUN)) {
    // Emoji sequences use joiners between pictographs; those are normal.
    const before = text.slice(Math.max(0, m.index - 2), m.index);
    const after = text.slice(m.index + m[0].length, m.index + m[0].length + 2);
    if (/^\u200D+$/.test(m[0]) && PICTOGRAPHIC.test(before) && PICTOGRAPHIC.test(after)) continue;
    hidden.push({ range: [m.index, m.index + m[0].length], what: `${m[0].length} invisible characters in a row` });
  }
  if (hidden.length) {
    findings.push({
      rule_id: "HIDDEN_TEXT", severity: "high", hash12: "000000000000",
      masked_preview: hidden.map((h) => h.what).slice(0, 3).join("; "),
      ranges: hidden.map((h) => h.range), count: hidden.length,
    });
  }
  const phrases = [];
  for (const re of PHRASES) for (const m of text.matchAll(re)) phrases.push({ range: [m.index, m.index + m[0].length], text: m[0] });
  if (phrases.length) {
    findings.push({
      rule_id: "INJECTION_PHRASE", severity: "medium", hash12: "000000000001",
      masked_preview: `“${phrases[0].text.slice(0, 60)}”`, ranges: phrases.map((p) => p.range), count: phrases.length,
    });
  }
  return findings;
}

/** The text without invisible control characters (emoji joiners between pictographs are kept). */
export function clean(text) {
  let out = text.replace(STRIP, "");
  out = out.replace(/\u200D+/g, (run, at, s) => (PICTOGRAPHIC.test(s.slice(Math.max(0, at - 2), at)) && PICTOGRAPHIC.test(s.slice(at + run.length, at + run.length + 2)) ? run : ""));
  return out;
}

export function hasHidden(text) {
  return TAG.test(text) || /[\u202A-\u202E\u2066-\u2069]/.test(text) || inspect(text).some((f) => f.rule_id === "HIDDEN_TEXT");
}

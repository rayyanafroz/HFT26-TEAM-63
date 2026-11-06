// Placeholders and the vault: "[OPENAI_API_KEY_1]" goes to the AI, the real value stays on this device.
//
// A vault belongs to one tab. The same value always gets the same placeholder in that tab, so the AI can
// refer back to it across messages, and its reply can be turned back into the real thing locally.

import { ruleInfo } from "./rules.js";

export const PLACEHOLDER_RE = /\[([A-Z][A-Z0-9_]*_\d+)\]/g;

// How a model may write a placeholder back: [NAME_1] as given, or <NAME_1>, {{NAME_1}}, or the bare
// NAME_1. The name must stand alone (not inside a longer identifier), and only names this tab's vault
// holds are restored, so unrelated text is never touched.
export const LOOSE_PLACEHOLDER_RE = /(?<![A-Za-z0-9_])(?:\[|<|\{\{)?([A-Z][A-Z0-9_]*_\d+)(?:\]|>|\}\})?(?![A-Za-z0-9_])/g;

export function emptyVault() {
  return { byKey: {}, counters: {}, values: {} };
}

/** The placeholder for this finding's value, created if new. */
export function placeholderFor(vault, finding, value) {
  const key = `${finding.rule_id}:${finding.hash12}`;
  let placeholder = vault.byKey[key];
  if (!placeholder) {
    const name = ruleInfo(finding.rule_id).placeholder ?? "SECRET";
    vault.counters[name] = (vault.counters[name] ?? 0) + 1;
    placeholder = `[${name}_${vault.counters[name]}]`;
    vault.byKey[key] = placeholder;
  }
  if (!(placeholder in vault.values)) vault.values[placeholder] = value;
  return placeholder;
}

/**
 * Replace every redactable finding in `text` (by its UTF-16 `ranges`) with its placeholder.
 * Returns the new text and what was replaced. Findings that cannot be redacted (code) are left alone.
 */
export function redact(text, findings, vault) {
  const edits = [];
  for (const f of findings) {
    if (!ruleInfo(f.rule_id).redactable) continue;
    for (const [a, b] of f.ranges ?? []) edits.push({ a, b, f });
  }
  edits.sort((x, y) => x.a - y.a || y.b - x.b);
  const kept = [];
  let end = -1;
  for (const e of edits) {
    if (e.a < end) continue; // inside or overlapping one already replaced
    kept.push(e);
    end = e.b;
  }
  const replaced = new Map();
  let out = "";
  let cursor = 0;
  for (const { a, b, f } of kept) {
    const placeholder = placeholderFor(vault, f, text.slice(a, b));
    out += text.slice(cursor, a) + placeholder;
    cursor = b;
    replaced.set(placeholder, { placeholder, rule_id: f.rule_id, title: ruleInfo(f.rule_id).title, masked_preview: f.masked_preview });
  }
  out += text.slice(cursor);
  return { text: out, replaced: [...replaced.values()] };
}

/** Put real values back for every placeholder this vault knows (in any of the written forms); others stay as written. */
export function restore(text, vault) {
  return text.replace(LOOSE_PLACEHOLDER_RE, (whole, name) => (`[${name}]` in vault.values ? vault.values[`[${name}]`] : whole));
}

/** The placeholders that appear in `text` and that this vault can restore, as "[NAME_1]". */
export function knownPlaceholders(text, vault) {
  const found = new Set();
  for (const m of text.matchAll(LOOSE_PLACEHOLDER_RE)) if (`[${m[1]}]` in vault.values) found.add(`[${m[1]}]`);
  return [...found];
}

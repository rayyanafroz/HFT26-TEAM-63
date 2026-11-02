# Detection engine conformance suite

The text detection engine is one function: given text, say what sensitive values it holds and give back
the text with them hidden. The Python engine (`src/shadowlens/analysis/`) is the reference. This suite is
how any other implementation (Rust, WebAssembly, JavaScript) proves it behaves the same way.

## The contract

```
analyze(text, settings) -> {
  findings:     [{ rule_id, masked_preview, hash12, spans: [[start, end], ...], count, truncated }],
  redacted_text: string,
  safe_to_send:  boolean,      // no findings and no detector failed
  failed:        [string]      // detectors that could not run; any entry means "not safe"
}
```

| Field | Meaning |
| :-- | :-- |
| `rule_id` | An id from the rule catalog (`rules.json`: severity and confidence per id) |
| `masked_preview` | At most 4 characters of the value, e.g. `sk-p... (len 56)`. Never the value |
| `hash12` | First 12 hex characters of `HMAC-SHA256(salt, value)`, where `value` is the matched text as UTF-8 |
| `spans` | Where the value sits in the **original** text |
| `count` | Number of occurrences for grouped rules (email, phone); otherwise `null` |
| `truncated` | `true` on entropy findings when more candidates existed than the cap allows |

**Span units are Unicode code points**, not bytes and not UTF-16 units. `"😀 key"` puts `key` at 2, not 3
(UTF-16) and not 5 (UTF-8). Detection runs on a folded view of the text (look-alike letters, zero-width
characters, `\uXXXX`, `%XX` and `&#NN;` escapes), and every match is mapped back onto the original, which is
the only text that is redacted or shown.

`context` (the redacted text around a finding) is not part of version 1.

## The suite

Built, not committed, because the cases hold fake secrets and the repository must contain nothing
token-shaped. Values come from `src/shadowlens/fakes.py`, which is deterministic.

```bash
python -m conformance.build      # writes conformance/build/{cases.jsonl, settings.json, rules.json}
python -m conformance.check      # runs the Python reference against it
```

| Category | What it tests |
| :-- | :-- |
| `secret` | Each named key format, plain |
| `disguised-secret` | The same keys hidden 15 ways: zero-width and soft-hyphen characters, full-width and look-alike letters, URL / `\u` / HTML / base64 / hex encodings, split across spaces, lines and string concatenation |
| `adjacent` | A key stuck to other characters (`KEY=`, `(`, `/v1`) |
| `assignment` | Passwords and tokens however they are phrased (`pwd:`, `--password`, `user:pass@host`) |
| `pii`, `pii-bad-checksum` | Cards (Luhn), Aadhaar (Verhoeff), SSN, PAN, IBAN, email, phone; and the same numbers with a wrong check digit, which must not be found |
| `span-units` | Emoji, accents and joiners before a key, to pin down the span unit |
| `clean` | Text that must produce no findings: prose, git SHAs, digests, UUIDs, example emails, code |
| `fixture` | The labeled payloads in `fixtures/payloads_labeled.jsonl` |

Every case states what it must find, must not find, or that it must stay clean, and the build fails if the
reference disagrees. Disguised secrets must also not appear, in any 5-character piece, in `redacted_text`.

Settings are fixed: the defaults in `config/rules.yaml` (see `settings.json`) and the salt `0x73 × 32`.

## Testing another implementation

Write a small adapter that reads JSON lines on stdin and writes JSON lines on stdout:

```
in:   {"id": "secret/openai-key", "text": "my key is ..."}
out:  {"id": "secret/openai-key", "findings": [...], "redacted_text": "...", "safe_to_send": false, "failed": []}
```

then run it:

```bash
python -m conformance.check --cmd "./target/release/engine-adapter"
```

It prints a pass count per category and the first mismatches, and exits 0 only if every case matches
exactly. `conformance/adapter.py` is the Python reference adapter.

## Adding a case

Add it to `cases()` in `conformance/build.py` with its intent (`must_find`, `must_not_find`,
`must_be_clean`, `min_findings`, or `hides`). Found a false positive or a miss in the Python engine? Fix
the engine, add a regression test, and add the case here so every port inherits it.

## Not covered yet

Agent behavior rules (shell commands, file reads, tool calls), the JSON body flattening used for full
requests, and `context`. These belong to the event layer and are not needed to protect a prompt box.

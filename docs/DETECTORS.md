# Detectors

How ShadowLens finds secrets, personal data and source code in AI traffic. For anyone changing the
rules, tuning them, or wondering why a finding did or did not appear.

For how this connects to the pipeline, see [ANALYSIS_INTEGRATION.md](ANALYSIS_INTEGRATION.md).

## The flow

```
NetEvent (only when visibility is "full")
  |
  |-- agent rules: tool declarations, calls and results     agent.py
  |-- auth headers: named patterns only, never entropy      engine.py
  |-- path and query: query is percent-decoded first        engine.py
  '-- body: JSON decoded and labelled by field              engine.py body_scan_text
        |
        v
  analyze_text                                              text.py
    named secrets, personal data, assignments, entropy, code
        |
        v
  resolve_overlaps -> findings with masks and hashes -> redaction -> context
```

The pipeline then stores one finding per (tool, rule, hash12), using its unique index.

## Entry points

Import these from `shadowlens.analysis`.

| Function | Use |
|---|---|
| `analyze(event, config, ctx)` | Everything about one event. The pipeline calls this |
| `analyze_text(text, settings)` | Secrets, personal data and code in plain text. Returns findings, `redacted_text` and `failed` |
| `redact_path(path, config)` | The path as it may be stored. Raises `DetectorFailure` if it could not be fully checked |
| `is_safe_to_send(text, config)` | The egress guard. Fails closed |
| `preview(text, mode, config)` | The analysis part of the Leak Lab route |
| `settings_for(config)` | Settings loaded once from `config/rules.yaml` and the salt file |

## Rules

Severities and confidences are frozen in SOT 6.5 and held in `analysis/catalog.py`.

### Secrets (`analysis/secrets.py`)

| Rule | Matches | Extra check |
|---|---|---|
| `SEC_PRIVATE_KEY` | A `BEGIN ... PRIVATE KEY` header | The match takes the key's lines and END marker too, so no key material stays in redacted text |
| `SEC_AWS_SECRET_KEY` | 40 characters after an AWS secret label | Only the value is the match |
| `SEC_AWS_ACCESS_KEY`, `SEC_OPENAI_KEY`, `SEC_ANTHROPIC_KEY`, `SEC_GITHUB_TOKEN`, `SEC_SLACK_TOKEN`, `SEC_GOOGLE_API_KEY`, `SEC_HF_TOKEN`, `SEC_STRIPE_KEY` | The provider's token format | None |
| `SEC_JWT` | Three `eyJ...` segments | The header must decode to JSON containing `alg` |
| `SEC_DB_URL` | A database URL with a password | None |
| `SEC_GENERIC_ASSIGNMENT` | A secret-like name, a separator, and a value | See below |
| `SEC_HIGH_ENTROPY` | A long random-looking token | See below |

**Assignments** match the name with anything but a letter in front, so `DB_PASSWORD`, `access_token` and
`JWT_SECRET` all count, plus camelCase such as `accessToken`. Nothing word-like may follow the name, so
`token_count` and `tokens` stay quiet.

A value must be at least `generic_password_min_len` long for password names, or `generic_min_len` for
others, and reach `generic_min_entropy`. It is rejected if it is one of these:

- A placeholder word from `generic_placeholder_words`
- A reference such as `settings.DB_PASSWORD`, `$VAR`, `%VAR%` or a path
- A URL
- Only digits
- A name: letters only, with capitals that follow word starts, such as `getPassword` or `DB_SECRET`

**Entropy** looks at tokens of at least `entropy_min_len` characters. A token is skipped if it is any of these:

- A UUID, or has no digit
- The value of a `model` field
- Follows `base64,` or `://`
- A `sha512-` style package hash
- Made of words, such as URL paths and identifiers
- An alphabet written out
- Base64 of a JSON object
- Pure hex of a length in `entropy_digest_lengths`, which is what git SHAs and file digests look like

The bar is `min(entropy_alnum, entropy_length_ratio x log2(length))`, because a short random token cannot
reach a fixed bar. Only the top `max_entropy_findings_per_event` become findings, but all are redacted.

### Personal data (`analysis/pii.py`)

| Rule | Matches | Extra check |
|---|---|---|
| `PII_CREDIT_CARD` | Digit groups, 13 to 19 digits | Starts with 3 to 6, passes Luhn, at most 5 groups of at least 3 digits |
| `PII_AADHAAR` | 12 digits, first is 2 to 9 | Passes Verhoeff |
| `PII_IBAN` | Country, check digits, then letters and digits, with or without spaces | Passes mod-97 |
| `PII_SSN` | `XXX-XX-XXXX` | The invalid ranges are excluded |
| `PII_PAN` | 5 letters, 4 digits, 1 letter | The 4th letter is a valid holder type |
| `PII_EMAIL` | An email address | Domains in `email_skip_domains` are ignored. One finding per event, with a count |
| `PII_PHONE` | Indian mobile numbers and `+` international numbers, with separators | One finding per event, with a count |
| `PII_INTERNAL_HOST` | `.corp`, `.internal`, `.intra`, `.lan` names and private IPv4 addresses | Each part of an IP must be at most 255 |

**Numbers near other numbers** were the one way a raw value stayed visible, so these rules look harder:

- **Cards** are tried in windows of digit groups. A card followed by its CVV reads as 19 digits and fails
  the checksum if read whole.
- **Aadhaar and IBAN** try every start. `2345 2726 6483 2751` would otherwise take the first 12 digits, fail
  the checksum and move past the real number.

If you add a rule with a checksum, do the same: a failed check must not use up the text after it.

### Code (`analysis/code.py`)

| Rule | Fires when |
|---|---|
| `CODE_CONFIDENTIAL_MARKER` | A word like "confidential" is within `marker_window` characters of a copyright notice |
| `CODE_POSSIBLE_SOURCE` | Inside a code fence with at least `code_min_distinct_tokens` keywords. Without a fence, the text also needs at least `code_min_lines` lines, of which `code_min_shaped_lines` are shaped like code |

If `SHADOWLENS_INTERNAL_MARKERS` is set, `CODE_POSSIBLE_SOURCE` also needs one of those words.

### Overlaps

When matches overlap, the higher priority wins, so one secret gives one finding: named secrets, then
database URLs, then checksummed personal data, then assignments, then other personal data, then entropy.
Code findings sit on top and do not compete.

## Masks and placeholders (`analysis/masking.py`)

| Where | Secret | Email | Card, ID, phone |
|---|---|---|---|
| `masked_preview` | `sk-p... (len 51)`, or `... (len 8)` under 20 characters | `j***@domain` | `****1234` |
| `context`, `argument`, LLM text | `[REDACTED:SEC_JWT:0123456789ab]` | `[PII:EMAIL]` | `[PII:CREDIT_CARD]` |

`context` is cut from the redacted text, never the original, so a slice cannot leave half a secret.
A secret inside a detected code block disappears with the block.

## Tuning

Change `config/rules.yaml`, then restart. Each value is checked at startup. Patterns for agent behavior are
in `config/agent_rules.yaml`.

Secret and personal data patterns stay in code, because each is tied to the check that follows it and a
bad edit could silently stop a rule. If you change one, add a row to `fixtures/payloads_labeled.jsonl`. If
you add a named pattern, also add its fixed part to `_NAMED_PREFILTER_RE`, or it will never run. A test
fails if you forget, as long as `fakes.py` has a value for it.

Keep pattern repeats bounded (`{0,400}`, not `*`), and anchor a pattern's start where you can. Two open-ended
patterns once took 8 and 21 seconds on a single 64 KB request. `tests/test_detectors.py` guards against that.

## When something fails

Detection keeps going wherever it safely can. Anything that decides safety fails closed instead.

| What goes wrong | What happens |
|---|---|
| A setting is missing, the wrong type or out of range | That setting uses its default and a warning is logged. The others still apply |
| `rules.yaml` is missing or damaged | All defaults, with a warning |
| The salt file cannot be read or written | A temporary salt for this run, with a warning. A finding could be stored again after a restart |
| `agent_rules.yaml` cannot be read | Agent rules find nothing, and an error is logged. Secrets and personal data keep working |
| One detector raises an error | Only its rules are lost. `analyze_text` lists it in `failed` |
| One part of an event fails (agent rules, a header, the path, the query, the body) | The other parts still report. `AnalysisResult.failed` lists it, and the upload summary says "analysis was incomplete for one event" |
| Redaction fails | `redacted_text` becomes `REDACTION_FAILED`. The raw text never comes back |
| A path cannot be fully checked | The pipeline stores `[path hidden]` |
| A detector could not run during the egress check | `is_safe_to_send` returns `False`, and the Leak Lab shows `would_block` |
| A body is not valid JSON, or is cut off at `MAX_BODY_BYTES` | The escapes are undone and the text is scanned anyway. Agent rules are skipped |
| JSON is nested too deeply | The deep part is scanned as one piece |
| A body contains a lone surrogate | It is replaced by `?`, so the event can still be stored |

Logs name the part and the error type only, never the text or a matched value.

## What this cannot catch

- **Encoded or split secrets:** a key in base64, or broken across two fields.
- **Formats we have no pattern for:** a random token under `entropy_min_len`, or in a field with no
  secret-like name, goes unseen.
- **All-lowercase random passwords with no digit:** `password=abcdefghjkmnpq` reads as a name.
- **Agent rules on long conversations:** a body cut off at `MAX_BODY_BYTES` cannot be parsed, so agent rules
  are skipped for it, while secrets and personal data are still scanned up to the cut. Raise the limit or
  use the transcript reader. The transcript reader sends one line at a time, so it is not affected.
- **Chance matches:** one random number in ten passes a checksum. A 12-digit ID can read as an Aadhaar, and
  a 13 to 19 digit one starting with 3 to 6 as a card. Both are `high` severity.
- **Real addresses in code:** emails in source files are reported. They are personal data, even if public.

## Trying it by hand

`scenarios/leak_lab.py` is an interactive Leak Lab for the terminal. Type or paste anything, and it
shows your text with the matches highlighted, what was found, the exact text an AI model would
receive, whether the egress guard would block it, the risk it would add and how long it took.

```powershell
# from the project folder, with the server running in another terminal
.venv\Scripts\python -m scenarios.leak_lab
```

Commands: `:paste` (several lines), `:agent` / `:text` (switch input type), `:samples` (three ready
examples), `:server` (look for the server again), `:help`, `:quit`.

It asks the running server at `SHADOWLENS_HOST:SHADOWLENS_PORT`, or `--server URL`. If none answers it
uses the same analyzer inside the program and says so. It never uses a system proxy, stores nothing
and keeps no history. Colors turn off when the output is not a terminal or `NO_COLOR` is set, and
severity is always a shape plus a word as well.

## How to test

```powershell
.venv\Scripts\python -m pytest tests/test_detectors.py tests/test_analysis_text.py tests/test_analysis_agent.py
.venv\Scripts\python -m pytest tests/test_analysis_integration.py tests/test_scenarios.py
.venv\Scripts\python -m shadowlens.eval.run
```

| File | Covers |
|---|---|
| `tests/test_analysis_text.py` | Each rule on values shaped to fit it, redaction, masks |
| `tests/test_detectors.py` | Real-world formats, slow inputs, malformed data, broken config, failing detectors, the guard, random surroundings, real standard library source |
| `tests/test_analysis_agent.py` | Protocols, agent rules, Windows and POSIX commands |
| `tests/test_analysis_integration.py` | The real API, pipeline and database, with nothing stubbed |
| `tests/test_leak_lab_cli.py` | The terminal Leak Lab, against a real server on a real port and with none |
| `tests/test_eval.py`, `fixtures/*_labeled.jsonl` | The numbers on the Evidence screen |

**Read the Evidence numbers with care.** The fake keys are built to match the patterns, so recall on the
fixtures shows the rules work on known formats, not that they catch everything. When this suite first
reported 100%, an audit with real-world formats still found 21 misses in 25. New rows from someone who has
not read the code are the most useful thing you can add.

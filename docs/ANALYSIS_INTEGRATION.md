# Analysis integration notes

For Rayyan and any agent working on the backend. Branch: `feature/saleha-analysis`.

The analyzer is already connected to the pipeline: `create_app` picks up `shadowlens.analysis.analyze`
through `_default_analyzer`, with no further wiring. This file lists what changed, how to review it,
and what is left to connect. How the detectors work, how to tune them and what they cannot catch is in
[DETECTORS.md](DETECTORS.md).

## Check it first

Run from the repo root, with the dependencies installed:

```powershell
.venv\Scripts\python -m pytest -q
.venv\Scripts\python -m shadowlens.eval.run
.venv\Scripts\python -m scenarios.generate
git status --short scenarios/templates
```

- All tests should pass. Last full run: 2400 passed, on Windows, Python 3.15.2, with the pinned
  fastapi, uvicorn, httpx, psutil, pydantic, PyYAML and pytest versions. `pywebview` was not installed.
- Not yet run on Python 3.11, the team's target.
- `scenarios.generate` should leave `scenarios/templates` unchanged.
- Uploading `fixtures/sample_http.jsonl` to `POST /api/ingest/log` should return exactly:
  `accepted 17, skipped 0, dropped_non_ai 3, findings 33, alerts 27, errors []`.

## Changes to your files: please review

Only two existing files of yours changed. `src/shadowlens/analysis/__init__.py` was empty and now
exports the analyzer.

### `src/shadowlens/core/pipeline.py`

`_process` stored `event.path` as received, so a secret in a URL path reached the database and
`event.new`. It now does this:

- `_with_safe_path(event)` runs before `insert_event`, on every event that matches a provider. That
  includes `metadata_only` and low-confidence events, which the analyzer never sees.
- The redacted copy goes to `insert_event` and `_event_lite`. The analyzer still reads the original
  path so it can report the finding.
- If the check raises an error, the stored path becomes `PATH_HIDDEN` (`"[path hidden]"`).
- Paths with nothing to redact keep the same event object.

### `ingest/conn_scan.py` and `core/capture.py` (two small additions)

Reset cleared the results but not the scanner's memory of connections it had seen in the last 60
seconds, so a scan right after Reset reported nothing for them. Found while building the guided demo
([DEMO.md](DEMO.md)): the live-laptop step showed 1 connection instead of 30.

- `ConnectionScanner.forget()` clears that memory.
- `CaptureManager.reset()` calls it. `tests/test_scan_after_reset.py` covers both.

### `tests/test_routes_ingest.py`

Only expected counts changed, because they assumed no analyzer. The sample now gives 15 policy
findings (13 alerts) plus 18 analyzer findings (14 alerts). Other new values:

- 6 secrets
- 4 findings for `python3|openai`
- 13 alerts at high or critical
- 14 alerts at low or medium

## How it fits your pipeline

| Topic | Who decides |
|---|---|
| Calling convention | `analyze(event, cfg, ctx)`, matching your `AnalyzeFn`. `cfg` is your `Config`; `ctx` is your `core.ctx.AgentSessionContext` |
| Salt and YAML loading | `settings_for(config)` reads them once and caches the result. `analyze` touches no disk after that |
| One finding per (tool, rule, hash12) | Your unique index, through `insert_finding` returning `False`. `analyze` only de-duplicates within one event, so replays return findings that your database refuses |
| Repeated agent calls | `ctx.seen_calls`, so activity rows are not repeated |
| Granted capabilities | `ctx.granted`, holding `CapabilityName` members. One `granted` activity row per capability, per session, under the first tool that granted it |
| Provider's own key in its own header | Your `_clean` with `catalog.native_key_ok`. The analyzer reports the credential; you filter it |
| Policy findings | The pipeline, as now |
| Titles | Your `core/rule_titles.py`. The catalog only holds severity, confidence, OWASP tags and overlap priority |
| `Finding.controls` | Left empty by the analyzer. Fill it from `config/compliance.yaml` |
| Reset | `Pipeline.reset` already covers this; the analyzer keeps no other state |

`AgentActivity.finding_id` can name a finding your database refused. `_store_activity` already clears
it, and `test_restart_with_the_same_database_does_not_crash_or_duplicate` covers this.

## What is left to connect

Each of these is ready to call, and nothing calls it yet.

### Demo routes

```python
from scenarios.loader import SCENARIO_NAMES, duration_s, schedule
from shadowlens.ingest.http_log import event_from_record

# POST /api/demo/load-scenario: the run ends at "now"
lines = schedule(name)
events = [event_from_record(line, max_body_bytes=config.max_body_bytes) for line in lines]
pipeline.ingest(events, source="scenario")

# POST /api/demo/play: each line's ts is when to send it
lines = schedule(name, speed=speed)
total_s = duration_s(name, speed)
```

- `schedule` has already expanded the fakes and replaced `t_ms` with `ts`, so do not pass `expand`.
- `schedule` raises `ValueError` for an unknown name.
- `scenarios/` is not an installed package, so this only imports when the app runs from the repo root.

### Leak Lab

```python
from shadowlens.analysis import preview
from shadowlens import fakes

# GET /api/analyze/samples
fakes.samples()                    # {"key": ..., "pii": ..., "agent": ...}

# POST /api/analyze/preview
preview(text, mode, config)        # {"findings": [...], "redacted_text": ..., "would_block": ...}
```

You add `points_preview`. `preview` returns one row per match so the UI can highlight each, so two
emails give two rows. Count each distinct finding once when computing `S`. Agent rows have span `[0, 0]`.

### Egress guard

```python
from shadowlens.analysis import is_safe_to_send

blocked = not is_safe_to_send(prompt, config)
```

Text that is already a placeholder is skipped. This fails closed: if a detector could not run, the
answer is no. Do not use `analyze_text(...).findings` for this, because it stays empty if a detector
failed.

### Ollama tap

```python
from shadowlens.ingest.ollama_proxy import OllamaTap

tap = OllamaTap.from_config(config, lambda event: pipeline.ingest([event], source="proxy"))
tap.start()     # False if it failed; the reason is in tap.error
tap.stop()
tap.status()    # the CaptureStatus "proxy" block
```

Start and stop it from the `ollama_proxy` source toggle. It is off by default.

### Evidence

`GET /api/evidence` can read `data/evidence.json`, written by `python -m shadowlens.eval.run` in the
`Evidence` shape. If the file is missing, return `available: false`.

### Transcript reader

- Build each event's body as §7.2.1 describes. `reader_body` in `tests/test_demo_helpers.py` is a
  working example, and `fixtures/sample_claude_transcript.jsonl` is the AT-28 sample. Its placeholders
  need `fakes.expand` first.
- Check real transcripts for content outside `message.content`. Lines on one Windows machine also had
  top-level `attachment`, `toolUseResult` and `tools` fields. `attachment` may hold file contents the
  reader would miss, and `tools` may supply the granted capabilities that §7.2.1 bodies lack.
- Without a declared tool, every Claude Code capability counts as used but not granted. Show the
  hatching only when a tool declared at least one capability.
- Set `SHADOWLENS_WORKSPACE_ROOTS` to the demo folder. Claude Code reads use absolute paths, so the
  default roots raise `AGENT_FS_READ_OUTSIDE_WORKSPACE` on most reads.

### Live log tail

`python -m scenarios.mock_ollama` appends to `data/live/ollama.jsonl`, and
`python -m scenarios.agent_sim` drives it. Use `parse_jsonl_line(line, source=Source.LIVE_LOG, ...)`.

## Known issues

1. **Port 11435 is not recognized.** §12.2 says to use `--port 11435` when real Ollama holds 11434, but
   `config/providers.yaml` lists only 11434 for `ollama`, so that traffic is dropped as non-AI. Add 11435
   to `ports`.
2. **AT-24 is tight.** 5,000 events of 1.6 KB through the full pipeline, on disk, on one laptop:

   | Run | Time | Limit |
   |---|---|---|
   | Storage only, no analyzer | 1.88 s | |
   | Real analyzer, clean traffic | 8.09 s | 10 s |
   | Real analyzer, a leak in every event (10,005 findings) | 16.69 s | 10 s |

   The p95 event-to-`finding.new` target has not been measured.
3. **`tests/test_scenarios.py` holds a copy of the §7.5 formula.** It uses the real parser, classifier,
   analyzer, pipeline and database, but not real scoring. Replace `score`, `org_risk`, `WEIGHT` and
   `EXPOSURE` with `core/scoring.py` when it exists, then confirm `quick_leak` is exactly 52.
4. **`full_demo` has exactly 3 critical findings,** the minimum its target allows.
5. **`provider_accuracy` is not measured.** The eval runner omits it until
   `fixtures/providers_labeled.jsonl` and a call to the classifier are added.
6. **Not built:** `AGENT_INJECTION_CHAIN` and `PII_BULK` (both P2).

## Where the code differs from the SOT

Please update the SOT if you agree, and say so if you do not.

- **§6.5, §7.3 `meta.truncated`:** `FindingMeta` has no such field and forbids extras, so the flag stays
  on the internal `TextFinding`.
- **§7.3 hex rule:** the rule flags 32+ hex characters, but §8.4 requires git SHAs and digests to stay
  silent. Pure hex of 32, 40 or 64 characters is now skipped, unless labelled like `token=...`.
- **§7.3 entropy:** a token must also contain a digit. Tokens after `base64,` or `://`, integrity hashes,
  tokens made of words (URL paths, identifiers) and written-out alphabets are skipped. Mid-token `=` ends
  a token. The bar is lower for short tokens: 4.2 cannot be reached by many random 24-character ones.
- **§7.3 end of AWS, Google and JWT patterns:** a lookahead replaces `\b`. A key can end in `/`, `+`, `=`
  or `-`, and `\b` then fails and loses the key.
- **§7.3 generic rule:** a name may have a non-letter in front (`DB_PASSWORD`, `access_token`) or be
  camelCase, and `pwd`, `passphrase`, `secret_key` and `access_key` count. `\b` could not see the first
  two, because `_` is a word character. Values may hold symbols, and password names need only 8
  characters. References, URLs, digits and names are rejected.
- **§7.3 cards:** digit groups are tried in windows, at most 5 groups of at least 3 digits. Read whole, a
  card and its CVV fail Luhn and the card stayed visible.
- **§7.3 phones, Aadhaar, IBAN, hostnames:** separators and capitals are accepted. Aadhaar and IBAN try
  every start, because a plain match on `2345 2726 6483 2751` takes the first 12 digits, fails the
  checksum and moves past the real number.
- **§7.3 email:** the pattern is anchored and length-limited. `\b` took 8 seconds on 64 KB of `a.a.a.`.
- **§7.3 code:** without a fence, 3 lines must also be shaped like code, so a long essay is not source.
- **§7.3 query and form bodies:** percent-encoding is decoded before scanning.
- **§6.11 `rules.yaml`:** it has more settings than the SOT lists. All are validated at startup.
- **§7.3 scan list:** the path is scanned too, as §4.2 and §7.1 say. Slashes count as separators there,
  so a long ordinary path is not read as one token.
- **§7.3 private keys:** the match takes the base64 lines and END marker too, so key material is not left
  in redacted text.
- **§7.3 body text:** JSON bodies are decoded first and labelled by key. In raw JSON a newline is the two
  characters `\n`, which hides a key at the start of a line.
- **§7.4 paths:** `.env.example`, `.env.sample` and `.env.template` are not sensitive. The `AppData`
  pattern now allows spaces, because Chrome's `Login Data` sits under `User Data`.
- **§7.4 network:** a shell command that reaches the network, such as `curl`, counts as using the
  `network` capability. `agent_attack` needs this.
- **§7.4 sensitive files:** file tools are judged on their path argument only, so writing a file that
  mentions `.env` stays quiet.
- **§7.4 patterns:** open-ended repeats are bounded to 200 to 400 characters. One took 21 seconds on a
  64 KB command. A dangerous command spread over more than 400 characters on one line can be missed.
- **§7.1 local ports:** the tap reports `host` as `localhost:<upstream port>`, as §7.2.2 says.

## Files

| Path | Purpose |
|---|---|
| `src/shadowlens/analysis/engine.py` | `analyze`, `preview`, `redact_path`, `body_scan_text` |
| `src/shadowlens/analysis/text.py` | `analyze_text` |
| `src/shadowlens/analysis/secrets.py`, `pii.py`, `code.py` | Detectors |
| `src/shadowlens/analysis/agent.py` | Protocol parsing and agent rules |
| `src/shadowlens/analysis/redact.py`, `masking.py`, `checksums.py` | Primitives |
| `src/shadowlens/analysis/catalog.py`, `settings.py` | Rule table and loaded settings |
| `config/rules.yaml` | Detector thresholds and word lists, which can be tuned |
| `config/agent_rules.yaml` | Agent patterns, which can be tuned |
| `docs/DETECTORS.md` | How each rule works, fallbacks, limits |
| `docs/DEMO.md`, `scenarios/demo.py` | The guided demo in one terminal, with the live event feed inline |
| `docs/INVENTORY.md`, `ingest/inventory.py`, `config/ai_tools.yaml` | What AI is on this machine, and whether it is really talking to its provider |
| `scenarios/leak_lab.py` | The terminal Leak Lab (type anything) |
| `src/shadowlens/fakes.py` | Runtime fake secrets |
| `src/shadowlens/ingest/ollama_proxy.py` | Opt-in tap |
| `src/shadowlens/eval/run.py` | Evidence runner |
| `scenarios/` | Templates, generator, loader, `mock_ollama`, `agent_sim`, `transcript_sim` |
| `fixtures/` | Labeled payloads and agent rows, sample transcript |

"""Builds the conformance suite for the text detection engine.

The engine is ``analyze_text(text, settings) -> findings + redacted_text``. Any implementation of it (the
Python one, a Rust or WebAssembly port, a JavaScript one) must give the same answers as this suite.

Nothing token-shaped is committed. Cases are written here as templates over ``shadowlens.fakes``, which is
deterministic, and the suite is built into ``conformance/build/`` (ignored by git):

    python -m conformance.build

Each case also says what it must find, or that it must stay clean, so the expected output is anchored to
human intent and not only to what the reference implementation printed. The build fails if the reference
disagrees with a case's own intent, or if a disguised secret survives in the redacted text.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import string
import urllib.parse
from dataclasses import asdict
from pathlib import Path
from typing import Any, Iterator

from shadowlens.analysis.catalog import RULES
from shadowlens.analysis.settings import AnalysisSettings
from shadowlens.analysis.text import analyze_text
from shadowlens.fakes import expand, fake

ROOT = Path(__file__).resolve().parent.parent
OUT = Path(__file__).resolve().parent / "build"
SALT = b"s" * 32                     # fixed so hash12 is reproducible; real installs use a random one
FIXTURES = ROOT / "fixtures" / "payloads_labeled.jsonl"

ZW = "\u200B"
FULLWIDTH = {i: i + 0xFEE0 for i in range(0x21, 0x7F)}
SECRET_KINDS = {
    "openai_key": "SEC_OPENAI_KEY", "anthropic_key": "SEC_ANTHROPIC_KEY", "aws_access_key": "SEC_AWS_ACCESS_KEY",
    "github_token": "SEC_GITHUB_TOKEN", "stripe_key": "SEC_STRIPE_KEY", "slack_token": "SEC_SLACK_TOKEN",
    "google_key": "SEC_GOOGLE_API_KEY", "hf_token": "SEC_HF_TOKEN",
}
PII_KINDS = {
    "card_visa": "PII_CREDIT_CARD", "card_mc": "PII_CREDIT_CARD", "card_amex": "PII_CREDIT_CARD",
    "aadhaar": "PII_AADHAAR", "ssn": "PII_SSN", "pan": "PII_PAN", "iban": "PII_IBAN", "email": "PII_EMAIL",
    "phone_in": "PII_PHONE", "internal_host": "PII_INTERNAL_HOST",
}
CHECKSUM_KINDS = ("card_visa", "card_mc", "card_amex", "aadhaar")


def settings() -> AnalysisSettings:
    return AnalysisSettings(salt=SALT)


def disguises(value: str) -> dict[str, str]:
    mid = len(value) // 2
    return {
        "plain": value,
        "zero-width inside": value[:mid] + ZW + value[mid:],
        "soft hyphen": value[:mid] + "\u00AD" + value[mid:],
        "word joiner and BOM": value[:mid] + "\u2060\uFEFF" + value[mid:],
        "fullwidth": value.translate(FULLWIDTH),
        "look-alike letters": value.replace("a", "а").replace("e", "е").replace("o", "о"),
        "url-encoded": urllib.parse.quote(value, safe=""),
        "json u escapes": "".join(f"\\u{ord(c):04x}" for c in value),
        "html entities": "".join(f"&#{ord(c)};" for c in value),
        "base64": base64.b64encode(value.encode()).decode(),
        "hex": binascii.hexlify(value.encode()).decode(),
        "two halves with a space": f"{value[:mid]} {value[mid:]}",
        "two halves on two lines": f"{value[:mid]}\n{value[mid:]}",
        "three pieces": f"{value[:8]} {value[8:16]} {value[16:]}",
        "string concatenation": f'"{value[:mid]}" + "{value[mid:]}"',
    }


def _slug(text: str) -> str:
    return "".join(c if c.isalnum() else "-" for c in text.lower()).strip("-")


def _case(category: str, name: str, text: str, **intent: Any) -> dict[str, Any]:
    return {"id": f"{category}/{_slug(name)}", "category": category, "text": text, **intent}


# ---- the cases ------------------------------------------------------------------------------------------

def cases() -> Iterator[dict[str, Any]]:
    """Each case: id, category, text and its intent (``must_find``, ``must_be_clean`` or ``hides``)."""
    for kind, rule in SECRET_KINDS.items():
        value = fake(kind, 7)
        for name, disguised in disguises(value).items():
            yield _case("disguised-secret", f"{kind} {name}", f"before {disguised} after", hides=value)
        yield _case("secret", kind, f"my key is {value} please check", must_find=[rule], hides=value)

    key = fake("openai_key", 4)
    for before in ["key_", "KEY=", "OPENAI_API_KEY_", "x-api-key:", "(", "[", '"', "'", "=", "/", "#", "::"]:
        yield _case("adjacent", f"before {before}", f"a {before}{key} b", must_find=["SEC_OPENAI_KEY"], hides=key)
    for after in [")", "]", '"', ",", ".", ";", "/v1"]:
        yield _case("adjacent", f"after {after}", f"a {key}{after} b", must_find=["SEC_OPENAI_KEY"], hides=key)

    for template in [
        "the admin password is {v} ok", "pwd: {v}", "pass={v}", "passwd {v}", "my api key: {v}", "apikey={v}",
        "export DB_PASS={v}", "password:\n  {v}", "PASSWORD={v}", "mysql -u root -p{v}", "tool --password {v}",
        "x-api-key: {v}", "client secret: {v}", "https://x.example/login?user=a&password={v}",
        "https://deploy:{v}@git.corp/repo.git", "sshpass -p {v} ssh host", "password：{v}", "pass\u200Bword={v}",
    ]:
        yield _case("assignment", template, template.replace("{v}", "Xk39aQ2zLm7pR"), min_findings=1, hides="Xk39aQ2zLm7pR")

    for kind, rule in PII_KINDS.items():
        value = fake(kind, 3)
        yield _case("pii", kind, f"Contact {value} about the invoice", must_find=[rule])
    for kind in CHECKSUM_KINDS:
        value = fake(kind, 3)
        wrong = value[:-1] + str((int(value[-1]) + 1) % 10)
        yield _case("pii-bad-checksum", kind, f"Reference number {wrong} was typed", must_not_find=[PII_KINDS[kind]])

    prefix = ["", "\U0001F600 ", "\U0001F600\U0001F680 ", "café ", "e\u0301 ", "日本語 ", "a\u200Db "]
    for lead in prefix:
        yield _case("span-units", f"after {lead!r}", f"{lead}{key} end", must_find=["SEC_OPENAI_KEY"], hides=key)

    for name, text in {
        "plain prose": "The quarterly report is attached. Let me know if the numbers look right to you.",
        "git sha": "fixed in commit 9fceb02d0ae598e95dc970b74767f19372d61af8 on main",
        "sha256 digest": "sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "uuid": "request id 123e4567-e89b-12d3-a456-426614174000 failed",
        "example email": "write to someone@example.com for details",
        "small code": "def add(a, b):\n    return a + b\n\nprint(add(1, 2))",
        "order number": "order 12345678 ships on Tuesday",
        "url": "see https://docs.python.org/3/library/re.html for the syntax",
        "empty": "",
        "only whitespace": "   \n\t  ",
    }.items():
        yield _case("clean", name, text, must_be_clean=True)

    for row in map(json.loads, FIXTURES.read_text(encoding="utf-8").splitlines()):
        body, extras = row["input"].get("body"), set(row["input"]) - {"body"}
        if isinstance(body, str) and not extras:
            yield _case("fixture", row["id"], expand(body), **({"must_find": row["expect"]} if row["expect"] else {"must_be_clean": True}))


# ---- running the reference ------------------------------------------------------------------------------

def answer(text: str, cfg: AnalysisSettings | None = None) -> dict[str, Any]:
    """The engine's output in the neutral shape every implementation must produce. ``context`` is not part of v1."""
    result = analyze_text(text, cfg or settings())
    return {
        "findings": [{"rule_id": f.rule_id, "masked_preview": f.masked_preview, "hash12": f.hash12,
                      "spans": [list(s) for s in f.spans], "count": f.count, "truncated": f.truncated}
                     for f in result.findings],
        "redacted_text": result.redacted_text,
        "safe_to_send": not result.findings and not result.failed,
        "failed": result.failed,
    }


def _check_intent(case: dict[str, Any], out: dict[str, Any]) -> list[str]:
    found = {f["rule_id"] for f in out["findings"]}
    problems = []
    if case.get("must_be_clean") and (found or out["failed"]):
        problems.append(f"expected clean, found {sorted(found)}")
    if not set(case.get("must_find", [])) <= found:
        problems.append(f"missing {sorted(set(case['must_find']) - found)}, found {sorted(found)}")
    if found & set(case.get("must_not_find", [])):
        problems.append(f"must not find {sorted(found & set(case['must_not_find']))}")
    if len(out["findings"]) < case.get("min_findings", 0):
        problems.append("found nothing")
    value = case.get("hides")
    if value and out["findings"]:
        redacted = out["redacted_text"]
        visible = {value[i:i + 5] for i in range(len(value) - 4)} & {redacted[i:i + 5] for i in range(len(redacted) - 4)}
        if visible:
            problems.append(f"left visible: {sorted(visible)[:2]}")
    elif value and not out["findings"]:
        problems.append("secret not found")
    return problems


def build(out_dir: Path = OUT) -> dict[str, Any]:
    """Write ``cases.jsonl``, ``settings.json`` and ``rules.json`` into ``out_dir``. Raises if intent and reference disagree."""
    out_dir.mkdir(parents=True, exist_ok=True)
    rows, problems, seen = [], [], set()
    for case in cases():
        base, n = case["id"], 1
        while case["id"] in seen:          # readable ids can collide ("key_" and "KEY="); the order is stable
            n += 1
            case["id"] = f"{base}~{n}"
        seen.add(case["id"])
        out = answer(case["text"])
        problems += [f"{case['id']}: {p}" for p in _check_intent(case, out)]
        rows.append({"id": case["id"], "category": case["category"], "text": case["text"], "expected": out})
    if problems:
        raise AssertionError(f"{len(problems)} case(s) disagree with their own intent:\n" + "\n".join(problems[:20]))
    (out_dir / "cases.jsonl").write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")
    cfg = {k: (list(v) if isinstance(v, tuple) else v) for k, v in asdict(settings()).items()
           if k not in ("salt", "agent_rules", "warnings")}
    cfg["salt_hex"] = SALT.hex()
    (out_dir / "settings.json").write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
    catalog = {rid: {"severity": r.severity, "confidence": r.confidence} for rid, r in sorted(RULES.items())}
    (out_dir / "rules.json").write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")
    cats: dict[str, int] = {}
    for r in rows:
        cats[r["category"]] = cats.get(r["category"], 0) + 1
    return {"cases": len(rows), "categories": cats, "out": str(out_dir)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build the detection-engine conformance suite.")
    parser.add_argument("--out", type=Path, default=OUT)
    summary = build(parser.parse_args().out)
    print(f"{summary['cases']} cases -> {summary['out']}")
    for name, n in sorted(summary["categories"].items()):
        print(f"  {name:18} {n}")

"""The conformance suite: it builds, the reference passes, and it catches implementations that are wrong."""

import json
import re
import sys
from pathlib import Path

import pytest

from conformance import build as suite
from conformance.check import compare, load, run
from shadowlens.analysis.secrets import find_named_secrets

CONFORMANCE = Path(suite.__file__).parent


@pytest.fixture(scope="module")
def rows(tmp_path_factory):
    out = tmp_path_factory.mktemp("suite")
    suite.build(out)
    return load(out)


def answers_from(rows, transform=lambda text, out: out):
    return {r["id"]: transform(r["text"], json.loads(json.dumps(r["expected"]))) for r in rows}


def test_the_suite_builds_with_every_category(rows):
    categories = {r["category"] for r in rows}
    assert {"secret", "disguised-secret", "adjacent", "assignment", "pii", "pii-bad-checksum", "span-units",
            "clean", "fixture"} <= categories
    assert len(rows) > 250 and len({r["id"] for r in rows}) == len(rows)


def test_building_twice_gives_identical_files(tmp_path):
    suite.build(tmp_path / "a")
    suite.build(tmp_path / "b")
    for name in ("cases.jsonl", "settings.json", "rules.json"):
        assert (tmp_path / "a" / name).read_bytes() == (tmp_path / "b" / name).read_bytes()


def test_the_reference_adapter_passes_every_case(rows):
    tally, misses = compare(rows, run([sys.executable, "-m", "conformance.adapter"], rows))
    assert misses == [] and all(p == t for p, t in tally.values())


def test_an_implementation_that_reports_utf16_spans_is_caught_only_where_it_matters(rows):
    def utf16(text, out):
        for finding in out["findings"]:
            finding["spans"] = [[len(text[:s].encode("utf-16-le")) // 2, len(text[:e].encode("utf-16-le")) // 2]
                                for s, e in finding["spans"]]
        return out

    tally, misses = compare(rows, answers_from(rows, utf16))
    failing = {m["id"].split("/")[0] for m in misses}
    assert failing == {"span-units"}
    assert tally["span-units"][0] < tally["span-units"][1]       # emoji before the key moves the spans
    assert tally["secret"][0] == tally["secret"][1]              # plain ASCII cannot tell the two apart


def test_an_implementation_that_misses_hidden_characters_is_caught(rows):
    def ignores_zero_width(text, out):
        return {"findings": [], "redacted_text": text, "safe_to_send": True, "failed": []} if "​" in text else out

    _, misses = compare(rows, answers_from(rows, ignores_zero_width))
    assert any("zero-width" in m["id"] for m in misses)


def test_a_missing_answer_is_a_failure_not_a_pass(rows):
    answers = answers_from(rows)
    answers.pop(rows[0]["id"])
    _, misses = compare(rows, answers)
    assert [m["id"] for m in misses] == [rows[0]["id"]]


def test_the_build_refuses_a_case_whose_intent_the_reference_does_not_meet(monkeypatch, tmp_path):
    monkeypatch.setattr(suite, "cases", lambda: iter([suite._case("secret", "x", "nothing here", must_find=["SEC_OPENAI_KEY"])]))
    with pytest.raises(AssertionError, match="disagree"):
        suite.build(tmp_path)


def test_nothing_token_shaped_is_committed_in_the_suite_sources():
    for path in CONFORMANCE.glob("*"):
        if path.suffix in {".py", ".md"}:
            assert find_named_secrets(path.read_text(encoding="utf-8")) == [], path.name


def test_the_generated_settings_match_the_documented_defaults(tmp_path):
    suite.build(tmp_path)
    cfg = json.loads((tmp_path / "settings.json").read_text())
    assert cfg["salt_hex"] == "73" * 32 and cfg["entropy_alnum"] == 4.2 and cfg["max_entropy_findings_per_event"] == 3
    rules = json.loads((tmp_path / "rules.json").read_text())
    assert rules["SEC_OPENAI_KEY"]["severity"] and re.fullmatch(r"[A-Z_0-9]+", next(iter(rules)))

"""AT-04, AT-05: detection meets its targets on the labeled fixtures (SOT 8.4)."""

import json
import re
from pathlib import Path

import pytest

from shadowlens.analysis import AnalysisSettings
from shadowlens.analysis.secrets import find_named_secrets
from shadowlens.eval.run import AGENTS, PAYLOADS, evaluate, load_rows, main, run_row, write_evidence
from shadowlens.models import Evidence

REPO_ROOT = Path(__file__).resolve().parents[1]
SETTINGS = AnalysisSettings(salt=b"s" * 32)
P0_RULES = {
    "SEC_PRIVATE_KEY", "SEC_AWS_SECRET_KEY", "SEC_GITHUB_TOKEN", "SEC_STRIPE_KEY", "SEC_DB_URL", "SEC_AWS_ACCESS_KEY",
    "SEC_OPENAI_KEY", "SEC_ANTHROPIC_KEY", "SEC_SLACK_TOKEN", "SEC_GOOGLE_API_KEY", "SEC_HF_TOKEN", "SEC_JWT",
    "SEC_GENERIC_ASSIGNMENT", "SEC_HIGH_ENTROPY", "PII_CREDIT_CARD", "PII_AADHAAR", "PII_SSN", "PII_PAN", "PII_EMAIL",
    "PII_PHONE", "PII_INTERNAL_HOST",
}


@pytest.fixture(scope="module")
def report():
    return evaluate(REPO_ROOT, SETTINGS)


def metric(report, metric_id):
    return next(m for m in report.metrics if m.id == metric_id)


# ---- the fixture files meet SOT 8.4 ------------------------------------------------

def test_payload_fixture_size_and_coverage():
    rows = load_rows(REPO_ROOT / PAYLOADS)
    positives = [row for row in rows if row.expect]
    assert len(positives) >= 42
    assert len(rows) - len(positives) >= 30
    for rule_id in P0_RULES:
        assert sum(rule_id in row.expect for row in rows) >= 2, rule_id


def test_agent_fixture_size_and_protocols():
    rows = load_rows(REPO_ROOT / AGENTS)
    assert len(rows) >= 20
    bodies = [json.dumps(row.input["body"]) for row in rows]
    assert any('"tool_calls"' in body for body in bodies)
    assert any('"tool_use"' in body for body in bodies)
    assert any('"/api/chat"' in json.dumps(row.input) for row in rows)
    assert any('"tools/call"' in body for body in bodies)


@pytest.mark.parametrize("path", [PAYLOADS, AGENTS])
def test_row_ids_are_unique_and_labels_are_real_rules(path):
    from shadowlens.models import RULE_IDS
    rows = load_rows(REPO_ROOT / path)
    assert len({row.id for row in rows}) == len(rows)
    assert all(set(row.expect) <= RULE_IDS for row in rows)


@pytest.mark.parametrize("path", [PAYLOADS, AGENTS])
def test_fixture_file_holds_no_token_shaped_literal(path):
    """AT-26: fakes appear only as placeholders."""
    raw = (REPO_ROOT / path).read_text(encoding="utf-8")
    assert find_named_secrets(re.sub(r"\{\{fake:[a-z0-9_]+(?:#\d+)?\}\}", "", raw)) == []


# ---- the targets --------------------------------------------------------------------

def test_at04_recall_and_false_positives(report):
    assert metric(report, "secret_recall").value >= 95
    assert metric(report, "pii_recall").value >= 95
    assert metric(report, "false_positives").value <= 2


def test_at05_agent_rules(report):
    assert metric(report, "agent_rules_hit").passed


def test_at12_no_raw_values_in_the_output(report):
    assert metric(report, "no_raw_secret_leak").value == 0


def test_no_problems_at_all_today(report):
    """Stricter than the SOT targets, so a new miss or false positive is seen straight away."""
    assert report.problems == []


# ---- the runner itself --------------------------------------------------------------

def test_a_missed_rule_is_reported_by_id_without_its_value(tmp_path):
    (tmp_path / "fixtures").mkdir()
    (tmp_path / PAYLOADS).write_text(
        '{"id":"r1","input":{"body":"plain words"},"expect":["SEC_JWT"]}\n'
        '{"id":"r2","input":{"body":"use {{fake:openai_key}} now"},"expect":[]}\n',
        encoding="utf-8",
    )
    outcome = evaluate(tmp_path, SETTINGS)
    assert "missed SEC_JWT in row r1" in outcome.problems
    assert "false positive SEC_OPENAI_KEY in row r2" in outcome.problems
    assert metric(outcome, "secret_recall").passed is False
    assert not any("sk-" in problem for problem in outcome.problems)


def test_leak_check_catches_a_raw_value():
    from shadowlens.eval.run import Report, _raw_leaks, Row, RowResult
    from shadowlens.fakes import fake
    row = Row("r", {}, [], "x {{fake:openai_key#1}} y")
    report = Report()
    assert _raw_leaks([RowResult(row, [], [], f"oops {fake('openai_key', 1)}")], report) == 1
    assert _raw_leaks([RowResult(row, [], [], "sk-p... (len 51)")], Report()) == 0


def test_run_row_gives_each_row_a_fresh_context():
    row = load_rows(REPO_ROOT / PAYLOADS)[0]
    assert run_row(row, SETTINGS).fired == run_row(row, SETTINGS).fired != []


def test_written_file_matches_the_evidence_shape(report, tmp_path):
    path = tmp_path / "data" / "evidence.json"
    write_evidence(report, path)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert all("pass" in item and "passed" not in item for item in data["metrics"])
    assert Evidence.model_validate(data).available is True


def test_main_without_fixtures_says_not_available(tmp_path, capsys):
    assert main(tmp_path) == 1
    data = json.loads((tmp_path / "data" / "evidence.json").read_text(encoding="utf-8"))
    assert data["available"] is False and data["metrics"] == []

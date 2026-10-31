"""AT-08: each scenario meets its expected result (SOT 8.2).

Scenarios go through the real parser, classifier, analyzer, pipeline and database. Only
``WEIGHT``, ``EXPOSURE`` and ``score`` are a small copy of SOT 7.5, until ``core/scoring.py`` exists.
"""

import math
import re
from datetime import datetime, timezone

import pytest

from scenarios.generate import SCENARIOS, render
from scenarios.loader import SCENARIO_NAMES, TEMPLATE_DIR, duration_s, read_lines, schedule
from shadowlens.analysis import analyze
from shadowlens.config import Config
from shadowlens.core.pipeline import Pipeline
from shadowlens.db import Database
from shadowlens.ingest.http_log import event_from_record
from shadowlens.providers.catalog import Catalog

CATALOG = Catalog.load()
EXPOSURE = {"cloud_llm": 1.0, "ai_app": 1.0, "model_hub": 1.1, "local_llm": 0.4}
WEIGHT = {"info": 1, "low": 5, "medium": 15, "high": 35, "critical": 60}
COUNT_FACTOR = (1.0, 0.5, 0.25)


class Run:
    def __init__(self, name, folder):
        config = Config.load(env={"SHADOWLENS_RESOLVE": "false"}, base_dir=folder, use_dotenv=False)
        self.db = Database(folder / "shadow.db")
        self.pipeline = Pipeline(config, self.db, CATALOG, analyze=analyze)
        self.lines = schedule(name)
        self.summary = self.pipeline.ingest(
            [event_from_record(line, max_body_bytes=config.max_body_bytes) for line in self.lines], source="scenario")
        self.findings = {}   # tool_id -> [(rule_id, severity, confidence)]
        self.meta = {}       # tool_id -> (category, sanctioned, provider_id)
        self.activity = {}
        overrides = self.db.get_provider_overrides()
        for event in self.db.list_events(limit=1000).items:
            if event.tool_id not in self.meta:
                provider = CATALOG.get(event.provider_id)
                self.meta[event.tool_id] = (provider.category.value,
                                            self.pipeline.is_sanctioned(event.provider_id, overrides), event.provider_id)
                self.findings[event.tool_id] = [
                    (f.rule_id, f.severity.value, f.confidence)
                    for f in self.db.list_findings(tool_id=event.tool_id, limit=1000).items
                ]
                self.activity[event.tool_id] = self.db.list_agent_activity(event.tool_id)

    def rules(self, tool_id):
        return sorted(rule for rule, _, _ in self.findings[tool_id])

    def score(self, tool_id):
        category, sanctioned, _ = self.meta[tool_id]
        seen = {}
        total = 0.0
        for rule_id, severity, confidence in self.findings[tool_id]:
            position = seen.get(rule_id, 0)
            seen[rule_id] = position + 1
            factor = COUNT_FACTOR[position] if position < 3 else (0.1 if position < 10 else 0.0)
            total += WEIGHT[severity] * confidence * EXPOSURE[category] * (0.5 if sanctioned else 1.0) * factor
        return total, int(100 * (1 - math.exp(-total / 80)) + 0.5)

    @property
    def org_risk(self):
        scores = sorted((self.score(t)[1] for t in self.meta), reverse=True)
        return int(0.7 * scores[0] + 0.3 * sum(scores[:3]) / len(scores[:3]) + 0.5)

    @property
    def alert_count(self):
        return self.summary.alerts

    @property
    def critical_count(self):
        return sum(1 for items in self.findings.values() for _, severity, _ in items if severity == "critical")


@pytest.fixture(scope="module")
def runs(tmp_path_factory):
    made = {name: Run(name, tmp_path_factory.mktemp(name)) for name in SCENARIO_NAMES}
    yield made
    for run in made.values():
        run.db.close()


# ---- expected results (SOT 8.2) --------------------------------------------------

def test_quick_leak_is_exactly_52(runs):
    run = runs["quick_leak"]
    assert run.summary.accepted == 12 and run.summary.errors == []
    assert run.rules("python3|openai") == ["POLICY_UNSANCTIONED_TOOL", "SEC_AWS_SECRET_KEY"]
    assert run.score("python3|openai")[0] == pytest.approx(58.5)
    assert run.org_risk == 52


def test_quick_leak_timing():
    lines = read_lines("quick_leak")
    assert [line["t_ms"] for line in lines if "aws_secret" in line["body"]] == [6000]
    assert duration_s("quick_leak") == 10


def test_clean_baseline(runs):
    run = runs["clean_baseline"]
    assert run.summary.accepted == 40 and run.summary.errors == []
    assert {meta[2] for meta in run.meta.values()} == {"openai", "anthropic", "ollama", "huggingface", "featherless"}
    assert run.org_risk <= 24
    assert run.rules("python3|openai") == ["PII_EMAIL", "POLICY_UNSANCTIONED_TOOL"]


def test_full_demo_totals(runs):
    run = runs["full_demo"]
    assert run.summary.accepted == 120 and run.summary.errors == []
    assert len({meta[2] for meta in run.meta.values()}) >= 8
    assert len(run.meta) >= 9
    assert run.alert_count >= 15
    assert run.critical_count >= 3
    assert 60 <= run.org_risk <= 100


def test_full_demo_each_tool_shows_what_the_sot_says(runs):
    run = runs["full_demo"]
    assert {"SEC_OPENAI_KEY", "SEC_AWS_ACCESS_KEY", "SEC_AWS_SECRET_KEY"} <= set(run.rules("python3|openai"))
    support = run.rules("supportbot|anthropic")
    assert support.count("PII_CREDIT_CARD") == 3 and "PII_AADHAAR" in support and "PII_EMAIL" in support
    assert "SEC_JWT" in run.rules("node|mistral")
    assert run.rules("curl|huggingface") == ["POLICY_UNSANCTIONED_TOOL"]
    assert {"CODE_CONFIDENTIAL_MARKER", "SEC_DB_URL", "POLICY_LOCAL_LLM"} <= set(run.rules("python3|ollama"))
    assert run.rules("browser|chatgpt_web") == ["POLICY_UNSANCTIONED_TOOL"]
    assert {"AGENT_EXCESSIVE_AGENCY", "AGENT_DANGEROUS_CMD", "AGENT_SHELL_EXEC"} <= set(run.rules("autogpt|openai"))
    assert run.rules("cursor|anthropic").count("AGENT_SENSITIVE_FILE_READ") == 2
    assert run.rules("app|groq") == ["POLICY_UNSANCTIONED_TOOL"]
    assert run.rules("triage-bot|featherless") == ["POLICY_UNSANCTIONED_TOOL"]


def test_full_demo_native_keys_are_not_findings(runs):
    # Its own key is in every header; only the key pasted into a prompt counts.
    assert runs["full_demo"].rules("python3|openai").count("SEC_OPENAI_KEY") == 1


def test_browser_traffic_is_metadata_only():
    lines = [line for line in read_lines("full_demo") if line["host"] == "chatgpt.com"]
    assert lines and all(line["body"] is None and line["source"] == "pcap" for line in lines)


def test_agent_attack(runs):
    run = runs["agent_attack"]
    assert run.summary.accepted == 30 and run.summary.errors == []
    assert list(run.meta) == ["agentx|openai"]
    used = {a.capability.value for a in run.activity["agentx|openai"] if a.kind.value == "used"}
    assert {"shell", "fs_read", "network", "sensitive_file"} <= used
    agent_rules = [rule for rule in run.rules("agentx|openai") if rule.startswith("AGENT_")]
    assert len(agent_rules) >= 4
    assert "AGENT_DANGEROUS_CMD" in agent_rules and "AGENT_EGRESS_COMMAND" in agent_rules


# ---- the files themselves ----------------------------------------------------------

@pytest.mark.parametrize("name", SCENARIO_NAMES)
def test_template_file_is_up_to_date(name):
    assert (TEMPLATE_DIR / f"{name}.jsonl").read_text(encoding="utf-8") == render(name)


def test_every_scenario_has_a_generator():
    assert set(SCENARIOS) == set(SCENARIO_NAMES)


@pytest.mark.parametrize("name", SCENARIO_NAMES)
def test_template_holds_no_token_shaped_text(name):
    """AT-26: fakes appear only as placeholders in anything committed."""
    raw = (TEMPLATE_DIR / f"{name}.jsonl").read_text(encoding="utf-8")
    without_placeholders = re.sub(r"\{\{fake:[a-z0-9_]+(?:#\d+)?\}\}", "", raw)
    assert not re.search(r"sk-|AKIA|gh[pousr]_|hf_[A-Za-z0-9]|eyJ|xox[abprs]-|://[^/\s]+:[^/\s]+@", without_placeholders)


@pytest.mark.parametrize("name", SCENARIO_NAMES)
def test_lines_have_the_required_fields_and_rise_in_time(name):
    lines = read_lines(name)
    assert all({"host", "method", "path", "t_ms"} <= set(line) for line in lines)
    times = [line["t_ms"] for line in lines]
    assert times == sorted(times) and times[0] == 0


def test_no_placeholder_survives_loading():
    for name in SCENARIO_NAMES:
        assert all("{{fake:" not in str(line) for line in read_lines(name))


# ---- timing -------------------------------------------------------------------------

NOW = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)


def test_load_mode_ends_now():
    lines = schedule("quick_leak", NOW)
    assert lines[-1]["ts"] == "2026-10-31T12:00:00.000Z"
    assert lines[0]["ts"] == "2026-10-31T11:59:50.000Z"
    assert all("t_ms" not in line for line in lines)


def test_play_mode_starts_now_and_follows_speed():
    lines = schedule("quick_leak", NOW, speed=2.0)
    assert lines[0]["ts"] == "2026-10-31T12:00:00.000Z"
    assert lines[-1]["ts"] == "2026-10-31T12:00:05.000Z"
    assert duration_s("quick_leak", 2.0) == 5


def test_bad_speed_means_normal_speed():
    assert schedule("quick_leak", NOW, speed=0)[-1]["ts"] == "2026-10-31T12:00:10.000Z"
    assert duration_s("quick_leak", -1) == 10


@pytest.mark.parametrize("bad", ["nope", "../secrets", ""])
def test_unknown_scenario_is_rejected(bad):
    with pytest.raises(ValueError):
        read_lines(bad)

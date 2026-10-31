import re
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from shadowlens.config import Config
from shadowlens.core.ctx import AgentContexts
from shadowlens.core.pipeline import AnalysisResult, Pipeline
from shadowlens.db import DROPPED_NON_AI, Database
from shadowlens.ingest.http_log import ParseResult, parse_log
from shadowlens.models import (
    AgentActivity, Alert, EventLite, Finding, NetEvent, Visibility, new_id,
)
from shadowlens.providers.catalog import Catalog

CATALOG = Catalog.load()
SAMPLE = Path(__file__).resolve().parents[1] / "fixtures" / "sample_http.jsonl"
TS = "2026-10-31T10:00:00.000Z"


# ---- builders ----------------------------------------------------------------

def make_config(tmp_path, **env):
    return Config.load(env={"SHADOWLENS_RESOLVE": "false", **env}, base_dir=tmp_path, use_dotenv=False)


@pytest.fixture
def db(tmp_path):
    database = Database(tmp_path / "shadow.db")
    yield database
    database.close()


class Published:
    def __init__(self):
        self.items = []

    def __call__(self, kind, payload):
        self.items.append((kind, payload))

    def kinds(self):
        return [k for k, _ in self.items]

    def of(self, kind):
        return [p for k, p in self.items if k == kind]


def make_pipeline(tmp_path, db, analyze=None, resolver=None, **env):
    published = Published()
    pipeline = Pipeline(make_config(tmp_path, **env), db, CATALOG, resolver=resolver, analyze=analyze,
                        publish=published)
    return pipeline, published


def ev(host="api.openai.com", process="python3", body=None, n=0, **o):
    base = dict(id=new_id(), ts=f"2026-10-31T10:00:{n:02d}.000Z", source="http_log", process=process,
                dst_ip="203.0.113.7", dst_port=443, host=host, host_basis="host_header", method="POST",
                path="/v1/chat/completions", body_text=body, body_bytes=len(body or ""))
    base.update(o)
    return NetEvent(**base)


def mk_finding(rule="SEC_AWS_SECRET_KEY", category="secret", severity="critical", hash12="aaaaaaaaaaaa",
               field="body", **o):
    base = dict(id=new_id(), event_id=new_id(), tool_id="wrong|tool", rule_id=rule, category=category,
                severity=severity, confidence=0.9, masked_preview="AKIA... (len 40)",
                location={"field": field}, meta={"hash12": hash12, "context": "x"}, created_at=TS)
    base.update(o)
    return Finding(**base)


def analyzer(*findings, activity=(), calls=None):
    """A fake analyzer. Like a real one it makes brand-new findings (new ids) on every call."""
    def analyze(event, config, ctx):
        if calls is not None:
            calls.append((event.id, ctx.tool_id, ctx, config))
        fresh = [f.model_copy(update={"id": new_id()}) for f in findings]
        return AnalysisResult(findings=fresh, agent_activity=list(activity))
    return analyze


def rules_of(db):
    return sorted((f.rule_id, f.tool_id) for f in db.list_findings().items)


# ---- dropping and storing ----------------------------------------------------

def test_non_ai_events_are_dropped_and_counted(tmp_path, db):
    pipeline, published = make_pipeline(tmp_path, db)
    summary = pipeline.ingest([ev(host="github.com"), ev(host="www.google.com")], source="http_log")
    assert (summary.accepted, summary.dropped_non_ai, summary.skipped, summary.findings) == (0, 2, 0, 0)
    assert db.count_events() == 0 and db.get_counter(DROPPED_NON_AI) == 2 and published.items == []


def test_ai_events_are_stored_and_counted(tmp_path, db):
    pipeline, _ = make_pipeline(tmp_path, db)
    summary = pipeline.ingest([ev(), ev(host="github.com"), ev(host="api.anthropic.com")], source="http_log")
    assert (summary.accepted, summary.dropped_non_ai) == (2, 1)
    assert {e.provider_id for e in db.list_events().items} == {"openai", "anthropic"}


def test_summary_carries_the_source_skipped_count_and_errors(tmp_path, db):
    pipeline, _ = make_pipeline(tmp_path, db)
    summary = pipeline.ingest([ev()], source="har", skipped=3, errors=["line 2: bad"])
    assert (summary.source, summary.skipped, summary.errors) == ("har", 3, ["line 2: bad"])
    many = pipeline.ingest([], source="x", errors=[f"e{i}" for i in range(50)])
    assert len(many.errors) == 20


def test_bodies_headers_and_queries_never_reach_the_database(tmp_path):
    path = tmp_path / "private.db"
    database = Database(path)
    pipeline, _ = make_pipeline(tmp_path, database)
    pipeline.ingest([ev(body="BODYMARKER prompt", query="key=QUERYMARKER",
                        headers={"Authorization": "Bearer HEADERMARKER"})], source="http_log")
    assert database.count_events() == 1
    database.close()
    for suffix in ("", "-wal", "-shm"):
        candidate = Path(str(path) + suffix)
        if candidate.exists():
            data = candidate.read_bytes()
            assert not any(m in data for m in (b"BODYMARKER", b"QUERYMARKER", b"HEADERMARKER"))


def test_event_new_carries_a_summary_of_the_event(tmp_path, db):
    pipeline, published = make_pipeline(tmp_path, db)
    event = ev(body="hello", n=5)
    pipeline.ingest([event], source="http_log")
    lite = published.of("event.new")[0]
    assert isinstance(lite, EventLite)
    assert (lite.id, lite.tool_id, lite.provider_id, lite.visibility, lite.body_bytes) == (
        event.id, "python3|openai", "openai", Visibility.FULL, 5)
    assert lite.finding_count == 1                                  # the policy finding


# ---- policy findings ---------------------------------------------------------

def test_an_unapproved_tool_gets_one_policy_finding_and_alert_ever(tmp_path, db):
    pipeline, published = make_pipeline(tmp_path, db)
    first = pipeline.ingest([ev(n=1)], source="http_log")
    again = pipeline.ingest([ev(n=2), ev(n=3)], source="http_log")
    assert (first.findings, first.alerts, again.findings, again.alerts) == (1, 1, 0, 0)
    alert = db.list_alerts().items[0]
    assert alert.rule_id == "POLICY_UNSANCTIONED_TOOL" and alert.severity.value == "low"
    assert alert.title == "Unapproved AI tool in use: OpenAI" and alert.provider_id == "openai"
    other_tool = pipeline.ingest([ev(process="curl", n=4)], source="http_log")
    assert (other_tool.findings, other_tool.alerts) == (1, 1)       # a different tool is its own case


def test_a_local_model_that_is_approved_gets_only_the_local_model_finding(tmp_path, db):
    pipeline, _ = make_pipeline(tmp_path, db)
    event = ev(host="localhost:11434", dst_ip="127.0.0.1", dst_port=11434, process="python3")
    summary = pipeline.ingest([event], source="http_log")                   # ollama is approved by default
    assert rules_of(db) == [("POLICY_LOCAL_LLM", "python3|ollama")]
    assert (summary.findings, summary.alerts) == (1, 0)                     # low severity and approved: no alert


def test_a_local_model_that_is_not_approved_gets_both_findings_and_one_alert(tmp_path, db):
    pipeline, _ = make_pipeline(tmp_path, db)
    event = ev(host="localhost:1234", dst_ip="127.0.0.1", dst_port=1234, process="lmstudio")
    summary = pipeline.ingest([event], source="http_log")
    assert rules_of(db) == [("POLICY_LOCAL_LLM", "lmstudio|lmstudio"), ("POLICY_UNSANCTIONED_TOOL", "lmstudio|lmstudio")]
    assert (summary.findings, summary.alerts) == (2, 1)


def test_the_sanctioned_list_in_the_config_is_respected(tmp_path, db):
    pipeline, _ = make_pipeline(tmp_path, db, SHADOWLENS_SANCTIONED="openai, ollama")
    summary = pipeline.ingest([ev()], source="http_log")
    assert (summary.findings, summary.alerts) == (0, 0)


def test_a_manual_choice_beats_the_default_list(tmp_path, db):
    db.set_provider_override("ollama", False)           # approved by default, switched off by hand
    db.set_provider_override("openai", True)            # not approved by default, switched on by hand
    pipeline, _ = make_pipeline(tmp_path, db)
    assert pipeline.is_sanctioned("ollama") is False and pipeline.is_sanctioned("openai") is True
    assert pipeline.is_sanctioned("groq") is False                         # no override, not on the list
    pipeline.ingest([ev(), ev(host="localhost:11434", dst_ip="127.0.0.1", dst_port=11434, process="p")],
                    source="http_log")
    assert rules_of(db) == [("POLICY_LOCAL_LLM", "p|ollama"), ("POLICY_UNSANCTIONED_TOOL", "p|ollama")]


def test_a_medium_confidence_match_lowers_the_policy_confidence(tmp_path, db):
    pipeline, _ = make_pipeline(tmp_path, db)
    pipeline.ingest([ev(host=None, dst_ip="127.0.0.1", dst_port=8080, path="/v1/chat/completions", process="x")],
                    source="http_log")
    assert {f.confidence for f in db.list_findings().items} == {0.6}
    assert len(db.list_findings().items) == 2


def test_a_low_confidence_guess_is_stored_but_creates_nothing_else(tmp_path, db):
    calls = []
    resolver = SimpleNamespace(ip_map={"198.51.100.2": "anthropic"})
    pipeline, published = make_pipeline(tmp_path, db, analyze=analyzer(mk_finding(), calls=calls), resolver=resolver)
    guess = ev(host=None, dst_ip="198.51.100.2", process="somescript", body="has a body")
    summary = pipeline.ingest([guess], source="conn_scan")
    assert (summary.accepted, summary.findings, summary.alerts) == (1, 0, 0)
    assert calls == [] and db.count_findings() == 0                         # not even analysed
    assert db.list_events().items[0].tool_id == "somescript|anthropic" and published.kinds() == ["event.new"]


# ---- the analyzer ------------------------------------------------------------

def test_analyzer_runs_only_for_readable_events(tmp_path, db):
    calls = []
    pipeline, _ = make_pipeline(tmp_path, db, analyze=analyzer(calls=calls))
    pipeline.ingest([ev(body=None), ev(body="text", n=1)], source="http_log")
    assert len(calls) == 1


def test_analyzer_gets_the_event_the_config_and_a_persistent_context(tmp_path, db):
    calls = []
    pipeline, _ = make_pipeline(tmp_path, db, analyze=analyzer(calls=calls))
    e1, e2 = ev(body="a"), ev(body="b", n=1)
    pipeline.ingest([e1, e2, ev(process="curl", body="c", n=2)], source="http_log")
    assert [c[1] for c in calls] == ["python3|openai", "python3|openai", "curl|openai"]
    assert calls[0][2] is calls[1][2] and calls[0][2] is not calls[2][2]    # one memory per tool
    assert calls[0][0] == e1.id and calls[0][3] is pipeline.config


def test_findings_are_stored_with_the_right_identity(tmp_path, db):
    event = ev(body="x")
    pipeline, published = make_pipeline(tmp_path, db, analyze=analyzer(mk_finding()))
    pipeline.ingest([event], source="http_log")
    stored = [f for f in db.list_findings().items if f.rule_id == "SEC_AWS_SECRET_KEY"][0]
    assert (stored.event_id, stored.tool_id) == (event.id, "python3|openai")       # stamped by the pipeline


@pytest.mark.parametrize("severity,alert", [("info", False), ("low", False), ("medium", True),
                                            ("high", True), ("critical", True)])
def test_only_medium_and_above_findings_raise_alerts(tmp_path, db, severity, alert):
    pipeline, _ = make_pipeline(tmp_path, db, analyze=analyzer(mk_finding(severity=severity)),
                                SHADOWLENS_SANCTIONED="openai")        # no policy noise
    summary = pipeline.ingest([ev(body="x")], source="http_log")
    assert (summary.findings, summary.alerts) == (1, int(alert))


def test_the_same_finding_in_later_events_is_not_counted_again(tmp_path, db):
    pipeline, published = make_pipeline(tmp_path, db, analyze=analyzer(mk_finding()), SHADOWLENS_SANCTIONED="openai")
    a = pipeline.ingest([ev(body="x", n=1)], source="http_log")
    b = pipeline.ingest([ev(body="x", n=2)], source="http_log")             # the conversation is re-sent
    assert (a.findings, a.alerts, b.findings, b.alerts) == (1, 1, 0, 0)
    assert db.count_findings() == 1 and len(published.of("alert.new")) == 1
    assert published.of("event.new")[1].finding_count == 0


def test_the_same_leak_sent_again_brings_its_alert_back_without_a_second_finding(tmp_path, db, monkeypatch):
    from shadowlens.core import pipeline as module
    monkeypatch.setattr(module, "REPEAT_ALERT_GAP_S", 0.0)
    pipeline, published = make_pipeline(tmp_path, db, analyze=analyzer(mk_finding()), SHADOWLENS_SANCTIONED="openai")
    first = pipeline.ingest([ev(body="x", n=1)], source="http_log")
    original = db.list_alerts().items[0]
    db.ack_alert(original.id)
    again = pipeline.ingest([ev(body="x", n=2)], source="http_log")
    assert (first.findings, first.alerts, again.findings, again.alerts) == (1, 1, 0, 0)      # nothing is counted twice
    assert db.count_findings() == 1 and db.count_open_alerts() == 1
    refreshed = db.list_alerts().items[0]
    assert refreshed.id == original.id and refreshed.status.value == "open" and refreshed.acked_at is None
    assert refreshed.created_at >= original.created_at
    pushed = published.of("alert.new")
    assert len(pushed) == 2 and pushed[1].id == original.id                                   # the toast fires again


def test_a_burst_of_the_same_leak_is_one_occurrence(tmp_path, db):
    pipeline, published = make_pipeline(tmp_path, db, analyze=analyzer(mk_finding()), SHADOWLENS_SANCTIONED="openai")
    pipeline.ingest([ev(body="x", n=i) for i in range(1, 6)], source="http_log")
    assert len(published.of("alert.new")) == 1


def test_a_repeat_does_not_change_the_score(tmp_path, db, monkeypatch):
    from shadowlens.core import pipeline as module
    monkeypatch.setattr(module, "REPEAT_ALERT_GAP_S", 0.0)
    pipeline, _ = make_pipeline(tmp_path, db, analyze=analyzer(mk_finding()), SHADOWLENS_SANCTIONED="openai")
    pipeline.ingest([ev(body="x", n=1)], source="http_log")
    before = [f.model_dump() for f in db.list_findings().items]
    pipeline.ingest([ev(body="x", n=2)], source="http_log")
    assert [f.model_dump() for f in db.list_findings().items] == before


def test_the_once_per_tool_policy_alert_does_not_repeat(tmp_path, db, monkeypatch):
    from shadowlens.core import pipeline as module
    monkeypatch.setattr(module, "REPEAT_ALERT_GAP_S", 0.0)
    pipeline, published = make_pipeline(tmp_path, db, analyze=analyzer())
    pipeline.ingest([ev(body="x", n=1)], source="http_log")
    pipeline.ingest([ev(body="x", n=2)], source="http_log")
    assert [a.rule_id for a in published.of("alert.new")] == ["POLICY_UNSANCTIONED_TOOL"]


def test_a_different_value_or_tool_is_a_new_finding(tmp_path, db):
    findings = [mk_finding(hash12="aaaaaaaaaaaa"), mk_finding(hash12="bbbbbbbbbbbb")]
    pipeline, _ = make_pipeline(tmp_path, db, analyze=analyzer(*findings), SHADOWLENS_SANCTIONED="openai")
    pipeline.ingest([ev(body="x"), ev(body="x", process="curl", n=1)], source="http_log")
    assert db.count_findings() == 4


@pytest.mark.parametrize("make_result", [
    lambda f: AnalysisResult(findings=[f]),
    lambda f: {"findings": [f], "agent_activity": []},
    lambda f: SimpleNamespace(findings=[f], agent_activity=[]),
    lambda f: {"findings": [f.model_dump(mode="json")]},                     # a plain dict is validated
])
def test_several_result_shapes_are_accepted(tmp_path, db, make_result):
    finding = mk_finding()
    pipeline, _ = make_pipeline(tmp_path, db, analyze=lambda e, c, x: make_result(finding),
                                SHADOWLENS_SANCTIONED="openai")
    assert pipeline.ingest([ev(body="x")], source="http_log").findings == 1


def test_empty_or_missing_results_are_fine(tmp_path, db):
    for result in (None, {}, SimpleNamespace(), AnalysisResult()):
        pipeline, _ = make_pipeline(tmp_path, db, analyze=lambda e, c, x, r=result: r, SHADOWLENS_SANCTIONED="openai")
        assert pipeline.ingest([ev(body="x")], source="http_log").findings == 0


def test_policy_findings_from_the_analyzer_are_ignored(tmp_path, db):
    fake_policy = mk_finding(rule="POLICY_LOCAL_LLM", category="policy", severity="low")
    pipeline, _ = make_pipeline(tmp_path, db, analyze=analyzer(fake_policy), SHADOWLENS_SANCTIONED="openai")
    assert pipeline.ingest([ev(body="x")], source="http_log").findings == 0


def test_the_providers_own_key_in_its_own_header_is_not_a_finding(tmp_path, db):
    openai_key = mk_finding(rule="SEC_OPENAI_KEY", severity="high", field="header:authorization")
    anthropic_key = mk_finding(rule="SEC_ANTHROPIC_KEY", severity="high", field="header:x-api-key", hash12="bbbbbbbbbbbb")
    jwt = mk_finding(rule="SEC_JWT", severity="high", field="header:authorization", hash12="cccccccccccc")
    body_key = mk_finding(rule="SEC_OPENAI_KEY", severity="high", field="body", hash12="dddddddddddd")
    pipeline, _ = make_pipeline(tmp_path, db, analyze=analyzer(openai_key, anthropic_key, jwt, body_key),
                                SHADOWLENS_SANCTIONED="openai,anthropic,mistral")
    pipeline.ingest([ev(host="api.openai.com", body="x")], source="http_log")
    stored = {(f.rule_id, f.location.field.value) for f in db.list_findings().items}
    assert ("SEC_OPENAI_KEY", "header:authorization") not in stored          # its own key, its own header
    assert ("SEC_OPENAI_KEY", "body") in stored                              # a key in the body is always a finding
    assert ("SEC_JWT", "header:authorization") in stored                     # a different kind of credential
    assert ("SEC_ANTHROPIC_KEY", "header:x-api-key") in stored               # Anthropic's key sent to OpenAI

    pipeline.ingest([ev(host="api.anthropic.com", body="x", process="sb", n=9)], source="http_log")
    anthropic_tool = {(f.rule_id, f.location.field.value) for f in db.list_findings().items if f.tool_id == "sb|anthropic"}
    assert ("SEC_ANTHROPIC_KEY", "header:x-api-key") not in anthropic_tool   # native for Anthropic


def test_a_failing_analyzer_does_not_stop_ingest(tmp_path, db):
    def broken(event, config, ctx):
        raise RuntimeError("SECRETMARKER inside the analyzer")

    pipeline, _ = make_pipeline(tmp_path, db, analyze=broken)
    summary = pipeline.ingest([ev(body="x"), ev(host="api.anthropic.com", body="y", n=1)], source="http_log")
    assert (summary.accepted, summary.skipped) == (2, 0)
    assert summary.errors == ["analysis failed for one event", "analysis failed for one event"]
    assert all("SECRETMARKER" not in e for e in summary.errors)
    assert summary.findings == 2                                             # the policy findings still happen


def test_agent_activity_is_stored_and_unknown_finding_links_are_cleared(tmp_path, db):
    created = {}

    def agent_analyzer(event, config, ctx):
        finding = mk_finding(rule="AGENT_DANGEROUS_CMD", category="agent")      # as a real analyzer: its own ids
        created["id"] = finding.id
        return AnalysisResult(findings=[finding], agent_activity=[
            AgentActivity(ts=TS, capability="shell", kind="used", risky=True, name="bash",
                          rule_id="AGENT_DANGEROUS_CMD", finding_id=finding.id, argument="curl x | sh"),
            AgentActivity(ts=TS, capability="shell", kind="used", name="bash", finding_id=new_id()),
            AgentActivity(ts=TS, capability="fs_read", kind="granted", name="read_file"),
        ])

    pipeline, _ = make_pipeline(tmp_path, db, analyze=agent_analyzer)
    pipeline.ingest([ev(body="x", process="autogpt")], source="http_log")
    stored = db.list_agent_activity("autogpt|openai")
    assert [a.name for a in stored] == ["bash", "bash", "read_file"]
    assert stored[0].finding_id == created["id"]                             # the link to a stored finding is kept
    assert stored[1].finding_id is None                                      # the link to a finding we do not have is dropped


# ---- the live stream ---------------------------------------------------------

def test_messages_are_published_in_a_sensible_order(tmp_path, db):
    pipeline, published = make_pipeline(tmp_path, db, analyze=analyzer(mk_finding()))
    pipeline.ingest([ev(body="x")], source="http_log")
    kinds = published.kinds()
    assert kinds[0] == "event.new"
    assert kinds.count("finding.new") == 2 and kinds.count("alert.new") == 2     # the key + the policy finding
    for i, kind in enumerate(kinds):
        if kind == "alert.new":
            assert kinds[i - 1] == "finding.new"                                 # each alert follows its finding
    assert isinstance(published.of("finding.new")[0], Finding) and isinstance(published.of("alert.new")[0], Alert)


def test_nothing_is_published_for_an_event_that_failed_to_store(tmp_path, db, monkeypatch):
    pipeline, published = make_pipeline(tmp_path, db)
    real = db.insert_alert
    calls = {"n": 0}

    def flaky(alert):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("disk full")
        return real(alert)

    monkeypatch.setattr(db, "insert_alert", flaky)
    summary = pipeline.ingest([ev(n=1), ev(host="api.anthropic.com", n=2)], source="http_log")
    assert (summary.accepted, summary.skipped, summary.errors) == (1, 1, ["an event could not be stored"])
    assert db.count_events() == 1                                     # the failed event was rolled back completely
    assert db.count_findings() == 1
    assert [e.provider_id for e in published.of("event.new")] == ["anthropic"]   # and never announced


def test_a_broken_listener_does_not_break_ingest(tmp_path, db):
    def explode(kind, payload):
        raise RuntimeError("listener bug")

    pipeline = Pipeline(make_config(tmp_path), db, CATALOG, publish=explode)
    assert pipeline.ingest([ev()], source="http_log").accepted == 1


def test_after_batch_hook_runs_once_per_ingest_and_cannot_break_it(tmp_path, db):
    count = {"n": 0}

    def hook():
        count["n"] += 1
        raise RuntimeError("scoring bug")

    pipeline = Pipeline(make_config(tmp_path), db, CATALOG, after_batch=hook)
    pipeline.ingest([ev(), ev(n=1)], source="http_log")
    pipeline.ingest([], source="http_log")
    assert count["n"] == 2


# ---- whole files -------------------------------------------------------------

def test_ingest_log_uses_the_parse_result(tmp_path, db):
    pipeline, _ = make_pipeline(tmp_path, db)
    result = ParseResult(events=[ev()], skipped=2, errors=["line 4: bad"], format="har")
    summary = pipeline.ingest_log(result)
    assert (summary.source, summary.accepted, summary.skipped, summary.errors) == ("har", 1, 2, ["line 4: bad"])


def test_the_sample_file_end_to_end(tmp_path, db):
    pipeline, published = make_pipeline(tmp_path, db)
    summary = pipeline.ingest_log(parse_log(SAMPLE.read_text(encoding="utf-8")))
    assert summary.model_dump() == {"source": "http_log", "accepted": 17, "skipped": 0, "dropped_non_ai": 3,
                                    "findings": 15, "alerts": 13, "errors": []}
    assert db.count_events() == 17 and db.get_counter(DROPPED_NON_AI) == 3
    assert len(published.of("event.new")) == 17
    unapproved = {f.tool_id for f in db.list_findings(rule_id="POLICY_UNSANCTIONED_TOOL").items}
    assert len(unapproved) == 13 and "python3|ollama" not in unapproved      # Ollama is approved by default
    assert {f.tool_id for f in db.list_findings(rule_id="POLICY_LOCAL_LLM").items} == {
        "python3|ollama", "lmstudio-client|lmstudio"}


# ---- reset and threads -------------------------------------------------------

def test_reset_clears_results_and_agent_memory(tmp_path, db):
    pipeline, published = make_pipeline(tmp_path, db, analyze=analyzer(calls=[]))
    pipeline.ingest([ev(body="x")], source="http_log")
    db.set_provider_override("openai", True)
    pipeline.contexts.get("python3|openai").seen_calls.add("abc")
    pipeline.reset()
    assert db.count_events() == 0 and db.count_findings() == 0 and db.get_provider_overrides() == {}
    assert pipeline.contexts.tool_ids() == [] and published.kinds()[-1] == "reset"
    assert pipeline.ingest([ev()], source="http_log").alerts == 1             # works again, policy alert is new


def test_concurrent_ingests_do_not_lose_or_duplicate_anything(tmp_path, db):
    pipeline, _ = make_pipeline(tmp_path, db)
    errors = []

    def worker(index):
        try:
            for n in range(25):
                pipeline.ingest([ev(n=n % 60, process=f"tool{index}")], source="http_log")
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert db.count_events() == 100
    assert db.list_findings(rule_id="POLICY_UNSANCTIONED_TOOL").total == 4    # one per tool, however many events
    assert db.list_alerts().total == 4


def test_contexts_registry():
    contexts = AgentContexts()
    first = contexts.get("a|b")
    assert contexts.get("a|b") is first and first.seen_calls == set() and first.granted == set()
    contexts.get("c|d")
    assert contexts.tool_ids() == ["a|b", "c|d"]
    contexts.reset()
    assert contexts.tool_ids() == [] and contexts.get("a|b") is not first

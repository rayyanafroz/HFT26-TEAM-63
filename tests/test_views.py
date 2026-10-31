import math
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from shadowlens.config import Config
from shadowlens.core.pipeline import AnalysisResult, Pipeline
from shadowlens.core.views import MAX_BUCKETS, Insights
from shadowlens.db import Database
from shadowlens.ingest.http_log import parse_log
from shadowlens.models import AgentActivity, Band, Finding, MatchConfidence, NetEvent, Severity, new_id
from shadowlens.providers.catalog import Catalog

CATALOG = Catalog.load()
SAMPLE = Path(__file__).resolve().parents[1] / "fixtures" / "sample_http.jsonl"
TS = "2026-10-31T10:00:00.000Z"


def make_config(tmp_path, **env):
    return Config.load(env={"SHADOWLENS_RESOLVE": "false", **env}, base_dir=tmp_path, use_dotenv=False)


@pytest.fixture
def db(tmp_path):
    database = Database(tmp_path / "shadow.db")
    yield database
    database.close()


def ev(host="api.openai.com", process="python3", body="x", ts=TS, **o):
    base = dict(id=new_id(), ts=ts, source="http_log", process=process, dst_ip="203.0.113.7", dst_port=443,
                host=host, host_basis="host_header", method="POST", path="/v1/chat/completions",
                body_text=body, body_bytes=len(body or ""), bytes_out=100)
    base.update(o)
    return NetEvent(**base)


def leak(rule="SEC_AWS_SECRET_KEY", severity="critical", confidence=0.9, category="secret", hash12="aaaaaaaaaaaa"):
    return Finding(id=new_id(), event_id=new_id(), tool_id="x|y", rule_id=rule, category=category,
                   severity=severity, confidence=confidence, masked_preview="AKIA... (len 40)",
                   location={"field": "body"}, meta={"hash12": hash12, "context": "c"}, created_at=TS)


def analyzer(*findings, activity=()):
    def analyze(event, config, ctx):
        return AnalysisResult(findings=[f.model_copy(update={"id": new_id()}) for f in findings],
                              agent_activity=list(activity))
    return analyze


class Setup:
    """A pipeline and the insights over the same database."""

    def __init__(self, tmp_path, db, analyze=None, resolver=None, scenario=None, **env):
        self.config = make_config(tmp_path, **env)
        self.db = db
        self.pipeline = Pipeline(self.config, db, CATALOG, analyze=analyze, resolver=resolver)
        self.insights = Insights(self.config, db, CATALOG, scenario=scenario)

    def ingest(self, *events):
        return self.pipeline.ingest(list(events), source="http_log")


@pytest.fixture
def setup(tmp_path, db):
    return lambda **kw: Setup(tmp_path, db, **kw)


# ---- tools and the score -----------------------------------------------------

def test_the_quick_leak_numbers_end_to_end(setup):
    s = setup(analyze=analyzer(leak()))                  # one AWS secret + the unapproved-tool policy finding
    s.ingest(ev())
    tool = s.insights.tools()[0]
    assert (tool.tool_id, tool.risk, tool.risk_band) == ("python3|openai", 52, Band.HIGH)     # SOT 7.5 case 5: S = 58.5
    assert (tool.finding_counts.critical, tool.finding_counts.low, tool.finding_counts.high) == (1, 1, 0)
    risk = s.insights.risk()
    assert (risk.org_risk, risk.compliance_score, risk.band) == (52, 48, Band.HIGH)            # SOT 8.2: quick_leak = 52


def test_tool_details(setup):
    s = setup()
    s.ingest(ev(ts="2026-10-31T10:00:05.000Z", bytes_out=100), ev(ts="2026-10-31T10:00:01.000Z", body=None, bytes_out=50))
    tool = s.insights.tools()[0]
    assert (tool.process, tool.provider_id, tool.display_name) == ("python3", "openai", "python3 → OpenAI")
    assert (tool.event_count, tool.bytes_out, tool.confidence, tool.unconfirmed) == (2, 150, MatchConfidence.HIGH, False)
    assert (tool.first_seen, tool.last_seen) == ("2026-10-31T10:00:01.000Z", "2026-10-31T10:00:05.000Z")
    assert (tool.visibility.full, tool.visibility.metadata_only, tool.sanctioned) == (1, 1, False)


def test_bytes_out_is_unknown_when_no_event_says(setup):
    s = setup()
    s.ingest(ev(bytes_out=None))
    assert s.insights.tools()[0].bytes_out is None


def test_approving_a_provider_rescores_everything_immediately(setup):
    s = setup(analyze=analyzer(leak()))
    s.ingest(ev())
    assert s.insights.risk().org_risk == 52
    s.db.set_provider_override("openai", True)           # no new events: only the approval changed
    approved = s.insights.tools()[0]
    assert (approved.sanctioned, approved.risk) == (True, 31)                  # S = 58.5 x 0.5 = 29.25
    assert s.insights.risk().org_risk == 31
    s.db.set_provider_override("openai", False)
    assert s.insights.risk().org_risk == 52


def test_local_models_count_less_because_they_stay_on_the_machine(setup):
    s = setup(analyze=analyzer(leak()))
    s.ingest(ev(host="localhost:1234", dst_ip="127.0.0.1", dst_port=1234, process="lmstudio"))
    tool = s.insights.tools()[0]
    assert tool.tool_id == "lmstudio|lmstudio"
    # 21.6 (critical) + 1.8 (unapproved) + 1.8 (local model), all x 0.4
    assert tool.risk == round(100 * (1 - math.exp(-25.2 / 80)))
    assert s.insights.score_explain("lmstudio|lmstudio").S == pytest.approx(25.2)


def test_a_guess_is_listed_but_scores_nothing_and_stays_out_of_the_org_score(setup):
    resolver = SimpleNamespace(ip_map={"198.51.100.2": "anthropic"})
    s = setup(analyze=analyzer(leak()), resolver=resolver)
    s.ingest(ev(host=None, dst_ip="198.51.100.2", process="claude"), ev(host="api.groq.com", process="app"))
    guess = next(t for t in s.insights.tools() if t.provider_id == "anthropic")
    assert (guess.unconfirmed, guess.confidence, guess.risk) == (True, MatchConfidence.LOW, 0)
    org = s.insights.org()
    assert org.max_tool_score == max(t.risk for t in s.insights.tools() if not t.unconfirmed)
    assert s.insights.summary().unsanctioned_tools == 1                         # only the confirmed one


def test_tools_are_listed_riskiest_first(setup):
    s = setup(analyze=lambda e, c, x: AnalysisResult(
        findings=[leak(hash12=("a" * 11) + str(i % 10)) for i in range(4)] if e.process == "bad" else []))
    s.ingest(ev(process="quiet"), ev(process="bad"), ev(process="other", host="api.groq.com"))
    assert [t.process for t in s.insights.tools()][0] == "bad"
    risks = [t.risk for t in s.insights.tools()]
    assert risks == sorted(risks, reverse=True)


def test_the_org_score_blends_the_worst_tool_with_the_top_three(setup):
    def by_process(event, config, ctx):
        n = {"worst": 4, "middle": 1}.get(event.process, 0)
        return AnalysisResult(findings=[leak(hash12=f"{i:012x}") for i in range(n)])

    s = setup(analyze=by_process)
    s.ingest(ev(process="worst"), ev(process="middle", host="api.groq.com"), ev(process="calm", host="api.mistral.ai"))
    scores = sorted((t.risk for t in s.insights.tools()), reverse=True)
    org = s.insights.org()
    assert org.max_tool_score == scores[0] and org.mean_top3 == round(sum(scores[:3]) / 3, 2)


def test_an_empty_database_is_all_zeros(setup):
    s = setup()
    assert s.insights.tools() == [] and s.insights.agents() == []
    risk = s.insights.risk()
    assert (risk.org_risk, risk.compliance_score, risk.band) == (0, 100, Band.LOW)
    summary = s.insights.summary()
    assert summary.totals.events == 0 and summary.top_tools == [] and summary.last_event_at is None


# ---- the cache ---------------------------------------------------------------

def test_results_are_reused_until_something_is_written(setup):
    s = setup()
    s.ingest(ev())
    first = s.insights.tools()[0]
    assert s.insights.tools()[0] is first                                      # same object: served from the cache
    s.ingest(ev(ts="2026-10-31T10:00:09.000Z"))
    assert s.insights.tools()[0] is not first and s.insights.tools()[0].event_count == 2


def test_recomputing_a_large_database_is_fast(setup, tmp_path):
    s = setup(analyze=lambda e, c, x: AnalysisResult(findings=[leak(hash12=f"{abs(hash(e.id)) % 10**12:012d}")]))
    s.ingest(*[ev(process=f"tool{i % 20}", ts=f"2026-10-31T10:{i % 60:02d}:00.000Z") for i in range(800)])
    s.db.set_provider_override("openai", True)                                 # invalidates the cache
    started = time.perf_counter()
    s.insights.summary()
    s.insights.graph()
    s.insights.score_explain()
    assert time.perf_counter() - started < 1.0                                 # SOT 6.7: re-score well under a second


# ---- agents ------------------------------------------------------------------

def act(n, capability, kind="used", risky=False, name="bash"):
    return AgentActivity(ts=f"2026-10-31T10:00:{n:02d}.000Z", capability=capability, kind=kind, risky=risky, name=name)


def test_only_tools_with_capabilities_appear_in_the_agent_matrix(setup):
    activity = [act(1, "shell", "granted"), act(2, "fs_read", "granted", name="read_file"),
                act(3, "shell", "used", risky=True), act(4, "sensitive_file", "used", risky=True, name="read_file")]
    s = setup(analyze=lambda e, c, x: AnalysisResult(agent_activity=activity if e.process == "autogpt" else []))
    s.ingest(ev(process="autogpt"), ev(process="plain", host="api.groq.com"))
    rows = s.insights.agents()
    assert [r.tool_id for r in rows] == ["autogpt|openai"]
    caps = rows[0].capabilities
    assert (caps.shell.granted, caps.shell.used, caps.shell.risky) == (True, True, True)
    assert (caps.fs_read.granted, caps.fs_read.used, caps.fs_read.risky) == (True, False, False)
    assert (caps.sensitive_file.granted, caps.sensitive_file.used, caps.sensitive_file.risky) == (False, True, True)
    assert (caps.network.granted, caps.network.used, caps.mcp.used) == (False, False, False)
    assert [a.ts[-7:-5] for a in rows[0].activity] == ["01", "02", "03", "04"]    # oldest first
    assert rows[0].risk == next(t.risk for t in s.insights.tools() if t.process == "autogpt")
    plain = next(t for t in s.insights.tools() if t.process == "plain")
    assert not plain.capabilities.shell.granted


# ---- providers ---------------------------------------------------------------

def test_every_catalog_provider_is_listed_with_its_usage(setup):
    s = setup()
    s.ingest(ev(), ev(ts="2026-10-31T10:00:09.000Z"), ev(host="api.groq.com", process="app"),
             ev(host="localhost:11434", dst_ip="127.0.0.1", dst_port=11434, process="py"))
    rows = s.insights.providers()
    assert len(rows) == 27
    seen = [r for r in rows if r.seen]
    assert {r.provider_id for r in seen} == {"openai", "groq", "ollama"}
    assert rows[0].provider_id == "openai" and rows[0].event_count == 2 and rows[0].tool_count == 1   # seen first, busiest first
    assert all(not r.seen for r in rows[3:]) and rows[-1].event_count == 0 and rows[-1].last_seen is None
    openai = s.insights.provider("openai")
    assert (openai.sanctioned, openai.sanction_source.value, openai.confirmed) == (False, "default", True)
    ollama = s.insights.provider("ollama")
    assert (ollama.sanctioned, ollama.sanction_source.value) == (True, "default")             # the SOT's default list
    assert s.insights.provider("nobody") is None


def test_filtering_providers_by_seen(setup):
    s = setup()
    s.ingest(ev())
    assert len(s.insights.providers(seen=True)) == 1 and len(s.insights.providers(seen=False)) == 26
    assert len(s.insights.providers(seen=None)) == 27


def test_a_manual_approval_is_reported_as_an_override(setup):
    s = setup()
    s.db.set_provider_override("openai", True)
    s.db.set_provider_override("ollama", False)
    assert (s.insights.provider("openai").sanctioned, s.insights.provider("openai").sanction_source.value) == (True, "override")
    assert (s.insights.provider("ollama").sanctioned, s.insights.provider("ollama").sanction_source.value) == (False, "override")
    assert s.insights.provider("groq").sanction_source.value == "default"


def test_a_provider_seen_only_through_a_guess_is_not_confirmed(setup):
    s = setup(resolver=SimpleNamespace(ip_map={"198.51.100.2": "anthropic"}))
    s.ingest(ev(host=None, dst_ip="198.51.100.2", process="claude"))
    row = s.insights.provider("anthropic")
    assert (row.seen, row.confirmed) == (True, False)


# ---- summary -----------------------------------------------------------------

def test_the_summary_adds_everything_up(setup):
    s = setup(analyze=analyzer(leak()), scenario=lambda: "quick_leak")
    s.ingest(ev(), ev(host="github.com"), ev(host="api.anthropic.com", process="bot"))
    summary = s.insights.summary()
    assert (summary.totals.events, summary.totals.ai_events, summary.totals.dropped_non_ai) == (3, 2, 1)
    assert (summary.totals.tools, summary.totals.providers) == (2, 2)
    assert summary.totals.findings == 4 and summary.totals.alerts_open == 4          # 2 keys + 2 unapproved-tool policy
    assert summary.alerts_by_severity.model_dump() == {"critical": 2, "high": 0, "medium": 0, "low": 2}
    assert summary.findings_by_category.model_dump() == {"secret": 2, "pii": 0, "code": 0, "agent": 0, "policy": 2}
    assert [(p.provider_id, p.count) for p in summary.events_by_provider] == [("anthropic", 1), ("openai", 1)]
    assert summary.unsanctioned_tools == 2
    assert (summary.coverage.full, summary.coverage.metadata_only) == (2, 0)
    assert [t.risk for t in summary.top_tools] == [52, 52] and summary.risk.org_risk == 52
    assert (summary.llm.mode.value, summary.llm.sent) == ("template", 0)
    assert summary.scenario == "quick_leak" and summary.last_event_at == TS


def test_acknowledged_alerts_leave_the_open_counts(setup):
    s = setup(analyze=analyzer(leak()))
    s.ingest(ev())
    for alert in s.db.list_alerts(severity=["critical"]).items:
        s.db.ack_alert(alert.id)
    summary = s.insights.summary()
    assert summary.totals.alerts_open == 1 and summary.alerts_by_severity.critical == 0
    assert summary.totals.findings == 2                                              # findings stay


def test_top_tools_is_capped_and_skips_zero_risk(setup):
    s = setup()
    s.ingest(*[ev(process=f"t{i}") for i in range(8)], ev(host="localhost:11434", dst_ip="127.0.0.1", dst_port=11434, process="o"))
    summary = s.insights.summary()
    assert len(summary.top_tools) == 5 and all(t.risk > 0 for t in summary.top_tools)


# ---- time series -------------------------------------------------------------

def test_buckets_cover_the_whole_range_including_quiet_minutes(setup):
    s = setup(analyze=analyzer(leak(severity="high")))
    s.ingest(ev(ts="2026-10-31T10:00:05.000Z"), ev(ts="2026-10-31T10:00:50.000Z", process="b"),
             ev(ts="2026-10-31T10:03:10.000Z", process="c"))
    series = s.insights.timeseries(bucket_s=60)
    assert [(b.t, b.events) for b in series.buckets] == [
        ("2026-10-31T10:00:00.000Z", 2), ("2026-10-31T10:01:00.000Z", 0),
        ("2026-10-31T10:02:00.000Z", 0), ("2026-10-31T10:03:00.000Z", 1)]
    assert [b.alerts for b in series.buckets] == [4, 0, 0, 2]                    # alerts sit at the time of their event
    assert series.bucket_s == 60


def test_bucket_size_and_since(setup):
    s = setup()
    s.ingest(ev(ts="2026-10-31T10:00:05.000Z"), ev(ts="2026-10-31T10:04:30.000Z", process="b"))
    coarse = s.insights.timeseries(bucket_s=3600)
    assert [(b.t, b.events) for b in coarse.buckets] == [("2026-10-31T10:00:00.000Z", 2)]
    later = s.insights.timeseries(bucket_s=60, since="2026-10-31T10:04:00.000Z")
    assert [b.events for b in later.buckets] == [1]
    assert s.insights.timeseries(bucket_s=60, since="2030-01-01T00:00:00.000Z").buckets == []
    with pytest.raises(ValueError):
        s.insights.timeseries(bucket_s=0)


def test_the_series_never_has_more_than_the_maximum_buckets(setup):
    s = setup()
    s.ingest(ev(ts="2026-01-01T00:00:00.000Z"), ev(ts="2026-10-31T10:00:00.000Z", process="b"))
    series = s.insights.timeseries(bucket_s=60)
    assert len(series.buckets) == MAX_BUCKETS and series.buckets[-1].events == 1       # the most recent are kept


# ---- score explanation -------------------------------------------------------

def test_score_explain_lists_every_contribution(setup):
    s = setup(analyze=lambda e, c, x: AnalysisResult(findings=[leak()] if e.process == "python3" else []))
    s.ingest(ev(), ev(process="calm", host="api.groq.com"))
    explain = s.insights.score_explain()                                          # default: the riskiest tool
    assert (explain.tool_id, explain.score, explain.S) == ("python3|openai", 52, pytest.approx(58.5))
    assert [i.rule_id for i in explain.items] == ["SEC_AWS_SECRET_KEY", "POLICY_UNSANCTIONED_TOOL"]
    top = explain.items[0]
    assert (top.w_sev, top.confidence, top.m_exposure, top.m_sanction, top.count_factor, top.points) == (60.0, 0.9, 1.0, 1.0, 1.0, 54.0)
    assert (explain.org.org_risk, explain.org.compliance_score, explain.org.band) == (45, 55, Band.MODERATE)   # 0.7 x 52 + 0.3 x mean(52, 5)
    assert s.insights.score_explain("calm|groq").score == s.insights.tools()[-1].risk


def test_score_explain_edge_cases(setup):
    s = setup()
    empty = s.insights.score_explain()
    assert (empty.tool_id, empty.S, empty.score, empty.items, empty.org.org_risk) == ("", 0, 0, [], 0)
    s.ingest(ev())
    assert s.insights.score_explain("nobody|nothing") is None


# ---- graph -------------------------------------------------------------------

def test_the_graph_connects_processes_to_providers(setup):
    def analyze(event, config, ctx):
        return AnalysisResult(findings=[leak(severity="high")] if event.process == "leaky" else [])

    s = setup(analyze=analyze)
    s.ingest(ev(process="leaky", bytes_out=500), ev(process="leaky", host="api.groq.com", bytes_out=50),
             ev(process="clean", host="api.anthropic.com", bytes_out=None))
    graph = s.insights.graph()
    nodes = {n.id: n for n in graph.nodes}
    assert set(nodes) == {"proc:leaky", "proc:clean", "prov:openai", "prov:groq", "prov:anthropic"}
    edges = {e.tool_id: e for e in graph.edges}
    assert (edges["leaky|openai"].source, edges["leaky|openai"].target) == ("proc:leaky", "prov:openai")
    assert (edges["leaky|openai"].has_finding, edges["leaky|openai"].max_severity) == (True, Severity.HIGH)
    assert edges["leaky|openai"].bytes_out == 500 and edges["clean|anthropic"].bytes_out is None
    assert (edges["clean|anthropic"].has_finding, edges["clean|anthropic"].max_severity) == (False, None)   # policy only: not red
    assert nodes["proc:leaky"].risk == max(t.risk for t in s.insights.tools() if t.process == "leaky")
    assert (nodes["prov:openai"].sanctioned, nodes["proc:leaky"].sanctioned) == (False, None)
    assert nodes["prov:openai"].label == "OpenAI" and nodes["proc:leaky"].kind.value == "process"


def test_approving_a_provider_updates_the_graph(setup):
    s = setup()
    s.ingest(ev())
    assert next(n for n in s.insights.graph().nodes if n.id == "prov:openai").sanctioned is False
    s.db.set_provider_override("openai", True)
    assert next(n for n in s.insights.graph().nodes if n.id == "prov:openai").sanctioned is True


# ---- the bundled sample, all views together -------------------------------------

def test_the_sample_file_gives_a_consistent_picture(setup):
    s = setup()
    s.pipeline.ingest_log(parse_log(SAMPLE.read_text(encoding="utf-8")))
    tools = s.insights.tools()
    assert len(tools) == 14 and s.insights.summary().totals.tools == 14
    by_id = {t.tool_id: t for t in tools}
    assert by_id["python3|openai"].risk == 5                      # one low policy finding: 4.5 points
    assert by_id["python3|ollama"].risk == 1                      # approved local model: 0.9 points
    assert by_id["lmstudio-client|lmstudio"].risk == 4            # two low findings on a local model: 3.6 points
    assert by_id["curl|huggingface"].risk == 6                    # a model hub counts 1.1x: 4.95 points
    assert s.insights.risk().org_risk == 6                        # 0.7 x 6 + 0.3 x mean(6, 5, 5)
    assert len(s.insights.providers(seen=True)) == 12
    graph = s.insights.graph()
    assert len(graph.edges) == 14 and not any(e.has_finding for e in graph.edges)      # no real leaks until detectors exist
    assert sum(b.events for b in s.insights.timeseries(bucket_s=60).buckets) == 17

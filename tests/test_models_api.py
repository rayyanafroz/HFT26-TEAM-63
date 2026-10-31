import json

import pytest
from pydantic import ValidationError

from shadowlens import models as m
from shadowlens.models import (
    AgentRow, Capabilities, CaptureStatus, Compliance, Evidence, EvidenceMetric, Graph, Health,
    IngestSummary, Page, Preview, ProviderRow, RiskBlock, ScoreExplain, SourceRow, Summary, new_id,
)

TS = "2026-10-31T10:00:00.000Z"


def names(model_instance, **dump):
    return set(json.loads(model_instance.model_dump_json(**dump)))


# ---- builders ----------------------------------------------------------------

def risk(org=52, **o):
    base = dict(org_risk=org, band=m.band_for_score(org), compliance_score=100 - org)
    base.update(o)
    return RiskBlock(**base)


def provider_row(**o):
    base = dict(provider_id="openai", display_name="OpenAI", category="cloud_llm", sanctioned=False,
                sanction_source="default", seen=True, confirmed=True, event_count=3, tool_count=1, last_seen=TS)
    base.update(o)
    return ProviderRow(**base)


def capture_status(**o):
    base = dict(
        mode="idle",
        scan=dict(enabled=False, interval_s=0, last_scan_at=None, scope="own_user", privileged=False, psutil_ok=True),
        live_tail=dict(enabled=True, dir="data/live", lines_ingested=0),
        transcripts=dict(enabled=False),
        proxy=dict(enabled=False, listen_port=11436, upstream="127.0.0.1:11434", upstream_ok=False),
        platform="windows",
    )
    base.update(o)
    return CaptureStatus(**base)


# ---- Page --------------------------------------------------------------------

def test_page_envelope():
    p = Page[ProviderRow](items=[provider_row()], total=1)
    assert names(p) == {"items", "total"}
    assert Page[ProviderRow].model_validate_json(p.model_dump_json()) == p


def test_page_total_cannot_be_below_item_count():
    with pytest.raises(ValidationError):
        Page[ProviderRow](items=[provider_row(), provider_row()], total=1)
    assert Page[ProviderRow](items=[provider_row()], total=500).total == 500   # paging: more exist


def test_page_rejects_wrong_item_type():
    with pytest.raises(ValidationError):
        Page[ProviderRow](items=[{"not": "a provider"}], total=1)


# ---- health ------------------------------------------------------------------

def test_health_shape():
    h = Health(version="0.1.0", llm=dict(enabled=True, key_present=False, model=None, mode="template"))
    assert json.loads(h.model_dump_json()) == {
        "status": "ok", "version": "0.1.0", "db": True,
        "llm": {"enabled": True, "key_present": False, "model": None, "mode": "template"}}
    with pytest.raises(ValidationError):
        Health(status="bad", version="1", llm=dict(enabled=True, key_present=True, mode="llm"))


# ---- ingest summary ----------------------------------------------------------

def test_ingest_summary():
    s = IngestSummary(source="http_log", accepted=20)
    assert names(s) == {"source", "accepted", "skipped", "dropped_non_ai", "findings", "alerts", "errors"}
    with pytest.raises(ValidationError):
        IngestSummary(source="x", errors=["e"] * 21)
    with pytest.raises(ValidationError):
        IngestSummary(source="x", accepted=-1)


def test_event_lite_names():
    e = m.EventLite(id=new_id(), ts=TS, source="http_log", tool_id="python3|openai", process="python3",
                    provider_id="openai", host="api.openai.com", dst_ip="1.2.3.4", dst_port=443,
                    method="POST", path="/v1", visibility="full")
    assert names(e) == {"id", "ts", "source", "tool_id", "process", "provider_id", "host", "dst_ip", "dst_port",
                        "method", "path", "visibility", "bytes_out", "body_bytes", "finding_count"}


# ---- agents / providers ------------------------------------------------------

def test_agent_row_names_and_band_check():
    row = AgentRow(tool_id="cursor|anthropic", display_name="Cursor", process="cursor", risk=60,
                   risk_band="high", capabilities=Capabilities())
    assert names(row) == {"tool_id", "display_name", "process", "risk", "risk_band", "capabilities", "activity"}
    with pytest.raises(ValidationError):
        AgentRow(tool_id="a|b", display_name="x", process="a", risk=60, risk_band="low", capabilities=Capabilities())


def test_agent_activity_is_capped_at_100():
    acts = [dict(ts=TS, capability="shell", kind="used", name="bash")] * 101
    with pytest.raises(ValidationError):
        AgentRow(tool_id="a|b", display_name="x", process="a", risk=0, risk_band="low",
                 capabilities=Capabilities(), activity=acts)


def test_provider_row_names_and_enums():
    assert names(provider_row()) == {"provider_id", "display_name", "category", "sanctioned", "sanction_source",
                                     "seen", "confirmed", "event_count", "tool_count", "last_seen"}
    with pytest.raises(ValidationError):
        provider_row(sanction_source="magic")


# ---- risk block / summary ----------------------------------------------------

def test_risk_block_rules():
    assert names(risk()) == {"org_risk", "band", "compliance_score"}
    with pytest.raises(ValidationError):
        risk(compliance_score=10)            # must be 100 - org_risk
    with pytest.raises(ValidationError):
        risk(band="low")                     # 52 is "high"
    assert risk(0).band is m.Band.LOW and risk(100).band is m.Band.CRITICAL


def test_summary_names_and_defaults():
    s = Summary(risk=risk(), llm=dict(mode="template"))
    assert names(s) == {"risk", "totals", "alerts_by_severity", "findings_by_category", "events_by_provider",
                        "unsanctioned_tools", "coverage", "top_tools", "llm", "scenario", "last_event_at"}
    data = json.loads(s.model_dump_json())
    assert set(data["totals"]) == {"events", "ai_events", "dropped_non_ai", "tools", "providers", "alerts_open", "findings"}
    assert set(data["alerts_by_severity"]) == {"critical", "high", "medium", "low"}      # no "info"
    assert set(data["findings_by_category"]) == {"secret", "pii", "code", "agent", "policy"}
    assert set(data["coverage"]) == {"full", "metadata_only"}
    assert set(data["llm"]) == {"mode", "sent", "blocked", "failed"}


def test_top_tool_band_check():
    assert m.TopTool(tool_id="a|b", risk=80, risk_band="critical")
    with pytest.raises(ValidationError):
        m.TopTool(tool_id="a|b", risk=80, risk_band="low")


def test_timeseries():
    t = m.Timeseries(bucket_s=60, buckets=[dict(t=TS, events=3, alerts=1)])
    assert names(t) == {"bucket_s", "buckets"}
    with pytest.raises(ValidationError):
        m.Timeseries(bucket_s=0)


# ---- score explain -----------------------------------------------------------

def score_item(points, **o):
    base = dict(finding_id=new_id(), rule_id="SEC_OPENAI_KEY", severity="high", w_sev=30.0, confidence=0.9,
                m_exposure=1.5, m_sanction=1.2, count_factor=1.0, points=points)
    base.update(o)
    return base


def test_score_explain_names():
    s = ScoreExplain(tool_id="a|b", S=51.0, score=47, items=[score_item(40), score_item(11)],
                     org=dict(max_tool_score=47, mean_top3=47.0, org_risk=47, compliance_score=53, band="moderate"))
    data = json.loads(s.model_dump_json())
    assert set(data) == {"tool_id", "S", "score", "items", "org"}
    assert set(data["items"][0]) == {"finding_id", "rule_id", "severity", "w_sev", "confidence", "m_exposure",
                                     "m_sanction", "count_factor", "points"}
    assert set(data["org"]) == {"max_tool_score", "mean_top3", "org_risk", "compliance_score", "band"}


def test_score_items_must_be_sorted_highest_first():
    org = dict(max_tool_score=1, mean_top3=1.0, org_risk=1, compliance_score=99, band="low")
    with pytest.raises(ValidationError):
        ScoreExplain(tool_id="a|b", S=3.0, score=1, items=[score_item(1), score_item(2)], org=org)


def test_score_org_must_be_consistent():
    with pytest.raises(ValidationError):
        ScoreExplain(tool_id="a|b", S=0, score=0, items=[],
                     org=dict(max_tool_score=0, mean_top3=0.0, org_risk=10, compliance_score=10, band="low"))


def test_score_item_unknown_rule():
    with pytest.raises(ValidationError):
        ScoreExplain(tool_id="a|b", S=1, score=1, items=[score_item(1, rule_id="NOPE")],
                     org=dict(max_tool_score=1, mean_top3=1.0, org_risk=1, compliance_score=99, band="low"))


# ---- graph -------------------------------------------------------------------

def graph_parts():
    nodes = [dict(id="proc:python3", kind="process", label="python3", risk=51, risk_band="high", sanctioned=None),
             dict(id="prov:openai", kind="provider", label="OpenAI", risk=51, risk_band="high", sanctioned=False)]
    edge = dict(source="proc:python3", target="prov:openai", tool_id="python3|openai", event_count=3,
                bytes_out=None, max_severity="high", has_finding=True)
    return nodes, edge


def test_graph_names():
    nodes, edge = graph_parts()
    g = Graph(nodes=nodes, edges=[edge])
    data = json.loads(g.model_dump_json())
    assert set(data) == {"nodes", "edges"}
    assert set(data["nodes"][0]) == {"id", "kind", "label", "risk", "risk_band", "sanctioned"}
    assert set(data["edges"][0]) == {"source", "target", "tool_id", "event_count", "bytes_out", "max_severity", "has_finding"}


def test_graph_edges_must_reference_nodes():
    nodes, edge = graph_parts()
    with pytest.raises(ValidationError):
        Graph(nodes=nodes, edges=[{**edge, "target": "prov:ghost"}])


def test_graph_node_ids_unique_and_prefixed():
    nodes, _ = graph_parts()
    with pytest.raises(ValidationError):
        Graph(nodes=[nodes[0], nodes[0]])
    with pytest.raises(ValidationError):
        Graph(nodes=[{**nodes[0], "id": "prov:python3"}])      # process node with a provider prefix
    with pytest.raises(ValidationError):
        Graph(nodes=[{**nodes[0], "id": "proc:"}])


def test_graph_edge_flag_matches_severity():
    nodes, edge = graph_parts()
    with pytest.raises(ValidationError):
        Graph(nodes=nodes, edges=[{**edge, "has_finding": False}])
    ok = Graph(nodes=nodes, edges=[{**edge, "max_severity": None, "has_finding": False}])
    assert ok.edges[0].has_finding is False


# ---- compliance --------------------------------------------------------------

def test_compliance_shape_and_disclaimer():
    fid = new_id()
    c = Compliance(compliance_score=48, org_risk=52, band="high",
                   controls=[dict(id="LLM02", framework="OWASP LLM Top 10", title="Sensitive information disclosure",
                                  status="gap", finding_count=1, finding_ids=[fid])])
    data = json.loads(c.model_dump_json())
    assert set(data) == {"compliance_score", "org_risk", "band", "controls", "disclaimer"}
    assert set(data["controls"][0]) == {"id", "framework", "title", "status", "finding_count", "finding_ids"}
    assert data["disclaimer"] == "This is an interpretation of risk, not an audit."


def test_compliance_rules():
    with pytest.raises(ValidationError):
        Compliance(compliance_score=1, org_risk=52, band="high")
    with pytest.raises(ValidationError):
        Compliance(compliance_score=48, org_risk=52, band="high", disclaimer="This is an audit.")
    with pytest.raises(ValidationError):
        Compliance(compliance_score=48, org_risk=52, band="high",
                   controls=[dict(id="x", framework="f", title="t", status="gap", finding_count=2, finding_ids=[new_id()])])


# ---- egress ledger -----------------------------------------------------------

def test_llm_call_and_egress():
    call = m.LlmCall(id=new_id(), ts=TS, alert_id=new_id(), model=None, bytes=0, status="blocked",
                     prompt_sha256="a" * 64, latency_ms=None)
    assert names(call) == {"id", "ts", "alert_id", "model", "bytes", "status", "prompt_sha256", "latency_ms"}
    e = m.EgressResponse(summary=dict(sent=0, blocked=1, failed=0, template_fallbacks=1), items=[call], total=1)
    assert names(e) == {"summary", "items", "total"}
    assert set(json.loads(e.model_dump_json())["summary"]) == {"sent", "blocked", "failed", "template_fallbacks"}
    with pytest.raises(ValidationError):
        m.LlmCall(id=new_id(), ts=TS, alert_id=new_id(), bytes=0, status="vanished", prompt_sha256="a" * 64)


# ---- evidence ----------------------------------------------------------------

def metric(**o):
    base = {"id": "secret_recall", "label": "Secret recall", "value": 0.97, "target": 0.95, "unit": "ratio",
            "pass": True, "fixture": "fixtures/payloads_labeled.jsonl", "command": "python -m shadowlens.eval.run"}
    base.update(o)
    return base


def test_evidence_metric_serializes_pass_with_the_sot_name():
    ev = Evidence(available=True, generated_at=TS, metrics=[metric()])
    dumped = ev.model_dump(mode="json", by_alias=True)
    assert set(dumped["metrics"][0]) == {"id", "label", "value", "target", "unit", "pass", "fixture", "command"}
    assert dumped["metrics"][0]["pass"] is True
    assert ev.metrics[0].passed is True


def test_evidence_metric_accepts_either_name_on_input():
    assert EvidenceMetric(**metric()).passed is True
    renamed = {k: v for k, v in metric().items() if k != "pass"}
    assert EvidenceMetric(**renamed, passed=False).passed is False


def test_evidence_unavailable():
    ev = Evidence(available=False)
    assert ev.metrics == [] and ev.generated_at is None


# ---- capture status ----------------------------------------------------------

def test_capture_status_names():
    data = json.loads(capture_status().model_dump_json())
    assert set(data) == {"mode", "scan", "live_tail", "transcripts", "proxy", "platform", "scenario",
                         "since", "stopped_at"}
    assert set(data["scan"]) == {"enabled", "interval_s", "last_scan_at", "scope", "privileged", "psutil_ok"}
    assert set(data["live_tail"]) == {"enabled", "dir", "lines_ingested"}
    assert set(data["transcripts"]) == {"enabled", "sources_active", "files_watched", "lines_ingested"}
    assert set(data["proxy"]) == {"enabled", "listen_port", "upstream", "upstream_ok", "requests_ingested", "error"}
    assert set(data["scenario"]) == {"name", "played", "total"}


def test_capture_status_enums_and_scenario_progress():
    with pytest.raises(ValidationError):
        capture_status(mode="sleeping")
    with pytest.raises(ValidationError):
        capture_status(platform="beos")
    with pytest.raises(ValidationError):
        capture_status(scenario=dict(name="quick_leak", played=5, total=3))
    assert capture_status(scenario=dict(name="quick_leak", played=3, total=3)).scenario.played == 3


# ---- sources / visibility ----------------------------------------------------

def test_source_row():
    row = SourceRow(id="claude_code", display_name="Claude Code transcripts", kind="transcript", found=True,
                    enabled=False, supported=True, paths=["~/.claude/projects"],
                    reads="Prompts, tool calls and tool results in these files.", stores="Masked findings only.")
    assert names(row) == {"id", "display_name", "kind", "found", "enabled", "supported", "error", "paths",
                          "files_watched", "lines_ingested", "last_event_at", "reads", "stores"}
    with pytest.raises(ValidationError):
        SourceRow(id="x", display_name="x", kind="carrier_pigeon", found=True, enabled=True, supported=True,
                  reads="r", stores="s")


def test_visibility_response():
    v = m.VisibilityResponse(statement="s", rows=[dict(source="conn_scan", can_see="a", cannot_see="b", visibility="metadata_only")])
    assert set(json.loads(v.model_dump_json())["rows"][0]) == {"source", "can_see", "cannot_see", "visibility"}


# ---- preview -----------------------------------------------------------------

def test_preview_names_and_rules():
    p = Preview(findings=[dict(rule_id="SEC_OPENAI_KEY", category="secret", severity="high", title="Key",
                               masked_preview="sk-p... (len 51)", confidence=0.9, span=[5, 56])],
                redacted_text="key [REDACTED:SEC_OPENAI_KEY:0123456789ab]", would_block=False,
                points_preview=dict(S=30.0, tool_score=31))
    data = json.loads(p.model_dump_json())
    assert set(data) == {"findings", "redacted_text", "would_block", "points_preview"}
    assert set(data["findings"][0]) == {"rule_id", "category", "severity", "title", "masked_preview", "confidence", "span"}
    assert set(data["points_preview"]) == {"S", "tool_score"}


@pytest.mark.parametrize("bad", [
    dict(rule_id="NOPE"), dict(category="pii"), dict(span=[9, 2]), dict(span=[-1, 2]),
])
def test_preview_finding_rejects_bad_values(bad):
    base = dict(rule_id="SEC_OPENAI_KEY", category="secret", severity="high", title="Key",
                masked_preview="x", confidence=0.9, span=[1, 2])
    with pytest.raises(ValidationError):
        m.PreviewFinding(**{**base, **bad})


# ---- request bodies and small responses --------------------------------------

def test_request_bodies():
    assert m.SanctionRequest(sanctioned=True).sanctioned is True
    assert m.AnalyzePreviewRequest(text="hi").mode is m.AnalyzeMode.TEXT
    with pytest.raises(ValidationError):
        m.AnalyzePreviewRequest(text="x" * 20001)
    with pytest.raises(ValidationError):
        m.AnalyzePreviewRequest(text="x", mode="telepathy")
    assert m.PlayScenarioRequest(name="quick_leak").speed == 1.0
    with pytest.raises(ValidationError):
        m.PlayScenarioRequest(name="quick_leak", speed=0)
    with pytest.raises(ValidationError):
        m.LoadScenarioRequest(name="not_a_scenario")
    assert m.SourceUpdateRequest(enabled=True).backfill is False
    assert m.CaptureControlRequest().scan is None


def test_scenario_names_are_the_four_from_the_sot():
    assert {s.value for s in m.ScenarioName} == {"clean_baseline", "full_demo", "agent_attack", "quick_leak"}


def test_small_responses():
    assert json.loads(m.OkResponse().model_dump_json()) == {"ok": True}
    assert json.loads(m.ErrorResponse(error="boom").model_dump_json()) == {"error": "boom"}
    assert names(m.PlayScenarioResponse(name="quick_leak", total=9, duration_s=12.5)) == {"name", "total", "duration_s"}
    assert names(m.SamplesResponse(key="a", pii="b", agent="c")) == {"key", "pii", "agent"}
    resp = m.SanctionResponse(provider=provider_row(), risk=risk())
    assert names(resp) == {"provider", "risk"}


def test_no_model_accepts_unknown_fields():
    with pytest.raises(ValidationError):
        risk(extra_field=1)

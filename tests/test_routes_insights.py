import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from shadowlens.api.app import create_app
from shadowlens.api.sse import EventBus
from shadowlens.config import Config
from shadowlens.core.pipeline import AnalysisResult
from shadowlens.core.visibility import COVERAGE_STATEMENT
from shadowlens.db import Database
from shadowlens.models import AgentActivity, Finding, new_id

SAMPLE = Path(__file__).resolve().parents[1] / "fixtures" / "sample_http.jsonl"
TS = "2026-10-31T10:00:00.000Z"


class RecordingBus(EventBus):
    def __init__(self):
        super().__init__()
        self.sent = []

    def publish(self, event_type, payload):
        self.sent.append((event_type, payload))
        super().publish(event_type, payload)

    def kinds(self):
        return [k for k, _ in self.sent]


def make_config(tmp_path, **env):
    return Config.load(env={"SHADOWLENS_RESOLVE": "false", **env}, base_dir=tmp_path, use_dotenv=False)


@pytest.fixture
def db(tmp_path):
    database = Database(tmp_path / "shadow.db")
    yield database
    database.close()


@pytest.fixture
def bus():
    return RecordingBus()


def start(tmp_path, db, bus, analyze=None):
    return TestClient(create_app(make_config(tmp_path), db=db, bus=bus, ui_dir=tmp_path / "none", analyze=analyze))


@pytest.fixture
def client(tmp_path, db, bus):
    with start(tmp_path, db, bus) as c:
        yield c


def upload(client, content, name="log.jsonl"):
    data = content if isinstance(content, bytes) else content.encode("utf-8")
    return client.post("/api/ingest/log", files={"file": (name, data, "application/octet-stream")})


@pytest.fixture
def loaded(client):
    assert upload(client, SAMPLE.read_bytes(), "sample_http.jsonl").status_code == 200


def leak_line(host="api.openai.com", process="python3", n=0):
    return json.dumps({"ts": f"2026-10-31T10:00:{n:02d}Z", "host": host, "method": "POST", "path": "/v1",
                       "process_name": process, "body": "prompt text"})


def aws_leak(event, config, ctx):
    """An analyzer that finds one critical secret per event (like quick_leak)."""
    finding = Finding(id=new_id(), event_id=event.id, tool_id=ctx.tool_id, rule_id="SEC_AWS_SECRET_KEY",
                      category="secret", severity="critical", confidence=0.9, masked_preview="****",
                      location={"field": "body"}, meta={"hash12": "aaaaaaaaaaaa", "context": "c"}, created_at=TS)
    return AnalysisResult(findings=[finding])


# ---- tools -------------------------------------------------------------------

def test_tools(client, loaded):
    page = client.get("/api/tools").json()
    assert page["total"] == 14 and len(page["items"]) == 14
    tool = next(t for t in page["items"] if t["tool_id"] == "curl|huggingface")
    assert set(tool) == {"tool_id", "process", "provider_id", "display_name", "category", "sanctioned", "confidence",
                         "event_count", "bytes_out", "first_seen", "last_seen", "risk", "risk_band", "finding_counts",
                         "capabilities", "visibility", "unconfirmed"}
    assert (tool["category"], tool["risk"], tool["risk_band"], tool["unconfirmed"]) == ("model_hub", 6, "low", False)
    assert [t["risk"] for t in page["items"]] == sorted((t["risk"] for t in page["items"]), reverse=True)


def test_empty_database_endpoints(client):
    assert client.get("/api/tools").json() == {"items": [], "total": 0}
    assert client.get("/api/agents").json() == {"items": [], "total": 0}
    assert client.get("/api/graph").json() == {"nodes": [], "edges": []}
    assert client.get("/api/stats/timeseries").json() == {"bucket_s": 60, "buckets": []}
    summary = client.get("/api/stats/summary").json()
    assert summary["risk"] == {"org_risk": 0, "band": "low", "compliance_score": 100}
    explain = client.get("/api/score/explain").json()
    assert (explain["tool_id"], explain["score"], explain["items"]) == ("", 0, [])


# ---- agents ------------------------------------------------------------------

def test_agents(tmp_path, db, bus):
    def analyze(event, config, ctx):
        return AnalysisResult(agent_activity=[
            AgentActivity(ts=TS, capability="shell", kind="granted", name="bash"),
            AgentActivity(ts=TS, capability="shell", kind="used", risky=True, name="bash", argument="rm -rf /")])

    with start(tmp_path, db, bus, analyze) as c:
        upload(c, leak_line(process="autogpt") + "\n" + leak_line(process="plain", host="api.groq.com"))
        page = c.get("/api/agents").json()
    assert page["total"] == 2                     # the stub analyzer gives both tools the same activity
    row = page["items"][0]
    assert set(row) == {"tool_id", "display_name", "process", "risk", "risk_band", "capabilities", "activity"}
    assert row["capabilities"]["shell"] == {"granted": True, "used": True, "risky": True}
    assert row["capabilities"]["network"] == {"granted": False, "used": False, "risky": False}
    assert [a["kind"] for a in row["activity"]] == ["granted", "used"]


# ---- providers and the approval switch ---------------------------------------

def test_providers(client, loaded):
    page = client.get("/api/providers").json()
    assert page["total"] == 27
    row = page["items"][0]
    assert set(row) == {"provider_id", "display_name", "category", "sanctioned", "sanction_source", "seen",
                        "confirmed", "event_count", "tool_count", "last_seen"}
    assert row["seen"] is True and row["event_count"] >= row["tool_count"] >= 1
    assert client.get("/api/providers", params={"seen": "true"}).json()["total"] == 12
    assert client.get("/api/providers", params={"seen": "false"}).json()["total"] == 15
    assert client.get("/api/providers", params={"seen": "maybe"}).status_code == 422


def test_approving_a_provider_rescores_the_organisation(tmp_path, db, bus):
    with start(tmp_path, db, bus, aws_leak) as c:
        upload(c, leak_line())
        assert c.get("/api/stats/summary").json()["risk"]["org_risk"] == 52
        bus.sent.clear()
        started = time.perf_counter()
        r = c.put("/api/providers/openai/sanction", json={"sanctioned": True})
        elapsed = time.perf_counter() - started
        assert r.status_code == 200 and elapsed < 0.3                       # AT-17: well under 300 ms
        body = r.json()
        assert body["provider"]["provider_id"] == "openai"
        assert (body["provider"]["sanctioned"], body["provider"]["sanction_source"]) == (True, "override")
        assert body["risk"] == {"org_risk": 31, "band": "moderate", "compliance_score": 69}
        assert c.get("/api/tools").json()["items"][0]["risk"] == 31          # every view agrees
        assert c.get("/api/stats/summary").json()["risk"]["org_risk"] == 31
        assert c.get("/api/graph").json()["nodes"][-1]["sanctioned"] is True
        assert bus.kinds() == ["score.update"]                              # other dashboards are told too
        update = bus.sent[0][1]
        assert update.risk.org_risk == 31 and update.tool.tool_id == "python3|openai"

        back = c.put("/api/providers/openai/sanction", json={"sanctioned": False}).json()
        assert back["risk"]["org_risk"] == 52 and back["provider"]["sanction_source"] == "override"


def test_approving_the_default_approved_provider_can_be_undone(client, loaded):
    before = client.get("/api/providers", params={"seen": "true"}).json()["items"]
    ollama = next(p for p in before if p["provider_id"] == "ollama")
    assert (ollama["sanctioned"], ollama["sanction_source"]) == (True, "default")
    tool = lambda: next(t for t in client.get("/api/tools").json()["items"] if t["tool_id"] == "python3|ollama")
    assert tool()["risk"] == 14                      # DB URL 10.8 + local-model policy 0.9 = 11.7 points, approved
    r = client.put("/api/providers/ollama/sanction", json={"sanctioned": False}).json()
    assert (r["provider"]["sanctioned"], r["provider"]["sanction_source"]) == (False, "override")
    assert tool()["sanctioned"] is False and tool()["risk"] == 25      # the approval discount is gone: 23.4 points


def test_sanction_errors(client):
    missing = client.put("/api/providers/not_a_provider/sanction", json={"sanctioned": True})
    assert missing.status_code == 404 and missing.json() == {"error": "provider not found"}
    for body in ({}, {"sanctioned": "sure"}, {"sanctioned": True, "extra": 1}):
        r = client.put("/api/providers/openai/sanction", json=body)
        assert r.status_code == 422 and set(r.json()) == {"error"}
    assert client.put("/api/providers/openai/sanction").status_code == 422


# ---- summary, time series, explain, graph, visibility --------------------------

def test_summary(client, loaded):
    s = client.get("/api/stats/summary").json()
    assert set(s) == {"risk", "totals", "alerts_by_severity", "findings_by_category", "events_by_provider",
                      "unsanctioned_tools", "coverage", "top_tools", "llm", "scenario", "last_event_at"}
    assert s["totals"] == {"events": 20, "ai_events": 17, "dropped_non_ai": 3, "tools": 14, "providers": 12,
                           "alerts_open": 27, "findings": 33}                 # 15 policy findings + 18 real ones
    assert s["risk"] == {"org_risk": 77, "band": "critical", "compliance_score": 23}
    assert s["alerts_by_severity"] == {"critical": 3, "high": 10, "medium": 1, "low": 13}
    assert s["findings_by_category"] == {"secret": 6, "pii": 6, "code": 0, "agent": 6, "policy": 15}
    assert s["unsanctioned_tools"] == 13 and s["coverage"] == {"full": 14, "metadata_only": 3}
    assert s["llm"] == {"mode": "template", "sent": 0, "blocked": 0, "failed": 0}
    assert s["events_by_provider"][0]["provider_id"] == "openai" and s["events_by_provider"][0]["count"] == 4
    assert len(s["top_tools"]) == 5 and s["top_tools"][0]["tool_id"] == "python3|openai"
    assert s["scenario"] is None and s["last_event_at"].endswith("Z")


def test_timeseries(client, loaded):
    series = client.get("/api/stats/timeseries").json()
    assert series["bucket_s"] == 60 and sum(b["events"] for b in series["buckets"]) == 17
    assert set(series["buckets"][0]) == {"t", "events", "alerts"}
    assert sum(b["alerts"] for b in series["buckets"]) == 27
    hourly = client.get("/api/stats/timeseries", params={"bucket_s": 3600}).json()
    assert hourly["bucket_s"] == 3600 and sum(b["events"] for b in hourly["buckets"]) == 17
    none = client.get("/api/stats/timeseries", params={"since": "2030-01-01T00:00:00.000Z"}).json()
    assert none["buckets"] == []


@pytest.mark.parametrize("params", [{"bucket_s": 0}, {"bucket_s": -5}, {"bucket_s": 100000}, {"bucket_s": "x"}, {"since": "soon"}])
def test_timeseries_validation(client, params):
    r = client.get("/api/stats/timeseries", params=params)
    assert r.status_code == 422 and set(r.json()) == {"error"}


def test_score_explain(tmp_path, db, bus):
    with start(tmp_path, db, bus, aws_leak) as c:
        upload(c, leak_line())
        e = c.get("/api/score/explain").json()
        assert set(e) == {"tool_id", "S", "score", "items", "org"}
        assert (e["tool_id"], e["score"], e["S"]) == ("python3|openai", 52, 58.5)
        assert [(i["rule_id"], i["points"]) for i in e["items"]] == [("SEC_AWS_SECRET_KEY", 54.0), ("POLICY_UNSANCTIONED_TOOL", 4.5)]
        assert set(e["items"][0]) == {"finding_id", "rule_id", "severity", "w_sev", "confidence", "m_exposure",
                                      "m_sanction", "count_factor", "points"}
        assert e["org"] == {"max_tool_score": 52, "mean_top3": 52.0, "org_risk": 52, "compliance_score": 48, "band": "high"}
        assert c.get("/api/score/explain", params={"tool_id": "python3|openai"}).json() == e
        missing = c.get("/api/score/explain", params={"tool_id": "nobody|x"})
        assert missing.status_code == 404 and missing.json() == {"error": "tool not found"}


def test_graph(client, loaded):
    g = client.get("/api/graph").json()
    assert len(g["edges"]) == 14 and len(g["nodes"]) == 10 + 12                    # 10 processes (python3 talks to three providers) + 12 providers
    ids = {n["id"] for n in g["nodes"]}
    assert all(e["source"] in ids and e["target"] in ids for e in g["edges"])
    assert set(g["nodes"][0]) == {"id", "kind", "label", "risk", "risk_band", "sanctioned"}
    assert set(g["edges"][0]) == {"source", "target", "tool_id", "event_count", "bytes_out", "max_severity", "has_finding"}


def test_visibility(client):
    v = client.get("/api/visibility").json()
    assert v["statement"] == COVERAGE_STATEMENT == (
        "Payload inspection only applies to events with full visibility. HTTPS traffic is reported as metadata only.")
    assert len(v["rows"]) == 6 and set(v["rows"][0]) == {"source", "can_see", "cannot_see", "visibility"}
    assert v["rows"][0]["source"].startswith("Live process scan") and v["rows"][0]["visibility"] == "metadata_only"
    assert {r["visibility"] for r in v["rows"]} == {"metadata_only", "full", "TLS metadata_only; plaintext full"}


# ---- the live score message ---------------------------------------------------

def test_every_upload_ends_with_a_score_update(tmp_path, db, bus):
    with start(tmp_path, db, bus, aws_leak) as c:
        upload(c, leak_line())
    kinds = bus.kinds()
    assert kinds[-1] == "score.update" and kinds.count("score.update") == 1
    update = bus.sent[-1][1]
    assert (update.risk.org_risk, update.tool.tool_id, update.tool.risk) == (52, "python3|openai", 52)

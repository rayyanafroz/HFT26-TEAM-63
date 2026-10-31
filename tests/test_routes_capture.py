import json
import time
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from shadowlens.api.app import create_app
from shadowlens.api.sse import EventBus
from shadowlens.config import Config
from shadowlens.core.pipeline import AnalysisResult
from shadowlens.db import Database
from shadowlens.ingest.conn_scan import ConnectionScanner
from shadowlens.models import Finding, new_id

TS = "2026-10-31T10:00:00.000Z"


def conn(ip="127.0.0.1", port=11434, pid=100):
    return SimpleNamespace(status="ESTABLISHED", raddr=(ip, port), pid=pid)


class RecordingBus(EventBus):
    def __init__(self):
        super().__init__()
        self.sent = []

    def publish(self, event_type, payload):
        self.sent.append((event_type, payload))
        super().publish(event_type, payload)

    def kinds(self):
        return [k for k, _ in self.sent]

    def of(self, kind):
        return [p for k, p in self.sent if k == kind]


@pytest.fixture
def db(tmp_path):
    database = Database(tmp_path / "shadow.db")
    yield database
    database.close()


@pytest.fixture
def bus():
    return RecordingBus()


@pytest.fixture
def templates(tmp_path):
    folder = tmp_path / "templates"
    folder.mkdir(exist_ok=True)
    return folder


def scenario_file(templates, name, records):
    (templates / f"{name}.jsonl").write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")


def record(t_ms, host="api.openai.com", **o):
    return {"t_ms": t_ms, "host": host, "method": "POST", "path": "/v1/chat/completions",
            "process_name": "python3", "body": "hello", **o}


def make_client(tmp_path, db, bus, templates, connections=None, analyze=None, **env):
    config = Config.load(env={"SHADOWLENS_RESOLVE": "false", "SHADOWLENS_LIVE_DIR": str(tmp_path / "live"), **env},
                         base_dir=tmp_path, use_dotenv=False)
    state = {"connections": connections if connections is not None else []}
    scanner = ConnectionScanner(list_connections=lambda: state["connections"], process_name=lambda pid: f"proc{pid}")
    app = create_app(config, db=db, bus=bus, ui_dir=tmp_path / "none", scanner=scanner,
                     templates_dir=templates, analyze=analyze)
    client = TestClient(app)
    client.connections = state
    return client


@pytest.fixture
def client(tmp_path, db, bus, templates):
    with make_client(tmp_path, db, bus, templates) as c:
        yield c


def wait_for(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return False


# ---- the process scan --------------------------------------------------------

def test_scan_connections(client):
    client.connections["connections"] = [conn(), conn(ip="203.0.113.7", port=443, pid=101)]
    r = client.post("/api/scan/connections")
    assert r.status_code == 200
    assert r.json() == {"source": "conn_scan", "accepted": 1, "skipped": 0, "dropped_non_ai": 1,
                        "findings": 1, "alerts": 0, "errors": []}           # ollama is approved: a local-model finding, no alert
    assert client.get("/api/events").json()["items"][0]["tool_id"] == "proc100|ollama"
    assert client.post("/api/scan/connections").json()["accepted"] == 0      # already seen


# ---- status and the switches --------------------------------------------------

def test_capture_status_shape(client):
    s = client.get("/api/capture/status").json()
    assert set(s) == {"mode", "scan", "live_tail", "transcripts", "proxy", "platform", "scenario"}
    assert set(s["scan"]) == {"enabled", "interval_s", "last_scan_at", "scope", "privileged", "psutil_ok"}
    assert set(s["proxy"]) == {"enabled", "listen_port", "upstream", "upstream_ok", "requests_ingested", "error"}
    assert s["live_tail"]["enabled"] is True and s["mode"] == "watching"      # the tail starts with the app
    assert s["scan"]["enabled"] is False and s["scenario"] == {"name": None, "played": 0, "total": 0}


def test_start_and_stop(client):
    assert client.post("/api/capture/start", json={"scan": True}).json()["scan"]["enabled"] is True
    assert client.get("/api/capture/status").json()["mode"] == "scanning"
    assert client.post("/api/capture/stop", json={"scan": True}).json()["scan"]["enabled"] is False
    both = client.post("/api/capture/start").json()                          # no body: both
    assert (both["scan"]["enabled"], both["live_tail"]["enabled"]) == (True, True)
    none = client.post("/api/capture/stop").json()
    assert (none["scan"]["enabled"], none["live_tail"]["enabled"]) == (False, False)
    assert none["mode"] == "idle"


def test_switch_validation(client):
    assert client.post("/api/capture/start", json={}).status_code == 200
    bad = client.post("/api/capture/start", json={"scan": "yes please"})
    assert bad.status_code == 422 and set(bad.json()) == {"error"}
    assert client.post("/api/capture/start", json={"scan": True, "extra": 1}).status_code == 422


def test_the_live_folder_is_created_and_watched(tmp_path, db, bus, templates):
    folder = tmp_path / "nested" / "live"
    with make_client(tmp_path, db, bus, templates, SHADOWLENS_LIVE_DIR=str(folder)) as c:
        assert folder.is_dir()
        line = json.dumps({"ts": TS, "host": "api.openai.com", "method": "POST", "path": "/v1", "process_name": "ollama"})
        (folder / "ollama.jsonl").write_text(line + "\n", encoding="utf-8")
        assert wait_for(lambda: c.get("/api/events").json()["total"] == 1)
        assert c.get("/api/events").json()["items"][0]["source"] == "live_log"
        assert c.get("/api/capture/status").json()["live_tail"]["lines_ingested"] == 1


# ---- demo scenarios -----------------------------------------------------------

def test_load_a_scenario(client, templates, bus):
    scenario_file(templates, "quick_leak", [record(0), record(3000, host="api.anthropic.com"), record(6000, host="github.com")])
    r = client.post("/api/demo/load-scenario", json={"name": "quick_leak"})
    assert r.status_code == 200
    assert (r.json()["source"], r.json()["accepted"], r.json()["dropped_non_ai"]) == ("scenario", 2, 1)
    assert client.get("/api/events").json()["total"] == 2
    status = client.get("/api/capture/status").json()["scenario"]
    assert status == {"name": "quick_leak", "played": 3, "total": 3}
    assert client.get("/api/stats/summary").json()["scenario"] == "quick_leak"
    assert bus.of("scenario.progress")[-1] == {"name": "quick_leak", "played": 3, "total": 3}


def test_play_a_scenario_in_real_time(client, templates, bus):
    scenario_file(templates, "quick_leak", [record(0), record(200), record(400)])
    r = client.post("/api/demo/play", json={"name": "quick_leak"})
    assert r.status_code == 200
    assert r.json() == {"name": "quick_leak", "total": 3, "duration_s": 0.4}
    assert wait_for(lambda: client.get("/api/events").json()["total"] == 3)
    assert [p["played"] for p in bus.of("scenario.progress")] == [0, 1, 2, 3]
    assert client.get("/api/capture/status").json()["mode"] in ("watching", "idle")     # finished


def test_play_faster_and_stop(client, templates):
    scenario_file(templates, "full_demo", [record(0), record(200), record(60000)])
    assert client.post("/api/demo/play", json={"name": "full_demo", "speed": 2}).json()["duration_s"] == 30.0
    assert wait_for(lambda: client.get("/api/events").json()["total"] == 2)
    assert client.post("/api/demo/stop").json() == {"ok": True}
    time.sleep(0.2)
    assert client.get("/api/events").json()["total"] == 2
    assert client.get("/api/capture/status").json()["scenario"]["played"] == 2


def test_reset_clears_everything_and_tells_the_dashboard(client, templates, bus):
    scenario_file(templates, "quick_leak", [record(0)])
    client.post("/api/demo/load-scenario", json={"name": "quick_leak"})
    client.put("/api/providers/openai/sanction", json={"sanctioned": True})
    bus.sent.clear()
    assert client.post("/api/demo/reset").json() == {"ok": True}
    assert client.get("/api/events").json() == {"items": [], "total": 0}
    assert client.get("/api/alerts").json()["total"] == 0
    assert client.get("/api/stats/summary").json()["risk"]["org_risk"] == 0
    assert client.get("/api/providers").json()["items"][0]["sanction_source"] == "default"
    assert client.get("/api/capture/status").json()["scenario"]["name"] is None
    assert "reset" in bus.kinds() and "score.update" in bus.kinds()
    assert bus.of("score.update")[-1].risk.org_risk == 0


@pytest.mark.parametrize("body,status", [
    ({"name": "not_a_scenario"}, 422), ({}, 422), ({"name": "quick_leak", "extra": 1}, 422),
    ({"name": "../secrets"}, 422),
])
def test_scenario_name_validation(client, body, status):
    assert client.post("/api/demo/load-scenario", json=body).status_code == status
    assert set(client.post("/api/demo/load-scenario", json=body).json()) == {"error"}


def test_a_scenario_whose_file_is_missing_is_a_404(client):
    r = client.post("/api/demo/load-scenario", json={"name": "clean_baseline"})
    assert r.status_code == 404 and r.json() == {"error": "scenario not found"}
    assert client.post("/api/demo/play", json={"name": "clean_baseline"}).status_code == 404


def test_a_broken_scenario_file_is_a_500_without_its_content(client, templates):
    (templates / "agent_attack.jsonl").write_text('{"t_ms": 0, "host": "x", "method": "POST", "path": "/", "pid": "SECRETMARKER"}\n',
                                                  encoding="utf-8")
    r = client.post("/api/demo/load-scenario", json={"name": "agent_attack"})
    assert r.status_code == 500 and "SECRETMARKER" not in r.text


@pytest.mark.parametrize("speed", [0, -1, "fast"])
def test_play_speed_validation(client, templates, speed):
    scenario_file(templates, "quick_leak", [record(0)])
    r = client.post("/api/demo/play", json={"name": "quick_leak", "speed": speed})
    assert r.status_code == 422 and set(r.json()) == {"error"}


def test_the_quick_leak_demo_end_to_end(tmp_path, db, bus, templates):
    """The shape of the W2 demo: a benign prompt, then a leak, and the score moves 0 -> 52."""
    def analyze(event, config, ctx):
        if "aws_secret_access_key" not in (event.body_text or ""):
            return AnalysisResult()
        return AnalysisResult(findings=[Finding(
            id=new_id(), event_id=event.id, tool_id=ctx.tool_id, rule_id="SEC_AWS_SECRET_KEY", category="secret",
            severity="critical", confidence=0.9, masked_preview="****", location={"field": "body"},
            meta={"hash12": "aaaaaaaaaaaa", "context": "c"}, created_at=TS)])

    scenario_file(templates, "quick_leak", [
        record(0, body="Summarise this meeting"),
        record(200, body="aws_secret_access_key = fake-value-here"),
        record(400, body="Thanks"),
    ])
    with make_client(tmp_path, db, bus, templates, analyze=analyze) as c:
        assert c.get("/api/stats/summary").json()["risk"]["org_risk"] == 0
        c.post("/api/demo/play", json={"name": "quick_leak"})
        assert wait_for(lambda: c.get("/api/stats/summary").json()["risk"]["org_risk"] == 52)
        assert wait_for(lambda: c.get("/api/capture/status").json()["scenario"]["played"] == 3)
        risk = c.get("/api/stats/summary").json()["risk"]
        assert risk == {"org_risk": 52, "band": "high", "compliance_score": 48}
        alerts = c.get("/api/alerts").json()["items"]
        assert [a["severity"] for a in alerts] == ["critical", "low"]           # the leak and the unapproved tool
        assert alerts[0]["title"] == "AWS secret access key sent to an AI tool"
        assert [p.risk.org_risk for p in bus.of("score.update")][-1] == 52
        edge = c.get("/api/graph").json()["edges"][0]
        assert (edge["has_finding"], edge["max_severity"]) == (True, "critical")


# ---- Leak Lab ------------------------------------------------------------------

def test_preview_and_samples_say_so_when_the_analysis_is_missing(client, monkeypatch):
    from shadowlens.core import hooks
    monkeypatch.setattr(hooks, "preview_function", lambda: None)
    monkeypatch.setattr(hooks, "samples_function", lambda: None)
    r = client.post("/api/analyze/preview", json={"text": "hello"})
    assert r.status_code == 501 and set(r.json()) == {"error"}
    assert client.get("/api/analyze/samples").status_code == 501


def test_samples(client):
    s = client.get("/api/analyze/samples").json()
    assert set(s) == {"key", "pii", "agent"}
    assert "sk-" in s["key"] and "@" in s["pii"]                    # real-looking fakes, made at run time
    agent = json.loads(s["agent"])
    assert agent["tools"][0]["function"]["name"] == "bash"


def test_a_clean_prompt_finds_nothing(client):
    p = client.post("/api/analyze/preview", json={"text": "just a normal prompt"}).json()
    assert set(p) == {"findings", "redacted_text", "would_block", "points_preview"}
    assert p == {"findings": [], "redacted_text": "just a normal prompt", "would_block": False,
                 "points_preview": {"S": 0.0, "tool_score": 0}}


def test_the_key_sample_is_found_masked_and_redacted(client):
    text = client.get("/api/analyze/samples").json()["key"]
    p = client.post("/api/analyze/preview", json={"text": text}).json()
    assert [(f["rule_id"], f["severity"], f["title"]) for f in p["findings"]] == [
        ("SEC_OPENAI_KEY", "high", "OpenAI-style API key sent to an AI tool")]
    finding = p["findings"][0]
    start, end = finding["span"]
    assert text[start:end].startswith("sk-") and finding["masked_preview"].startswith("sk-p...")
    assert text[start:end] not in p["redacted_text"] and "[REDACTED:SEC_OPENAI_KEY:" in p["redacted_text"]
    assert p["would_block"] is False                                # the redacted text is clean
    assert p["points_preview"] == {"S": 31.5, "tool_score": 33}     # 35 x 0.9, as if sent to an unapproved cloud tool
    assert client.get("/api/events").json()["total"] == 0           # nothing was stored


def test_the_pii_sample_finds_each_kind_once_per_value(client):
    text = client.get("/api/analyze/samples").json()["pii"]
    p = client.post("/api/analyze/preview", json={"text": text}).json()
    assert {f["rule_id"] for f in p["findings"]} == {"PII_EMAIL", "PII_CREDIT_CARD", "PII_AADHAAR", "PII_PHONE"}
    assert p["would_block"] is False and "[PII:" in p["redacted_text"]
    spans = [f["span"] for f in p["findings"]]
    assert spans == sorted(spans)                                   # in the order they appear in the text


def test_the_same_value_twice_highlights_twice_but_scores_once(client):
    one = "contact jordan.lee@acme-demo.invalid today"
    two = one + " and again jordan.lee@acme-demo.invalid"
    a = client.post("/api/analyze/preview", json={"text": one}).json()
    b = client.post("/api/analyze/preview", json={"text": two}).json()
    assert len(a["findings"]) == 1 and len(b["findings"]) == 2         # every occurrence is highlighted
    assert b["points_preview"] == a["points_preview"]                 # but it is still one finding for the score


def test_the_agent_sample_in_agent_mode(client):
    text = client.get("/api/analyze/samples").json()["agent"]
    p = client.post("/api/analyze/preview", json={"text": text, "mode": "agent_json"}).json()
    rules = {f["rule_id"] for f in p["findings"]}
    assert {"AGENT_SHELL_TOOL_DECLARED", "AGENT_SHELL_EXEC", "AGENT_SENSITIVE_FILE_READ"} <= rules
    assert all(f["span"] == [0, 0] for f in p["findings"])           # agent findings have no position in the text
    assert p["points_preview"]["tool_score"] > 60
    as_text = client.post("/api/analyze/preview", json={"text": text}).json()
    assert not {f["rule_id"] for f in as_text["findings"]} & {"AGENT_SHELL_EXEC"}   # plain text mode ignores tool calls


def test_the_guard_result_is_passed_through(client, monkeypatch):
    from shadowlens.core import hooks
    monkeypatch.setattr(hooks, "preview_function", lambda: lambda text, mode, cfg: {
        "findings": [], "redacted_text": text, "would_block": True})
    assert client.post("/api/analyze/preview", json={"text": "x"}).json()["would_block"] is True


def test_preview_never_leaks_the_secret_it_found(client):
    text = client.get("/api/analyze/samples").json()["key"]
    start, end = client.post("/api/analyze/preview", json={"text": text}).json()["findings"][0]["span"]
    secret = text[start:end]
    body = client.post("/api/analyze/preview", json={"text": text}).text
    assert secret not in body                                        # not in the findings, not in the redacted text


@pytest.mark.parametrize("body", [
    {}, {"text": "x" * 20001}, {"text": "x", "mode": "telepathy"}, {"text": 5}, {"text": "x", "extra": 1},
])
def test_preview_validation(client, body):
    r = client.post("/api/analyze/preview", json=body)
    assert r.status_code == 422 and set(r.json()) == {"error"}


def test_preview_accepts_the_longest_allowed_text(client):
    assert client.post("/api/analyze/preview", json={"text": "hello " * 3333}).status_code == 200
    assert client.post("/api/analyze/preview", json={"text": "x" * 20000}).status_code == 200

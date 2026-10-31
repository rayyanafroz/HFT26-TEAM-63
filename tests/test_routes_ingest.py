import json
import sys
import types
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from shadowlens.api.app import create_app
from shadowlens.api.sse import EventBus
from shadowlens.config import Config
from shadowlens.core.pipeline import AnalysisResult
from shadowlens.db import Database
from shadowlens.ingest import http_log
from shadowlens.models import new_id

SAMPLE = Path(__file__).resolve().parents[1] / "fixtures" / "sample_http.jsonl"


class RecordingBus(EventBus):
    def __init__(self):
        super().__init__()
        self.sent = []

    def publish(self, event_type, payload):
        self.sent.append(event_type)
        super().publish(event_type, payload)


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


@pytest.fixture
def client(tmp_path, db, bus):
    app = create_app(make_config(tmp_path), db=db, bus=bus, ui_dir=tmp_path / "none")
    with TestClient(app) as c:
        yield c


def upload(client, content, name="log.jsonl"):
    data = content if isinstance(content, bytes) else content.encode("utf-8")
    return client.post("/api/ingest/log", files={"file": (name, data, "application/octet-stream")})


@pytest.fixture
def loaded(client):
    """The sample file, already uploaded."""
    r = upload(client, SAMPLE.read_bytes(), "sample_http.jsonl")
    assert r.status_code == 200
    return r.json()


# ---- POST /api/ingest/log ----------------------------------------------------

def test_uploading_the_sample_file(client, bus):
    r = upload(client, SAMPLE.read_bytes(), "sample_http.jsonl")
    assert r.status_code == 200
    # 15 policy findings (13 alerts) plus 18 from the real analyzer (14 alerts).
    assert r.json() == {"source": "http_log", "accepted": 17, "skipped": 0, "dropped_non_ai": 3,
                        "findings": 33, "alerts": 27, "errors": []}
    assert bus.sent.count("event.new") == 17 and bus.sent.count("alert.new") == 27


def test_bad_lines_are_reported_not_fatal(client):
    good = json.dumps({"ts": "2026-10-31T10:00:00Z", "host": "api.openai.com", "method": "POST", "path": "/v1"})
    r = upload(client, f"{good}\nnot json\n{{\"host\": \"x\"}}\n")
    body = r.json()
    assert r.status_code == 200 and (body["accepted"], body["skipped"]) == (1, 2)
    assert body["errors"][0].startswith("line 2:") and body["errors"][1].startswith("line 3:")


def test_har_upload(client):
    har = {"log": {"entries": [{"startedDateTime": "2026-10-31T10:00:00Z", "request": {
        "method": "POST", "url": "https://chatgpt.com/backend-api/conversation", "headers": [],
        "postData": {"text": "hello"}}}]}}
    r = upload(client, json.dumps(har), "export.har")
    assert r.json()["source"] == "har" and r.json()["accepted"] == 1
    assert client.get("/api/events").json()["items"][0]["tool_id"] == "browser|chatgpt_web"


def test_empty_file_is_fine(client):
    assert upload(client, b"").json() == {"source": "http_log", "accepted": 0, "skipped": 0,
                                          "dropped_non_ai": 0, "findings": 0, "alerts": 0, "errors": []}


def test_oversized_upload_is_a_413(client, monkeypatch):
    monkeypatch.setattr(http_log, "MAX_LOG_BYTES", 100)
    r = upload(client, b"x" * 101)
    assert r.status_code == 413 and set(r.json()) == {"error"}
    assert upload(client, b"x" * 100).status_code == 200                       # exactly at the limit is fine


def test_missing_file_is_a_422_json_error(client):
    r = client.post("/api/ingest/log")
    assert r.status_code == 422 and set(r.json()) == {"error"}


def test_placeholders_are_expanded_when_the_fake_data_module_exists(tmp_path, db, monkeypatch):
    fakes = types.ModuleType("shadowlens.fakes")
    fakes.expand = lambda text: text.replace("{{fake:openai_key#1}}", "EXPANDED-VALUE")
    monkeypatch.setitem(sys.modules, "shadowlens.fakes", fakes)
    seen = []

    def spy(event, config, ctx):
        if event.body_text:
            seen.append(event.body_text)
        return AnalysisResult()

    with TestClient(create_app(make_config(tmp_path), db=db, ui_dir=tmp_path, analyze=spy)) as c:
        upload(c, json.dumps({"ts": "2026-10-31T10:00:00Z", "host": "api.openai.com", "method": "POST",
                              "path": "/v1", "body": "key={{fake:openai_key#1}}"}))
    assert seen == ["key=EXPANDED-VALUE"]


def test_without_the_fake_data_module_placeholders_stay_as_text(tmp_path, db, monkeypatch):
    monkeypatch.setitem(sys.modules, "shadowlens.fakes", None)                  # makes the import fail
    seen = []

    def spy(event, config, ctx):
        seen.append(event.body_text)
        return AnalysisResult()

    with TestClient(create_app(make_config(tmp_path), db=db, ui_dir=tmp_path, analyze=spy)) as c:
        upload(c, json.dumps({"ts": "2026-10-31T10:00:00Z", "host": "api.openai.com", "method": "POST",
                              "path": "/v1", "body": "key={{fake:openai_key#1}}"}))
    assert seen == ["key={{fake:openai_key#1}}"]


def test_nothing_from_the_request_body_is_returned_by_the_api(client):
    upload(client, json.dumps({"ts": "2026-10-31T10:00:00Z", "host": "api.openai.com", "method": "POST",
                               "path": "/v1?k=QUERYMARKER", "body": "BODYMARKER", "headers": {"x-api-key": "HEADERMARKER"}}))
    everything = "".join(client.get(p).text for p in ("/api/events", "/api/findings", "/api/alerts"))
    assert not any(m in everything for m in ("BODYMARKER", "QUERYMARKER", "HEADERMARKER"))


# ---- GET /api/events ---------------------------------------------------------

def test_list_events(client, loaded):
    page = client.get("/api/events").json()
    assert set(page) == {"items", "total"} and page["total"] == 17 and len(page["items"]) == 17
    assert set(page["items"][0]) == {"id", "ts", "source", "tool_id", "process", "provider_id", "host", "dst_ip",
                                     "dst_port", "method", "path", "visibility", "bytes_out", "body_bytes",
                                     "finding_count"}
    stamps = [e["ts"] for e in page["items"]]
    assert stamps == sorted(stamps, reverse=True)                               # newest first


def test_event_filters(client, loaded):
    assert client.get("/api/events", params={"provider_id": "openai"}).json()["total"] == 4
    assert client.get("/api/events", params={"tool_id": "supportbot|anthropic"}).json()["total"] == 2
    assert client.get("/api/events", params={"visibility": "metadata_only"}).json()["total"] == 3
    assert client.get("/api/events", params={"visibility": "full"}).json()["total"] == 14
    assert client.get("/api/events", params={"since": "2026-10-30T14:03:30.000Z"}).json()["total"] < 17
    assert client.get("/api/events", params={"provider_id": "nobody"}).json() == {"items": [], "total": 0}


def test_event_paging(client, loaded):
    first = client.get("/api/events", params={"limit": 5}).json()
    rest = client.get("/api/events", params={"limit": 5, "offset": 15}).json()
    assert len(first["items"]) == 5 and first["total"] == 17 and len(rest["items"]) == 2
    assert len(client.get("/api/events", params={"limit": 99999}).json()["items"]) == 17      # clamped, not an error


@pytest.mark.parametrize("params", [{"visibility": "psychic"}, {"since": "yesterday"}, {"limit": "many"}])
def test_bad_event_filters_are_422_json(client, params):
    r = client.get("/api/events", params=params)
    assert r.status_code == 422 and set(r.json()) == {"error"}


# ---- GET /api/findings -------------------------------------------------------

def test_list_findings_and_filters(client, loaded):
    page = client.get("/api/findings").json()
    assert page["total"] == 33 and set(page["items"][0]) == {
        "id", "event_id", "tool_id", "rule_id", "category", "severity", "confidence", "masked_preview",
        "location", "owasp", "controls", "meta", "created_at"}
    assert client.get("/api/findings", params={"category": "policy"}).json()["total"] == 15
    assert client.get("/api/findings", params={"rule_id": "POLICY_LOCAL_LLM"}).json()["total"] == 2
    # Policy, plus the AWS access key, the AWS secret and the pasted OpenAI key.
    assert client.get("/api/findings", params={"tool_id": "python3|openai"}).json()["total"] == 4
    event_id = client.get("/api/events", params={"provider_id": "groq"}).json()["items"][0]["id"]
    assert client.get("/api/findings", params={"event_id": event_id}).json()["total"] == 1
    # AWS access and secret, OpenAI, JWT, database URL, Google key.
    assert client.get("/api/findings", params={"category": "secret"}).json()["total"] == 6
    assert client.get("/api/findings", params={"category": "nonsense"}).status_code == 422
    assert client.get("/api/findings", params={"event_id": "not-a-uuid"}).status_code == 422


# ---- GET /api/alerts and ack -------------------------------------------------

def test_list_alerts(client, loaded):
    page = client.get("/api/alerts").json()
    assert page["total"] == 27
    alert = page["items"][0]
    assert set(alert) == {"id", "finding_id", "tool_id", "provider_id", "rule_id", "severity", "title",
                          "status", "created_at", "acked_at", "finding", "remediation"}
    assert alert["status"] == "open" and alert["remediation"] is None and alert["finding"]["id"] == alert["finding_id"]


def test_alert_filters(client, loaded):
    assert client.get("/api/alerts", params={"severity": "low"}).json()["total"] == 13
    assert client.get("/api/alerts", params={"severity": "high,critical"}).json()["total"] == 13
    assert client.get("/api/alerts", params={"severity": "low, medium"}).json()["total"] == 14
    assert client.get("/api/alerts", params={"status": "open"}).json()["total"] == 27
    assert client.get("/api/alerts", params={"status": "acked"}).json()["total"] == 0
    assert client.get("/api/alerts", params={"tool_id": "browser|chatgpt_web"}).json()["total"] == 1
    assert client.get("/api/alerts", params={"rule_id": "POLICY_UNSANCTIONED_TOOL"}).json()["total"] == 13
    assert len(client.get("/api/alerts", params={"limit": 4}).json()["items"]) == 4


@pytest.mark.parametrize("params", [{"severity": "catastrophic"}, {"severity": "low,bogus"}, {"status": "snoozed"}])
def test_bad_alert_filters_are_422_json(client, loaded, params):
    r = client.get("/api/alerts", params=params)
    assert r.status_code == 422 and set(r.json()) == {"error"}


def test_acknowledge_an_alert(client, loaded):
    alert_id = client.get("/api/alerts").json()["items"][0]["id"]
    r = client.post(f"/api/alerts/{alert_id}/ack")
    assert r.status_code == 200
    assert r.json()["status"] == "acked" and r.json()["acked_at"].endswith("Z")
    again = client.post(f"/api/alerts/{alert_id}/ack").json()
    assert again["acked_at"] == r.json()["acked_at"]                           # a second ack changes nothing
    assert client.get("/api/alerts", params={"status": "acked"}).json()["total"] == 1
    assert client.get("/api/alerts", params={"status": "open"}).json()["total"] == 26


def test_acknowledging_an_unknown_or_malformed_id(client):
    missing = client.post(f"/api/alerts/{new_id()}/ack")
    assert missing.status_code == 404 and missing.json() == {"error": "alert not found"}
    assert client.post("/api/alerts/not-a-uuid/ack").status_code == 422


# ---- the live stream is wired to the app -------------------------------------

def test_the_app_publishes_to_its_bus(client, bus):
    upload(client, json.dumps({"ts": "2026-10-31T10:00:00Z", "host": "api.openai.com", "method": "POST", "path": "/v1"}))
    assert bus.sent == ["event.new", "finding.new", "alert.new"]
    assert client.app.state.pipeline is not None and client.app.state.bus is bus


def test_the_real_analyzer_is_picked_up_automatically_when_it_exists(tmp_path, db, monkeypatch):
    from shadowlens import analysis

    calls = []
    monkeypatch.setattr(analysis, "analyze", lambda e, c, x: calls.append(e.id) or AnalysisResult(), raising=False)
    with TestClient(create_app(make_config(tmp_path), db=db, ui_dir=tmp_path)) as c:
        upload(c, json.dumps({"ts": "2026-10-31T10:00:00Z", "host": "api.openai.com", "method": "POST",
                              "path": "/v1", "body": "text"}))
    assert len(calls) == 1

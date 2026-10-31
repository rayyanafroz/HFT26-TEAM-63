"""Compliance, evidence and the local-only guard (SOT 7.6, 8.5, AT-21)."""

import json

import pytest
from fastapi.testclient import TestClient

from shadowlens.api.app import create_app
from shadowlens.config import Config
from shadowlens.core import compliance as comp
from shadowlens.models import Compliance


def make_config(tmp_path, **env):
    return Config.load(env={"SHADOWLENS_RESOLVE": "false", **env}, base_dir=tmp_path, use_dotenv=False)


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(make_config(tmp_path))) as c:
        yield c


# ---- compliance -------------------------------------------------------------

def test_the_shipped_mapping_loads_and_has_every_control_from_the_sot():
    controls = {c.id: c for c in comp.load_controls()}
    assert len(controls) == 12
    assert controls["OWASP-LLM01"].rules == ["AGENT_INJECTION_CHAIN"]
    assert controls["GDPR-28-44"].rules == ["POLICY_UNSANCTIONED_TOOL"]


@pytest.mark.parametrize("rule,pattern,expected", [
    ("SEC_AWS_ACCESS_KEY", "SEC_*", True), ("PII_EMAIL", "SEC_*", False),
    ("POLICY_UNSANCTIONED_TOOL", "POLICY_UNSANCTIONED_TOOL", True), ("POLICY_LOCAL_LLM", "POLICY_UNSANCTIONED_TOOL", False),
    ("SEC", "SEC_*", False)])
def test_pattern_matching(rule, pattern, expected):
    assert comp.rule_matches(rule, pattern) is expected


@pytest.mark.parametrize("text", ["controls: []\nextra: 1", "- not a mapping", "controls: [{id: a}]",
                                  "controls: [{id: a, framework: f, title: t, rules: [x]}, {id: a, framework: f, title: t, rules: [x]}]"])
def test_a_bad_mapping_file_is_refused_with_a_clear_error(tmp_path, text):
    path = tmp_path / "c.yaml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(comp.ComplianceConfigError):
        comp.load_controls(path)
    with pytest.raises(comp.ComplianceConfigError):
        comp.load_controls(tmp_path / "missing.yaml")


def test_with_nothing_found_every_control_is_ok(client):
    body = client.get("/api/compliance").json()
    assert body["disclaimer"] == "This is an interpretation of risk, not an audit."
    assert len(body["controls"]) == 12 and all(c["status"] == "ok" for c in body["controls"])
    assert body["org_risk"] == 0 and body["compliance_score"] == 100
    Compliance.model_validate(body)


def test_findings_open_gaps_and_acknowledging_their_alerts_closes_them(client):
    client.post("/api/demo/load-scenario", json={"name": "quick_leak"})
    gaps = {c["id"]: c for c in client.get("/api/compliance").json()["controls"] if c["status"] == "gap"}
    assert {"OWASP-LLM02", "OWASP-LLM03", "NIST-AIRMF-GOVERN-6.1", "GDPR-28-44"} <= set(gaps)
    assert "OWASP-LLM01" not in gaps                                    # no injection finding in this scenario
    findings = {f["id"] for f in client.get("/api/findings").json()["items"]}
    assert all(set(c["finding_ids"]) <= findings and c["finding_count"] == len(c["finding_ids"]) for c in gaps.values())
    for alert in client.get("/api/alerts").json()["items"]:
        client.post(f"/api/alerts/{alert['id']}/ack")
    after = client.get("/api/compliance").json()
    assert all(c["status"] == "ok" for c in after["controls"])         # every finding of this scenario raised an alert


def test_the_compliance_score_is_one_hundred_minus_the_org_risk(client):
    client.post("/api/demo/load-scenario", json={"name": "full_demo"})
    body = client.get("/api/compliance").json()
    assert body["compliance_score"] == 100 - body["org_risk"] > 0
    assert body["org_risk"] == client.get("/api/stats/summary").json()["risk"]["org_risk"]


# ---- evidence ----------------------------------------------------------------

def test_evidence_is_unavailable_without_a_file(client):
    assert client.get("/api/evidence").json() == {"available": False, "generated_at": None, "metrics": []}


def test_evidence_serves_the_runner_file_with_pass_as_its_field_name(tmp_path):
    config = make_config(tmp_path)
    config.db_path.parent.mkdir(parents=True, exist_ok=True)
    metric = {"id": "secret_recall", "label": "Secret recall", "value": 100.0, "target": 95.0, "unit": "%",
              "pass": True, "fixture": "fixtures/payloads_labeled.jsonl", "command": "python -m shadowlens.eval.run"}
    (config.db_path.parent / "evidence.json").write_text(json.dumps(
        {"available": True, "generated_at": "2026-10-31T00:00:00.000Z", "metrics": [metric]}), encoding="utf-8")
    with TestClient(create_app(config)) as c:
        body = c.get("/api/evidence").json()
    assert body["available"] is True and body["metrics"] == [metric]


@pytest.mark.parametrize("text", ["not json", "[]", '{"available": true, "metrics": [{"id": 1}]}'])
def test_a_broken_evidence_file_means_unavailable_not_an_error(tmp_path, text):
    config = make_config(tmp_path)
    config.db_path.parent.mkdir(parents=True, exist_ok=True)
    (config.db_path.parent / "evidence.json").write_text(text, encoding="utf-8")
    with TestClient(create_app(config)) as c:
        response = c.get("/api/evidence")
    assert response.status_code == 200 and response.json()["available"] is False


# ---- local-only guard ----------------------------------------------------------

@pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.1:8787", "localhost", "localhost:8787", "[::1]:8787", "LOCALHOST"])
def test_requests_addressed_to_this_machine_are_served(client, host):
    assert client.get("/api/health", headers={"host": host}).status_code == 200


@pytest.mark.parametrize("host", ["evil.example", "evil.example:8787", "127.0.0.1.evil.example", "192.168.1.5:8787",
                                  "localhost.evil.example", "0.0.0.0:8787"])
def test_a_foreign_host_header_is_refused(client, host):
    response = client.get("/api/health", headers={"host": host})
    assert response.status_code == 403 and response.json() == {"error": "requests must be addressed to this machine"}


@pytest.mark.parametrize("origin,allowed", [
    ("http://127.0.0.1:8787", True), ("http://localhost:8787", True),
    ("https://evil.example", False), ("null", False), ("http://127.0.0.1.evil.example", False)])
def test_a_request_from_another_website_is_refused(client, origin, allowed):
    response = client.post("/api/demo/stop", headers={"origin": origin})
    assert (response.status_code == 200) is allowed
    if not allowed:
        assert response.status_code == 403 and "other websites" in response.json()["error"]


def test_a_refused_request_changes_nothing(client):
    client.post("/api/demo/reset", headers={"origin": "https://evil.example"})
    client.post("/api/demo/load-scenario", json={"name": "quick_leak"})
    client.post("/api/demo/reset", headers={"origin": "https://evil.example"})
    assert client.get("/api/stats/summary").json()["totals"]["events"] > 0


def test_the_stream_is_protected_too(client):
    assert client.get("/api/stream", headers={"host": "evil.example"}).status_code == 403

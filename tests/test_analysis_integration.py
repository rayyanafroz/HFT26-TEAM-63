"""The real analyzer inside the real pipeline and API, with nothing stubbed (SOT 4.2)."""

import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from shadowlens.analysis import engine
from shadowlens.api.app import create_app
from shadowlens.config import Config
from shadowlens.core import pipeline as pipeline_module
from shadowlens.core.pipeline import PATH_HIDDEN, Pipeline
from shadowlens.db import Database
from shadowlens.fakes import fake
from shadowlens.ingest.http_log import event_from_record
from shadowlens.providers.catalog import Catalog

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLE = REPO_ROOT / "fixtures" / "sample_http.jsonl"
CATALOG = Catalog.load()
TS = "2026-10-31T10:00:00Z"


def make_config(tmp_path):
    return Config.load(env={"SHADOWLENS_RESOLVE": "false"}, base_dir=tmp_path, use_dotenv=False)


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(make_config(tmp_path), ui_dir=tmp_path / "none")) as c:
        yield c


@pytest.fixture
def db(tmp_path):
    database = Database(tmp_path / "shadow.db")
    yield database
    database.close()


@pytest.fixture
def pipeline(tmp_path, db):
    return Pipeline(make_config(tmp_path), db, CATALOG, analyze=engine.analyze)


def upload(client, data, name="log.jsonl"):
    payload = data if isinstance(data, bytes) else data.encode("utf-8")
    return client.post("/api/ingest/log", files={"file": (name, payload, "application/octet-stream")}).json()


def record(content="hello", **fields):
    body = json.dumps({"model": "gpt-4o", "messages": [{"role": "user", "content": content}]})
    return {"ts": TS, "host": "api.openai.com", "method": "POST", "path": "/v1/chat/completions",
            "process_name": "python3", "body": body, **fields}


def findings_for(client, tool_id):
    items = client.get("/api/findings", params={"tool_id": tool_id, "limit": 1000}).json()["items"]
    return sorted(item["rule_id"] for item in items)


def sample_fakes():
    text = SAMPLE.read_text(encoding="utf-8")
    return sorted({fake(kind, int(idx or 0)) for kind, idx in re.findall(r"\{\{fake:([a-z0-9_]+)(?:#(\d+))?\}\}", text)})


# ---- the sample file, tool by tool --------------------------------------------------------

def test_each_tool_in_the_sample_gets_exactly_what_it_did(client):
    upload(client, SAMPLE.read_bytes())
    policy = "POLICY_UNSANCTIONED_TOOL"
    assert findings_for(client, "python3|openai") == sorted(
        [policy, "SEC_AWS_ACCESS_KEY", "SEC_AWS_SECRET_KEY", "SEC_OPENAI_KEY"])
    assert findings_for(client, "supportbot|anthropic") == sorted(
        [policy, "PII_AADHAAR", "PII_CREDIT_CARD", "PII_CREDIT_CARD", "PII_EMAIL", "PII_EMAIL", "PII_PHONE"])
    assert findings_for(client, "node|mistral") == sorted([policy, "SEC_JWT"])
    assert findings_for(client, "curl|huggingface") == [policy]              # its own token in its own header
    assert findings_for(client, "python3|ollama") == sorted(["POLICY_LOCAL_LLM", "SEC_DB_URL"])
    assert findings_for(client, "autogpt|openai") == sorted([
        policy, "AGENT_SHELL_EXEC", "AGENT_DANGEROUS_CMD", "AGENT_EXCESSIVE_AGENCY", "AGENT_NETWORK_TOOL"])
    assert findings_for(client, "cursor|anthropic") == sorted(
        [policy, "AGENT_SENSITIVE_FILE_READ", "AGENT_SENSITIVE_FILE_READ"])
    assert findings_for(client, "python3|google_gemini") == sorted([policy, "SEC_GOOGLE_API_KEY"])
    assert findings_for(client, "app|groq") == [policy]
    assert findings_for(client, "browser|chatgpt_web") == [policy]           # no readable body


def test_alerts_use_the_shared_titles_and_masked_values(client):
    upload(client, SAMPLE.read_bytes())
    alert = client.get("/api/alerts", params={"rule_id": "SEC_AWS_SECRET_KEY"}).json()["items"][0]
    assert alert["title"] == "AWS secret access key sent to an AI tool" and alert["severity"] == "critical"
    assert alert["finding"]["masked_preview"].endswith("(len 40)")
    assert alert["finding"]["owasp"] == ["LLM02"]


def test_agent_activity_reaches_the_database(pipeline, db):
    line = json.loads(SAMPLE.read_text(encoding="utf-8").splitlines()[8])
    from shadowlens.fakes import expand
    pipeline.ingest([event_from_record(line, expand=expand)], source="http_log")
    rows = db.list_agent_activity("autogpt|openai")
    assert {(row.capability.value, row.kind.value) for row in rows} >= {
        ("shell", "granted"), ("fs_read", "granted"), ("network", "granted"), ("shell", "used"), ("network", "used")}
    used = next(row for row in rows if row.capability.value == "shell" and row.kind.value == "used")
    assert used.risky and db.get_finding(used.finding_id).rule_id == "AGENT_DANGEROUS_CMD"


# ---- AT-12, AT-35: no raw secret anywhere ----------------------------------------------------

def test_no_fake_from_the_sample_is_in_the_database_files_or_any_response(client, tmp_path):
    upload(client, SAMPLE.read_bytes())
    responses = "".join(
        client.get(url, params={"limit": 1000}).text for url in ("/api/events", "/api/findings", "/api/alerts"))
    client.app.state.db._conn.execute("PRAGMA wal_checkpoint(FULL)")
    stored = b"".join(path.read_bytes() for path in (tmp_path / "data").glob("shadow.db*"))
    values = sample_fakes()
    assert len(values) >= 14
    for value in values:
        assert value not in responses
        assert value.encode("utf-8") not in stored
        if len(value) >= 12:
            assert value[4:12] not in responses and value[4:12].encode("utf-8") not in stored


def test_only_the_tail_of_a_card_is_kept(client):
    card = fake("card_visa", 8)
    upload(client, json.dumps(record(f"card {card}")))
    item = client.get("/api/findings", params={"rule_id": "PII_CREDIT_CARD"}).json()["items"][0]
    assert item["masked_preview"] == "****" + card[-4:]


# ---- secrets in paths ---------------------------------------------------------------------------

def test_secret_in_a_path_is_found_and_not_stored_or_sent(client):
    key = fake("github_token", 5)
    summary = upload(client, json.dumps(record(path=f"/hook/{key}")))
    assert summary["errors"] == []
    events = client.get("/api/events").text
    assert key not in events and "[REDACTED:SEC_GITHUB_TOKEN:" in events and "/hook/" in events
    item = client.get("/api/findings", params={"rule_id": "SEC_GITHUB_TOKEN"}).json()["items"][0]
    assert item["location"]["field"] == "path"


def test_path_of_an_event_with_no_body_is_still_redacted(client):
    key = fake("github_token", 6)
    upload(client, json.dumps(record(path=f"/hook/{key}", body=None)))
    assert key not in client.get("/api/events").text
    # Nothing readable, so no detector ran on it (SOT 2.5).
    assert client.get("/api/findings", params={"rule_id": "SEC_GITHUB_TOKEN"}).json()["total"] == 0


def test_published_event_has_the_redacted_path(tmp_path, db):
    sent = []
    instance = Pipeline(make_config(tmp_path), db, CATALOG, analyze=engine.analyze,
                        publish=lambda kind, payload: sent.append((kind, payload)))
    key = fake("github_token", 7)
    instance.ingest([event_from_record(record(path=f"/hook/{key}"))], source="http_log")
    lite = next(payload for kind, payload in sent if kind == "event.new")
    assert key not in lite.path and "/hook/" in lite.path


def test_ordinary_paths_are_left_exactly_as_they_are(client):
    long_path = "/openai/deployments/gpt-4o-2024-08-06-production/chat/completions/v1/stream2"
    upload(client, json.dumps(record(path=long_path)))
    assert client.get("/api/events").json()["items"][0]["path"] == long_path
    assert client.get("/api/findings", params={"category": "secret"}).json()["total"] == 0


def test_path_is_withheld_if_it_cannot_be_checked(pipeline, db, monkeypatch):
    def broken(path, cfg):
        raise RuntimeError("detector failure")

    monkeypatch.setattr(pipeline_module, "redact_path", broken)
    pipeline.ingest([event_from_record(record(path="/hook/anything"))], source="http_log")
    assert db.list_events().items[0].path == PATH_HIDDEN


# ---- AT-10: no double counting, across requests and restarts ------------------------------------

def test_replaying_the_sample_adds_no_findings_or_alerts(client):
    first = upload(client, SAMPLE.read_bytes())
    second = upload(client, SAMPLE.read_bytes())
    assert first["findings"] == 33 and first["alerts"] == 27
    assert second["accepted"] == first["accepted"] and second["findings"] == 0 and second["alerts"] == 0
    assert client.get("/api/findings", params={"limit": 1000}).json()["total"] == 33


def test_conversation_resent_with_a_new_message_adds_only_the_new_call(pipeline, db):
    def call(command):
        return {"role": "assistant", "tool_calls": [
            {"function": {"name": "bash", "arguments": json.dumps({"command": command})}}]}

    history = [call("ls -la")]
    first = pipeline.ingest([event_from_record(record(body=json.dumps({"messages": history})))], source="http_log")
    history = history + [call("rm -rf ~")]
    second = pipeline.ingest([event_from_record(record(body=json.dumps({"messages": history})))], source="http_log")
    assert first.findings == 2                                               # policy + shell
    assert second.findings == 2                                              # the new call: shell + dangerous
    used = [row for row in db.list_agent_activity("python3|openai") if row.kind.value == "used"]
    assert len(used) == 2


def test_restart_with_the_same_database_does_not_crash_or_duplicate(tmp_path, db):
    """After a restart the memory is empty but the database is not: the old findings get new ids,
    are refused, and their activity must not point at them (a foreign key would fail)."""
    line = json.loads(SAMPLE.read_text(encoding="utf-8").splitlines()[8])
    from shadowlens.fakes import expand

    def run():
        instance = Pipeline(make_config(tmp_path), db, CATALOG, analyze=engine.analyze)
        return instance.ingest([event_from_record(line, expand=expand)], source="http_log")

    first = run()
    second = run()
    assert first.findings == 5 and first.skipped == 0
    assert second.findings == 0 and second.skipped == 0 and second.errors == [] and second.accepted == 1


def test_reset_lets_everything_fire_again(pipeline, db):
    event = lambda: event_from_record(record(f"key {fake('openai_key', 9)}"))  # noqa: E731
    assert pipeline.ingest([event()], source="http_log").findings == 2
    assert pipeline.ingest([event()], source="http_log").findings == 0
    pipeline.reset()
    assert pipeline.ingest([event()], source="http_log").findings == 2


# ---- provider-native keys, through the real catalog (AT-09) ---------------------------------------

def test_own_key_in_own_header_is_fine_and_another_providers_is_not(client):
    own = record(headers={"authorization": f"Bearer {fake('openai_key', 3)}"})
    foreign = record(headers={"authorization": f"Bearer {fake('anthropic_key', 3)}"}, process_name="other")
    upload(client, json.dumps(own) + "\n" + json.dumps(foreign))
    assert findings_for(client, "python3|openai") == ["POLICY_UNSANCTIONED_TOOL"]
    assert findings_for(client, "other|openai") == ["POLICY_UNSANCTIONED_TOOL", "SEC_ANTHROPIC_KEY"]


def test_own_key_pasted_into_a_prompt_still_counts(client):
    upload(client, json.dumps(record(f"why does {fake('openai_key', 4)} fail")))
    assert "SEC_OPENAI_KEY" in findings_for(client, "python3|openai")


# ---- the pieces fit ----------------------------------------------------------------------------------

def test_the_app_uses_the_real_analyzer_by_default(client):
    summary = upload(client, json.dumps(record(f"key {fake('stripe_key', 2)}")))
    assert summary["errors"] == [] and summary["findings"] == 2


def test_analyzer_accepts_the_pipeline_call_signature(tmp_path):
    from shadowlens.core.ctx import AgentSessionContext
    result = engine.analyze(event_from_record(record(f"key {fake('hf_token', 2)}")), make_config(tmp_path),
                            AgentSessionContext(tool_id="python3|openai"))
    assert [finding.rule_id for finding in result.findings] == ["SEC_HF_TOKEN"]
    assert result.findings[0].tool_id == "python3|openai"


def test_salt_is_created_once_at_the_configured_path(client, tmp_path):
    upload(client, json.dumps(record(f"key {fake('stripe_key', 3)}")))
    salt = (tmp_path / "data" / "salt").read_bytes()
    upload(client, json.dumps(record(f"key {fake('stripe_key', 4)}")))
    assert len(salt) == 32 and (tmp_path / "data" / "salt").read_bytes() == salt


def test_every_rule_has_a_title_and_every_catalog_rule_is_a_real_rule():
    from shadowlens.analysis.catalog import RULES
    from shadowlens.core.rule_titles import RULE_TITLES
    from shadowlens.models import RULE_IDS
    assert set(RULES) <= RULE_IDS and RULE_IDS == set(RULE_TITLES)
    assert set(RULES) == {rule for rule in RULE_IDS if not rule.startswith("POLICY_")}

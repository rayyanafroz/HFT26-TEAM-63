import json
import re

import pytest
from pydantic import ValidationError

from shadowlens import models as m
from shadowlens.models import (
    Finding,
    HostBasis,
    NetEvent,
    ProviderMatch,
    Severity,
    Source,
    Visibility,
    make_tool_id,
    new_id,
    utc_now_iso,
)


def event(**overrides):
    base = dict(
        id=new_id(), ts="2026-10-31T10:00:00.000Z", source="http_log", process="Python3",
        dst_ip="203.0.113.7", dst_port=443, host="API.OpenAI.com.", host_basis="host_header",
    )
    base.update(overrides)
    return NetEvent(**base)


def finding(**overrides):
    base = dict(
        id=new_id(), event_id=new_id(), tool_id="python3|openai", rule_id="SEC_OPENAI_KEY",
        category="secret", severity="high", confidence=0.9, masked_preview="sk-p... (len 51)",
        location={"field": "body", "offset": 12}, owasp=["LLM02"], controls=[],
        meta={"hash12": "0123456789ab", "spans": [[12, 63]], "context": "key=[REDACTED:SEC_OPENAI_KEY:0123456789ab]"},
        created_at="2026-10-31T10:00:00.100Z",
    )
    base.update(overrides)
    return Finding(**base)


# ---- helpers -----------------------------------------------------------------

def test_new_id_is_a_lowercase_uuid4():
    assert re.fullmatch(r"[0-9a-f-]{36}", new_id())
    assert new_id() != new_id()


def test_utc_now_iso_format():
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", utc_now_iso())


def test_make_tool_id():
    assert make_tool_id("Python3", "openai") == "python3|openai"
    assert make_tool_id(None, "openai") == "unknown|openai"
    assert make_tool_id("  ", "openai") == "unknown|openai"


# ---- vocabulary (exact SOT values) -------------------------------------------

def test_enum_values_are_the_sot_strings():
    assert {x.value for x in Source} == {"conn_scan", "http_log", "har", "pcap", "live_log", "transcript", "proxy", "browser", "scenario"}
    assert {x.value for x in HostBasis} == {"sni", "host_header", "url", "resolved_ip", "dns_query", "port_only", "transcript"}
    assert {x.value for x in Visibility} == {"full", "metadata_only"}
    assert {x.value for x in m.AuthScheme} == {"bearer", "x-api-key", "x-goog-api-key", "basic"}
    assert {x.value for x in Severity} == {"info", "low", "medium", "high", "critical"}
    assert {x.value for x in m.Band} == {"low", "moderate", "high", "critical"}
    assert {x.value for x in m.Category} == {"cloud_llm", "local_llm", "model_hub", "ai_app"}
    assert {x.value for x in m.MatchConfidence} == {"high", "medium", "low"}
    assert {x.value for x in m.MatchBasis} == {"host", "port", "resolved_ip"}
    assert {x.value for x in m.FindingCategory} == {"secret", "pii", "code", "agent", "policy"}
    assert {x.value for x in m.LocationField} == {
        "body", "path", "header:authorization", "header:x-api-key", "tool_call", "tool_declaration", "tool_result"}


def test_severity_rank_orders_correctly():
    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    assert [s.rank for s in order] == [0, 1, 2, 3, 4]
    assert Severity.CRITICAL.rank > Severity.HIGH.rank


def test_rule_catalog_has_every_prefix_and_count():
    assert len(m.RULE_IDS) == 37
    for prefix in ("SEC_", "PII_", "CODE_", "AGENT_", "POLICY_"):
        assert any(r.startswith(prefix) for r in m.RULE_IDS)
    assert m.category_for_rule("PII_EMAIL") is m.FindingCategory.PII
    with pytest.raises(ValueError):
        m.category_for_rule("NOPE_X")


# ---- NetEvent ----------------------------------------------------------------

def test_event_normalizes_process_and_host():
    e = event()
    assert e.process == "python3"
    assert e.host == "api.openai.com"


@pytest.mark.parametrize("given,expected", [
    ("python.exe", "python"), ("Claude.EXE", "claude"), ("Cursor.exe ", "cursor"), ("python3", "python3"),
    ("node.js", "node.js"), ("tool.exe.exe", "tool.exe"), (".exe", ".exe"), ("  ", None), (None, None),
])
def test_process_names_are_normalized_for_windows(given, expected):
    assert event(process=given).process == expected


def test_visibility_is_derived_from_body_text():
    assert event(body_text=None).visibility is Visibility.METADATA_ONLY
    assert event(body_text="").visibility is Visibility.METADATA_ONLY
    assert event(body_text="hello").visibility is Visibility.FULL


def test_visibility_cannot_be_set_by_hand():
    with pytest.raises(ValidationError):
        event(visibility="full")


def test_visibility_is_in_the_json_output():
    assert event(body_text="x").model_dump(mode="json")["visibility"] == "full"


def test_only_whitelisted_headers_are_kept_and_lowercased():
    e = event(headers={"Authorization": "Bearer x", "Cookie": "session=abc", "User-Agent": "u",
                       "X-Api-Key": ["a", "b"], "Set-Cookie": "z"})
    assert e.headers == {"authorization": "Bearer x", "user-agent": "u", "x-api-key": "a, b"}


def test_headers_none_becomes_empty():
    assert event(headers=None).headers == {}


def test_path_must_not_contain_a_query():
    with pytest.raises(ValidationError):
        event(path="/v1/chat?key=abc")
    assert event(path="/v1/chat", query="key=abc").query == "key=abc"


@pytest.mark.parametrize("ip", ["203.0.113.7", "127.0.0.1", "0.0.0.0", "::1", "2001:db8::1"])
def test_valid_ips(ip):
    assert event(dst_ip=ip).dst_ip == ip


@pytest.mark.parametrize("ip", ["", "localhost", "999.1.1.1", "api.openai.com"])
def test_invalid_ips_rejected(ip):
    with pytest.raises(ValidationError):
        event(dst_ip=ip)


@pytest.mark.parametrize("port", [-1, 65536])
def test_invalid_ports_rejected(port):
    with pytest.raises(ValidationError):
        event(dst_port=port)


@pytest.mark.parametrize("field,value", [
    ("id", "not-a-uuid"), ("id", "ABCDEF12-1234-4123-8123-123456789ABC"),   # uppercase
    ("ts", "2026-10-31 10:00:00"), ("ts", "2026-10-31T10:00:00+05:30"),
    ("body_sha256", "abc"), ("auth_hint", "short"),
    ("source", "carrier_pigeon"), ("host_basis", "magic"), ("auth_scheme", "digest"),
    ("pid", -4), ("body_bytes", -1), ("bytes_out", -1),
])
def test_invalid_fields_rejected(field, value):
    with pytest.raises(ValidationError):
        event(**{field: value})


def test_unknown_field_rejected():
    with pytest.raises(ValidationError):
        event(secret_field="x")


def test_event_json_round_trip_uses_sot_field_names():
    e = event(body_text="hi", body_bytes=2, method="POST", path="/v1/chat", pid=4123, bytes_out=None)
    data = json.loads(e.model_dump_json())
    assert set(data) == {
        "id", "ts", "source", "process", "pid", "dst_ip", "dst_port", "host", "host_basis", "method", "path",
        "query", "headers", "body_text", "body_bytes", "body_sha256", "body_truncated", "bytes_out", "bytes_in",
        "auth_scheme", "auth_hint", "visibility"}
    assert NetEvent.model_validate({k: v for k, v in data.items() if k != "visibility"}) == e


def test_assignment_is_validated():
    e = event()
    with pytest.raises(ValidationError):
        e.dst_port = 70000


# ---- ProviderMatch -----------------------------------------------------------

def provider(**overrides):
    base = dict(provider_id="openai", display_name="OpenAI", category="cloud_llm", confidence="high",
                match_basis="host", tool_id="python3|openai")
    base.update(overrides)
    return ProviderMatch(**base)


def test_provider_match_ok():
    assert provider().tool_id == "python3|openai"


@pytest.mark.parametrize("tool_id", ["openai", "python3|anthropic", "|openai", "python3|"])
def test_provider_match_tool_id_must_agree(tool_id):
    with pytest.raises(ValidationError):
        provider(tool_id=tool_id)


def test_provider_match_enums_checked():
    with pytest.raises(ValidationError):
        provider(category="cloud")
    with pytest.raises(ValidationError):
        provider(match_basis="vibes")


# ---- Finding -----------------------------------------------------------------

def test_finding_ok_and_json_names():
    f = finding()
    data = json.loads(f.model_dump_json())
    assert set(data) == {"id", "event_id", "tool_id", "rule_id", "category", "severity", "confidence",
                         "masked_preview", "location", "owasp", "controls", "meta", "created_at"}
    assert set(data["meta"]) == {"hash12", "spans", "context", "in_tool_args", "count", "tool_name", "argument"}
    assert set(data["location"]) == {"field", "offset"}
    assert Finding.model_validate(data) == f


def test_unknown_rule_rejected():
    with pytest.raises(ValidationError):
        finding(rule_id="SEC_MADE_UP")


def test_category_must_match_rule_prefix():
    with pytest.raises(ValidationError):
        finding(category="pii")
    ok = finding(rule_id="PII_EMAIL", category="pii", severity="low")
    assert ok.category.value == "pii"


@pytest.mark.parametrize("confidence", [-0.1, 1.1])
def test_confidence_bounds(confidence):
    with pytest.raises(ValidationError):
        finding(confidence=confidence)


def test_context_and_argument_are_capped_at_200():
    with pytest.raises(ValidationError):
        finding(meta={"hash12": "0123456789ab", "context": "x" * 201})
    with pytest.raises(ValidationError):
        finding(meta={"hash12": "0123456789ab", "argument": "x" * 201})


@pytest.mark.parametrize("spans", [[[5, 2]], [[-1, 3]]])
def test_bad_spans_rejected(spans):
    with pytest.raises(ValidationError):
        finding(meta={"hash12": "0123456789ab", "spans": spans})


def test_hash12_must_be_12_hex_chars():
    with pytest.raises(ValidationError):
        finding(meta={"hash12": "0123456789abcdef"})
    with pytest.raises(ValidationError):
        finding(meta={"hash12": "XYZ"})


def test_location_field_is_one_of_the_sot_values():
    assert finding(location={"field": "header:authorization", "offset": None}).location.offset is None
    with pytest.raises(ValidationError):
        finding(location={"field": "header:cookie"})

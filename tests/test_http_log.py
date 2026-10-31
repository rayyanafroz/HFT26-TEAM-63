import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import pytest

from shadowlens.ingest import http_log
from shadowlens.ingest.http_log import (
    LogLineError, LogTooLargeError, ParseResult, detect_auth_scheme, event_from_record, format_ts,
    parse_jsonl_line, parse_log, parse_ts,
)
from shadowlens.models import AuthScheme, HostBasis, Source, Visibility
from shadowlens.providers.catalog import Catalog
from shadowlens.providers.classify import classify

SAMPLE = Path(__file__).resolve().parents[1] / "fixtures" / "sample_http.jsonl"
BASE = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)


def rec(**o):
    base = {"ts": "2026-10-30T14:03:22.114Z", "host": "api.openai.com", "method": "post",
            "path": "/v1/chat/completions"}
    base.update(o)
    return base


def line(**o):
    return json.dumps(rec(**o))


def placeholders(text):
    """A stand-in for fakes.expand: {{fake:kind#n}} becomes <kind-n>."""
    return re.sub(r"\{\{fake:([a-z_]+)#(\d+)\}\}", r"<\1-\2>", text)


# ---- one record -> one event ---------------------------------------------------

def test_minimal_record_gets_sensible_defaults():
    e = event_from_record(rec())
    assert (e.host, e.method, e.path, e.query) == ("api.openai.com", "POST", "/v1/chat/completions", None)
    assert e.ts == "2026-10-30T14:03:22.114Z"
    assert (e.dst_ip, e.dst_port) == ("0.0.0.0", 443)
    assert e.process == "unknown" and e.pid is None
    assert e.source is Source.HTTP_LOG and e.host_basis is HostBasis.HOST_HEADER
    assert e.visibility is Visibility.METADATA_ONLY and (e.body_text, e.body_bytes, e.body_sha256) == (None, 0, None)
    assert e.headers == {} and e.bytes_out is None and e.auth_scheme is None and e.auth_hint is None


def test_all_the_optional_fields():
    e = event_from_record(rec(dst_ip="203.0.113.7", dst_port=8443, process_name="Python.EXE", pid=4123,
                              bytes_out=321, body="hello", headers={"User-Agent": "x", "Cookie": "no"}))
    assert (e.dst_ip, e.dst_port, e.process, e.pid, e.bytes_out) == ("203.0.113.7", 8443, "python", 4123, 321)
    assert e.headers == {"user-agent": "x"}                      # cookie dropped by the whitelist
    assert e.visibility is Visibility.FULL


@pytest.mark.parametrize("fields,port", [
    ({}, 443), ({"tls": True}, 443), ({"tls": False}, 80),
    ({"dst_port": 9000}, 9000), ({"dst_port": 9000, "tls": False}, 9000),
    ({"host": "localhost:11434"}, 11434), ({"host": "localhost:11434", "tls": False}, 11434),
    ({"host": "localhost:11434", "dst_port": 1}, 1),
    ({"host": "example.com:99999"}, 443),                        # not a real port: ignored
])
def test_destination_port_rules(fields, port):
    assert event_from_record(rec(**fields)).dst_port == port


def test_host_that_is_an_address_sets_dst_ip():
    assert event_from_record(rec(host="127.0.0.1:11434")).dst_ip == "127.0.0.1"
    assert event_from_record(rec(host="10.0.0.5")).dst_ip == "10.0.0.5"
    assert event_from_record(rec(host="127.0.0.1", dst_ip="192.168.0.9")).dst_ip == "192.168.0.9"   # explicit wins
    assert event_from_record(rec(host="example.com")).dst_ip == "0.0.0.0"


def test_query_string_is_split_off_the_path():
    e = event_from_record(rec(path="/v1beta/models/x:generate?key=abc&alt=json#frag"))
    assert (e.path, e.query) == ("/v1beta/models/x:generate", "key=abc&alt=json")
    assert "?" not in e.path
    assert event_from_record(rec(path="/a#only-fragment")).path == "/a"
    assert event_from_record(rec(path="/a?")).query is None
    assert event_from_record(rec(path="?x=1")).path == "/"


# ---- the body ------------------------------------------------------------------

def test_body_hash_and_size_cover_the_whole_body():
    e = event_from_record(rec(body="héllo wörld"))
    data = "héllo wörld".encode("utf-8")
    assert e.body_text == "héllo wörld" and e.body_bytes == len(data)
    assert e.body_sha256 == hashlib.sha256(data).hexdigest() and e.body_truncated is False


def test_long_bodies_are_truncated_but_still_hashed_in_full():
    body = "a" * 100
    e = event_from_record(rec(body=body), max_body_bytes=40)
    assert e.body_text == "a" * 20 + "\n" + "a" * 20 and e.body_bytes == 100 and e.body_truncated is True
    assert e.body_sha256 == hashlib.sha256(body.encode()).hexdigest()
    exact = event_from_record(rec(body=body), max_body_bytes=100)
    assert exact.body_truncated is False and len(exact.body_text) == 100


def test_truncation_never_splits_a_character():
    e = event_from_record(rec(body="é" * 10), max_body_bytes=5)    # each é is 2 bytes
    assert e.body_text == "é\né" and e.body_bytes == 20 and e.body_truncated is True


@pytest.mark.parametrize("body", [None, ""])
def test_missing_or_empty_body_means_metadata_only(body):
    e = event_from_record(rec(body=body))
    assert e.body_text is None and e.visibility is Visibility.METADATA_ONLY


def test_json_object_bodies_are_accepted_as_text():
    e = event_from_record(rec(body={"model": "x", "n": 1}))
    assert json.loads(e.body_text) == {"model": "x", "n": 1}


@pytest.mark.parametrize("body", [5, True])
def test_other_body_types_are_rejected(body):
    with pytest.raises(LogLineError, match="body"):
        event_from_record(rec(body=body))


# ---- auth scheme (the credential itself is never read) -------------------------

@pytest.mark.parametrize("headers,scheme", [
    ({"Authorization": "Bearer abc"}, AuthScheme.BEARER), ({"authorization": "bearer abc"}, AuthScheme.BEARER),
    ({"Authorization": "Basic dXNlcjpwdw=="}, AuthScheme.BASIC), ({"x-api-key": "k"}, AuthScheme.X_API_KEY),
    ({"X-Goog-Api-Key": "k"}, AuthScheme.X_GOOG_API_KEY), ({"Authorization": "Token abc"}, None),
    ({"authorization": "Bearer a", "x-api-key": "b"}, AuthScheme.BEARER), ({}, None),
])
def test_auth_scheme(headers, scheme):
    assert detect_auth_scheme(headers) is scheme
    assert event_from_record(rec(headers=headers)).auth_scheme is scheme
    assert event_from_record(rec(headers=headers)).auth_hint is None   # hashing needs the salt: the pipeline's job


# ---- timestamps ----------------------------------------------------------------

@pytest.mark.parametrize("given,expected", [
    ("2026-10-30T14:03:22.114Z", "2026-10-30T14:03:22.114Z"),
    ("2026-10-30T14:03:22Z", "2026-10-30T14:03:22.000Z"),
    ("2026-10-30T14:03:22.114+05:30", "2026-10-30T08:33:22.114Z"),
    ("2026-10-30T14:03:22.114-02:00", "2026-10-30T16:03:22.114Z"),
    ("2026-10-30T14:03:22", "2026-10-30T14:03:22.000Z"),            # no zone: UTC
    ("2026-10-30T14:03:22.123456Z", "2026-10-30T14:03:22.123Z"),
])
def test_timestamps_become_utc_with_milliseconds(given, expected):
    assert event_from_record(rec(ts=given)).ts == expected


@pytest.mark.parametrize("bad", ["yesterday", "", "2026-13-45T00:00:00Z", 12345])
def test_bad_timestamps_are_rejected(bad):
    with pytest.raises(LogLineError, match="timestamp"):
        event_from_record(rec(ts=bad))


def test_t_ms_counts_from_the_base_time():
    r = rec(t_ms=1500)
    del r["ts"]
    assert event_from_record(r, base_time=BASE).ts == "2026-10-31T12:00:01.500Z"
    r["t_ms"] = 0
    assert event_from_record(r, base_time=BASE).ts == "2026-10-31T12:00:00.000Z"


def test_ts_wins_over_t_ms_and_one_is_required():
    assert event_from_record(rec(t_ms=5000), base_time=BASE).ts == "2026-10-30T14:03:22.114Z"
    r = rec()
    del r["ts"]
    with pytest.raises(LogLineError, match="ts"):
        event_from_record(r)
    with pytest.raises(LogLineError, match="t_ms"):
        event_from_record({**r, "t_ms": -1})


def test_timestamp_helpers_round_trip():
    moment = parse_ts("2026-10-30T14:03:22.114Z")
    assert format_ts(moment) == "2026-10-30T14:03:22.114Z"


# ---- sources -------------------------------------------------------------------

def test_source_rules():
    assert event_from_record(rec()).source is Source.HTTP_LOG
    assert event_from_record(rec(source="scenario")).source is Source.SCENARIO
    assert event_from_record(rec(source="pcap")).source is Source.PCAP
    assert event_from_record(rec(source="scenario"), source=Source.LIVE_LOG).source is Source.LIVE_LOG   # caller wins
    assert event_from_record(rec(), source=Source.LIVE_LOG).source is Source.LIVE_LOG
    for not_allowed in ("har", "live_log", "carrier_pigeon", 5):
        with pytest.raises(LogLineError, match="source"):
            event_from_record(rec(source=not_allowed))


# ---- bad records ---------------------------------------------------------------

@pytest.mark.parametrize("record,fragment", [
    ("a string", "JSON object"), (["a"], "JSON object"), (None, "JSON object"), (5, "JSON object"),
    ({"method": "GET", "path": "/", "ts": "2026-10-30T14:03:22Z"}, "host"),
    (rec(host=""), "host"), (rec(host=None), "host"), (rec(host=5), "host"),
    (rec(method=None), "method"), (rec(path=None), "path"),
    (rec(pid="12"), "pid"), (rec(pid=True), "pid"), (rec(pid=-1), "pid"),
    (rec(dst_port=70000), "dst_port"), (rec(dst_port="443"), "dst_port"), (rec(dst_port=-1), "dst_port"),
    (rec(tls="yes"), "tls"), (rec(dst_ip=5), "dst_ip"), (rec(dst_ip="not-an-ip"), "dst_ip"),
    (rec(headers=["a"]), "headers"), (rec(process_name=5), "process_name"), (rec(bytes_out=-3), "bytes_out"),
    (rec(bytes_out="big"), "bytes_out"),
])
def test_bad_records_raise_a_clear_error(record, fragment):
    with pytest.raises(LogLineError) as err:
        event_from_record(record)
    assert fragment in str(err.value)


def test_error_messages_never_contain_request_content():
    secret = "SECRETMARKER-do-not-leak"
    for bad in (rec(body=secret, pid="x"), rec(body=secret, dst_ip=secret), rec(body=secret, ts=secret),
                rec(headers={"authorization": secret}, tls=secret), rec(body=secret, dst_port=secret)):
        with pytest.raises(LogLineError) as err:
            event_from_record(bad)
        assert secret not in str(err.value)


# ---- placeholder expansion -----------------------------------------------------

def test_placeholders_are_expanded_in_body_path_and_header_values():
    e = event_from_record(
        rec(path="/x?key={{fake:google_key#1}}", body="a {{fake:email#1}} b", headers={"x-api-key": "{{fake:openai_key#1}}"}),
        expand=placeholders)
    assert e.body_text == "a <email-1> b"
    assert (e.path, e.query) == ("/x", "key=<google_key-1>")
    assert e.headers["x-api-key"] == "<openai_key-1>"


def test_expansion_is_applied_before_hashing_and_sizing():
    e = event_from_record(rec(body="{{fake:email#1}}"), expand=placeholders)
    assert e.body_bytes == len("<email-1>") and e.body_sha256 == hashlib.sha256(b"<email-1>").hexdigest()


def test_a_failing_expander_skips_the_record_without_leaking():
    def boom(text):
        raise RuntimeError(text)                                  # would leak the text if it were propagated
    with pytest.raises(LogLineError) as err:
        event_from_record(rec(body="SECRETMARKER"), expand=boom)
    assert str(err.value) == "placeholder expansion failed"


# ---- JSONL files ---------------------------------------------------------------

def test_parse_jsonl_counts_good_and_bad_lines():
    text = "\n".join([line(), "not json at all", line(host=""), "", line(path="/b"), '["array"]'])
    r = parse_log(text)
    assert (len(r.events), r.skipped, r.format, r.source) == (2, 3, "jsonl", "http_log")
    assert r.errors[0].startswith("line 2: not valid JSON")
    assert r.errors[1].startswith("line 3:") and "host" in r.errors[1]
    assert r.errors[2].startswith("line 6:")                       # numbers are file line numbers; blanks count


def test_only_the_first_20_errors_are_kept_but_all_are_counted():
    r = parse_log("\n".join(["garbage"] * 50 + [line()]))
    assert (len(r.events), r.skipped, len(r.errors)) == (1, 50, 20)


def test_line_endings_bom_and_bytes_input():
    crlf = (line() + "\r\n" + line(path="/b") + "\r\n").encode("utf-8")
    assert len(parse_log(crlf).events) == 2
    assert len(parse_log(b"\xef\xbb\xbf" + crlf).events) == 2        # UTF-8 BOM (Windows Notepad)
    assert len(parse_log("﻿" + line()).events) == 1
    assert len(parse_log(b"").events) == 0 and parse_log(b"").skipped == 0
    assert len(parse_log(line().encode("utf-8") + b"\n\xff\xfe").events) == 1   # undecodable tail: one bad line
    assert parse_log(line().encode("utf-8") + b"\n\xff\xfe").skipped == 1


def test_single_line_jsonl_is_not_mistaken_for_har():
    r = parse_log(line())
    assert r.format == "jsonl" and len(r.events) == 1


def test_options_are_passed_through():
    r = parse_log(line(body="x" * 50), max_body_bytes=10, source=Source.LIVE_LOG)
    assert r.events[0].body_truncated and r.events[0].source is Source.LIVE_LOG


def test_size_limit():
    big = line() + "\n" + line()
    with pytest.raises(LogTooLargeError):
        parse_log(big, max_log_bytes=len(big) - 1)
    assert len(parse_log(big, max_log_bytes=len(big)).events) == 2          # exactly at the limit is fine
    with pytest.raises(LogTooLargeError):
        parse_log(big.encode("utf-8"), max_log_bytes=10)
    assert http_log.MAX_LOG_BYTES == 20 * 1024 * 1024


def test_parse_jsonl_line_helper():
    assert parse_jsonl_line(line(), source=Source.LIVE_LOG).source is Source.LIVE_LOG
    with pytest.raises(LogLineError, match="not valid JSON"):
        parse_jsonl_line("{broken")


# ---- HAR -----------------------------------------------------------------------

def har(*entries):
    return json.dumps({"log": {"version": "1.2", "creator": {"name": "test"}, "entries": list(entries)}})


def har_entry(url="https://chatgpt.com/backend-api/conversation?x=1", method="POST", text='{"prompt":"hi"}',
              started="2026-10-30T14:03:22.114+05:30", **o):
    entry = {"startedDateTime": started, "request": {
        "method": method, "url": url, "headers": [{"name": "Content-Type", "value": "application/json"},
                                                   {"name": "Cookie", "value": "session=secret"}],
        "postData": {"mimeType": "application/json", "text": text}, "bodySize": len(text or "")}}
    entry.update(o)
    return entry


def test_har_entry_becomes_an_event():
    r = parse_log(har(har_entry()))
    assert (r.format, r.source, len(r.events), r.skipped) == ("har", "har", 1, 0)
    e = r.events[0]
    assert (e.host, e.method, e.path, e.query, e.dst_port) == ("chatgpt.com", "POST", "/backend-api/conversation", "x=1", 443)
    assert (e.source, e.host_basis, e.process) == (Source.HAR, HostBasis.URL, "browser")
    assert e.ts == "2026-10-30T08:33:22.114Z"
    assert e.body_text == '{"prompt":"hi"}' and e.visibility is Visibility.FULL and e.bytes_out == 15
    assert e.headers == {"content-type": "application/json"}           # the cookie is dropped


def test_har_ports_schemes_and_server_ip():
    r = parse_log(har(
        har_entry(url="http://localhost:11434/api/chat", text="x"),
        har_entry(url="http://example.com/a", text="x"),
        har_entry(url="wss://example.com:8443/socket", text="x"),
        har_entry(url="https://example.com/a", text="x", serverIPAddress="[2001:db8::1]"),
        har_entry(url="https://example.com/b", text="x", serverIPAddress="203.0.113.9")))
    ports = [(e.host, e.dst_port, e.dst_ip) for e in r.events]
    assert ports == [("localhost", 11434, "0.0.0.0"), ("example.com", 80, "0.0.0.0"),
                     ("example.com", 8443, "0.0.0.0"), ("example.com", 443, "2001:db8::1"),
                     ("example.com", 443, "203.0.113.9")]


def test_har_without_a_body_is_metadata_only():
    entry = har_entry()
    del entry["request"]["postData"]
    e = parse_log(har(entry)).events[0]
    assert e.body_text is None and e.visibility is Visibility.METADATA_ONLY


def test_har_form_params_are_joined():
    entry = har_entry()
    entry["request"]["postData"] = {"params": [{"name": "a", "value": "1"}, {"name": "b", "value": "2"}]}
    assert parse_log(har(entry)).events[0].body_text == "a=1&b=2"


def test_har_unknown_sizes_are_none():
    entry = har_entry()
    entry["request"]["bodySize"] = -1
    assert parse_log(har(entry)).events[0].bytes_out is None


def test_bad_har_entries_are_skipped_not_fatal():
    r = parse_log(har(har_entry(), {"nope": 1}, har_entry(url="data:text/plain,hi"), har_entry(url=""),
                      har_entry(url="https://example.com:abc/x"), "string", har_entry(started="never")))
    assert (len(r.events), r.skipped) == (1, 6)
    assert [e.split(":")[0] for e in r.errors] == [f"entry {n}" for n in (2, 3, 4, 5, 6, 7)]


def test_har_structure_problems():
    for bad in ('{"log": {}}', '{"log": {"entries": "no"}}', '{"log": 5}'):
        r = parse_log(bad)
        assert r.format == "har" and r.events == [] and r.skipped == 1
    r = parse_log("{ not json", filename="export.har")
    assert r.format == "har" and r.skipped == 1 and r.errors == ["har: not a valid HAR file"]
    # A file named .har must be a HAR: JSONL content under that name is rejected, with a clear message.
    named = parse_log(line(), filename="whatever.har")
    assert named.format == "har" and named.events == [] and named.errors == ["har: not a valid HAR file"]


def test_har_expansion_and_options():
    r = parse_log(har(har_entry(text="{{fake:email#1}}")), expand=placeholders, source=Source.SCENARIO, max_body_bytes=4)
    assert r.events[0].body_text == "<e\n1>" and r.events[0].source is Source.SCENARIO


# ---- the bundled sample (fixtures/sample_http.jsonl) ---------------------------

def test_sample_file_parses_completely_with_and_without_expansion():
    text = SAMPLE.read_text(encoding="utf-8")
    for expand in (None, placeholders):
        r = parse_log(text, expand=expand)
        assert (len(r.events), r.skipped, r.errors) == (20, 0, [])


def test_sample_file_has_only_placeholders_never_token_shaped_strings():
    text = SAMPLE.read_text(encoding="utf-8")
    assert "{{fake:" in text
    leftovers = re.sub(r"\{\{fake:[a-z_]+#\d+\}\}", "", text)
    assert not re.search(r"sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-|eyJ[A-Za-z0-9_-]{15,}|"
                         r"-----BEGIN|AIza[0-9A-Za-z_-]{20,}|hf_[A-Za-z0-9]{20,}", leftovers)
    kinds = set(re.findall(r"\{\{fake:([a-z_]+)#", text))
    allowed = {"openai_key", "anthropic_key", "aws_access_key", "aws_secret_key", "github_token", "slack_token",
               "google_key", "hf_token", "stripe_key", "jwt", "private_key_header", "db_url", "card_visa", "card_mc",
               "card_amex", "aadhaar", "ssn", "pan", "iban", "email", "phone_in", "internal_host", "password"}
    assert kinds <= allowed                                              # SOT 8.1 kinds only


def test_sample_file_covers_the_variety_the_demo_needs():
    catalog = Catalog.load()
    events = parse_log(SAMPLE.read_text(encoding="utf-8"), expand=placeholders).events
    matches = [classify(e, catalog) for e in events]
    providers = {m.provider_id for m in matches if m}
    assert providers >= {"openai", "anthropic", "mistral", "huggingface", "ollama", "groq", "featherless",
                         "chatgpt_web", "claude_web", "cursor", "google_gemini", "lmstudio"}
    assert sum(1 for m in matches if m is None) == 3                      # github, google, a local dev server
    assert any(e.visibility is Visibility.METADATA_ONLY for e in events)  # HTTPS web apps: no body
    assert sum(1 for e in events if e.visibility is Visibility.FULL) >= 14
    assert any(e.query for e in events)                                   # a secret in a query string
    assert any(m and m.provider_id == "ollama" and e.dst_port == 11434 for e, m in zip(events, matches))
    assert {e.process for e in events} >= {"python3", "supportbot", "autogpt", "cursor", "browser"}
    assert all(e.ts.endswith("Z") for e in events)


def test_sample_file_native_keys_are_present_where_the_sot_describes():
    events = parse_log(SAMPLE.read_text(encoding="utf-8"), expand=placeholders).events
    by_host = {}
    for e in events:
        by_host.setdefault(e.host, []).append(e)
    assert all(e.auth_scheme is AuthScheme.BEARER for e in by_host["api.openai.com"])
    assert by_host["api.mistral.ai"][0].headers["authorization"].startswith("Bearer <jwt-")       # foreign credential
    assert by_host["api-inference.huggingface.co"][0].headers["authorization"].startswith("Bearer <hf_token-")


# ---- characters that str.splitlines() would break a line at --------------------------------

# Only these can appear raw inside a valid JSON string (JSON requires control characters to be escaped).
NASTY_CHARS = ["\u2028", "\u2029", "\u0085"]


@pytest.mark.parametrize("char", NASTY_CHARS)
def test_a_valid_request_containing_a_line_separator_character_is_not_torn_apart(char):
    line = json.dumps(rec(path="/ok", body=f"before{char}after"), ensure_ascii=False)
    assert "\n" not in line and char in line                       # one line, as far as JSONL is concerned
    result = parse_log(line + "\n")
    assert (len(result.events), result.skipped) == (1, 0)
    assert result.events[0].body_text == f"before{char}after"       # intact, so the detectors can read all of it


def test_a_secret_after_such_a_character_is_still_seen_by_the_pipeline_input():
    line = json.dumps(rec(body="intro\u2028the key is {{fake:openai_key#1}}"), ensure_ascii=False)
    event = parse_log(line, expand=placeholders).events[0]
    assert "<openai_key-1>" in event.body_text


def test_split_lines_only_breaks_at_real_line_ends():
    assert http_log.split_lines("a\nb\r\nc") == ["a", "b", "c"]
    assert http_log.split_lines("a\u2028b\x0cc\rd") == ["a\u2028b\x0cc\rd"]     # a lone \r is not a line end
    assert http_log.split_lines("") == [""] and http_log.split_lines("x\n") == ["x", ""]
    assert http_log.split_lines("\r\n\r\n") == ["", "", ""]


def test_line_numbers_in_errors_still_count_real_lines():
    text = rec_line("/a") + "\nbad\u2028still the same bad line\n" + rec_line("/c") + "\n"
    result = parse_log(text)
    assert result.errors[0].startswith("line 2:") and len(result.events) == 2


def rec_line(path):
    return json.dumps(rec(path=path))

"""The detectors against what they were not written around (SOT 7.3).

``test_analysis_text`` checks the rules on values shaped to fit them. These tests come from auditing
that: real-world secret formats, inputs built to be slow, malformed data, broken configuration and
real text with no secrets. Every case here failed at some point. Keys are built at runtime (AT-26).
"""

import json
import logging
import random
import string
import sys
import time
import uuid
from pathlib import Path

import pytest
import yaml

from shadowlens.analysis import engine, text as text_module
from shadowlens.analysis.engine import analyze, body_scan_text, is_safe_to_send, preview, redact_path
from shadowlens.analysis.redact import redact_text
from shadowlens.analysis.catalog import TextFinding
from shadowlens.analysis.settings import AnalysisSettings, settings_for
from shadowlens.analysis.text import REDACTION_FAILED, analyze_text
from shadowlens.config import Config
from shadowlens.core.ctx import AgentSessionContext
from shadowlens.core.pipeline import PATH_HIDDEN, Pipeline
from shadowlens.db import Database
from shadowlens.fakes import fake
from shadowlens.ingest.http_log import event_from_record
from shadowlens.models import NetEvent, utc_now_iso
from shadowlens.providers.catalog import Catalog

REPO_ROOT = Path(__file__).resolve().parents[1]
SETTINGS = AnalysisSettings(salt=b"s" * 32)
ALNUM = string.ascii_letters + string.digits
RANDOM = random.Random(63)


def token(length, alphabet=ALNUM):
    return "".join(RANDOM.choices(alphabet, k=length))


def rules_in(text, settings=SETTINGS):
    return sorted(f.rule_id for f in analyze_text(text, settings).findings)


def event(body=None, **fields):
    defaults = dict(id=str(uuid.uuid4()), ts=utc_now_iso(), source="http_log", process="python3", dst_ip="0.0.0.0",
                    dst_port=443, host="api.openai.com", host_basis="host_header", method="POST", path="/v1",
                    body_text=body)
    return NetEvent(**{**defaults, **fields})


def session():
    return AgentSessionContext(tool_id="python3|openai")


def grouped(value, size=4, separator=" "):
    return separator.join(value[i:i + size] for i in range(0, len(value), size))


# ---- secrets as people really write them -------------------------------------------------------

AWS = ["aws_secret_access_key", "AWS_SECRET_ACCESS_KEY", "aws-secret-key", "secret_access_key", "SECRET_ACCESS_KEY"]


@pytest.mark.parametrize("ending", ["/", "+", "=", "a"])
def test_aws_secret_can_end_in_any_of_its_characters(ending):
    value = token(39) + ending
    result = analyze_text(f"aws_secret_access_key = {value}\nthanks", SETTINGS)
    assert [f.rule_id for f in result.findings] == ["SEC_AWS_SECRET_KEY"]
    assert value not in result.redacted_text and result.redacted_text.endswith("thanks")


@pytest.mark.parametrize("label", AWS)
@pytest.mark.parametrize("shape", ["{} = {}", "{}={}", "{}: {}", '"{}": "{}"', "{} := {}"])
def test_aws_secret_labels_and_separators(label, shape):
    assert rules_in(shape.format(label, token(40))) == ["SEC_AWS_SECRET_KEY"]


@pytest.mark.parametrize("ending", ["-", "_", "a"])
def test_google_key_can_end_in_any_of_its_characters(ending):
    value = "AI" + "za" + token(34) + ending
    assert rules_in(f"key {value} here") == ["SEC_GOOGLE_API_KEY"]


def test_jwt_signature_ending_in_a_dash_is_covered_in_full():
    value = fake("jwt", 5)[:-1] + "-"
    result = analyze_text(f"token is {value} ok", SETTINGS)
    assert value not in result.redacted_text and "-" not in result.redacted_text.replace("[REDACTED:SEC_JWT:", "")


@pytest.mark.parametrize("name", [
    "DB_PASSWORD", "MYSQL_ROOT_PASSWORD", "POSTGRES_PASSWORD", "password", "passwd", "pwd", "PASSPHRASE",
    "access_token", "auth_token", "REFRESH_TOKEN", "token", "JWT_SECRET", "SECRET_KEY", "secret", "CLIENT_SECRET",
    "api_key", "API-KEY", "MY_API_KEY", "OPENAI_API_KEY", "x-api-key", "apikey",
    "apiKey", "accessToken", "clientSecret", "dbPassword", "authToken", "secretKey",
])
@pytest.mark.parametrize("shape", ["{}={}", "{} = {}", "{}: {}", '"{}": "{}"', "'{}': '{}'", "{} := {}", "{} => {}"])
def test_assignment_names_and_separators(name, shape):
    assert rules_in(shape.format(name, token(16))) == ["SEC_GENERIC_ASSIGNMENT"]


@pytest.mark.parametrize("value", ["P@ssw0rd!2024#x", "Hunter2024", "s3cr3t-Pa55", "correct_Horse_9", "Tr0ub4dor&3".replace("&", "!")])
def test_real_passwords_are_found_and_hidden_in_full(value):
    result = analyze_text(f'password = "{value}"', SETTINGS)
    assert [f.rule_id for f in result.findings] == ["SEC_GENERIC_ASSIGNMENT"]
    assert value not in result.redacted_text


@pytest.mark.parametrize("line", [
    "password = settings.DB_PASSWORD", "token = jwt.encode", "api_key = os.environ", "password: str",
    "token: Optional", "secret = getSecret", "password=${DB_PASSWORD}", "password=$DB_PASSWORD", "password: %PASSWORD%",
    "token_count = 1234567890123", "max_tokens: 4096", "tokens = 12345678901234", "tokenizer: cl100k_base_tokenizer",
    "secret_santa = alice_and_bobby", "password_field = passwordInput", "the token is expired and the secret: unknown",
    "token: https://example.invalid/oauth/callback", "secret=/etc/app/secret.conf", "password: 12345678",
    "password=aaaaaaaaaaaa", "password=changeme2024", "api_key=<YOUR_API_KEY_HERE>", "token = {{ secrets.TOKEN }}",
    "self.passwd = password_mgr", "user, password = _splitpasswd",
])
def test_things_that_only_look_like_assignments(line):
    assert "SEC_GENERIC_ASSIGNMENT" not in rules_in(line)


def test_generic_name_in_front_of_a_named_key_gives_only_the_named_rule():
    assert rules_in(f"OPENAI_API_KEY={fake('openai_key', 8)}") == ["SEC_OPENAI_KEY"]
    assert rules_in(f"DATABASE_PASSWORD={fake('db_url', 8)}") == ["SEC_DB_URL"]


def test_database_url_stops_at_a_closing_quote():
    value = fake("db_url", 9)
    result = analyze_text(f'connect("{value}", timeout=3)', SETTINGS)
    assert result.redacted_text.endswith('", timeout=3)') and value not in result.redacted_text


# ---- a number next to a card must not hide it -------------------------------------------------

@pytest.mark.parametrize("build", [
    lambda c: f"{c} 123",                          # followed by the CVV
    lambda c: f"{c} 12 25 123",                    # expiry and CVV
    lambda c: f"2 {c}",                            # a quantity in front
    lambda c: f"7 {c} 1",                          # both sides
    lambda c: f"card {c} exp 12/25",
    lambda c: f"{grouped(c)} 123",                 # grouped card and CVV
    lambda c: f"{grouped(c, separator='-')} 123",
])
@pytest.mark.parametrize("kind", ["card_visa", "card_mc", "card_amex"])
@pytest.mark.parametrize("idx", range(5))
def test_card_with_digits_around_it_is_found_and_hidden(build, kind, idx):
    card = fake(kind, idx)
    text = build(card)
    result = analyze_text(text, SETTINGS)
    assert "PII_CREDIT_CARD" in [f.rule_id for f in result.findings]
    digits_left = "".join(ch for ch in result.redacted_text if ch.isdigit())
    assert card not in digits_left and card[:12] not in digits_left


def test_two_cards_in_one_run_are_two_findings():
    assert rules_in(f"{fake('card_visa', 1)} {fake('card_mc', 1)}") == ["PII_CREDIT_CARD", "PII_CREDIT_CARD"]


def test_digits_beside_a_card_stay_visible():
    assert analyze_text(f"qty 7 {fake('card_visa', 2)} ok", SETTINGS).redacted_text == "qty 7 [PII:CREDIT_CARD] ok"


def test_digit_runs_that_fail_every_window_stay_quiet():
    assert "PII_CREDIT_CARD" not in rules_in("1234 5678 9012 3456 7890 1234")
    assert rules_in("1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6") == []


def test_a_long_digit_string_is_not_a_card():
    assert "PII_CREDIT_CARD" not in rules_in(fake("card_visa", 3) * 2)


# ---- personal data in other common shapes --------------------------------------------------------

@pytest.mark.parametrize("text", [
    "call +91 98765 43210 today", "call 98765-43210 today", "call 9876543210 today", "call +919876543210 today",
    "call +1 (415) 555-2671 today", "call +44 20 7946 0958 today", "call +91-98765-43210 today",
])
def test_phone_shapes(text):
    assert rules_in(text) == ["PII_PHONE"]


@pytest.mark.parametrize("text", [
    "Decimal('1.2345E+12345680')", "see https://pubs.opengroup.org/onlinepubs/9799919799/basedefs", "version 1.9876543210",
])
def test_things_that_only_look_like_phones(text):
    assert rules_in(text) == []


@pytest.mark.parametrize("separator", [" ", "-", ""])
def test_aadhaar_separators(separator):
    plain = fake("aadhaar", 4).replace(" ", "")
    assert rules_in("id " + grouped(plain, separator=separator)) == ["PII_AADHAAR"]


def test_iban_with_and_without_spaces():
    value = fake("iban", 4)
    assert rules_in(value) == ["PII_IBAN"]
    assert rules_in(grouped(value)) == ["PII_IBAN"]


def test_spaced_iban_leaves_following_capitals_alone():
    result = analyze_text(f"{grouped(fake('iban', 5))} FROM ACME", SETTINGS)
    assert result.redacted_text == "[PII:IBAN] FROM ACME"


def test_hostname_in_capitals():
    assert rules_in("server BILLING-1.CORP is down") == ["PII_INTERNAL_HOST"]


# ---- entropy: real text is not random ---------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "# http://zgp.org/pipermail/p2p-hackers/2001-September/000316.html",
    "# https://learn.microsoft.com/en-us/windows/win32/inputdev/virtual-key-codes",
    "see msdn.microsoft.com/en-us/library/17w5ykft-section-notes.aspx",
    "https://github.com/tcltk/tk/blob/064ff9941b4b80b85916a8afe86a6c21fd388b54/library/text.tcl",
    'characters = "abcdefghijklmnopqrstuvwxyz0123456789_"',
    'digits = b"abcdefghijklmnopqrstuvwxyz0123456789"',
    "CALL_BUILTIN_FAST_WITH_KEYWORDS=149,",
    "INSTRUMENTED_JUMP_BACKWARD_2=252,",
    "extra_args=_B32_DECODE_MAP01_DOCSTRING",
    "Based on data from ftp://dkuug.dk/i18n/charmaps/HP-ROMAN8",
])
def test_paths_identifiers_and_alphabets_are_not_secrets(text):
    assert "SEC_HIGH_ENTROPY" not in rules_in(text)


def test_short_random_tokens_are_found_most_of_the_time():
    tokens = [token(24) for _ in range(300)]
    found = sum(rules_in(f"value {t} end") == ["SEC_HIGH_ENTROPY"] for t in tokens)
    assert found / len(tokens) >= 0.8


def test_tokens_over_the_entropy_cap_are_still_hidden():
    tokens = [fake("aws_secret_key", i) for i in range(6)]
    result = analyze_text(" ".join(tokens), SETTINGS)
    assert len(result.findings) == 3
    assert not any(value in result.redacted_text for value in tokens)


# ---- code: English is not source code --------------------------------------------------------------

def test_a_long_essay_full_of_keywords_is_not_source_code():
    essay = "\n".join(["Let me explain where the money came from and why it will return next quarter.",
                       "The private class of investors will function as a public package of support."] * 12)
    assert rules_in(essay) == []


def test_long_code_without_a_fence_is_source_code():
    code = "\n".join(["import os", "from sys import path", "def f(a):", "    x = a + 1", "    return x"] * 6)
    assert rules_in(code) == ["CODE_POSSIBLE_SOURCE"]


# ---- never a raw value in the output ----------------------------------------------------------------

@pytest.mark.parametrize("seed", range(4))
def test_raw_values_never_survive_random_surroundings(seed):
    rng = random.Random(seed)
    kinds = ("openai_key", "anthropic_key", "github_token", "stripe_key", "jwt", "db_url", "card_visa", "card_mc",
             "card_amex", "aadhaar", "iban", "ssn", "pan", "hf_token", "slack_token", "google_key", "aws_access_key")
    for _ in range(400):
        value = fake(rng.choice(kinds), rng.randint(0, 50))
        pieces = ["".join(rng.choices(string.printable, k=rng.randint(0, 30))) for _ in range(rng.randint(1, 6))]
        pieces.insert(rng.randint(0, len(pieces)), f" {value} ")
        result = analyze_text("".join(pieces), SETTINGS)
        output = result.redacted_text + "".join(f.context + f.masked_preview for f in result.findings)
        assert value not in output


@pytest.mark.parametrize("seed", range(4))
def test_raw_values_never_survive_noise_full_of_digits_and_capitals(seed):
    """Random text hides these rarely, so this noise is built to cause false starts."""
    rng = random.Random(100 + seed)
    kinds = ("card_visa", "card_mc", "card_amex", "aadhaar", "iban", "ssn", "pan", "phone_in", "aws_access_key")
    noise = string.ascii_uppercase + string.digits + "  -"
    for _ in range(500):
        value = fake(rng.choice(kinds), rng.randint(0, 80))
        before = "".join(rng.choices(noise, k=rng.randint(0, 24)))
        after = "".join(rng.choices(noise, k=rng.randint(0, 24)))
        result = analyze_text(f"{before} {value} {after}", SETTINGS)
        assert value not in result.redacted_text, (before, value, after)


@pytest.mark.parametrize("prefix", ["2345", "2345 6789", "9876-5432", "1 2 3", "1234567"])
@pytest.mark.parametrize("idx", range(5))
def test_digit_groups_before_an_aadhaar_do_not_hide_it(prefix, idx):
    value = fake("aadhaar", idx)
    result = analyze_text(f"phone {prefix} {value} ok", SETTINGS)
    assert "PII_AADHAAR" in [f.rule_id for f in result.findings] and value not in result.redacted_text


@pytest.mark.parametrize("prefix", ["LL64", "AB12 CDEF", "ZZ99 WXYZ 1234", "AB12"])
@pytest.mark.parametrize("idx", range(5))
def test_capitals_before_an_iban_do_not_hide_it(prefix, idx):
    value = fake("iban", idx)
    result = analyze_text(f"{prefix} {value} ok", SETTINGS)
    assert "PII_IBAN" in [f.rule_id for f in result.findings] and value not in result.redacted_text


def test_partial_overlap_never_leaves_a_tail_behind():
    findings = [TextFinding("SEC_JWT", "m", "0123456789ab", [(0, 10)]), TextFinding("SEC_JWT", "m", "ba9876543210", [(5, 16)])]
    redacted = redact_text("0123456789SECRETTAIL", findings)
    assert "SECRET" not in redacted and redacted.endswith("TAIL")


@pytest.mark.parametrize("kind", ["openai_key", "anthropic_key", "aws_access_key", "github_token", "slack_token",
                                  "google_key", "hf_token", "stripe_key", "jwt", "private_key_header", "db_url"])
def test_every_named_pattern_passes_the_prefilter(kind):
    from shadowlens.analysis.secrets import _NAMED_PREFILTER_RE
    assert _NAMED_PREFILTER_RE.search(fake(kind, 1))
    assert rules_in(f"text {fake(kind, 1)} text") != []


@pytest.mark.parametrize("label", AWS)
def test_aws_secret_labels_pass_the_prefilter(label):
    from shadowlens.analysis.secrets import _NAMED_PREFILTER_RE
    assert _NAMED_PREFILTER_RE.search(f"{label} = x")


def test_every_named_pattern_has_a_fake_that_exercises_it():
    from shadowlens.analysis.secrets import NAMED_PATTERNS, find_named_secrets
    found = set()
    for kind in ("openai_key", "anthropic_key", "aws_access_key", "github_token", "slack_token", "google_key",
                 "hf_token", "stripe_key", "private_key_header", "db_url"):
        found |= {candidate.rule_id for candidate in find_named_secrets(fake(kind, 2))}
    assert found == set(NAMED_PATTERNS)


# ---- inputs built to be slow ----------------------------------------------------------------------------

K = 64000
SLOW_TEXTS = {
    "dotted then at": ("a." * (K // 2)) + "@",
    "hyphens then at": ("a-" * (K // 2)) + "@",
    "dotted with corp elsewhere": ("a." * (K // 2)) + " x.corp",
    "digits": "1" * K,
    "spaced digits": "1 " * (K // 2),
    "dashed digits": "1-" * (K // 2),
    "at signs": "a@" * (K // 2),
    "url prefixes": "postgres://a:" * (K // 13),
    "fences": "```" * (K // 3),
    "markers": "confidential " * (K // 13),
    "assignments": "password=" * (K // 9),
    "camel assignments": "aToken=" * (K // 7),
    "key headers": (fake("private_key_header") + "\n") * (K // 32),
    "iban starts": "LL64 " * (K // 5),
    "aadhaar starts": "2345 " * (K // 5),
    "jwt prefixes": "eyJaaaaaaaaaa." * (K // 14),
    "newlines": "\n" * K,
    "capitals": "GB12 ABCD " * (K // 10),
}


@pytest.mark.parametrize("name", sorted(SLOW_TEXTS))
def test_slow_text_finishes_quickly(name):
    started = time.perf_counter()
    analyze_text(SLOW_TEXTS[name], SETTINGS)
    assert time.perf_counter() - started < 3


@pytest.mark.parametrize("command", [
    "curl " * (K // 5), "curl " + "a" * K, "rm -" + "r" * K, "AppData/Local/" + "a/" * (K // 2),
    "service_account" * (K // 15), "Remove-Item " * (K // 12), "cat " * (K // 4),
], ids=["curl", "curl-no-pipe", "rm", "appdata", "service-account", "remove-item", "cat"])
def test_slow_agent_command_finishes_quickly(command):
    body = json.dumps({"messages": [{"role": "assistant", "tool_calls": [
        {"function": {"name": "bash", "arguments": json.dumps({"command": command})}}]}]})
    started = time.perf_counter()
    analyze(event(body), SETTINGS, session())
    assert time.perf_counter() - started < 3


# ---- malformed requests ------------------------------------------------------------------------------------

@pytest.fixture
def pipeline(tmp_path):
    config = Config.load(env={"SHADOWLENS_RESOLVE": "false"}, base_dir=tmp_path, use_dotenv=False)
    database = Database(tmp_path / "shadow.db")
    yield Pipeline(config, database, Catalog.load(), analyze=analyze)
    database.close()


def ingest(pipeline, body, **fields):
    record = {"ts": "2026-10-31T10:00:00Z", "host": "api.openai.com", "method": "POST", "path": "/v1",
              "process_name": "app", "body": body, **fields}
    return pipeline.ingest([event_from_record(record)], source="http_log")


def test_lone_surrogate_does_not_lose_the_event_or_the_key(pipeline):
    key = fake("github_token", 10)
    summary = ingest(pipeline, '{"messages":[{"content":"\\ud83d ' + key + '"}]}')
    assert summary.errors == [] and summary.accepted == 1
    assert pipeline.db.list_findings(rule_id="SEC_GITHUB_TOKEN").total == 1


def test_lone_surrogate_in_a_path_is_stored(pipeline):
    summary = ingest(pipeline, "x", path="/a\ud83db")
    assert summary.errors == [] and summary.accepted == 1
    assert pipeline.db.list_events().items[0].path == "/a?b"


def test_key_used_as_a_json_field_name_is_found():
    assert "SEC_GITHUB_TOKEN" in [f.rule_id for f in
                                  analyze(event(json.dumps({fake("github_token", 11): {"x": 1}})), SETTINGS, session()).findings]


def test_key_nested_far_too_deep_is_still_found():
    body = "[" * 60 + json.dumps(fake("github_token", 12)) + "]" * 60
    assert "SEC_GITHUB_TOKEN" in [f.rule_id for f in analyze(event(body), SETTINGS, session()).findings]


def test_json_too_deep_for_the_parser_falls_back_to_the_raw_text():
    body = "[" * 200000 + json.dumps(fake("github_token", 13))
    assert fake("github_token", 13) in body_scan_text(body)


def test_oversized_number_falls_back_to_the_raw_text():
    body = '{"a":' + "9" * 5000 + ', "b": "' + fake("github_token", 14) + '"}'
    assert "SEC_GITHUB_TOKEN" in [f.rule_id for f in analyze(event(body), SETTINGS, session()).findings]


def test_percent_encoded_form_body_and_query():
    form = f"api_key%3D{token(16)}%26password%3D{token(14)}"
    assert rules_in(body_scan_text(form)).count("SEC_GENERIC_ASSIGNMENT") == 2
    found = analyze(event("x", query=f"token%3D{token(16)}"), SETTINGS, session()).findings
    assert [f.rule_id for f in found] == ["SEC_GENERIC_ASSIGNMENT"]


@pytest.mark.parametrize("where", ["declared", "called", "mcp"])
def test_key_used_as_a_tool_name_is_never_stored_raw(pipeline, tmp_path, where):
    key = fake("github_token", 15)
    bodies = {
        "declared": {"tools": [{"name": key, "description": f"see {fake('stripe_key', 15)}"}], "messages": []},
        "called": {"messages": [{"role": "assistant", "content": [
            {"type": "tool_use", "name": key, "input": {"path": "~/.ssh/id_rsa", "x": fake("stripe_key", 16)}}]}]},
        "mcp": {"method": "tools/call", "params": {"name": key, "arguments": {"path": "~/.ssh/id_rsa"}}},
    }
    summary = ingest(pipeline, json.dumps(bodies[where]))
    assert summary.errors == [] and summary.findings >= 2
    dumped = json.dumps([f.model_dump(mode="json") for f in pipeline.db.list_findings(limit=100).items])
    dumped += json.dumps([a.model_dump(mode="json") for a in pipeline.db.list_agent_activity("app|openai")])
    assert key not in dumped
    pipeline.db._conn.execute("PRAGMA wal_checkpoint(FULL)")
    assert key.encode() not in b"".join(path.read_bytes() for path in tmp_path.glob("shadow.db*"))


# ---- broken configuration --------------------------------------------------------------------------------------

def settings_from(tmp_path, text):
    (tmp_path / "config").mkdir(exist_ok=True)
    (tmp_path / "config" / "rules.yaml").write_text(text, encoding="utf-8")
    return AnalysisSettings.from_config(Config.load(env={}, base_dir=tmp_path, use_dotenv=False))


@pytest.mark.parametrize("line,name", [
    ('entropy_alnum: "high"', "entropy_alnum"), ("entropy_alnum: null", "entropy_alnum"), ("entropy_alnum: 99", "entropy_alnum"),
    ("entropy_alnum: true", "entropy_alnum"), ("entropy_min_len: -5", "entropy_min_len"), ("entropy_min_len: abc", "entropy_min_len"),
    ("entropy_min_len: 2.5", "entropy_min_len"), ("max_entropy_findings_per_event: 1.5", "max_entropy_findings_per_event"),
    ("code_min_lines: 0", "code_min_lines"), ("email_skip_domains: nope", "email_skip_domains"),
    ("email_skip_domains: [1, 2]", "email_skip_domains"), ("entropy_digest_lengths: []", "entropy_digest_lengths"),
    ("generic_placeholder_words: [true]", "generic_placeholder_words"), ("entropy_alnmu: 4.2", "entropy_alnmu"),
])
def test_a_bad_setting_falls_back_and_says_so_and_detection_keeps_working(tmp_path, line, name):
    settings = settings_from(tmp_path, line + "\n")
    assert any(name in warning for warning in settings.warnings)
    assert "SEC_HIGH_ENTROPY" in rules_in(f"value {fake('aws_secret_key', 1)} x", settings)
    assert "SEC_OPENAI_KEY" in rules_in(fake("openai_key"), settings)


@pytest.mark.parametrize("content", ["- a\n- list\n", "just text", "{{{ not yaml", ""])
def test_a_damaged_settings_file_falls_back(tmp_path, content):
    settings = settings_from(tmp_path, content)
    assert settings.entropy_alnum == 4.2 and "SEC_OPENAI_KEY" in rules_in(fake("openai_key"), settings)


def test_good_setting_beside_a_bad_one_still_applies(tmp_path):
    settings = settings_from(tmp_path, "entropy_alnum: 4.5\nentropy_hex: nope\n")
    assert settings.entropy_alnum == 4.5 and settings.entropy_hex == 3.3


def test_a_warning_never_repeats_the_value(tmp_path):
    settings = settings_from(tmp_path, "entropy_alnum: SECRETVALUE\n")
    assert not any("SECRETVALUE" in warning for warning in settings.warnings)


def test_settings_can_tune_detection(tmp_path):
    settings = settings_from(tmp_path, "generic_password_min_len: 30\nemail_skip_domains: [acme-demo.invalid]\nmarker_window: 5\n")
    assert rules_in("password=Hunter2024", settings) == []
    assert rules_in(fake("email", 1), settings) == []
    assert rules_in("Copyright 2026 and then a long way on and on and on: confidential", settings) == []


def test_the_shipped_settings_file_matches_the_built_in_fallback_and_has_no_warnings():
    shipped = yaml.safe_load((REPO_ROOT / "config" / "rules.yaml").read_text(encoding="utf-8"))
    for name, value in shipped.items():
        expected = getattr(SETTINGS, name)
        assert (list(expected) if isinstance(expected, tuple) else expected) == value, name
    settings = AnalysisSettings.from_config(Config.load(env={}, base_dir=REPO_ROOT, use_dotenv=False))
    assert [w for w in settings.warnings if "salt" not in w] == []


def test_settings_file_next_to_the_code_is_used_when_run_from_another_folder(tmp_path):
    settings = AnalysisSettings.from_config(Config.load(env={}, base_dir=tmp_path, use_dotenv=False))
    assert settings.warnings == ()


def test_unusable_salt_falls_back_and_detection_keeps_working(tmp_path):
    folder = tmp_path / "salt_is_a_folder"
    folder.mkdir()
    config = Config.load(env={"SHADOWLENS_SALT_PATH": str(folder)}, base_dir=tmp_path, use_dotenv=False)
    settings = AnalysisSettings.from_config(config)
    assert len(settings.salt) == 32 and any("salt" in warning for warning in settings.warnings)
    assert rules_in(fake("openai_key"), settings) == ["SEC_OPENAI_KEY"]


def test_settings_for_reads_once_and_passes_settings_through(tmp_path):
    config = Config.load(env={}, base_dir=tmp_path, use_dotenv=False)
    assert settings_for(config) is settings_for(config)
    assert settings_for(SETTINGS) is SETTINGS


# ---- one part failing does not take the rest with it ---------------------------------------------------------------

def boom(*args, **kwargs):
    raise RuntimeError("SECRETMARKER inside a detector")


@pytest.mark.parametrize("name,target", [
    ("named_secrets", "find_named_secrets"), ("pii", "find_pii"), ("generic_assignments", "find_generic_assignments"),
    ("high_entropy", "find_high_entropy"), ("code", "find_code"),
])
def test_a_failing_detector_costs_only_its_own_rules(monkeypatch, caplog, name, target):
    monkeypatch.setattr(text_module, target, boom)
    text = f"{fake('card_visa')} {fake('openai_key')} password={token(14)} {fake('aws_secret_key')}"
    with caplog.at_level(logging.WARNING):
        result = analyze_text(text, SETTINGS)
    assert result.failed == [name]
    assert (("PII_CREDIT_CARD" in [f.rule_id for f in result.findings]) == (name != "pii"))
    assert (("SEC_OPENAI_KEY" in [f.rule_id for f in result.findings]) == (name != "named_secrets"))
    assert "SECRETMARKER" not in caplog.text and "RuntimeError" in caplog.text


def test_failed_redaction_withholds_the_text(monkeypatch):
    monkeypatch.setattr(text_module, "redact_text", boom)
    value = fake("openai_key")
    result = analyze_text(f"key {value}", SETTINGS)
    assert result.redacted_text == REDACTION_FAILED and result.failed == ["redaction"]
    assert [f.rule_id for f in result.findings] == ["SEC_OPENAI_KEY"]


def test_failing_agent_rules_still_leave_the_body_findings(monkeypatch):
    monkeypatch.setattr(engine, "parse_agent_body", boom)
    result = analyze(event(json.dumps({"content": fake("openai_key")})), SETTINGS, session())
    assert [f.rule_id for f in result.findings] == ["SEC_OPENAI_KEY"] and result.failed == ["agent rules"]


def test_failing_header_check_still_leaves_the_body_findings(monkeypatch):
    monkeypatch.setattr(engine, "_scan_auth_header", boom)
    found = analyze(event(json.dumps({"content": fake("openai_key")}), headers={"authorization": "Bearer x"}), SETTINGS, session())
    assert [f.rule_id for f in found.findings] == ["SEC_OPENAI_KEY"] and found.failed == ["authorization header"]


def test_incomplete_analysis_is_reported_in_the_upload_summary(pipeline, monkeypatch):
    monkeypatch.setattr(text_module, "find_pii", boom)
    summary = ingest(pipeline, json.dumps({"content": fake("openai_key")}))
    assert summary.errors == ["analysis was incomplete for one event"]
    assert pipeline.db.list_findings(rule_id="SEC_OPENAI_KEY").total == 1


def test_path_is_hidden_when_a_detector_could_not_check_it(pipeline, monkeypatch):
    monkeypatch.setattr(text_module, "find_named_secrets", boom)
    ingest(pipeline, "x", path="/hook/anything")
    assert pipeline.db.list_events().items[0].path == PATH_HIDDEN


def test_redact_path_refuses_when_a_detector_could_not_run(monkeypatch):
    monkeypatch.setattr(text_module, "find_pii", boom)
    with pytest.raises(engine.DetectorFailure):
        redact_path("/a", SETTINGS)


# ---- the egress guard fails closed --------------------------------------------------------------------------------------

def test_guard_allows_clean_text_and_placeholders():
    assert is_safe_to_send("rule SEC_JWT with context [REDACTED:SEC_JWT:0123456789ab] and [PII:EMAIL]", SETTINGS)


@pytest.mark.parametrize("kind", ["openai_key", "card_visa", "email", "db_url", "jwt"])
def test_guard_blocks_a_planted_value(kind):
    assert not is_safe_to_send(f"context {fake(kind, 20)}", SETTINGS)


@pytest.mark.parametrize("target", ["find_named_secrets", "find_pii", "find_high_entropy"])
def test_guard_blocks_when_a_detector_could_not_run(monkeypatch, target):
    monkeypatch.setattr(text_module, target, boom)
    assert not is_safe_to_send("perfectly clean text", SETTINGS)


def test_guard_blocks_when_everything_breaks(monkeypatch):
    monkeypatch.setattr(engine, "analyze_text", boom)
    assert not is_safe_to_send("perfectly clean text", SETTINGS)


def test_guard_can_read_the_apps_config(tmp_path):
    assert is_safe_to_send("clean", Config.load(env={}, base_dir=tmp_path, use_dotenv=False))


def test_leak_lab_says_blocked_when_a_detector_could_not_run(monkeypatch):
    monkeypatch.setattr(text_module, "find_pii", boom)
    assert preview("clean text", "text", SETTINGS)["would_block"] is True


# ---- real text with no secrets --------------------------------------------------------------------------------------------

def test_the_standard_library_is_nearly_free_of_false_secrets():
    """Real, varied source with no secrets in it. Skipped parts would only make this easier."""
    root = Path(sys.base_prefix) / "Lib"
    files = sorted(p for p in root.glob("*.py"))[:150]
    if len(files) < 50:
        pytest.skip("standard library sources not available")
    secrets_found = []
    for path in files:
        text = path.read_text(encoding="utf-8", errors="replace")[:65536]
        secrets_found += [(path.name, f.rule_id) for f in analyze_text(text, SETTINGS).findings
                          if f.rule_id.startswith("SEC_")]
    assert len(secrets_found) <= 3, secrets_found

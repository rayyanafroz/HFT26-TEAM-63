import hashlib
import re
import uuid

import pytest

from shadowlens.analysis.checksums import verhoeff_check_digit
from shadowlens.analysis.masking import PLACEHOLDER_RE
from shadowlens.analysis.settings import AnalysisSettings
from shadowlens.analysis.text import analyze_text
from shadowlens.fakes import fake

SETTINGS = AnalysisSettings(salt=b"s" * 32)

# Aadhaar-shaped, with a check digit that is deliberately wrong.
BAD_AADHAAR = "23456789012" + str((int(verhoeff_check_digit("23456789012")) + 1) % 10)


def rules_in(text, settings=SETTINGS):
    return sorted(f.rule_id for f in analyze_text(text, settings).findings)


# ---- each rule fires on its fake, exactly once --------------------------------

@pytest.mark.parametrize("kind,rule_id", [
    ("openai_key", "SEC_OPENAI_KEY"),
    ("anthropic_key", "SEC_ANTHROPIC_KEY"),
    ("aws_access_key", "SEC_AWS_ACCESS_KEY"),
    ("github_token", "SEC_GITHUB_TOKEN"),
    ("slack_token", "SEC_SLACK_TOKEN"),
    ("google_key", "SEC_GOOGLE_API_KEY"),
    ("hf_token", "SEC_HF_TOKEN"),
    ("stripe_key", "SEC_STRIPE_KEY"),
    ("jwt", "SEC_JWT"),
    ("private_key_header", "SEC_PRIVATE_KEY"),
    ("db_url", "SEC_DB_URL"),
    ("card_visa", "PII_CREDIT_CARD"),
    ("card_mc", "PII_CREDIT_CARD"),
    ("card_amex", "PII_CREDIT_CARD"),
    ("aadhaar", "PII_AADHAAR"),
    ("iban", "PII_IBAN"),
    ("ssn", "PII_SSN"),
    ("pan", "PII_PAN"),
    ("email", "PII_EMAIL"),
    ("phone_in", "PII_PHONE"),
    ("internal_host", "PII_INTERNAL_HOST"),
])
@pytest.mark.parametrize("idx", range(10))
def test_one_value_gives_one_finding(kind, rule_id, idx):
    assert rules_in(f"please look at {fake(kind, idx)} for me") == [rule_id]


def test_aws_secret_needs_its_label_and_gives_one_finding():
    assert rules_in(f"aws_secret_access_key = {fake('aws_secret_key', 1)}") == ["SEC_AWS_SECRET_KEY"]


def test_quick_leak_line_gives_only_the_aws_secret():
    prompt = f"why does this fail?\naws_secret_access_key = {fake('aws_secret_key', 1)}\nthanks"
    assert rules_in(prompt) == ["SEC_AWS_SECRET_KEY"]


def test_generic_assignment():
    assert rules_in(f"password={fake('password', 2)}") == ["SEC_GENERIC_ASSIGNMENT"]
    assert rules_in(f'"client_secret": "{fake("password", 3)}"') == ["SEC_GENERIC_ASSIGNMENT"]


def test_named_key_in_an_assignment_is_not_also_generic():
    assert rules_in(f"api_key={fake('openai_key')}") == ["SEC_OPENAI_KEY"]


def test_high_entropy_mixed_token():
    token = "".join(chr(ord("a") + (i * 7) % 26) + str(i % 10) + chr(ord("A") + (i * 11) % 26) for i in range(12))
    assert rules_in(f"blob {token} end") == ["SEC_HIGH_ENTROPY"]


def test_entropy_cap_keeps_three_and_marks_truncation():
    tokens = [fake("aws_secret_key", i) for i in range(6)]
    findings = analyze_text(" ".join(tokens), SETTINGS).findings
    assert [f.rule_id for f in findings] == ["SEC_HIGH_ENTROPY"] * 3
    assert all(f.truncated for f in findings)


# ---- negatives from SOT 8.4 ---------------------------------------------------

@pytest.mark.parametrize("text", [
    "a plain sentence about nothing in particular",
    str(uuid.UUID(int=123456789)),
    hashlib.sha1(b"commit").hexdigest(),
    hashlib.sha256(b"file").hexdigest(),
    hashlib.md5(b"file").hexdigest(),
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor.",
    "def add(a, b):\n    return a + b\n",
    "we use sk-learn for this model",
    "mail me at someone@example.com or other@test.com",
    "order 123456789012 and " + BAD_AADHAAR,
    "card 4111 1111 1111 1112 fails its check",
    "password=changeme_please_now",
    "api_key=your_api_key_here",
    "src/shadowlens/analysis/secrets/detectors/module/file",
    "getUserAccountByEmailAddressAndStatus",
    '"model": "meta-llama/Llama-3.1-70B-Instruct-v2-xyz7"',
    "abcde1234 is not a PAN and ABCDE1234F has a bad fourth letter",
    "10.999.1.1 is not an address",
])
def test_negatives_stay_silent(text):
    assert rules_in(text) == []


def test_jwt_shape_without_alg_is_not_a_jwt():
    import base64
    head = base64.urlsafe_b64encode(b'{"foo":"barbarbar"}').decode().rstrip("=")
    assert "SEC_JWT" not in rules_in(f"{head}.{head}.abcdefghij")


# ---- grouped and repeated values ----------------------------------------------

def test_emails_collapse_into_one_finding_with_a_count_and_all_spans():
    text = " ".join(fake("email", i) for i in range(3))
    result = analyze_text(text, SETTINGS)
    assert [f.rule_id for f in result.findings] == ["PII_EMAIL"]
    assert result.findings[0].count == 3 and len(result.findings[0].spans) == 3
    assert "@" not in result.redacted_text


def test_same_key_twice_is_one_finding_with_both_spans_redacted():
    key = fake("openai_key")
    result = analyze_text(f"{key} and {key}", SETTINGS)
    assert len(result.findings) == 1 and len(result.findings[0].spans) == 2
    assert key not in result.redacted_text


# ---- code ---------------------------------------------------------------------

def test_confidential_marker_needs_a_copyright_nearby():
    assert rules_in("this is confidential") == []
    assert rules_in("Copyright 2026 Acme. Confidential.") == ["CODE_CONFIDENTIAL_MARKER"]


def test_code_fence_needs_three_tokens():
    assert rules_in("```\nhello\n```") == []
    assert rules_in("```\nimport os\ndef f():\n    return 1\n```") == ["CODE_POSSIBLE_SOURCE"]


def test_long_text_without_fence_counts_as_source():
    body = "\n".join(["import os", "def f():", "    return 1"] + ["x = 1"] * 20)
    assert rules_in(body) == ["CODE_POSSIBLE_SOURCE"]


def test_internal_markers_are_required_when_set():
    code = "```\nimport os\ndef f():\n    return 1\n```"
    with_markers = AnalysisSettings(salt=b"s" * 32, internal_markers=("acmecorp",))
    assert rules_in(code, with_markers) == []
    assert rules_in(code + " for AcmeCorp", with_markers) == ["CODE_POSSIBLE_SOURCE"]


def test_key_inside_code_gives_both_findings_and_no_raw_value():
    key = fake("github_token")
    text = f"```\nimport os\ndef f():\n    return '{key}'\n```"
    result = analyze_text(text, SETTINGS)
    assert sorted(f.rule_id for f in result.findings) == ["CODE_POSSIBLE_SOURCE", "SEC_GITHUB_TOKEN"]
    assert key not in result.redacted_text
    assert all(key not in f.context for f in result.findings)


# ---- redaction and privacy (AT-12, guard) --------------------------------------

def _all_fakes():
    return [fake(kind, 1) for kind in (
        "openai_key", "anthropic_key", "aws_access_key", "github_token", "slack_token", "google_key", "hf_token",
        "stripe_key", "jwt", "db_url", "card_visa", "aadhaar", "ssn", "pan", "iban",
    )]


def test_redacted_text_and_contexts_hold_no_raw_value():
    values = _all_fakes()
    result = analyze_text(" | ".join(values), SETTINGS)
    assert len(result.findings) == len(values)
    outputs = [result.redacted_text] + [f.context for f in result.findings] + [f.masked_preview for f in result.findings]
    for value in values:
        assert all(value not in output for output in outputs)


def test_no_more_than_4_characters_of_a_secret_in_the_preview():
    key = fake("openai_key")
    preview = analyze_text(key, SETTINGS).findings[0].masked_preview
    assert preview == f"{key[:4]}... (len {len(key)})"


def test_context_slice_never_leaves_half_a_neighbouring_secret():
    neighbour = fake("github_token")
    text = neighbour + " " + "x " * 28 + fake("openai_key")
    for finding in analyze_text(text, SETTINGS).findings:
        for size in (8, 12, 20):
            assert neighbour[-size:] not in finding.context


def test_context_is_short_enough_for_the_model():
    text = "a " * 500 + fake("openai_key") + " b" * 500
    finding = analyze_text(text, SETTINGS).findings[0]
    assert len(finding.context) <= 200 and finding.hash12 in finding.context


def test_private_key_body_is_redacted_with_its_header():
    body = "QUJD" * 16
    header = fake("private_key_header")
    footer = header.replace("BEGIN", "END")
    result = analyze_text(f"key:\n{header}\n{body}\n{body}\n{footer}\nbye", SETTINGS)
    assert [f.rule_id for f in result.findings] == ["SEC_PRIVATE_KEY"]
    assert body not in result.redacted_text and "END" not in result.redacted_text
    assert result.redacted_text.endswith("bye")


def test_redacted_text_is_clean_on_a_second_pass():
    result = analyze_text(" | ".join(_all_fakes()), SETTINGS)
    assert PLACEHOLDER_RE.search(result.redacted_text)
    assert analyze_text(result.redacted_text, SETTINGS).findings == []


def test_hash_depends_on_the_salt():
    key = fake("openai_key")
    first = analyze_text(key, SETTINGS).findings[0].hash12
    assert re.fullmatch(r"[0-9a-f]{12}", first)
    assert first != analyze_text(key, AnalysisSettings(salt=b"t" * 32)).findings[0].hash12


# ---- settings -----------------------------------------------------------------

@pytest.mark.parametrize("bad", [None, "", 123])
def test_bad_input_gives_nothing(bad):
    assert analyze_text(bad, SETTINGS).findings == []


def test_settings_from_config_uses_defaults_without_yaml(tmp_path):
    from shadowlens.config import Config
    settings = AnalysisSettings.from_config(Config.load(env={}, base_dir=tmp_path, use_dotenv=False))
    assert settings.entropy_alnum == 4.2 and len(settings.salt) == 32


def test_settings_from_config_reads_rules_yaml(tmp_path):
    from shadowlens.config import Config
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "rules.yaml").write_text("entropy_alnum: 4.5\nmax_entropy_findings_per_event: 1\n", encoding="utf-8")
    settings = AnalysisSettings.from_config(Config.load(env={}, base_dir=tmp_path, use_dotenv=False))
    assert settings.entropy_alnum == 4.5 and settings.max_entropy_findings_per_event == 1

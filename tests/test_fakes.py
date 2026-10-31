import base64
import json
import re
from pathlib import Path

import pytest

from shadowlens.analysis.checksums import iban_valid, luhn_valid, verhoeff_valid
from shadowlens.fakes import KINDS, expand, fake

# The detector patterns from SOT 7.3. Replace with imports once the detectors exist.
PATTERNS = {
    "private_key_header": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----",
    "aws_access_key": r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
    "anthropic_key": r"\bsk-ant-[A-Za-z0-9_\-]{20,}",
    "openai_key": r"\bsk-(?!ant-)(?:(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{20,}|[A-Za-z0-9]{32,})",
    "github_token": r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b",
    "slack_token": r"\bxox[abprs]-[A-Za-z0-9\-]{10,}",
    "google_key": r"\bAIza[0-9A-Za-z_\-]{35}\b",
    "hf_token": r"\bhf_[A-Za-z0-9]{34,}\b",
    "stripe_key": r"\b[sr]k_live_[A-Za-z0-9]{24,}\b",
    "jwt": r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b",
    "db_url": r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:/@]+:[^\s@/]+@[^\s/]+",
    "card_visa": r"\b(?:\d[ \-]?){13,19}\b",
    "card_mc": r"\b(?:\d[ \-]?){13,19}\b",
    "card_amex": r"\b(?:\d[ \-]?){13,19}\b",
    "aadhaar": r"(?<!\d)[2-9]\d{3}\s?\d{4}\s?\d{4}(?!\d)",
    "ssn": r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b",
    "pan": r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
    "iban": r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b",
    "email": r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
    "phone_in": r"(?<!\d)(?:\+91[\-\s]?)?[6-9]\d{9}(?!\d)",
    "internal_host": r"\b[a-z0-9\-]+(?:\.[a-z0-9\-]+)*\.(?:corp|internal|intra|lan)\b",
}
AWS_SECRET_LINE = (
    r"(?i)\b(?:aws_secret_access_key|aws[_\-]?secret[_\-]?(?:access[_\-]?)?key|secret_access_key)\b"
    r"[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})\b"
)
GENERIC_LINE = (
    r"(?i)\b(?:api[_\-]?key|secret|token|passwd|password|client[_\-]?secret)\b"
    r"[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_\-/+=]{12,})"
)
INDEXES = range(25)


def _entropy(value):
    from collections import Counter
    from math import log2
    return -sum(n / len(value) * log2(n / len(value)) for n in Counter(value).values())


def test_all_sot_kinds_exist():
    assert KINDS == {
        "openai_key", "anthropic_key", "aws_access_key", "aws_secret_key", "github_token", "slack_token",
        "google_key", "hf_token", "stripe_key", "jwt", "private_key_header", "db_url", "card_visa", "card_mc",
        "card_amex", "aadhaar", "ssn", "pan", "iban", "email", "phone_in", "internal_host", "password",
    }


@pytest.mark.parametrize("kind", sorted(PATTERNS))
@pytest.mark.parametrize("idx", INDEXES)
def test_fake_is_matched_whole_by_its_detector_pattern(kind, idx):
    value = fake(kind, idx)
    match = re.search(PATTERNS[kind], f"text before {value} text after")
    assert match and match.group(0).strip() == value


@pytest.mark.parametrize("idx", INDEXES)
def test_aws_secret_matches_in_an_assignment_line(idx):
    value = fake("aws_secret_key", idx)
    match = re.search(AWS_SECRET_LINE, f"aws_secret_access_key = {value}\n")
    assert match and match.group(1) == value


@pytest.mark.parametrize("idx", INDEXES)
def test_password_passes_the_generic_rule(idx):
    value = fake("password", idx)
    match = re.search(GENERIC_LINE, f"password={value}")
    assert match and match.group(1) == value
    assert _entropy(value) >= 3.0
    assert not any(word in value.lower() for word in ("your_", "xxx", "changeme", "example"))


@pytest.mark.parametrize("idx", INDEXES)
def test_structured_values_pass_their_checks(idx):
    assert luhn_valid(fake("card_visa", idx)) and fake("card_visa", idx).startswith("4")
    assert luhn_valid(fake("card_mc", idx)) and 51 <= int(fake("card_mc", idx)[:2]) <= 55
    amex = fake("card_amex", idx)
    assert luhn_valid(amex) and amex[:2] in ("34", "37") and len(amex) == 15
    assert verhoeff_valid(fake("aadhaar", idx).replace(" ", ""))
    assert iban_valid(fake("iban", idx))
    assert fake("pan", idx)[3] == "P"


@pytest.mark.parametrize("idx", INDEXES)
def test_jwt_header_decodes_to_json_with_alg(idx):
    header = fake("jwt", idx).split(".")[0]
    assert "alg" in json.loads(base64.urlsafe_b64decode(header + "=" * (-len(header) % 4)))


def test_openai_key_length_matches_the_sot_example():
    assert len(fake("openai_key")) == 51


def test_quick_leak_email_and_host_do_not_use_skipped_domains():
    assert not fake("email").endswith(("example.com", "example.org", "test.com", "localhost"))


# ---- determinism -------------------------------------------------------------

@pytest.mark.parametrize("kind", sorted(KINDS))
def test_same_input_gives_same_output(kind):
    assert fake(kind, 3) == fake(kind, 3)


@pytest.mark.parametrize("kind", sorted(KINDS - {"private_key_header"}))
def test_different_index_gives_different_value(kind):
    assert fake(kind, 1) != fake(kind, 2)


def test_unknown_kind_is_an_error():
    with pytest.raises(ValueError):
        fake("nope")


# ---- expand ------------------------------------------------------------------

def test_expand_with_and_without_index():
    assert expand("a {{fake:openai_key#1}} b") == f"a {fake('openai_key', 1)} b"
    assert expand("{{fake:email}}") == fake("email", 0)


def test_expand_handles_several_tokens_and_leaves_other_text():
    text = "{{fake:ssn#2}}, {{fake:pan#3}} and {{ not_a_token }}"
    assert expand(text) == f"{fake('ssn', 2)}, {fake('pan', 3)} and {{{{ not_a_token }}}}"


def test_expand_keeps_unknown_kinds():
    assert expand("{{fake:nope#1}}") == "{{fake:nope#1}}"


# ---- the source file itself holds no token-shaped literal (AT-26) ------------

def test_fakes_source_has_no_token_shaped_literal():
    source = (Path(__file__).resolve().parents[1] / "src" / "shadowlens" / "fakes.py").read_text(encoding="utf-8")
    for kind, pattern in PATTERNS.items():
        if kind not in ("email", "internal_host"):
            assert not re.search(pattern, source), kind

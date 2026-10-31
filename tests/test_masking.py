import re

import pytest

from shadowlens.analysis.masking import (
    PLACEHOLDER_RE,
    SALT_BYTES,
    hash12,
    load_or_create_salt,
    mask_email,
    mask_for,
    mask_last4,
    mask_secret,
    placeholder_for,
)

SALT = b"s" * SALT_BYTES


# ---- salt --------------------------------------------------------------------

def test_salt_is_created_with_parents_and_stays_the_same(tmp_path):
    path = tmp_path / "nested" / "salt"
    first = load_or_create_salt(path)
    assert len(first) == SALT_BYTES
    assert load_or_create_salt(path) == first


def test_damaged_salt_is_replaced(tmp_path):
    path = tmp_path / "salt"
    path.write_bytes(b"short")
    assert len(load_or_create_salt(path)) == SALT_BYTES


# ---- hash12 ------------------------------------------------------------------

def test_hash12_shape_and_stability():
    value = hash12("some value", SALT)
    assert re.fullmatch(r"[0-9a-f]{12}", value)
    assert hash12("some value", SALT) == value


def test_hash12_depends_on_value_and_salt():
    assert hash12("a", SALT) != hash12("b", SALT)
    assert hash12("a", SALT) != hash12("a", b"t" * SALT_BYTES)


def test_hash12_accepts_odd_unicode():
    assert hash12("café \ud83d", SALT)


# ---- display masks -----------------------------------------------------------

def test_mask_secret_boundary_at_20():
    assert mask_secret("a" * 19) == "... (len 19)"
    assert mask_secret("abcd" + "e" * 16) == "abcd... (len 20)"


def test_mask_secret_matches_the_sot_example():
    assert mask_secret("sk-p" + "x" * 47) == "sk-p... (len 51)"


@pytest.mark.parametrize("length", [1, 4, 19, 20, 21, 51, 200])
def test_mask_secret_never_shows_more_than_4_characters(length):
    value = "Z" * length
    assert mask_secret(value).count("Z") <= 4


def test_mask_email():
    assert mask_email("jordan@acme.invalid") == "j***@acme.invalid"


@pytest.mark.parametrize("bad", ["no-at-sign", "@domain", "local@"])
def test_mask_email_without_a_full_address_falls_back(bad):
    assert mask_email(bad) == mask_secret(bad)


@pytest.mark.parametrize("value,expected", [
    ("1234 5678 9012 3456", "****3456"),
    ("123-45-6789", "****6789"),
    ("ABCPD1234E", "****234E"),
    ("1234", "****"),
    ("", "****"),
])
def test_mask_last4(value, expected):
    assert mask_last4(value) == expected


@pytest.mark.parametrize("rule_id,value,expected", [
    ("SEC_OPENAI_KEY", "sk-p" + "x" * 47, "sk-p... (len 51)"),
    ("PII_EMAIL", "a@b.invalid", "a***@b.invalid"),
    ("PII_CREDIT_CARD", "1234567890123456", "****3456"),
    ("PII_AADHAAR", "2345 6789 0123", "****0123"),
    ("PII_SSN", "123-45-6789", "****6789"),
    ("PII_PHONE", "+919876543210", "****3210"),
    ("PII_PAN", "ABCPD1234E", "****234E"),
    ("PII_INTERNAL_HOST", "billing.corp", "... (len 12)"),
])
def test_mask_for(rule_id, value, expected):
    assert mask_for(rule_id, value) == expected


# ---- placeholders ------------------------------------------------------------

@pytest.mark.parametrize("rule_id,expected", [
    ("SEC_JWT", "[REDACTED:SEC_JWT:0123456789ab]"),
    ("CODE_POSSIBLE_SOURCE", "[REDACTED:CODE_POSSIBLE_SOURCE:0123456789ab]"),
    ("PII_CREDIT_CARD", "[PII:CREDIT_CARD]"),
])
def test_placeholders_and_the_guard_pattern_agree(rule_id, expected):
    text = placeholder_for(rule_id, "0123456789ab")
    assert text == expected
    assert PLACEHOLDER_RE.fullmatch(text)

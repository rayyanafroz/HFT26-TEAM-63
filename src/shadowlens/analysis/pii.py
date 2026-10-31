"""Personal data detectors (SOT 7.3). Checksums reject random numbers."""

from __future__ import annotations

import re

from shadowlens.analysis.catalog import Candidate
from shadowlens.analysis.checksums import iban_valid, luhn_valid, verhoeff_valid

_CARD_RE = re.compile(r"\b(?:\d[ \-]?){13,19}\b")
_AADHAAR_RE = re.compile(r"(?<!\d)[2-9]\d{3}\s?\d{4}\s?\d{4}(?!\d)")
_IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")
_SSN_RE = re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
_PAN_RE = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")
_PAN_FOURTH_LETTERS = frozenset("PCHFATBLJG")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_EMAIL_SKIP_DOMAINS = frozenset({"example.com", "example.org", "test.com", "localhost"})
_PHONE_PATTERNS = (
    re.compile(r"(?<!\d)(?:\+91[\-\s]?)?[6-9]\d{9}(?!\d)"),
    re.compile(r"(?<!\d)\+\d{1,3}[\s\-]?\d{6,12}(?!\d)"),
)
_HOSTNAME_RE = re.compile(r"\b[a-z0-9\-]+(?:\.[a-z0-9\-]+)*\.(?:corp|internal|intra|lan)\b")
_HOST_SUFFIXES = (".corp", ".internal", ".intra", ".lan")
_PRIVATE_IP_RE = re.compile(
    r"(?<![\d.])(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})(?![\d.])"
)

# The rules that give one finding per event, with a count (SOT 7.3).
GROUPED_RULES = frozenset({"PII_EMAIL", "PII_PHONE"})


def _digits_only(value: str) -> str:
    return re.sub(r"\D", "", value)


def _is_card(value: str) -> bool:
    digits = _digits_only(value)
    return 13 <= len(digits) <= 19 and digits[0] in "3456" and luhn_valid(digits)


def _is_email_to_report(value: str) -> bool:
    return value.rpartition("@")[2].lower() not in _EMAIL_SKIP_DOMAINS


def _valid_octets(value: str) -> bool:
    return all(int(part) <= 255 for part in value.split("."))


def find_pii(text: str) -> list[Candidate]:
    found: list[Candidate] = []

    def collect(rule_id: str, pattern: re.Pattern[str], accept=None) -> None:
        for match in pattern.finditer(text):
            if accept is None or accept(match.group(0)):
                found.append(Candidate(rule_id, match.start(), match.end(), match.group(0)))

    collect("PII_CREDIT_CARD", _CARD_RE, _is_card)
    collect("PII_AADHAAR", _AADHAAR_RE, lambda v: verhoeff_valid(_digits_only(v)))
    collect("PII_IBAN", _IBAN_RE, iban_valid)
    collect("PII_SSN", _SSN_RE)
    collect("PII_PAN", _PAN_RE, lambda v: v[3] in _PAN_FOURTH_LETTERS)
    # These two patterns are the slowest on ordinary prose, and rarely apply.
    if "@" in text:
        collect("PII_EMAIL", _EMAIL_RE, _is_email_to_report)
    for pattern in _PHONE_PATTERNS:
        collect("PII_PHONE", pattern)
    if any(suffix in text for suffix in _HOST_SUFFIXES):
        collect("PII_INTERNAL_HOST", _HOSTNAME_RE)
    collect("PII_INTERNAL_HOST", _PRIVATE_IP_RE, _valid_octets)
    return found

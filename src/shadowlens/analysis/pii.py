"""Personal data detectors (SOT 7.3). Checksums reject random numbers."""

from __future__ import annotations

import re
from typing import Iterator

from shadowlens.analysis.catalog import Candidate
from shadowlens.analysis.checksums import iban_valid, luhn_valid, verhoeff_valid
from shadowlens.analysis.settings import AnalysisSettings

# A run of digits, in groups split by one space or dash. Which groups form the card is decided
# afterwards (see _cards), because a stray digit nearby would otherwise swallow the whole card.
_DIGIT_RUN_RE = re.compile(r"(?<!\w)\d+(?:[ \-]\d+)*(?!\w)")
_DIGIT_GROUP_RE = re.compile(r"\d+")
_CARD_LENGTHS = (16, 15, 19, 18, 17, 14, 13)   # the common lengths first
_CARD_MIN_DIGITS, _CARD_MAX_DIGITS = 13, 19
_CARD_FIRST_DIGITS = "3456"
# How cards are written (4-4-4-4, 4-6-5). Without this, "1 2 3 4 5 ..." gets many tries at the
# checksum, which one number in ten passes by chance.
_CARD_MAX_GROUPS, _CARD_MIN_GROUP_DIGITS = 5, 3

# The lookahead tries every start. A plain match on "2345 2726 6483 2751" takes the first 12 digits,
# fails the checksum and moves past the real number. The same applies to "LL64 " before an IBAN.
_AADHAAR_RE = re.compile(r"(?<!\d)(?=([2-9]\d{3}[\s\-]?\d{4}[\s\-]?\d{4})(?!\d))")
_IBAN_START_RE = re.compile(r"\b(?=[A-Z]{2}\d{2})")
_IBAN_RUN_RE = re.compile(r"[A-Z]{2}\d{2}(?: ?[A-Z0-9]{1,4}){3,9}\b")
_IBAN_GROUP_RE = re.compile(r"[A-Z0-9]+")
_SSN_RE = re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
_PAN_RE = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")
_PAN_FOURTH_LETTERS = frozenset("PCHFATBLJG")

# Anchored to the start of the address and length-limited. A plain \b start tries again at every
# "." and "-", which took 8 seconds on 64 KB of "a.a.a.a...".
_EMAIL_RE = re.compile(r"(?<![A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,255}\.[A-Za-z]{2,24}\b")

# Not after a letter or "+" (1.2E+12345680), and not inside a URL or a longer number.
_PHONE_PATTERNS = (
    re.compile(r"(?<![\d/.])(?:\+?91[\-\s]?)?[6-9]\d{4}[\-\s]?\d{5}(?![\d])"),
    re.compile(r"(?<![\w+])\+\d{1,3}(?:[\s\-.()]{0,2}\d){6,12}(?!\d)"),
)
_HOSTNAME_RE = re.compile(r"(?i)(?<![a-z0-9.\-])[a-z0-9\-]+(?:\.[a-z0-9\-]+)*\.(?:corp|internal|intra|lan)\b")
_HOST_SUFFIXES = (".corp", ".internal", ".intra", ".lan")
_PRIVATE_IP_RE = re.compile(
    r"(?<![\d.])(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})(?![\d.])"
)

# The rules that give one finding per event, with a count (SOT 7.3).
GROUPED_RULES = frozenset({"PII_EMAIL", "PII_PHONE"})


def _digits_only(value: str) -> str:
    return re.sub(r"\D", "", value)


def _is_card(digits: str) -> bool:
    return digits[0] in _CARD_FIRST_DIGITS and luhn_valid(digits)


def _cards(text: str) -> Iterator[Candidate]:
    """Cards inside runs of digit groups.

    "4111 1111 1111 1111 123" is a card and its CVV, and "qty 2 4111..." has a digit in front. Read
    whole, those fail the checksum and the card would go unseen, so the groups are tried in windows.
    """
    for run in _DIGIT_RUN_RE.finditer(text):
        groups = list(_DIGIT_GROUP_RE.finditer(run.group(0)))
        first = 0
        while first < len(groups):
            windows: dict[int, int] = {}          # digit count -> last group of that window
            digits = 0
            for last in range(first, min(first + _CARD_MAX_GROUPS, len(groups))):
                digits += len(groups[last].group(0))
                if digits > _CARD_MAX_DIGITS or len(groups[last].group(0)) < _CARD_MIN_GROUP_DIGITS:
                    break
                if digits >= _CARD_MIN_DIGITS:
                    windows[digits] = last
            matched = None
            for length in _CARD_LENGTHS:
                if length in windows:
                    last = windows[length]
                    number = "".join(group.group(0) for group in groups[first:last + 1])
                    if _is_card(number):
                        matched = last
                        break
            if matched is None:
                first += 1
                continue
            start = run.start() + groups[first].start()
            end = run.start() + groups[matched].end()
            yield Candidate("PII_CREDIT_CARD", start, end, text[start:end])
            first = matched + 1


def _ibans(text: str) -> Iterator[Candidate]:
    """The run may also take following capitals ("GB82 WEST ... FROM"), so shorter runs are tried."""
    covered_until = 0
    for start in _IBAN_START_RE.finditer(text):
        if start.start() < covered_until:
            continue
        run = _IBAN_RUN_RE.match(text, start.start())
        if run is None:
            continue
        groups = list(_IBAN_GROUP_RE.finditer(run.group(0)))
        for last in range(len(groups) - 1, -1, -1):   # an IBAN with no spaces is one group
            end = run.start() + groups[last].end()
            value = text[run.start():end]
            if iban_valid(value.replace(" ", "")):
                yield Candidate("PII_IBAN", run.start(), end, value)
                covered_until = end
                break


def _valid_octets(value: str) -> bool:
    return all(int(part) <= 255 for part in value.split("."))


def find_pii(text: str, settings: AnalysisSettings) -> list[Candidate]:
    found: list[Candidate] = list(_cards(text))
    skip_domains = {domain.lower() for domain in settings.email_skip_domains}

    def collect(rule_id: str, pattern: re.Pattern[str], accept=None) -> None:
        for match in pattern.finditer(text):
            if accept is None or accept(match.group(0)):
                found.append(Candidate(rule_id, match.start(), match.end(), match.group(0)))

    for match in _AADHAAR_RE.finditer(text):
        if verhoeff_valid(_digits_only(match.group(1))):
            found.append(Candidate("PII_AADHAAR", match.start(1), match.end(1), match.group(1)))
    found.extend(_ibans(text))
    collect("PII_SSN", _SSN_RE)
    collect("PII_PAN", _PAN_RE, lambda v: v[3] in _PAN_FOURTH_LETTERS)
    if "@" in text:
        collect("PII_EMAIL", _EMAIL_RE, lambda v: v.rpartition("@")[2].lower() not in skip_domains)
    for pattern in _PHONE_PATTERNS:
        collect("PII_PHONE", pattern)
    lowered = text.lower()
    if any(suffix in lowered for suffix in _HOST_SUFFIXES):
        collect("PII_INTERNAL_HOST", _HOSTNAME_RE)
    collect("PII_INTERNAL_HOST", _PRIVATE_IP_RE, _valid_octets)
    return found

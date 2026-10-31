"""Secret detectors: named patterns, assignments and entropy (SOT 7.3)."""

from __future__ import annotations

import base64
import binascii
import json
import math
import re
from collections import Counter
from functools import lru_cache

from shadowlens.analysis.catalog import Candidate
from shadowlens.analysis.settings import AnalysisSettings

# The header alone would leave the key material behind in redacted text, so the
# match also takes the base64 lines and END marker that follow. "\\[rn]" covers
# line breaks that are still JSON-escaped.
_BREAK = r"(?:\s|\\[rn])"
PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"
    rf"(?:{_BREAK}+[A-Za-z0-9+/=]{{16,}})*"
    rf"(?:{_BREAK}*-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----)?"
)
AWS_SECRET_RE = re.compile(
    r"(?i)\b(?:aws_secret_access_key|aws[_\-]?secret[_\-]?(?:access[_\-]?)?key|secret_access_key)\b"
    r"[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})\b"
)
GENERIC_RE = re.compile(
    r"(?i)\b(?:api[_\-]?key|secret|token|passwd|password|client[_\-]?secret)\b"
    r"[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_\-/+=]{12,})"
)
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b")

NAMED_PATTERNS: dict[str, re.Pattern[str]] = {
    "SEC_PRIVATE_KEY": PRIVATE_KEY_RE,
    "SEC_AWS_ACCESS_KEY": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "SEC_ANTHROPIC_KEY": re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}"),
    "SEC_OPENAI_KEY": re.compile(r"\bsk-(?!ant-)(?:(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{20,}|[A-Za-z0-9]{32,})"),
    "SEC_GITHUB_TOKEN": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b"),
    "SEC_SLACK_TOKEN": re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}"),
    "SEC_GOOGLE_API_KEY": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    "SEC_HF_TOKEN": re.compile(r"\bhf_[A-Za-z0-9]{34,}\b"),
    "SEC_STRIPE_KEY": re.compile(r"\b[sr]k_live_[A-Za-z0-9]{24,}\b"),
    "SEC_DB_URL": re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:/@]+:[^\s@/]+@[^\s/]+"),
}

_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_MODEL_FIELD_BEFORE_RE = re.compile(r"[\"']?model[\"']?\s*:\s*[\"']?$")
_INTEGRITY_HASH_RE = re.compile(r"^sha(?:256|384|512)-")  # package lock files

_GENERIC_PLACEHOLDER_WORDS = ("your_", "xxx", "changeme", "example", "<", "${", "{{")
_GENERIC_MIN_ENTROPY = 3.0

# Pure hex of these lengths is what MD5, SHA-1 and SHA-256 digests look like. SOT 8.4
# requires git SHAs and digests to stay silent; "token = <hex>" still hits the generic rule.
_DIGEST_LENGTHS = frozenset({32, 40, 64})


@lru_cache(maxsize=4)
def _entropy_token_re(min_len: int) -> re.Pattern[str]:
    # The minimum length is in the pattern so ordinary words never reach Python code.
    return re.compile(rf"[A-Za-z0-9+/=_\-]{{{min_len},}}")


def shannon_entropy(value: str) -> float:
    """Shannon entropy over characters, in bits per character."""
    if not value:
        return 0.0
    total = len(value)
    return -sum(n / total * math.log2(n / total) for n in Counter(value).values())


def _jwt_header_has_alg(token: str) -> bool:
    header = token.split(".", 1)[0]
    try:
        decoded = json.loads(base64.urlsafe_b64decode(header + "=" * (-len(header) % 4)))
    except (ValueError, binascii.Error):
        return False
    return isinstance(decoded, dict) and "alg" in decoded


def _is_generic_placeholder(value: str) -> bool:
    lowered = value.lower()
    return any(word in lowered for word in _GENERIC_PLACEHOLDER_WORDS)


def _decodes_to_json_object(token: str) -> bool:
    try:
        raw = base64.b64decode(token.replace("-", "+").replace("_", "/") + "=" * (-len(token) % 4))
    except (ValueError, binascii.Error):
        return False
    return raw.lstrip()[:1] == b"{"


def _entropy_score(token: str, before: str, settings: AnalysisSettings) -> float | None:
    """The token's entropy when it should be flagged, else ``None``."""
    if _UUID_RE.match(token):
        return None
    # Random tokens this long nearly always hold a digit; paths and identifiers often do not.
    if not any(char.isdigit() for char in token):
        return None
    if _MODEL_FIELD_BEFORE_RE.search(before):
        return None
    if _decodes_to_json_object(token):
        return None
    if before.endswith("base64,") or _INTEGRITY_HASH_RE.match(token):
        return None
    entropy = shannon_entropy(token)
    if _HEX_RE.match(token):
        if len(token) < 32 or len(token) in _DIGEST_LENGTHS:
            return None
        return entropy if entropy >= settings.entropy_hex else None
    return entropy if entropy >= settings.entropy_alnum else None


def find_named_secrets(text: str) -> list[Candidate]:
    """Patterns with a recognizable shape. Headers use only these (SOT 7.1)."""
    found: list[Candidate] = []
    for rule_id, pattern in NAMED_PATTERNS.items():
        found.extend(Candidate(rule_id, m.start(), m.end(), m.group(0)) for m in pattern.finditer(text))
    for match in AWS_SECRET_RE.finditer(text):
        found.append(Candidate("SEC_AWS_SECRET_KEY", match.start(1), match.end(1), match.group(1)))
    for match in JWT_RE.finditer(text):
        if _jwt_header_has_alg(match.group(0)):
            found.append(Candidate("SEC_JWT", match.start(), match.end(), match.group(0)))
    return found


def find_generic_assignments(text: str) -> list[Candidate]:
    found: list[Candidate] = []
    for match in GENERIC_RE.finditer(text):
        value = match.group(1)
        if shannon_entropy(value) >= _GENERIC_MIN_ENTROPY and not _is_generic_placeholder(value):
            found.append(Candidate("SEC_GENERIC_ASSIGNMENT", match.start(1), match.end(1), value))
    return found


def find_high_entropy(text: str, settings: AnalysisSettings) -> list[tuple[float, Candidate]]:
    """Every entropy hit with its score. The cap is applied after overlaps are resolved."""
    found: list[tuple[float, Candidate]] = []
    for match in _entropy_token_re(settings.entropy_min_len).finditer(text):
        token = match.group(0)
        score = _entropy_score(token, text[max(0, match.start() - 20):match.start()], settings)
        if score is not None:
            found.append((score, Candidate("SEC_HIGH_ENTROPY", match.start(), match.end(), token)))
    return found

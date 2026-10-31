"""Secret detectors: named patterns, assignments and entropy (SOT 7.3).

The patterns stay in code because each is tied to the check that follows it. Thresholds and word
lists are in ``config/rules.yaml``. See ``docs/DETECTORS.md`` for why each rule is shaped as it is.
"""

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
# These end in a lookahead, not the SOT's \b: a key can end in "/", "+", "=" or "-", and \b would
# then fail against the following space, losing the secret.
AWS_SECRET_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?:aws[_\-]?secret[_\-]?(?:access[_\-]?)?key|secret[_\-]?access[_\-]?key)\b"
    r"[\"'\\]*\s*(?::=|=>|=|:)\s*[\"'\\]*([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"
)
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")

NAMED_PATTERNS: dict[str, re.Pattern[str]] = {
    "SEC_PRIVATE_KEY": PRIVATE_KEY_RE,
    "SEC_AWS_ACCESS_KEY": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "SEC_ANTHROPIC_KEY": re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}"),
    "SEC_OPENAI_KEY": re.compile(r"\bsk-(?!ant-)(?:(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{20,}|[A-Za-z0-9]{32,})"),
    "SEC_GITHUB_TOKEN": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b"),
    "SEC_SLACK_TOKEN": re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}"),
    "SEC_GOOGLE_API_KEY": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}(?![0-9A-Za-z_\-])"),
    "SEC_HF_TOKEN": re.compile(r"\bhf_[A-Za-z0-9]{34,}\b"),
    "SEC_STRIPE_KEY": re.compile(r"\b[sr]k_live_[A-Za-z0-9]{24,}\b"),
    "SEC_DB_URL": re.compile(
        r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:/@]+:[^\s@/]+@[^\s/\"'`<>]+"
    ),
}

# Something every pattern above must contain. If you add a pattern, add its fixed part here too:
# test_every_named_pattern_passes_the_prefilter checks that this was not forgotten.
_NAMED_PREFILTER_RE = re.compile(
    r"-----BEGIN |AKIA|ASIA|sk-|gh[pousr]_|github_pat_|xox[abprs]-|AIza|hf_|[sr]k_live_|eyJ|://|(?i:secret)"
)

# ---- assignments ----------------------------------------------------------------------------
# A secret is rarely named just "password": DB_PASSWORD, access_token and JWT_SECRET are the usual
# shapes, and "\b" cannot see those because "_" counts as a word character. So a name may have any
# non-letter in front of it, and nothing word-like after it (token_count and tokens stay quiet).
_PASSWORD_WORDS = r"passwd|password|pwd|passphrase"
_OTHER_WORDS = r"api[_\-]?key|secret(?:[_\-]?key)?|token|client[_\-]?secret|access[_\-]?key"
_SEPARATOR = r"[\"'\\]*\s*(?::=|=>|=|:)\s*[\"'\\]*"
_VALUE = r"([^\s\"'`,;&<>{}()\[\]\\]+)"
GENERIC_RE = re.compile(
    rf"(?i)(?<![A-Za-z])(?:({_PASSWORD_WORDS})|{_OTHER_WORDS})(?![A-Za-z0-9_\-]){_SEPARATOR}{_VALUE}"
)
# accessToken, clientSecret, dbPassword: the same names in camelCase, so this one is case-sensitive.
GENERIC_CAMEL_RE = re.compile(
    rf"[a-z0-9](?:(Password|Passwd|Pwd|Passphrase)|Token|Secret|SecretKey|ApiKey|AccessKey)"
    rf"(?![A-Za-z0-9_\-]){_SEPARATOR}{_VALUE}"
)
_REFERENCE_RE = re.compile(r"^(?:[A-Za-z_$][\w$]*\.)+[A-Za-z_$][\w$]*$")  # settings.DB_PASSWORD
_NOT_A_VALUE_PREFIXES = ("$", "%", "/", "./", "../", "~", "#")

# ---- entropy ----------------------------------------------------------------------------------
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_MODEL_FIELD_BEFORE_RE = re.compile(r"[\"']?model[\"']?\s*:\s*[\"']?$")
_INTEGRITY_HASH_RE = re.compile(r"^sha(?:256|384|512)-")  # package lock files
_WORD_PART_RE = re.compile(r"^(?:[a-z]+|[A-Z]+|[A-Z][a-z]+|\d+)$")
_SEPARATORS_RE = re.compile(r"[/_\-]")


def shannon_entropy(value: str) -> float:
    """Shannon entropy over characters, in bits per character."""
    if not value:
        return 0.0
    total = len(value)
    return -sum(n / total * math.log2(n / total) for n in Counter(value).values())


@lru_cache(maxsize=4)
def _entropy_token_re(min_len: int) -> re.Pattern[str]:
    # The minimum length is in the pattern so ordinary words never reach Python code. "=" only
    # counts as padding at the end, so FOO_BAR=149 is the name FOO_BAR and not one long token.
    return re.compile(rf"[A-Za-z0-9+/_\-]{{{min_len},}}={{0,2}}")


def _jwt_header_has_alg(token: str) -> bool:
    header = token.split(".", 1)[0]
    try:
        decoded = json.loads(base64.urlsafe_b64decode(header + "=" * (-len(header) % 4)))
    except (ValueError, binascii.Error):
        return False
    return isinstance(decoded, dict) and "alg" in decoded


def _decodes_to_json_object(token: str) -> bool:
    try:
        raw = base64.b64decode(token.replace("-", "+").replace("_", "/") + "=" * (-len(token) % 4))
    except (ValueError, binascii.Error):
        return False
    return raw.lstrip()[:1] == b"{"


def _is_made_of_words(token: str) -> bool:
    """URL paths and identifiers: p2p-hackers/2001-September/000316, B32_DECODE_MAP_DOC.

    Random text rarely splits into three or more parts that are mostly plain words or numbers.
    """
    parts = [part for part in _SEPARATORS_RE.split(token) if part]
    if len(parts) < 3:
        return False
    return sum(bool(_WORD_PART_RE.match(part)) for part in parts) * 2 >= len(parts)


def _is_a_sequence(token: str) -> bool:
    """abcdefghijklmnopqrstuvwxyz0123456789: an alphabet, written out in code."""
    steps = sum(ord(b) - ord(a) == 1 for a, b in zip(token, token[1:]))
    return steps * 2 > len(token)


def _entropy_score(token: str, before: str, settings: AnalysisSettings) -> float | None:
    """The token's entropy when it should be flagged, else ``None``."""
    if _UUID_RE.match(token):
        return None
    # Random tokens this long nearly always hold a digit; paths and identifiers often do not.
    if not any(char.isdigit() for char in token):
        return None
    if _MODEL_FIELD_BEFORE_RE.search(before):
        return None
    if before.endswith(("base64,", "://")) or _INTEGRITY_HASH_RE.match(token):
        return None
    if _is_made_of_words(token) or _is_a_sequence(token):
        return None
    if _decodes_to_json_object(token):
        return None
    entropy = shannon_entropy(token)
    if _HEX_RE.match(token):
        if len(token) < 32 or len(token) in settings.entropy_digest_lengths:
            return None
        return entropy if entropy >= settings.entropy_hex else None
    # A random 24-character token often cannot reach the fixed bar, because it has too few
    # characters to spread out: log2(24) is only 4.58.
    needed = min(settings.entropy_alnum, settings.entropy_length_ratio * math.log2(len(token)))
    return entropy if entropy >= needed else None


def find_named_secrets(text: str) -> list[Candidate]:
    """Patterns with a recognizable shape. Headers use only these (SOT 7.1)."""
    found: list[Candidate] = []
    if not _NAMED_PREFILTER_RE.search(text):         # the common case: one scan instead of twelve
        return found
    for rule_id, pattern in NAMED_PATTERNS.items():
        found.extend(Candidate(rule_id, m.start(), m.end(), m.group(0)) for m in pattern.finditer(text))
    for match in AWS_SECRET_RE.finditer(text):
        found.append(Candidate("SEC_AWS_SECRET_KEY", match.start(1), match.end(1), match.group(1)))
    for match in JWT_RE.finditer(text):
        if _jwt_header_has_alg(match.group(0)):
            found.append(Candidate("SEC_JWT", match.start(), match.end(), match.group(0)))
    return found


def _reads_as_a_name(value: str) -> bool:
    """password = getPassword, token: Optional, secret = DB_SECRET. Letters only, and the capitals
    follow word starts. Random letters are about half capitals, which names never are."""
    letters = value.replace("_", "").replace("-", "")
    if not letters.isalpha():
        return False
    capitals = sum(char.isupper() for char in letters)
    return capitals == len(letters) or capitals * 4 <= len(letters)


def _is_real_value(value: str, is_password: bool, settings: AnalysisSettings) -> bool:
    """An assignment's right-hand side, unless it is a placeholder or a reference to something else."""
    if len(value) < (settings.generic_password_min_len if is_password else settings.generic_min_len):
        return False
    lowered = value.lower()
    if any(word in lowered for word in settings.generic_placeholder_words):
        return False
    if value.startswith(_NOT_A_VALUE_PREFIXES) or "://" in value or value.isdigit():
        return False
    if _REFERENCE_RE.match(value):
        return False
    if shannon_entropy(value) < settings.generic_min_entropy:
        return False
    return not _reads_as_a_name(value)


def find_generic_assignments(text: str, settings: AnalysisSettings) -> list[Candidate]:
    found: list[Candidate] = []
    for pattern in (GENERIC_RE, GENERIC_CAMEL_RE):
        for match in pattern.finditer(text):
            value = match.group(2)
            if _is_real_value(value, match.group(1) is not None, settings):
                found.append(Candidate("SEC_GENERIC_ASSIGNMENT", match.start(2), match.end(2), value))
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

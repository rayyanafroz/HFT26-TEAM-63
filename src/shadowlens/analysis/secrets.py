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
    r"(?i)-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"
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
    "SEC_AWS_ACCESS_KEY": re.compile(r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Za-z0-9])"),
    "SEC_ANTHROPIC_KEY": re.compile(r"(?<![A-Za-z0-9])sk-ant-[A-Za-z0-9_\-]{20,}"),
    # A letter or digit in front means it is part of a longer word ("task-..."), but "_" and "=" are fine:
    # OPENAI_API_KEY_sk-... is still the key. sk-proj-, sk-svcacct-, sk-None-, sk-or-v1-: any short label, then the secret.
    "SEC_OPENAI_KEY": re.compile(
        r"(?<![A-Za-z0-9])sk-(?!ant-)(?:[A-Za-z][A-Za-z0-9]{1,11}-(?:[A-Za-z0-9]{1,6}-)?[A-Za-z0-9_\-]{20,}|[A-Za-z0-9]{32,})"),
    "SEC_GITHUB_TOKEN": re.compile(r"(?<![A-Za-z0-9])(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})(?![A-Za-z0-9])"),
    "SEC_SLACK_TOKEN": re.compile(
        r"\bxox[abprs]-[A-Za-z0-9\-]{10,}|(?<![A-Za-z0-9])xapp-\d-[A-Za-z0-9]+-\d+-[A-Za-z0-9]+|https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{16,}"),
    "SEC_GOOGLE_API_KEY": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}(?![0-9A-Za-z_\-])"),
    "SEC_HF_TOKEN": re.compile(r"\bhf_[A-Za-z0-9]{34,}\b"),
    "SEC_STRIPE_KEY": re.compile(r"\b[sr]k_live_[A-Za-z0-9]{24,}\b"),
    "SEC_DB_URL": re.compile(
        r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver|oracle|cockroachdb|"
        r"clickhouse|neo4j|bolt|couchdb)://[^\s:/@]+:[^\s@/]+@[^\s/\"'`<>]+"
    ),
}

# Tokens with a clear prefix whose vendor has no rule of its own in the frozen catalog (SOT 6.5). They are
# reported as SEC_GENERIC_ASSIGNMENT, "possible secret".
VENDOR_PATTERNS: tuple[re.Pattern[str], ...] = tuple(re.compile(p) for p in (
    r"\bdo[por]_v1_[a-f0-9]{64}\b",                               # DigitalOcean
    r"\bshp(?:at|ca|pa|ss)_[a-f0-9]{32}\b",                       # Shopify
    r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}",            # SendGrid
    r"\bnpm_[A-Za-z0-9]{36}\b",                                   # npm
    r"\bya29\.[A-Za-z0-9_\-]{20,}",                               # Google OAuth access token
    r"\bSK[0-9a-f]{32}\b",                                        # Twilio API key
    r"\bkey-[0-9a-f]{32}\b",                                      # Mailgun
    r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}",                  # PyPI
    r"\b\d{8,10}:AA[A-Za-z0-9_\-]{33}\b",                         # Telegram bot
    r"\bsq0(?:atp|csp)-[A-Za-z0-9_\-]{22,}",                       # Square
    r"\bglpat-[A-Za-z0-9_\-]{20}\b",                              # GitLab
    r"\bgsk_[A-Za-z0-9]{40,}",                                     # Groq
    r"\br8_[A-Za-z0-9]{36,}",                                      # Replicate
    r"\bpplx-[A-Za-z0-9]{40,}",                                    # Perplexity
    r"\bxai-[A-Za-z0-9]{60,}",                                     # xAI
    r"\bnvapi-[A-Za-z0-9_\-]{40,}",                                # NVIDIA
    r"\blsv2_(?:pt|sk)_[a-f0-9]{32}_[a-f0-9]{10}\b",               # LangSmith
    r"\bfw_[A-Za-z0-9]{24,}",                                      # Fireworks
    r"\b(?:rk|pk)_(?:live|test)_[A-Za-z0-9]{24,}\b",               # Stripe restricted/publishable-looking
))

# Something every pattern above must contain. If you add a pattern, add its fixed part here too:
# test_every_named_pattern_passes_the_prefilter checks that this was not forgotten.
_NAMED_PREFILTER_RE = re.compile(
    r"(?i:-----BEGIN )|AKIA|ASIA|sk-|gh[pousr]_|github_pat_|xox[abprs]-|AIza|hf_|[sr]k_live_|eyJ|://|(?i:secret)"
    r"|xapp-|do[por]_v1_|shp(?:at|ca|pa|ss)_|SG\.|npm_|ya29\.|SK[0-9a-f]{32}|key-|pypi-|:AA|sq0|glpat-|[rp]k_(?:live|test)_"
    r"|gsk_|r8_|pplx-|xai-|nvapi-|lsv2_|fw_"
)

# ---- assignments ----------------------------------------------------------------------------
# A secret is rarely named just "password": DB_PASSWORD, access_token and JWT_SECRET are the usual
# shapes, and "\b" cannot see those because "_" counts as a word character. So a name may have any
# non-letter in front of it, and nothing word-like after it (token_count and tokens stay quiet).
_PASSWORD_WORDS = r"passwd|password|passcode|passphrase|pwd|pass|pw"
_OTHER_WORDS = (r"api[_\-\s]?key|secret(?:[_\-]?key)?|token|client[_\-]?secret|access[_\-]?key|private[_\-]?key|"
                r"auth(?:orization)?|account[_\-]?key|credentials?")
_SEPARATOR = r"[\"'\\]*\s*(?::=|=>|=|:)\s*[\"'\\]*"
_SAYS = r"\s+(?:is|was|are)\s+[\"'\\]*"                     # "the password is hunter2xyz"
_VALUE = r"(?P<v>[^\s\"'`,;&<>{}()\[\]\\]+)"
_NAME_START = r"(?i)(?<![A-Za-z])"
_NAME_END = r"(?![A-Za-z0-9_\-])"
GENERIC_RE = re.compile(
    rf"{_NAME_START}(?:(?P<pw>{_PASSWORD_WORDS})|{_OTHER_WORDS}){_NAME_END}(?:{_SEPARATOR}|{_SAYS}){_VALUE}"
)
# "passwd hunter2xyz", "with the password Xk39...": only password words may be followed by nothing but a space,
# and the value must then look chosen, not like a word.
GENERIC_PLAIN_RE = re.compile(rf"{_NAME_START}(?P<pw>{_PASSWORD_WORDS}){_NAME_END}\s+[\"'\\]*{_VALUE}")
# password = 'my secret phrase 99': a quoted value may hold spaces.
GENERIC_QUOTED_RE = re.compile(
    rf"{_NAME_START}(?:(?P<pw>{_PASSWORD_WORDS})|{_OTHER_WORDS}){_NAME_END}\s*(?::=|=>|=|:)\s*([\"'`])(?P<v>[^\"'`\n]{{8,80}})\2"
)
# login: admin / Xk39...: a user and a password written as a pair.
PAIR_RE = re.compile(r"(?i)\b(?:credentials?|creds|login)\s*[:=]\s*[\w.@\-]{1,40}\s*[/|,]\s*(?P<v>\S{8,})")
BEARER_RE = re.compile(r"(?i)\bbearer\s+(?P<v>[A-Za-z0-9._~+/\-]{20,}=*)")
# mysql -u root -pSECRET, sshpass -p SECRET: the client programs where a password follows -p.
CLI_PASSWORD_RE = re.compile(
    r"(?i)\b(?:mysql|mysqldump|mysqladmin|mariadb|mongo\w*|psql|redis-cli|sqlcmd)\b[^\n]{0,200}\s-p(?P<v>\S{6,})"
    r"|\bsshpass\s+-p\s*(?P<v2>\S+)"
)
# https://user:SECRET@host for the schemes that are not databases (SEC_DB_URL has those).
URL_CREDENTIALS_RE = re.compile(r"\b[a-z][a-z0-9+.\-]{1,15}://[^\s:/@]+:(?P<v>[^\s@/]{3,})@")
# accessToken, clientSecret, dbPassword: the same names in camelCase, so this one is case-sensitive.
GENERIC_CAMEL_RE = re.compile(
    rf"[a-z0-9](?:(?P<pw>Password|Passwd|Pwd|Passphrase)|Token|Secret|SecretKey|ApiKey|AccessKey)"
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
    for pattern in VENDOR_PATTERNS:
        found.extend(Candidate("SEC_GENERIC_ASSIGNMENT", m.start(), m.end(), m.group(0)) for m in pattern.finditer(text))
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


def _looks_chosen(value: str) -> bool:
    """A password nobody wrote a label for needs a letter and a digit or symbol, so prose does not count."""
    return any(c.isalpha() for c in value) and any(not c.isalpha() for c in value)


def find_generic_assignments(text: str, settings: AnalysisSettings) -> list[Candidate]:
    found: list[Candidate] = []

    def add(match: re.Match[str], group: str, is_password: bool, extra=lambda value: True) -> None:
        value = match.group(group)
        if value and _is_real_value(value, is_password, settings) and extra(value):
            found.append(Candidate("SEC_GENERIC_ASSIGNMENT", match.start(group), match.end(group), value))

    for pattern in (GENERIC_RE, GENERIC_CAMEL_RE):
        for match in pattern.finditer(text):
            add(match, "v", match.group("pw") is not None)
    for match in GENERIC_PLAIN_RE.finditer(text):
        add(match, "v", True, _looks_chosen)
    for match in GENERIC_QUOTED_RE.finditer(text):
        add(match, "v", match.group("pw") is not None, lambda value: " " in value and _looks_chosen(value))
    for match in BEARER_RE.finditer(text):
        add(match, "v", False)
    for match in PAIR_RE.finditer(text):
        add(match, "v", True, _looks_chosen)
    for match in CLI_PASSWORD_RE.finditer(text):
        add(match, "v" if match.group("v") else "v2", True)
    for match in URL_CREDENTIALS_RE.finditer(text):
        add(match, "v", True)
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

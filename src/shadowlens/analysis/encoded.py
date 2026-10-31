"""Secrets that are broken up or encoded, found without guessing (SOT 7.3).

Two disguises are handled, both only for secrets with a recognizable shape (the named patterns):

* split: a key cut by spaces, line breaks, quotes or ``+`` (``"sk-proj-" + "abc..."``);
* encoded: a base64 or hex string that decodes to text holding a secret or personal data.

Every hit is reported over the span of the disguised text in the ORIGINAL view, so redaction hides
exactly what was typed. The value reported is the plain secret, so the same key written plainly, split or
encoded is one finding.
"""

from __future__ import annotations

import base64
import binascii
import re

from shadowlens.analysis.catalog import Candidate
from shadowlens.analysis.pii import find_pii
from shadowlens.analysis.secrets import NAMED_PATTERNS, find_generic_assignments, find_named_secrets, shannon_entropy
from shadowlens.analysis.settings import AnalysisSettings

MAX_TOKENS = 30                 # encoded tokens examined per text
MAX_TOKEN_CHARS = 4096
MIN_DECODED_CHARS = 12
PRINTABLE_RATIO = 0.95

# The start of a key (its fixed prefix) and the pieces that may follow it after a break.
_B64 = re.compile(r"(?<![A-Za-z0-9+/_\-=])[A-Za-z0-9+/_\-]{24,%d}={0,2}(?![A-Za-z0-9+/_\-])" % MAX_TOKEN_CHARS)
_HEX = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){12,%d}(?![0-9A-Fa-f])" % (MAX_TOKEN_CHARS // 2))
_KEY_START = re.compile(
    r"(?<![A-Za-z0-9_\-])(?:AKIA|ASIA|sk-|gh[pousr]_|github_pat_|xox[abprs]-|AIza|hf_|[sr]k_live_)[A-Za-z0-9_\-]*"
)
_NEXT_PIECE = re.compile(r"[ \t\r\n\"'`+]{1,40}([A-Za-z0-9_\-]+)")
MAX_PIECES = 8
MIN_PIECE_ENTROPY = 3.0


def _looks_random(piece: str) -> bool:
    """A later piece of a key has a digit, or is a long, varied string. A plain word is not part of it."""
    if any(ch.isdigit() for ch in piece):
        return True
    if len(piece) >= 6 and any(ch.islower() for ch in piece) and any(ch.isupper() for ch in piece[1:]):
        return True                                           # capitals inside a word: tMWFJZgg, not "Hello"
    return len(piece) >= 8 and shannon_entropy(piece) >= MIN_PIECE_ENTROPY


def find_split_secrets(text: str) -> list[Candidate]:
    """Named secrets cut by spaces, line breaks, quotes or ``+``: ``"sk-proj-" + "abc..."``.

    Starts at a known key prefix and takes the pieces after it that look random, stopping at the first
    word that does not, so neighboring words are never glued on.
    """
    found: list[Candidate] = []
    for first in _KEY_START.finditer(text):
        pieces = [(first.start(), first.end())]
        cursor = first.end()
        while len(pieces) < MAX_PIECES:
            following = _NEXT_PIECE.match(text, cursor)
            if following is None or not _looks_random(following.group(1)):
                break
            pieces.append((following.start(1), following.end(1)))
            cursor = following.end()
        if len(pieces) == 1:
            continue                                         # nothing was split: the plain pass has it
        compact = "".join(text[a:b] for a, b in pieces)
        for rule_id, pattern in NAMED_PATTERNS.items():
            hit = pattern.match(compact)
            if hit is None or hit.end() <= pieces[0][1] - pieces[0][0]:
                continue
            used, end = hit.end(), pieces[0][1]
            for a, b in pieces:                              # where the match ends in the original text
                if used <= b - a:
                    end = a + used
                    break
                used -= b - a
            found.append(Candidate(rule_id, first.start(), end, hit.group(0)))
            break
    return found


def _decoded_text(raw: bytes) -> str | None:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(text) < MIN_DECODED_CHARS:
        return None
    printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in text)
    return text if printable >= PRINTABLE_RATIO * len(text) else None


def _from_base64(token: str) -> str | None:
    cleaned = token.replace("-", "+").replace("_", "/").rstrip("=")
    try:
        return _decoded_text(base64.b64decode(cleaned + "=" * (-len(cleaned) % 4), validate=True))
    except (ValueError, binascii.Error):
        return None


def _from_hex(token: str) -> str | None:
    try:
        return _decoded_text(binascii.unhexlify(token))
    except (ValueError, binascii.Error):
        return None


def find_encoded_secrets(text: str, settings: AnalysisSettings) -> list[Candidate]:
    """Secrets and personal data inside base64 or hex tokens."""
    found: list[Candidate] = []
    tokens = 0
    for pattern, decode in ((_B64, _from_base64), (_HEX, _from_hex)):
        for match in pattern.finditer(text):
            tokens += 1
            if tokens > MAX_TOKENS:
                return found
            decoded = decode(match.group(0))
            if decoded is None:
                continue
            inner = find_named_secrets(decoded) + find_generic_assignments(decoded, settings) + find_pii(decoded, settings)
            found.extend(Candidate(hit.rule_id, match.start(), match.end(), hit.value) for hit in inner)
    return found

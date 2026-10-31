"""Source code and confidentiality markers (SOT 7.3). At most one finding per rule, per event."""

from __future__ import annotations

import re

from shadowlens.analysis.catalog import Candidate

_MARKER_RE = re.compile(r"(?i)\b(confidential|proprietary|internal use only|do not distribute|trade secret)\b")
_COPYRIGHT_RE = re.compile(r"(?i)(copyright|©|\(c\))")
_MARKER_WINDOW = 200

_FENCE_RE = re.compile(r"```.*?(?:```|\Z)", re.DOTALL)
_CODE_TOKEN_RE = re.compile(
    r"(?<![\w#])(def|class|import|from|function|const|let|public|private|return|package)\b|(#include)\b"
)
_MIN_LINES = 20
_MIN_DISTINCT_TOKENS = 3


def _find_confidential_marker(text: str) -> Candidate | None:
    for match in _MARKER_RE.finditer(text):
        window = text[max(0, match.start() - _MARKER_WINDOW):match.end() + _MARKER_WINDOW]
        if _COPYRIGHT_RE.search(window):
            return Candidate("CODE_CONFIDENTIAL_MARKER", match.start(), match.end(), match.group(0).lower())
    return None


def _distinct_code_tokens(text: str) -> int:
    return len({m.group(1) or m.group(2) for m in _CODE_TOKEN_RE.finditer(text)})


def _find_possible_source(text: str, markers: tuple[str, ...]) -> Candidate | None:
    fences = [m for m in _FENCE_RE.finditer(text)]
    if fences:
        start, end = fences[0].start(), fences[-1].end()
    elif text.count("\n") + 1 >= _MIN_LINES:
        start, end = 0, len(text)
    else:
        return None
    region = text[start:end]
    if _distinct_code_tokens(region) < _MIN_DISTINCT_TOKENS:
        return None
    if markers and not any(marker.lower() in text.lower() for marker in markers):
        return None
    return Candidate("CODE_POSSIBLE_SOURCE", start, end, region)


def find_code(text: str, markers: tuple[str, ...] = ()) -> list[Candidate]:
    found = (_find_confidential_marker(text), _find_possible_source(text, markers))
    return [candidate for candidate in found if candidate is not None]

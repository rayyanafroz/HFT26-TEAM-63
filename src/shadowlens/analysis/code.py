"""Source code and confidentiality markers (SOT 7.3). At most one finding per rule, per event."""

from __future__ import annotations

import re

from shadowlens.analysis.catalog import Candidate
from shadowlens.analysis.settings import AnalysisSettings

def _spaced(phrase: str) -> str:
    """The phrase with an optional space or dot between letters, so "C O N F I D E N T I A L" still counts."""
    words = [r"[ .]?".join(re.escape(ch) for ch in word) for word in phrase.split()]
    return r"\s+".join(words)


_MARKER_RE = re.compile(
    r"(?i)(?<![A-Za-z])(" + "|".join(_spaced(p) for p in (
        "confidential", "proprietary", "internal use only", "do not distribute", "trade secret")) + r")(?![A-Za-z])")
_COPYRIGHT_RE = re.compile(r"(?i)(copyright|©|\(c\))")

_FENCE_RE = re.compile(r"```.*?(?:```|\Z)", re.DOTALL)
_CODE_TOKEN_RE = re.compile(
    r"(?<![\w#])(def|class|import|from|function|const|let|public|private|return|package)\b|(#include)\b"
)
# English also says "let", "from", "return" and "public". What prose does not have is lines like these.
_CODE_LINE_RE = re.compile(
    r"(?:[;{}]\s*$|[)\]]\s*:?\s*$|:\s*$|\w\s*=\s*\S|^\s*(?:#include|import\s|from\s+\S+\s+import\b|def\s+\w+\s*\(|class\s+\w+))",
    re.MULTILINE,
)


def _find_confidential_marker(text: str, settings: AnalysisSettings) -> Candidate | None:
    for match in _MARKER_RE.finditer(text):
        window = text[max(0, match.start() - settings.marker_window):match.end() + settings.marker_window]
        if _COPYRIGHT_RE.search(window):
            return Candidate("CODE_CONFIDENTIAL_MARKER", match.start(), match.end(), match.group(0).lower())
    return None


def _distinct_code_tokens(text: str) -> int:
    return len({m.group(1) or m.group(2) for m in _CODE_TOKEN_RE.finditer(text)})


def _shaped_lines(text: str, enough: int) -> int:
    count = 0
    for line in text.splitlines():
        if _CODE_LINE_RE.search(line):
            count += 1
            if count >= enough:
                break
    return count


def _find_possible_source(text: str, settings: AnalysisSettings) -> Candidate | None:
    fences = list(_FENCE_RE.finditer(text))
    if fences:
        start, end = fences[0].start(), fences[-1].end()
    elif text.count("\n") + 1 >= settings.code_min_lines:
        start, end = 0, len(text)
        if _shaped_lines(text, settings.code_min_shaped_lines) < settings.code_min_shaped_lines:
            return None
    else:
        return None
    region = text[start:end]
    if _distinct_code_tokens(region) < settings.code_min_distinct_tokens:
        return None
    markers = settings.internal_markers
    if markers and not any(marker.lower() in text.lower() for marker in markers):
        return None
    return Candidate("CODE_POSSIBLE_SOURCE", start, end, region)


def find_code(text: str, settings: AnalysisSettings) -> list[Candidate]:
    found = (_find_confidential_marker(text, settings), _find_possible_source(text, settings))
    return [candidate for candidate in found if candidate is not None]

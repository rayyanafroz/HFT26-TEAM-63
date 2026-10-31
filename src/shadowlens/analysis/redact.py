"""Overlap resolution and redaction (SOT 7.3)."""

from __future__ import annotations

from bisect import bisect_left
from typing import Iterable

from shadowlens.analysis.catalog import RULES, Candidate, TextFinding
from shadowlens.analysis.masking import PLACEHOLDER_RE, placeholder_for

CONTEXT_MAX = 200
_CONTEXT_SIDE = 60


def _overlaps(a: Candidate, b: Candidate) -> bool:
    return a.start < b.end and b.start < a.end


def resolve_overlaps(candidates: Iterable[Candidate]) -> list[Candidate]:
    """Keep the higher-priority match wherever spans overlap, so one secret gives one finding.

    Within a priority, the order of ``candidates`` decides, then the longer match.
    Result is sorted by position.

    The kept matches never overlap each other, so a new one can only touch its two neighbours by
    position. That keeps this fast when a hostile text holds thousands of matches.
    """
    indexed = list(enumerate(candidates))
    indexed.sort(key=lambda item: (RULES[item[1].rule_id].priority, item[0], item[1].start - item[1].end))
    kept: list[Candidate] = []
    starts: list[int] = []
    for _, candidate in indexed:
        at = bisect_left(starts, candidate.start)
        if at > 0 and kept[at - 1].end > candidate.start:
            continue
        if at < len(kept) and kept[at].start < candidate.end:
            continue
        if at < len(kept) and kept[at].start == candidate.start:       # an empty span at the same place
            continue
        kept.insert(at, candidate)
        starts.insert(at, candidate.start)
    return sorted(kept, key=lambda c: (c.start, c.end))


def drop_already_redacted(text: str, candidates: Iterable[Candidate]) -> list[Candidate]:
    """Text that is already a placeholder is not a new hit (the guard depends on this)."""
    spans = [m.span() for m in PLACEHOLDER_RE.finditer(text)]
    if not spans:
        return list(candidates)
    starts = [start for start, _ in spans]
    kept = []
    for c in candidates:
        at = bisect_left(starts, c.end)                  # placeholders that begin before the candidate ends
        if at > 0 and spans[at - 1][1] > c.start:        # the last of them reaches into the candidate
            continue
        kept.append(c)
    return kept


def _apply(text: str, findings: Iterable[TextFinding]) -> tuple[str, dict[tuple[int, int], int]]:
    """Replace every span; also return where each original span landed in the result.

    A span inside a larger one (a key inside a redacted code block) disappears with it. A span that
    only partly overlaps the previous one is removed in full too: its tail must not stay visible.
    """
    items = [(start, end, f) for f in findings for start, end in f.spans]
    items.sort(key=lambda item: (item[0], item[0] - item[1]))
    parts: list[str] = []
    positions: dict[tuple[int, int], int] = {}
    cursor = 0
    length = 0
    outer_start = 0
    for start, end, finding in items:
        if start < cursor:  # inside the previous span
            positions[(start, end)] = outer_start
            cursor = max(cursor, end)
            continue
        parts.append(text[cursor:start])
        length += start - cursor
        positions[(start, end)] = outer_start = length
        placeholder = placeholder_for(finding.rule_id, finding.hash12)
        parts.append(placeholder)
        length += len(placeholder)
        cursor = end
    parts.append(text[cursor:])
    return "".join(parts), positions


def redact_text(text: str, findings: Iterable[TextFinding]) -> str:
    """``text`` with every detected span replaced by its placeholder."""
    return _apply(text, findings)[0]


def fill_contexts(text: str, findings: list[TextFinding]) -> None:
    """Set each finding's ``context``: text around it, sliced AFTER redaction.

    Slicing first could cut another secret in half and leave the visible half behind.
    """
    redacted, positions = _apply(text, findings)
    for finding in findings:
        if not finding.spans:
            continue
        position = positions[finding.spans[0]]
        placeholder = placeholder_for(finding.rule_id, finding.hash12)
        start = max(0, position - _CONTEXT_SIDE)
        finding.context = redacted[start:position + len(placeholder) + _CONTEXT_SIDE][:CONTEXT_MAX]

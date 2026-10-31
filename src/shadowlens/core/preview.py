"""Leak Lab: analyse text a person types, without storing anything (SOT 6.7, 9.3.2).

The analysis itself is Saleha's ``analysis.preview``: the findings with their positions, the text an
AI model would be sent (secrets replaced by placeholders), and whether the egress guard would block
that text. This module adds the one thing that needs the scoring maths: how many risk points the
text would add. Nothing is written to the database or the log.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..config import Config
from ..models import AnalyzeMode, PointsPreview, Preview, PreviewFinding, SamplesResponse, Severity
from . import hooks
from .scoring import score_tool

PREVIEW_TIME = "2026-01-01T00:00:00.000Z"     # only used to put findings in a fixed order


class AnalysisUnavailable(RuntimeError):
    """The analysis module this feature needs has not been installed yet."""


@dataclass(frozen=True)
class _Counted:
    """A finding in the form the scorer reads."""

    id: str
    rule_id: str
    severity: Severity
    confidence: float
    created_at: str = PREVIEW_TIME


def build_preview(text: str, mode: AnalyzeMode, config: Config) -> Preview:
    run = hooks.preview_function()
    if run is None:
        raise AnalysisUnavailable("text analysis is not installed yet")
    result: dict[str, Any] = run(text, mode.value, config)

    rows = [PreviewFinding(**row) for row in result["findings"]]
    rows.sort(key=lambda r: r.span)

    # One row per match lets the screen highlight each one, but two matches of the same value are one
    # finding for scoring (SOT 7.5 counts a finding once). Matches of different values stay separate.
    distinct: dict[tuple[str, str], PreviewFinding] = {}
    for row in rows:
        distinct.setdefault((row.rule_id, row.masked_preview), row)
    counted = [_Counted(id=f"{i:04d}", rule_id=r.rule_id, severity=r.severity, confidence=r.confidence)
               for i, r in enumerate(distinct.values())]
    # "as if sent from an unsanctioned cloud tool": full exposure, no approval discount
    scored = score_tool("leak-lab|preview", counted, exposure=1.0, sanctioned=False)

    return Preview(findings=rows, redacted_text=result["redacted_text"], would_block=bool(result["would_block"]),
                   points_preview=PointsPreview(S=scored.s, tool_score=scored.score))


def build_samples() -> SamplesResponse:
    """Fake test inputs for the three Leak Lab buttons. Built at run time, never stored in git."""
    make = hooks.samples_function()
    if make is None:
        raise AnalysisUnavailable("fake test data is not installed yet")
    return SamplesResponse(**make())

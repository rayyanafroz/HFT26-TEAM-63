"""The risk score (SOT 7.5). Pure functions: no database, no clock.

For every finding of a tool:

    points = W_sev x confidence x M_exposure x M_sanction x count_factor

    W_sev        info 1, low 5, medium 15, high 35, critical 60
    M_exposure   how exposed the kind of tool is (cloud 1.0 ... local model 0.4)
    M_sanction   0.5 if the tool's provider is approved, else 1.0
    count_factor the Nth finding of the same rule for the same tool counts less:
                 1st 1.0, 2nd 0.5, 3rd 0.25, 4th to 10th 0.1, after that nothing

    S           = sum of the points of the tool
    tool_score  = round_half_up(100 x (1 - exp(-S / 80)))              0 to 100
    org_risk    = round_half_up(0.7 x best tool + 0.3 x mean of the top 3 tools)
    compliance  = 100 - org_risk

Points are never stored: they are computed from the findings every time, so a
change (such as approving a provider) re-scores everything.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Iterable, Protocol, Sequence

from ..models import Band, Severity, band_for_score

W_SEV: dict[Severity, int] = {
    Severity.INFO: 1, Severity.LOW: 5, Severity.MEDIUM: 15, Severity.HIGH: 35, Severity.CRITICAL: 60,
}
M_SANCTIONED = 0.5
M_UNSANCTIONED = 1.0
SCORE_SCALE = 80.0            # the "80" in the tool_score formula
MAX_COUNTED = 10              # only the first 10 findings of a rule per tool count
_ROUND_EPSILON = 1e-9         # makes an exact .5 round up even when floating point is a hair below it


def round_half_up(value: float) -> int:
    """Round to the nearest integer, halves go up (Python's ``round`` goes to the even number)."""
    return int(math.floor(value + 0.5 + _ROUND_EPSILON))


def count_factor(rank: int) -> float:
    """How much the ``rank``-th (1-based) finding of the same rule for the same tool counts."""
    if rank < 1:
        raise ValueError("rank starts at 1")
    if rank == 1:
        return 1.0
    if rank == 2:
        return 0.5
    if rank == 3:
        return 0.25
    return 0.1 if rank <= MAX_COUNTED else 0.0


def tool_score_from_s(s: float) -> int:
    """The 0-100 score for a tool whose points add up to ``s``."""
    if s <= 0:
        return 0
    return min(100, round_half_up(100 * (1 - math.exp(-s / SCORE_SCALE))))


class Scorable(Protocol):
    """What the scorer needs from a finding. ``Finding`` satisfies it."""

    id: str
    rule_id: str
    severity: Severity
    confidence: float
    created_at: str


@dataclass(frozen=True)
class ScoredFinding:
    finding_id: str
    rule_id: str
    severity: Severity
    w_sev: float
    confidence: float
    m_exposure: float
    m_sanction: float
    count_factor: float
    points: float


@dataclass(frozen=True)
class ToolScore:
    tool_id: str
    s: float                              # sum of points
    score: int                            # 0-100
    items: tuple[ScoredFinding, ...]      # highest points first

    @property
    def band(self) -> Band:
        return band_for_score(self.score)


@dataclass(frozen=True)
class OrgScore:
    max_tool_score: int
    mean_top3: float
    org_risk: int
    compliance_score: int

    @property
    def band(self) -> Band:
        return band_for_score(self.org_risk)


def score_tool(
    tool_id: str,
    findings: Iterable[Scorable],
    *,
    exposure: float,
    sanctioned: bool,
) -> ToolScore:
    """Score one tool from its findings.

    ``exposure`` is the category multiplier from the provider catalog;
    ``sanctioned`` says whether the tool's provider is approved. The caller leaves out
    findings of tools whose provider match is only a guess (SOT 7.5).
    """
    ordered = sorted(findings, key=lambda f: (f.created_at, f.id))       # oldest first, ties by id: repeatable
    m_sanction = M_SANCTIONED if sanctioned else M_UNSANCTIONED
    seen_per_rule: dict[str, int] = {}
    items: list[ScoredFinding] = []
    for finding in ordered:
        rank = seen_per_rule[finding.rule_id] = seen_per_rule.get(finding.rule_id, 0) + 1
        factor = count_factor(rank)
        w = W_SEV[finding.severity]
        points = w * finding.confidence * exposure * m_sanction * factor
        items.append(ScoredFinding(
            finding_id=finding.id, rule_id=finding.rule_id, severity=finding.severity, w_sev=float(w),
            confidence=finding.confidence, m_exposure=exposure, m_sanction=m_sanction,
            count_factor=factor, points=round(points, 6)))
    items.sort(key=lambda i: i.points, reverse=True)                      # stable: ties keep their time order
    total = round(sum(i.points for i in items), 6)
    return ToolScore(tool_id=tool_id, s=total, score=tool_score_from_s(total), items=tuple(items))


def org_score(tool_scores: Sequence[int]) -> OrgScore:
    """The organisation-wide score from the tools' 0-100 scores (0 when there are no tools)."""
    if not tool_scores:
        return OrgScore(max_tool_score=0, mean_top3=0.0, org_risk=0, compliance_score=100)
    top = sorted(tool_scores, reverse=True)
    best = top[0]
    mean_top3 = sum(top[:3]) / len(top[:3])
    risk = min(100, round_half_up(0.7 * best + 0.3 * mean_top3))
    return OrgScore(max_tool_score=best, mean_top3=round(mean_top3, 2), org_risk=risk, compliance_score=100 - risk)

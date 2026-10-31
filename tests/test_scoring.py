import itertools
from dataclasses import dataclass

import pytest

from shadowlens.core.scoring import (
    OrgScore, count_factor, org_score, round_half_up, score_tool, tool_score_from_s,
)
from shadowlens.models import Band, Severity

CLOUD, APP, HUB, LOCAL = 1.0, 1.0, 1.1, 0.4          # category exposure multipliers (SOT 7.1)
_ids = itertools.count(1)


@dataclass
class F:
    """A synthetic finding: only what the scorer reads."""
    rule_id: str
    severity: Severity
    confidence: float
    created_at: str = "2026-10-31T10:00:00.000Z"
    id: str = ""

    def __post_init__(self):
        self.id = self.id or f"f{next(_ids):04d}"


def finding(rule, severity, confidence, minute=0):
    return F(rule, Severity(severity), confidence, f"2026-10-31T10:{minute:02d}:00.000Z")


# ---- the eight cases pinned in SOT 7.5 ---------------------------------------

def test_pinned_1_one_critical_on_a_cloud_tool():
    result = score_tool("t", [finding("SEC_PRIVATE_KEY", "critical", 0.95)], exposure=CLOUD, sanctioned=False)
    assert (result.s, result.score) == (57.0, 51)


def test_pinned_2_two_criticals_of_the_same_rule():
    result = score_tool("t", [finding("SEC_PRIVATE_KEY", "critical", 0.95, 0),
                              finding("SEC_PRIVATE_KEY", "critical", 0.95, 1)], exposure=CLOUD, sanctioned=False)
    assert (result.s, result.score) == (85.5, 66)                          # 57 + 28.5


def test_pinned_3_plus_a_high_of_a_different_rule():
    result = score_tool("t", [finding("SEC_PRIVATE_KEY", "critical", 0.95, 0),
                              finding("SEC_PRIVATE_KEY", "critical", 0.95, 1),
                              finding("SEC_OPENAI_KEY", "high", 0.9, 2)], exposure=CLOUD, sanctioned=False)
    assert (result.s, result.score) == (117.0, 77)                         # 57 + 28.5 + 31.5


def test_pinned_4_a_critical_on_a_local_model():
    result = score_tool("t", [finding("SEC_PRIVATE_KEY", "critical", 0.95)], exposure=LOCAL, sanctioned=False)
    assert (result.s, result.score) == (22.8, 25)                          # 60 x 0.95 x 0.4


def test_pinned_5_aws_secret_plus_the_unapproved_tool_policy_finding():
    result = score_tool("t", [finding("SEC_AWS_SECRET_KEY", "critical", 0.9, 0),
                              finding("POLICY_UNSANCTIONED_TOOL", "low", 0.9, 1)], exposure=CLOUD, sanctioned=False)
    assert (result.s, result.score) == (58.5, 52)                          # 54.0 + 4.5


def test_pinned_6_a_low_finding_on_an_approved_local_model():
    result = score_tool("t", [finding("PII_EMAIL", "low", 0.9)], exposure=LOCAL, sanctioned=True)
    assert (result.s, result.score) == (0.9, 1)                            # 5 x 0.9 x 0.4 x 0.5


def test_pinned_7_org_score_for_tools_80_and_20():
    org = org_score([80, 20])
    assert (org.org_risk, org.compliance_score) == (71, 29)                # 0.7 x 80 + 0.3 x mean(80, 20)


def test_pinned_8_org_score_for_a_single_tool():
    assert org_score([52]).org_risk == 52


# ---- rounding ----------------------------------------------------------------

@pytest.mark.parametrize("value,expected", [
    (0, 0), (0.4, 0), (0.5, 1), (0.6, 1), (1.5, 2), (2.5, 3), (3.5, 4), (51.4999, 51), (51.5, 52),
    (0.49999999999999994, 1),                       # float noise right at .5 counts as .5
    (99.5, 100), (100, 100),
])
def test_round_half_up_always_rounds_halves_up(value, expected):
    assert round_half_up(value) == expected         # Python's round(2.5) would give 2


# ---- the count factor ----------------------------------------------------------

@pytest.mark.parametrize("rank,factor", [(1, 1.0), (2, 0.5), (3, 0.25), (4, 0.1), (7, 0.1), (10, 0.1), (11, 0.0), (50, 0.0)])
def test_count_factor(rank, factor):
    assert count_factor(rank) == factor


def test_count_factor_needs_a_positive_rank():
    with pytest.raises(ValueError):
        count_factor(0)


def test_only_the_first_ten_findings_of_a_rule_count():
    findings = [finding("SEC_PRIVATE_KEY", "critical", 1.0, minute=i) for i in range(12)]
    result = score_tool("t", findings, exposure=CLOUD, sanctioned=False)
    assert result.s == pytest.approx(60 * (1 + 0.5 + 0.25 + 7 * 0.1))      # 147.0
    assert [i.count_factor for i in result.items][-2:] == [0.0, 0.0]       # the 11th and 12th add nothing


def test_the_count_factor_is_per_rule_and_follows_time_not_input_order():
    late_first = finding("SEC_JWT", "high", 1.0, minute=30)
    early = finding("SEC_JWT", "high", 1.0, minute=5)
    other_rule = finding("SEC_OPENAI_KEY", "high", 1.0, minute=40)
    result = score_tool("t", [late_first, early, other_rule], exposure=CLOUD, sanctioned=False)
    factors = {i.finding_id: i.count_factor for i in result.items}
    assert factors[early.id] == 1.0 and factors[late_first.id] == 0.5       # the older one is "first"
    assert factors[other_rule.id] == 1.0                                    # a different rule starts again


def test_equal_timestamps_are_ordered_repeatably():
    a, b = F("SEC_JWT", Severity.HIGH, 1.0, id="aaa"), F("SEC_JWT", Severity.HIGH, 1.0, id="bbb")
    first = score_tool("t", [a, b], exposure=CLOUD, sanctioned=False)
    second = score_tool("t", [b, a], exposure=CLOUD, sanctioned=False)
    assert [(i.finding_id, i.count_factor) for i in first.items] == [(i.finding_id, i.count_factor) for i in second.items]


# ---- items and the multipliers ---------------------------------------------------

def test_items_are_sorted_by_points_and_show_every_factor():
    result = score_tool("t", [finding("PII_EMAIL", "low", 0.9, 0), finding("SEC_PRIVATE_KEY", "critical", 0.9, 1)],
                        exposure=HUB, sanctioned=True)
    top, bottom = result.items
    assert top.rule_id == "SEC_PRIVATE_KEY" and top.points > bottom.points
    assert (top.w_sev, top.confidence, top.m_exposure, top.m_sanction, top.count_factor) == (60.0, 0.9, 1.1, 0.5, 1.0)
    assert top.points == pytest.approx(60 * 0.9 * 1.1 * 0.5)
    assert result.s == pytest.approx(top.points + bottom.points)


def test_approving_a_provider_halves_the_points():
    findings = [finding("SEC_PRIVATE_KEY", "critical", 0.9)]
    unapproved = score_tool("t", findings, exposure=CLOUD, sanctioned=False)
    approved = score_tool("t", findings, exposure=CLOUD, sanctioned=True)
    assert approved.s == pytest.approx(unapproved.s / 2) and approved.score < unapproved.score


@pytest.mark.parametrize("severity,weight", [("info", 1), ("low", 5), ("medium", 15), ("high", 35), ("critical", 60)])
def test_severity_weights(severity, weight):
    assert score_tool("t", [finding("SEC_JWT", severity, 1.0)], exposure=1.0, sanctioned=False).s == weight


def test_no_findings_scores_zero():
    result = score_tool("t", [], exposure=CLOUD, sanctioned=False)
    assert (result.s, result.score, result.items, result.band) == (0, 0, (), Band.LOW)


def test_the_tool_score_stays_between_0_and_100_and_never_drops_when_points_are_added():
    scores = [tool_score_from_s(s) for s in (-5, 0, 0.001, 1, 10, 50, 100, 500, 5000, 1e9)]
    assert scores[0] == scores[1] == 0 and scores[-1] == 100
    assert scores == sorted(scores) and all(0 <= s <= 100 for s in scores)


def test_adding_a_finding_never_lowers_the_score():
    findings, previous = [], 0
    for i in range(15):
        findings.append(finding("SEC_JWT" if i % 2 else "PII_EMAIL", "high" if i % 3 else "low", 0.8, minute=i))
        score = score_tool("t", findings, exposure=CLOUD, sanctioned=False).score
        assert score >= previous
        previous = score


@pytest.mark.parametrize("score,band", [(0, Band.LOW), (24, Band.LOW), (25, Band.MODERATE), (49, Band.MODERATE),
                                        (50, Band.HIGH), (74, Band.HIGH), (75, Band.CRITICAL), (100, Band.CRITICAL)])
def test_the_bands_follow_the_score(score, band):
    assert OrgScore(0, 0.0, score, 100 - score).band is band


def test_an_empty_tool_is_in_the_low_band():
    assert score_tool("t", [], exposure=1, sanctioned=False).band is Band.LOW


# ---- the organisation score ----------------------------------------------------

def test_org_score_with_no_tools_is_zero_risk():
    assert org_score([]) == OrgScore(max_tool_score=0, mean_top3=0.0, org_risk=0, compliance_score=100)


def test_org_score_uses_only_the_top_three_for_the_mean():
    org = org_score([90, 60, 30, 10, 0])
    assert org.mean_top3 == 60.0 and org.max_tool_score == 90
    assert org.org_risk == round_half_up(0.7 * 90 + 0.3 * 60)               # 63 + 18 = 81


def test_org_score_ignores_input_order():
    assert org_score([10, 90, 30, 60]) == org_score([90, 60, 30, 10])


@pytest.mark.parametrize("scores,risk", [
    ([100, 100, 100], 100), ([100], 100), ([0], 0), ([0, 0, 0], 0), ([50, 50], 50),
    ([80, 20, 0], 66),                      # a zero-score tool still counts in the mean: 56 + 0.3 x 33.3
    ([1], 1), ([25, 24], 25),
])
def test_org_score_examples(scores, risk):
    org = org_score(scores)
    assert org.org_risk == risk and org.compliance_score == 100 - risk and 0 <= org.org_risk <= 100


def test_org_score_never_exceeds_100_and_compliance_is_its_complement():
    for scores in ([100, 100], [99, 100, 100, 100], list(range(0, 101, 5))):
        org = org_score(scores)
        assert 0 <= org.org_risk <= 100 and org.org_risk + org.compliance_score == 100


def test_one_very_bad_tool_dominates_the_org_score():
    # 95 + two small ones: 0.7 x 95 + 0.3 x 35
    assert org_score([95, 5, 5]).org_risk == round_half_up(0.7 * 95 + 0.3 * 35)
    assert org_score([95, 5, 5]).org_risk > org_score([30, 30, 30]).org_risk

"""Detection over plain text: secrets, personal data and code (SOT 7.3)."""

from __future__ import annotations

from dataclasses import dataclass

from shadowlens.analysis.catalog import Candidate, TextFinding
from shadowlens.analysis.code import find_code
from shadowlens.analysis.masking import hash12, mask_for
from shadowlens.analysis.pii import GROUPED_RULES, find_pii
from shadowlens.analysis.redact import drop_already_redacted, fill_contexts, redact_text, resolve_overlaps
from shadowlens.analysis.secrets import find_generic_assignments, find_high_entropy, find_named_secrets
from shadowlens.analysis.settings import AnalysisSettings


@dataclass
class TextResult:
    findings: list[TextFinding]
    redacted_text: str


def _build_findings(candidates: list[Candidate], salt: bytes) -> list[TextFinding]:
    """One finding per distinct value; email and phone collapse into one per text."""
    findings: list[TextFinding] = []
    by_key: dict[tuple[str, str], TextFinding] = {}
    grouped: dict[str, TextFinding] = {}
    for candidate in candidates:
        digest = hash12(candidate.value, salt)
        span = (candidate.start, candidate.end)
        existing = grouped.get(candidate.rule_id) or by_key.get((candidate.rule_id, digest))
        if existing is not None:
            existing.spans.append(span)
            if existing.count is not None:
                existing.count += 1
            continue
        finding = TextFinding(
            rule_id=candidate.rule_id,
            masked_preview=mask_for(candidate.rule_id, candidate.value),
            hash12=digest,
            spans=[span],
            count=1 if candidate.rule_id in GROUPED_RULES else None,
        )
        findings.append(finding)
        by_key[(candidate.rule_id, digest)] = finding
        if candidate.rule_id in GROUPED_RULES:
            grouped[candidate.rule_id] = finding
    return findings


def analyze_text(text: str | None, settings: AnalysisSettings) -> TextResult:
    """All findings in ``text`` plus the redacted text. Also used by the Leak Lab and the egress guard."""
    if not text or not isinstance(text, str):
        return TextResult(findings=[], redacted_text=text if isinstance(text, str) else "")

    # Order matters inside a priority: an earlier detector wins a tie.
    span_candidates = find_named_secrets(text) + find_pii(text) + find_generic_assignments(text)
    entropy_hits = find_high_entropy(text, settings)
    scores = {id(candidate): score for score, candidate in entropy_hits}
    resolved = resolve_overlaps(drop_already_redacted(text, span_candidates + [c for _, c in entropy_hits]))

    # The entropy cap applies only to what survived the stronger detectors.
    surviving = [c for c in resolved if id(c) in scores]
    surviving.sort(key=lambda c: scores[id(c)], reverse=True)
    allowed = {id(c) for c in surviving[:settings.max_entropy_findings_per_event]}
    truncated = len(surviving) > len(allowed)
    resolved = [c for c in resolved if id(c) not in scores or id(c) in allowed]

    # Code findings sit on top: they may contain other findings and never suppress them.
    code = drop_already_redacted(text, find_code(text, settings.internal_markers))
    findings = _build_findings(sorted(resolved + code, key=lambda c: (c.start, c.end)), settings.salt)
    if truncated:
        for finding in findings:
            if finding.rule_id == "SEC_HIGH_ENTROPY":
                finding.truncated = True

    fill_contexts(text, findings)
    return TextResult(findings=findings, redacted_text=redact_text(text, findings))

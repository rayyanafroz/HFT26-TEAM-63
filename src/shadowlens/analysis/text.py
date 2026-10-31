"""Detection over plain text: secrets, personal data and code (SOT 7.3).

Each detector runs on its own, so one that fails costs only its own rules. ``failed`` says which
did, and anything that decides whether text is safe to send must treat a failure as unsafe.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field, replace
from typing import Callable, TypeVar

from shadowlens.analysis.catalog import Candidate, TextFinding
from shadowlens.analysis.code import find_code
from shadowlens.analysis.encoded import find_encoded_secrets, find_split_secrets
from shadowlens.analysis.normalize import fold, to_original
from shadowlens.analysis.masking import hash12, mask_for
from shadowlens.analysis.pii import GROUPED_RULES, find_pii
from shadowlens.analysis.redact import drop_already_redacted, fill_contexts, redact_text, resolve_overlaps
from shadowlens.analysis.secrets import find_generic_assignments, find_high_entropy, find_named_secrets
from shadowlens.analysis.settings import AnalysisSettings

log = logging.getLogger("shadowlens.analysis")

T = TypeVar("T")

# Shown in place of the text if redaction itself fails, because the raw text must never come back.
REDACTION_FAILED = "[text withheld: redaction failed]"


@dataclass
class TextResult:
    findings: list[TextFinding]
    redacted_text: str
    failed: list[str] = field(default_factory=list)  # names of detectors that could not run


def clean_text(text: str) -> str:
    """Lone surrogates, which JSON can carry ("\\ud83d") and neither pydantic nor SQLite will accept.
    Each becomes one "?", so positions in the text do not move."""
    try:
        text.encode("utf-8")
        return text
    except UnicodeEncodeError:
        return text.encode("utf-8", "replace").decode("utf-8")


def _guarded(name: str, run: Callable[[], list[T]], failed: list[str]) -> list[T]:
    try:
        return run()
    except Exception as exc:  # noqa: BLE001 - one broken detector must not silence the others
        log.warning("detector %s failed (%s)", name, type(exc).__name__)  # the type only, never the text
        failed.append(name)
        return []


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


def _to_original(candidates: list[Candidate], starts: list[int] | None, ends: list[int] | None) -> list[Candidate]:
    """Matches found in the folded view, as matches over the text that was actually typed."""
    if starts is None:
        return candidates
    out = []
    for candidate in candidates:
        start, end = to_original(candidate.start, candidate.end, starts, ends)
        out.append(replace(candidate, start=start, end=end))
    return out


def analyze_text(text: str | None, settings: AnalysisSettings) -> TextResult:
    """All findings in ``text`` plus the redacted text. Also used by the Leak Lab and the egress guard.

    Detection runs on a folded view of the text (look-alike letters, zero-width characters, ``\\uXXXX``,
    ``%XX`` and ``&#NN;`` written out), then every match is moved back onto the original text, which is the
    only text that is redacted or shown.
    """
    if not text or not isinstance(text, str):
        return TextResult(findings=[], redacted_text=text if isinstance(text, str) else "")
    text = clean_text(text)
    failed: list[str] = []
    view, starts, ends = fold(text)

    # Order matters inside a priority: an earlier detector wins a tie.
    span_candidates = (
        _guarded("named_secrets", lambda: find_named_secrets(view), failed)
        + _guarded("pii", lambda: find_pii(view, settings), failed)
        + _guarded("generic_assignments", lambda: find_generic_assignments(view, settings), failed)
        + _guarded("split_secrets", lambda: find_split_secrets(view), failed)
        + _guarded("encoded_secrets", lambda: find_encoded_secrets(view, settings), failed)
    )
    entropy_hits = _guarded("high_entropy", lambda: find_high_entropy(view, settings), failed)
    scores = {id(candidate): score for score, candidate in entropy_hits}
    resolved = resolve_overlaps(drop_already_redacted(view, span_candidates + [c for _, c in entropy_hits]))

    # The entropy cap applies only to what survived the stronger detectors.
    surviving = [c for c in resolved if id(c) in scores]
    surviving.sort(key=lambda c: scores[id(c)], reverse=True)
    allowed = {id(c) for c in surviving[:settings.max_entropy_findings_per_event]}
    truncated = len(surviving) > len(allowed)
    # Redaction still covers tokens over the cap: the cap limits findings, not what gets hidden.
    kept = [c for c in resolved if id(c) not in scores or id(c) in allowed]
    capped = [c for c in resolved if id(c) in scores and id(c) not in allowed]

    # Code findings sit on top: they may contain other findings and never suppress them.
    code = _guarded("code", lambda: drop_already_redacted(view, find_code(view, settings)), failed)
    kept, code, capped = (_to_original(group, starts, ends) for group in (kept, code, capped))
    findings = _build_findings(sorted(kept + code, key=lambda c: (c.start, c.end)), settings.salt)
    if truncated:
        for finding in findings:
            if finding.rule_id == "SEC_HIGH_ENTROPY":
                finding.truncated = True

    try:
        fill_contexts(text, findings)
        over_cap = _build_findings(capped, settings.salt)
        redacted = redact_text(text, findings + over_cap)
    except Exception as exc:  # noqa: BLE001 - never hand back text that was not redacted
        log.warning("redaction failed (%s)", type(exc).__name__)
        failed.append("redaction")
        for finding in findings:
            finding.context = ""
        redacted = REDACTION_FAILED
    return TextResult(findings=findings, redacted_text=redacted, failed=failed)

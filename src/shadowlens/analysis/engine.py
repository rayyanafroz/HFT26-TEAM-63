"""``analyze``: everything the analysis says about one event (SOT 7.3, 7.4).

The pipeline calls ``analyze(event, config, ctx)``. Body, headers and query are only read
here; what comes out holds masks, hashes and redacted text. Apart from loading the salt
once (``settings_for``) there is no disk, no network and no logging of matches.

A finding can come out more than once across events (agents resend whole conversations).
That is fine: the database keeps one per (tool, rule, hash12), which is the single place that
decides. Agent calls are the exception, remembered in ``ctx`` so their activity is not repeated.

Each part of an event is analyzed on its own, so a failure in one (say, the agent rules on a
strange body) still leaves the findings from the others. See ``docs/DETECTORS.md``.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field, replace
from typing import Any, Callable, Iterable
from urllib.parse import unquote

from shadowlens.analysis.agent import (
    AgentHit,
    all_strings,
    evaluate_calls,
    evaluate_declarations,
    parse_agent_body,
)
from shadowlens.analysis.catalog import RULES, TextFinding
from shadowlens.analysis.masking import hash12, mask_for
from shadowlens.analysis.redact import fill_contexts, redact_text, resolve_overlaps
from shadowlens.analysis.secrets import find_named_secrets
from shadowlens.analysis.settings import AnalysisSettings, settings_for
from shadowlens.analysis.text import TextResult, analyze_text, clean_text
from shadowlens.core.ctx import AgentSessionContext
from shadowlens.core.rule_titles import title_for
from shadowlens.models import (
    ActivityKind,
    AgentActivity,
    CapabilityName,
    Finding,
    FindingMeta,
    Location,
    LocationField,
    NetEvent,
    Severity,
    Visibility,
    category_for_rule,
    new_id,
)

log = logging.getLogger("shadowlens.analysis")

_ARGUMENT_MAX = 200
_PREVIEW_ARGUMENT_MAX = 80
_MAX_JSON_DEPTH = 40

# Binary blobs inside AI requests: base64, and noise for the entropy rule.
_BINARY_BLOCK_TYPES = frozenset({"image", "image_url", "input_image", "document"})
# Skipped when flattening: the SOT excludes the model name from the entropy rule.
_SKIPPED_KEYS = frozenset({"model"})
_JSON_ESCAPES = (("\\n", "\n"), ("\\r", "\r"), ("\\t", "\t"), ('\\"', '"'), ("\\/", "/"), ("\\\\", "\\"))
_PLAIN_FIELD_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_\-]{0,31}$")
_PERCENT_ESCAPE_RE = re.compile(r"%[0-9A-Fa-f]{2}")

_AUTH_HEADERS = {
    "authorization": LocationField.HEADER_AUTHORIZATION,
    "x-api-key": LocationField.HEADER_X_API_KEY,
    "x-goog-api-key": LocationField.HEADER_X_API_KEY,
}
_AUTH_SCHEMES = ("bearer ", "basic ", "token ")


class DetectorFailure(RuntimeError):
    """A safety decision could not be made, because a detector did not run."""


@dataclass
class AnalysisResult:
    """The shape the pipeline reads (SOT 7.3). ``failed`` names the parts that could not run."""

    findings: list[Finding] = field(default_factory=list)
    agent_activity: list[AgentActivity] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)


# ---- reading a body ------------------------------------------------------------

def _flatten(value: Any, lines: list[str], key: str = "", depth: int = 0) -> None:
    if depth > _MAX_JSON_DEPTH:
        # Deeper than anything real. Scan what is there as one piece, rather than not at all.
        lines.append(json.dumps(value, ensure_ascii=False))
        return
    if isinstance(value, dict):
        if value.get("type") in _BINARY_BLOCK_TYPES:
            return
        for name, item in value.items():
            field_name = str(name)
            if not _PLAIN_FIELD_NAME_RE.match(field_name):
                lines.append(field_name)  # a field name can be the leak too
            if field_name not in _SKIPPED_KEYS or not isinstance(item, str):
                _flatten(item, lines, field_name, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _flatten(item, lines, key, depth + 1)
    elif isinstance(value, str):
        stripped = value.strip()
        if stripped[:1] in ("{", "["):  # OpenAI tool arguments are JSON inside a string
            try:
                _flatten(json.loads(stripped), lines, key, depth + 1)
                return
            except (ValueError, RecursionError):
                pass
        lines.append(f"{key}: {value}" if key else value)
    elif isinstance(value, int) and not isinstance(value, bool):
        lines.append(f"{key}: {value}" if key else str(value))


def _percent_decoded(text: str) -> str:
    """Form bodies and query strings: password%3Dabc reads as password=abc."""
    return unquote(text) if _PERCENT_ESCAPE_RE.search(text) else text


def body_scan_text(body: str) -> str:
    """The text to scan: a JSON body with its strings decoded, labelled by their key.

    Raw JSON hides matches: a newline inside a prompt is the two characters ``\\n``, so
    ``\\b`` fails in front of a key on a new line, and ``\\"`` breaks assignment patterns.
    """
    if body.lstrip()[:1] not in ("{", "["):
        return _percent_decoded(body)
    try:
        decoded = json.loads(body)
        lines: list[str] = []
        _flatten(decoded, lines)
        return "\n".join(lines)
    except (ValueError, RecursionError):
        # Most likely cut off at MAX_BODY_BYTES: undo the escapes and scan what is there.
        for escaped, plain in _JSON_ESCAPES:
            body = body.replace(escaped, plain)
        return body


# ---- paths and headers ----------------------------------------------------------

def _scan_path(path: str, settings: AnalysisSettings) -> TextResult:
    """Slashes count as spaces (same length, so spans still fit): to the entropy rule, a long
    ordinary path would otherwise look like one random-looking token."""
    path = clean_text(path)
    scanned = analyze_text(path.replace("/", " "), settings)
    return TextResult(findings=scanned.findings, redacted_text=redact_text(path, scanned.findings),
                      failed=scanned.failed)


def redact_path(path: str, cfg: Any) -> str:
    """The path as it may be stored and shown: it is kept for every event, and can hold a secret.

    Raises ``DetectorFailure`` if a detector did not run, because the path is then unchecked.
    """
    result = _scan_path(path, settings_for(cfg))
    if result.failed:
        raise DetectorFailure("path check incomplete")
    return result.redacted_text


def _scan_auth_header(value: str, native_key_rules: Iterable[str], settings: AnalysisSettings) -> list[TextFinding]:
    """Named patterns only, never entropy (SOT 7.1)."""
    credential = clean_text(value).strip()
    for scheme in _AUTH_SCHEMES:
        if credential.lower().startswith(scheme):
            credential = credential[len(scheme):].strip()
            break
    native = set(native_key_rules)
    findings = []
    for candidate in resolve_overlaps(find_named_secrets(credential)):
        if candidate.rule_id not in native:
            findings.append(TextFinding(
                rule_id=candidate.rule_id,
                masked_preview=mask_for(candidate.rule_id, candidate.value),
                hash12=hash12(candidate.value, settings.salt),
                spans=[(candidate.start, candidate.end)],
            ))
    fill_contexts(credential, findings)
    return findings


# ---- building the output --------------------------------------------------------

class _Collector:
    """Findings for one event. One value seen in several places is reported at the first."""

    def __init__(self, event: NetEvent, tool_id: str):
        self.event = event
        self.tool_id = tool_id
        self.seen: set[tuple[str, str]] = set()
        self.findings: list[Finding] = []

    def _is_new(self, rule_id: str, digest: str) -> bool:
        key = (rule_id, digest)
        if key in self.seen:
            return False
        self.seen.add(key)
        return True

    def _add(self, rule_id: str, severity: str, preview: str, location: Location, meta: FindingMeta) -> Finding:
        finding = Finding(
            id=new_id(),
            event_id=self.event.id,
            tool_id=self.tool_id,
            rule_id=rule_id,
            category=category_for_rule(rule_id),
            severity=Severity(severity),
            confidence=RULES[rule_id].confidence,
            masked_preview=preview,
            location=location,
            owasp=list(RULES[rule_id].owasp),
            meta=meta,
            created_at=self.event.ts,
        )
        self.findings.append(finding)
        return finding

    def text(self, found: Iterable[TextFinding], field_: LocationField, in_tool_args: bool = False,
             tool_name: str | None = None) -> None:
        for item in found:
            if self._is_new(item.rule_id, item.hash12):
                self._add(
                    item.rule_id, item.severity, item.masked_preview,
                    Location(field=field_, offset=item.spans[0][0] if item.spans else None),
                    FindingMeta(hash12=item.hash12, spans=item.spans, context=item.context,
                                in_tool_args=in_tool_args, count=item.count, tool_name=tool_name),
                )

    def agent(self, hit: AgentHit, argument: str | None) -> Finding | None:
        if not self._is_new(hit.rule_id, hit.hash12):
            return None
        preview = f"{hit.tool_name}: {argument[:_PREVIEW_ARGUMENT_MAX]}" if argument else hit.tool_name
        return self._add(
            hit.rule_id, hit.severity, preview, Location(field=LocationField(hit.field)),
            FindingMeta(hash12=hit.hash12, tool_name=hit.tool_name, argument=argument),
        )


def _redacted_argument(argument: str | None, settings: AnalysisSettings) -> str | None:
    if argument is None:
        return None
    return analyze_text(argument, settings).redacted_text[:_ARGUMENT_MAX]


def _safe_name(name: str, settings: AnalysisSettings) -> str:
    """A tool's name comes from the request like everything else, so it can hold a secret too."""
    return analyze_text(name, settings).redacted_text


def _analyze_agent(event: NetEvent, collector: _Collector, session: AgentSessionContext,
                   settings: AnalysisSettings) -> list[AgentActivity]:
    parsed = parse_agent_body(event.body_text)
    if parsed is None:
        return []

    activity: list[AgentActivity] = []

    # Secrets and personal data inside tool traffic are reported as such.
    for name, description in parsed.declared:
        found = analyze_text(f"{name}\n{description}", settings).findings
        collector.text(found, LocationField.TOOL_DECLARATION, True, _safe_name(name, settings))
    for call in parsed.calls + parsed.mcp_calls:
        text = "\n".join([call.name, *all_strings(call.args)])
        collector.text(analyze_text(text, settings).findings, LocationField.TOOL_CALL, True,
                       _safe_name(call.name, settings))
    for result in parsed.results:
        collector.text(analyze_text(result, settings).findings, LocationField.TOOL_RESULT, True)

    hits, grants = evaluate_declarations(parsed, session, settings)
    for hit in hits:
        collector.agent(replace(hit, tool_name=_safe_name(hit.tool_name, settings)),
                        _redacted_argument(hit.argument, settings))
    for capability, name in grants:
        activity.append(AgentActivity(ts=event.ts, capability=CapabilityName(capability),
                                      kind=ActivityKind.GRANTED, name=_safe_name(name, settings)))

    for outcome in evaluate_calls(parsed, session, settings):
        argument = _redacted_argument(outcome.argument, settings)
        name = _safe_name(outcome.call.name, settings)
        created = {hit.rule_id: collector.agent(replace(hit, tool_name=name), argument) for hit in outcome.hits}
        risky = outcome.risky_hit
        linked_hit = risky or (outcome.hits[0] if outcome.hits else None)
        linked = created.get(linked_hit.rule_id) if linked_hit else None
        for capability in sorted(outcome.capabilities):
            activity.append(AgentActivity(
                ts=event.ts, capability=CapabilityName(capability), kind=ActivityKind.USED,
                risky=risky is not None, name=name,
                rule_id=linked_hit.rule_id if linked_hit else None,
                finding_id=linked.id if linked else None, argument=argument,
            ))
    return activity


def _stage(name: str, run: Callable[[], Any], failed: list[str]) -> Any:
    """One part of an event. A failure here costs only this part's findings."""
    try:
        return run()
    except Exception as exc:  # noqa: BLE001 - the rest of the event must still be analyzed
        log.warning("analysis of the %s failed (%s)", name, type(exc).__name__)  # the type only, never the text
        failed.append(name)
        return None


# ---- entry points ----------------------------------------------------------------

def analyze(event: NetEvent, cfg: Any, ctx: AgentSessionContext,
            native_key_rules: Iterable[str] = ()) -> AnalysisResult:
    """Findings and agent activity for one event. Detectors run only when visibility is ``full``.

    ``cfg`` is the app's ``Config`` (or ready ``AnalysisSettings``). The pipeline filters a
    provider's own keys using its catalog; ``native_key_rules`` is for calling this without one.
    """
    result = AnalysisResult()
    if event.visibility != Visibility.FULL:
        return result

    settings = settings_for(cfg)
    collector = _Collector(event, ctx.tool_id)
    failed = result.failed

    def text_stage(name: str, scan: Callable[[], TextResult], field_: LocationField) -> None:
        def run() -> None:
            scanned = scan()
            failed.extend(scanned.failed)
            collector.text(scanned.findings, field_)
        _stage(name, run, failed)

    # Tool traffic first, so a key in a tool call is reported there and not just as "body".
    result.agent_activity = _stage(
        "agent rules", lambda: _analyze_agent(event, collector, ctx, settings), failed) or []

    for name, field_ in _AUTH_HEADERS.items():
        value = event.headers.get(name)
        if value:
            _stage(f"{name} header",
                   lambda value=value, field_=field_: collector.text(
                       _scan_auth_header(value, native_key_rules, settings), field_),
                   failed)

    if event.path:
        text_stage("path", lambda: _scan_path(event.path, settings), LocationField.PATH)
    if event.query:
        text_stage("query", lambda: analyze_text(_percent_decoded(event.query), settings), LocationField.PATH)
    text_stage("body", lambda: analyze_text(body_scan_text(event.body_text or ""), settings), LocationField.BODY)

    result.findings = collector.findings
    return result


def is_safe_to_send(text: str, cfg: Any) -> bool:
    """The egress guard (SOT 7.7): may this text leave the machine?

    Fails closed. If anything goes wrong, or any detector did not run, the answer is no.
    """
    try:
        scanned = analyze_text(text, settings_for(cfg))
        return not scanned.findings and not scanned.failed
    except Exception as exc:  # noqa: BLE001 - an unchecked prompt is not a safe prompt
        log.warning("egress check failed (%s)", type(exc).__name__)
        return False


def preview(text: str, mode: str, cfg: Any) -> dict[str, Any]:
    """The analysis part of ``POST /api/analyze/preview`` (SOT 6.7). Nothing is stored or remembered.

    One row per match, so the UI can highlight each. Agent findings have no position in the
    text, so their span is ``[0, 0]``. ``redacted_text`` is what the model would receive, and
    ``would_block`` also covers a check that could not run.
    """
    settings = settings_for(cfg)
    scanned = analyze_text(text, settings)
    rows = [
        {
            "rule_id": item.rule_id, "category": item.category, "severity": item.severity, "title": item.title,
            "masked_preview": item.masked_preview, "confidence": item.confidence, "span": list(span),
        }
        for item in scanned.findings for span in item.spans
    ]
    if mode == "agent_json":
        session = AgentSessionContext(tool_id="preview")
        parsed = parse_agent_body(text)
        if parsed is not None:
            hits, _ = evaluate_declarations(parsed, session, settings)
            hits += [hit for outcome in evaluate_calls(parsed, session, settings) for hit in outcome.hits]
            for hit in hits:
                argument = _redacted_argument(hit.argument, settings)
                tool_name = _safe_name(hit.tool_name, settings)
                rows.append({
                    "rule_id": hit.rule_id, "category": "agent", "severity": hit.severity,
                    "title": title_for(hit.rule_id),
                    "masked_preview": f"{tool_name}: {argument[:_PREVIEW_ARGUMENT_MAX]}" if argument else tool_name,
                    "confidence": RULES[hit.rule_id].confidence, "span": [0, 0],
                })
    return {
        "findings": rows,
        "redacted_text": scanned.redacted_text,
        "would_block": not is_safe_to_send(scanned.redacted_text, settings) or bool(scanned.failed),
    }

"""The ingest pipeline: events in, stored events, findings and alerts out (SOT 4.2, 7.5).

For every event:

  1. ``classify`` it. Not AI traffic is counted (``dropped_non_ai``) and dropped.
  2. Store its metadata (never the body, headers or query string, and with any secret in
     the path redacted).
  3. A match we are only guessing at (confidence ``low``) stops here: it is shown as
     "unconfirmed" but creates no findings, alerts or score.
  4. If the event has a readable body, run the analyzer (``analyze``: Saleha's module,
     injected so tests can use a stub).
  5. Add the pipeline's own policy findings (unapproved tool, local model).
  6. Store the findings, one alert for each that matters, and the agent activity.
  7. Tell the live stream (after the database has committed, never before).

Events are handled one at a time, each in its own transaction, so a problem with one
event never loses the others.
"""

from __future__ import annotations

import hashlib
import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterable, Mapping

from pydantic import BaseModel

from ..analysis.engine import redact_path
from ..config import Config
from ..db import DROPPED_NON_AI, Database
from ..ingest.http_log import ParseResult
from ..models import (
    AgentActivity,
    Alert,
    Category,
    EventLite,
    Finding,
    FindingCategory,
    FindingMeta,
    IngestSummary,
    Location,
    LocationField,
    MatchConfidence,
    NetEvent,
    ProviderMatch,
    Severity,
    Visibility,
    new_id,
    utc_now_iso,
)
from ..providers.catalog import Catalog
from ..providers.classify import classify
from ..providers.resolver import Resolver
from .ctx import AgentContexts, AgentSessionContext
from .rule_titles import title_for
from .sanction import effective_sanctioned

log = logging.getLogger("shadowlens.pipeline")

Publish = Callable[[str, "BaseModel | dict[str, Any]"], None]

MAX_ERRORS = 20
REPEAT_ALERT_GAP_S = 5.0                     # the same leak sent again within this long is one occurrence
ALERT_MIN_SEVERITY = Severity.MEDIUM          # SOT 7.5: one alert per finding of at least medium
POLICY_UNSANCTIONED = "POLICY_UNSANCTIONED_TOOL"
POLICY_LOCAL = "POLICY_LOCAL_LLM"
PATH_HIDDEN = "[path hidden]"

# A credential in these headers is normal use when it is the provider's own kind of key (SOT 7.1).
_CREDENTIAL_HEADERS = {LocationField.HEADER_AUTHORIZATION, LocationField.HEADER_X_API_KEY}


@dataclass
class AnalysisResult:
    """What an analyzer returns. A plain dict with the same two keys is accepted too."""

    findings: list[Finding] = field(default_factory=list)
    agent_activity: list[AgentActivity] = field(default_factory=list)


AnalyzeFn = Callable[[NetEvent, Config, AgentSessionContext], Any]


def no_analysis(event: NetEvent, config: Config, ctx: AgentSessionContext) -> AnalysisResult:
    """Used until the real analyzer is available: finds nothing."""
    return AnalysisResult()


def _as_result(raw: Any) -> AnalysisResult:
    if raw is None:
        return AnalysisResult()
    if isinstance(raw, Mapping):
        findings, activity = raw.get("findings", []), raw.get("agent_activity", [])
    else:
        findings, activity = getattr(raw, "findings", []), getattr(raw, "agent_activity", [])
    return AnalysisResult(list(findings or []), list(activity or []))


class _Batch:
    """Counters and context for one ``ingest`` call."""

    def __init__(self, source: str, skipped: int, errors: Iterable[str]):
        self.source = source
        self.accepted = 0
        self.skipped = skipped
        self.dropped = 0
        self.findings = 0
        self.alerts = 0
        self.errors = list(errors)[:MAX_ERRORS]
        self.sanction_overrides: dict[str, bool] = {}

    def error(self, message: str) -> None:
        if len(self.errors) < MAX_ERRORS:
            self.errors.append(message)

    def summary(self) -> IngestSummary:
        return IngestSummary(source=self.source, accepted=self.accepted, skipped=self.skipped,
                             dropped_non_ai=self.dropped, findings=self.findings, alerts=self.alerts,
                             errors=self.errors)


class Pipeline:
    def __init__(
        self,
        config: Config,
        db: Database,
        catalog: Catalog,
        *,
        resolver: Resolver | None = None,
        contexts: AgentContexts | None = None,
        analyze: AnalyzeFn | None = None,
        publish: Publish | None = None,
        after_batch: Callable[[], None] | None = None,
    ):
        self.config = config
        self.db = db
        self.catalog = catalog
        self.resolver = resolver
        self.contexts = contexts or AgentContexts()
        self._analyze = analyze or no_analysis
        self._publish = publish
        self._after_batch = after_batch
        self._lock = threading.RLock()

    # ---- public API ------------------------------------------------------

    def is_sanctioned(self, provider_id: str, overrides: Mapping[str, bool] | None = None) -> bool:
        """Approved? A manual choice (``PUT /api/providers/{id}/sanction``) beats the default list."""
        if overrides is None:
            overrides = self.db.get_provider_overrides()
        return effective_sanctioned(self.config, overrides, provider_id)

    def ingest_log(self, result: ParseResult) -> IngestSummary:
        """Ingest a parsed upload (JSONL or HAR)."""
        return self.ingest(result.events, source=result.source, skipped=result.skipped, errors=result.errors)

    def ingest(
        self,
        events: Iterable[NetEvent],
        *,
        source: str,
        skipped: int = 0,
        errors: Iterable[str] = (),
    ) -> IngestSummary:
        with self._lock:
            batch = _Batch(source, skipped, errors)
            batch.sanction_overrides = self.db.get_provider_overrides()
            for event in events:
                try:
                    self._process(event, batch)
                except Exception as exc:  # noqa: BLE001 - one bad event must not lose the rest
                    log.warning("could not store an event (%s)", type(exc).__name__)
                    batch.skipped += 1
                    batch.error("an event could not be stored")
            if self._after_batch is not None:
                try:
                    self._after_batch()
                except Exception:  # noqa: BLE001
                    log.exception("after-batch hook failed")
            return batch.summary()

    def reset(self) -> None:
        """Clear all results and agent memory (the Reset button)."""
        with self._lock:
            self.db.reset()
            self.contexts.reset()
            self._emit("reset", {})

    # ---- one event -------------------------------------------------------

    def _process(self, event: NetEvent, batch: _Batch) -> None:
        match = classify(event, self.catalog, self.resolver.ip_map if self.resolver else None)
        if match is None:
            self.db.bump_counter(DROPPED_NON_AI)
            batch.dropped += 1
            return

        messages: list[tuple[str, BaseModel | dict[str, Any]]] = []
        stored: list[Finding] = []
        alerts: list[Alert] = []
        storable = self._with_safe_path(event)                   # the analyzer still reads the original
        with self.db.transaction():
            self.db.insert_event(storable, match)
            if match.confidence is not MatchConfidence.LOW:     # guesses stay "unconfirmed"
                result = self._run_analysis(event, match, batch)
                findings = self._clean(result.findings, event, match)
                findings += self._policy_findings(event, match, batch)
                for finding in findings:
                    if not self.db.insert_finding(finding):
                        # Already known for this tool: not counted twice. The person did it again, though, so
                        # its alert comes back (policy findings are once per tool and stay quiet).
                        again = self._repeat_alert(finding)
                        if again is not None:
                            messages.append(("alert.new", again))
                        continue
                    stored.append(finding)
                    messages.append(("finding.new", finding))
                    alert = self._alert_for(finding, match)
                    if alert is not None:
                        self.db.insert_alert(alert)
                        alerts.append(alert)
                        messages.append(("alert.new", alert))
                self._store_activity(match, result.agent_activity, {f.id for f in stored})
            messages.insert(0, ("event.new", self._event_lite(storable, match, len(stored))))

        batch.accepted += 1
        batch.findings += len(stored)
        batch.alerts += len(alerts)
        for kind, payload in messages:                           # only after the commit
            self._emit(kind, payload)

    def _with_safe_path(self, event: NetEvent) -> NetEvent:
        """The event as it may be stored and published (SOT 6.10). This covers every event,
        including ones the analyzer never sees. If the check fails the path is withheld."""
        if not event.path:
            return event
        try:
            safe = redact_path(event.path, self.config)
        except Exception as exc:  # noqa: BLE001 - never store a path we could not check
            log.warning("could not check a path (%s)", type(exc).__name__)
            safe = PATH_HIDDEN
        return event if safe == event.path else event.model_copy(update={"path": safe})

    def _run_analysis(self, event: NetEvent, match: ProviderMatch, batch: _Batch) -> AnalysisResult:
        if event.visibility is not Visibility.FULL:              # nothing readable: nothing to analyse (SOT 4.3)
            return AnalysisResult()
        try:
            raw = self._analyze(event, self.config, self.contexts.get(match.tool_id))
            if getattr(raw, "failed", None):                     # partial results: keep them, but say so
                batch.error("analysis was incomplete for one event")
            return _as_result(raw)
        except Exception as exc:  # noqa: BLE001 - a broken analyzer must not stop ingest
            log.warning("analysis failed (%s)", type(exc).__name__)
            batch.error("analysis failed for one event")
            return AnalysisResult()

    # ---- findings and alerts ---------------------------------------------

    def _clean(self, raw: list[Any], event: NetEvent, match: ProviderMatch) -> list[Finding]:
        """Keep what the pipeline trusts from the analyzer, and stamp identity fields on it."""
        out: list[Finding] = []
        for item in raw:
            finding = Finding.model_validate(item) if isinstance(item, Mapping) else item
            if not isinstance(finding, Finding):
                continue
            if finding.category is FindingCategory.POLICY:       # policy findings are the pipeline's alone
                continue
            if (finding.location.field in _CREDENTIAL_HEADERS
                    and self.catalog.native_key_ok(match.provider_id, finding.rule_id)):
                continue                                         # the provider's own key in its own header
            out.append(finding.model_copy(update={"event_id": event.id, "tool_id": match.tool_id}))
        return out

    def _policy_findings(self, event: NetEvent, match: ProviderMatch, batch: _Batch) -> list[Finding]:
        confidence = 0.9 if match.confidence is MatchConfidence.HIGH else 0.6
        out: list[Finding] = []
        if not self.is_sanctioned(match.provider_id, batch.sanction_overrides):
            out.append(self._policy(event, match, POLICY_UNSANCTIONED, confidence, f"{match.display_name} (not approved)"))
        if match.category is Category.LOCAL_LLM:
            out.append(self._policy(event, match, POLICY_LOCAL, confidence, f"{match.display_name} (local model)"))
        return out

    @staticmethod
    def _policy(event: NetEvent, match: ProviderMatch, rule_id: str, confidence: float, preview: str) -> Finding:
        # hash12 is derived from the tool id, so a tool gets each policy finding exactly once.
        return Finding(
            id=new_id(), event_id=event.id, tool_id=match.tool_id, rule_id=rule_id,
            category=FindingCategory.POLICY, severity=Severity.LOW, confidence=confidence,
            masked_preview=preview, location=Location(field=LocationField.BODY, offset=None),
            meta=FindingMeta(hash12=hashlib.sha256(f"{rule_id}|{match.tool_id}".encode()).hexdigest()[:12],
                             context=f"{event.process or 'unknown'} -> {match.display_name}"),
            created_at=utc_now_iso())

    def _repeat_alert(self, finding: Finding) -> Alert | None:
        if finding.category is FindingCategory.POLICY:
            return None
        now = datetime.now(timezone.utc)
        stamp = lambda moment: moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"
        return self.db.repeat_alert(finding.tool_id, finding.rule_id, finding.meta.hash12, stamp(now),
                                    stamp(now - timedelta(seconds=REPEAT_ALERT_GAP_S)))

    @staticmethod
    def _alert_for(finding: Finding, match: ProviderMatch) -> Alert | None:
        """An alert for every finding of at least medium severity, and for each unapproved tool (SOT 7.5)."""
        unsanctioned = finding.rule_id == POLICY_UNSANCTIONED
        if not unsanctioned and finding.severity.rank < ALERT_MIN_SEVERITY.rank:
            return None
        title = f"{title_for(finding.rule_id)}: {match.display_name}" if unsanctioned else title_for(finding.rule_id)
        return Alert(id=new_id(), finding_id=finding.id, tool_id=finding.tool_id, provider_id=match.provider_id,
                     rule_id=finding.rule_id, severity=finding.severity, title=title,
                     created_at=utc_now_iso(), finding=finding)

    def _store_activity(self, match: ProviderMatch, activity: list[AgentActivity], new_finding_ids: set[str]) -> None:
        for item in activity:
            if not isinstance(item, AgentActivity):
                continue
            fid = item.finding_id
            if fid and fid not in new_finding_ids and self.db.get_finding(fid) is None:
                item = item.model_copy(update={"finding_id": None})     # its finding was a duplicate we did not store
            self.db.add_agent_activity(match.tool_id, item)

    @staticmethod
    def _event_lite(event: NetEvent, match: ProviderMatch, finding_count: int) -> EventLite:
        return EventLite(
            id=event.id, ts=event.ts, source=event.source, tool_id=match.tool_id, process=event.process,
            provider_id=match.provider_id, host=event.host, dst_ip=event.dst_ip, dst_port=event.dst_port,
            method=event.method, path=event.path, visibility=event.visibility, bytes_out=event.bytes_out,
            body_bytes=event.body_bytes, finding_count=finding_count)

    def _emit(self, kind: str, payload: "BaseModel | dict[str, Any]") -> None:
        if self._publish is None:
            return
        try:
            self._publish(kind, payload)
        except Exception:  # noqa: BLE001 - a broken listener must never break ingest
            log.exception("could not publish %s", kind)

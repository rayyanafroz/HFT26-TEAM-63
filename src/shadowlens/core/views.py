"""Everything the dashboard reads that is worked out from the stored rows (SOT 6.9, 7.5).

Tools, risk scores, the agent matrix, provider rows, the exposure graph and the summary are
never stored. They are computed here from events, findings and agent activity, so a change
(a new finding, approving a provider) shows up everywhere at once.

The result is cached and thrown away whenever the database changes, so repeated reads
(the dashboard polls) cost almost nothing.
"""

from __future__ import annotations

import threading
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from ..config import Config
from ..db import DROPPED_NON_AI, Database
from ..ingest.http_log import format_ts, parse_ts
from ..models import (
    AgentRow,
    AlertsBySeverity,
    Capabilities,
    Capability,
    Compliance,
    FindingCounts,
    FindingsByCategory,
    Graph,
    GraphEdge,
    GraphNode,
    LlmMode,
    LlmSummary,
    MatchConfidence,
    NodeKind,
    ProviderCount,
    ProviderRow,
    RiskBlock,
    SanctionSource,
    ScoreExplain,
    ScoreItem,
    ScoreOrg,
    Severity,
    Summary,
    SummaryTotals,
    TimeBucket,
    Timeseries,
    Tool,
    TopTool,
    VisibilityCounts,
    band_for_score,
)
from ..providers.catalog import Catalog
from . import compliance as compliance_map
from .sanction import effective_sanctioned
from .scoring import OrgScore, ToolScore, org_score, score_tool

_CONFIDENCE_BY_RANK = (MatchConfidence.HIGH, MatchConfidence.MEDIUM, MatchConfidence.LOW)
_CAPABILITIES = ("shell", "fs_read", "fs_write", "network", "mcp", "sensitive_file")
MAX_BUCKETS = 1000
TOP_TOOLS = 5


@dataclass(frozen=True)
class _Row:
    """A finding as the scorer reads it (see ``scoring.Scorable``)."""

    id: str
    rule_id: str
    severity: Severity
    confidence: float
    created_at: str
    category: str


@dataclass
class _Snapshot:
    """Everything computed from one state of the database."""

    tools: list[Tool] = field(default_factory=list)
    scores: dict[str, ToolScore] = field(default_factory=dict)
    org: OrgScore = field(default_factory=lambda: org_score([]))
    max_real_severity: dict[str, Severity] = field(default_factory=dict)   # per tool, policy findings excluded
    overrides: dict[str, bool] = field(default_factory=dict)
    provider_stats: dict[str, Any] = field(default_factory=dict)
    tool_bytes: dict[str, int | None] = field(default_factory=dict)


class Insights:
    def __init__(
        self,
        config: Config,
        db: Database,
        catalog: Catalog,
        *,
        scenario: Callable[[], str | None] | None = None,
    ):
        self.config = config
        self.db = db
        self.catalog = catalog
        self._scenario = scenario or (lambda: None)
        self._lock = threading.RLock()
        self._control_defs: list | None = None
        self._cached_version = -1
        self._cache: dict[str, Any] = {}

    def set_scenario_source(self, scenario: Callable[[], str | None]) -> None:
        """Tell the summary how to find out which demo scenario is showing (the player is made later)."""
        self._scenario = scenario
        with self._lock:
            self._cache.clear()

    # ---- cache -----------------------------------------------------------

    def _cached(self, key: str, build: Callable[[], Any]) -> Any:
        with self._lock:
            if self.db.version != self._cached_version:
                self._cache.clear()
                self._cached_version = self.db.version
            if key not in self._cache:
                self._cache[key] = build()
            return self._cache[key]

    def _snapshot(self) -> _Snapshot:
        return self._cached("snapshot", self._build)

    def _build(self) -> _Snapshot:
        db, catalog = self.db, self.catalog
        snap = _Snapshot(overrides=db.get_provider_overrides())

        findings: dict[str, list[_Row]] = defaultdict(list)
        for r in db.scoring_findings():
            findings[r["tool_id"]].append(_Row(r["id"], r["rule_id"], Severity(r["severity"]),
                                               r["confidence"], r["created_at"], r["category"]))
        flags: dict[str, dict[str, Any]] = defaultdict(dict)
        for r in db.capability_flags():
            flags[r["tool_id"]][r["capability"]] = r

        for row in db.tool_stats():
            provider = catalog.get(row["provider_id"])
            if provider is None:                                  # a provider that left the catalog
                continue
            tool_id = row["tool_id"]
            confidence = _CONFIDENCE_BY_RANK[row["conf_rank"]]
            unconfirmed = confidence is MatchConfidence.LOW
            sanctioned = effective_sanctioned(self.config, snap.overrides, provider.id)
            rows = [] if unconfirmed else findings.get(tool_id, [])      # a guess creates no findings (SOT 7.5)

            result = score_tool(tool_id, rows, exposure=catalog.exposure(provider.category), sanctioned=sanctioned)
            snap.scores[tool_id] = result

            counts = FindingCounts()
            for r in rows:
                setattr(counts, r.severity.value, getattr(counts, r.severity.value) + 1)
            real = [r.severity for r in rows if r.category != "policy"]
            if real:
                snap.max_real_severity[tool_id] = max(real, key=lambda s: s.rank)

            caps = Capabilities()
            for name, flag in flags.get(tool_id, {}).items():
                setattr(caps, name, Capability(granted=bool(flag["granted"]), used=bool(flag["used"]),
                                               risky=bool(flag["risky"])))

            snap.tool_bytes[tool_id] = row["bytes_out"]
            snap.tools.append(Tool(
                tool_id=tool_id, process=row["process"] or "unknown", provider_id=provider.id,
                display_name=f"{row['process'] or 'unknown'} → {provider.display_name}",
                category=provider.category, sanctioned=sanctioned, confidence=confidence,
                event_count=row["event_count"], bytes_out=row["bytes_out"],
                first_seen=row["first_seen"], last_seen=row["last_seen"],
                risk=result.score, risk_band=result.band, finding_counts=counts, capabilities=caps,
                visibility=VisibilityCounts(full=row["full_events"], metadata_only=row["meta_events"]),
                unconfirmed=unconfirmed))

        snap.tools.sort(key=lambda t: (-t.risk, t.tool_id))
        snap.org = org_score([t.risk for t in snap.tools if not t.unconfirmed])
        snap.provider_stats = {r["provider_id"]: r for r in db.provider_stats()}
        return snap

    # ---- risk ------------------------------------------------------------

    def org(self) -> OrgScore:
        return self._snapshot().org

    def risk(self) -> RiskBlock:
        org = self.org()
        return RiskBlock(org_risk=org.org_risk, band=org.band, compliance_score=org.compliance_score)

    def top_tools(self, n: int = TOP_TOOLS) -> list[TopTool]:
        return [TopTool(tool_id=t.tool_id, risk=t.risk, risk_band=t.risk_band)
                for t in self._snapshot().tools if t.risk > 0][:n]

    # ---- tools, agents, providers ------------------------------------------

    def tools(self) -> list[Tool]:
        return list(self._snapshot().tools)

    def agents(self) -> list[AgentRow]:
        """Tools that have been given, or have used, any capability (the permission matrix)."""
        rows = []
        for tool in self._snapshot().tools:
            caps = tool.capabilities
            if not any(getattr(caps, name).granted or getattr(caps, name).used for name in _CAPABILITIES):
                continue
            rows.append(AgentRow(
                tool_id=tool.tool_id, display_name=tool.display_name, process=tool.process, risk=tool.risk,
                risk_band=tool.risk_band, capabilities=caps,
                activity=self.db.list_agent_activity(tool.tool_id, limit=100)))
        return rows

    def providers(self, seen: bool | None = None) -> list[ProviderRow]:
        snap = self._snapshot()
        rows = []
        for provider in self.catalog.providers:
            stats = snap.provider_stats.get(provider.id)
            is_seen = stats is not None
            if seen is not None and is_seen != seen:
                continue
            rows.append(ProviderRow(
                provider_id=provider.id, display_name=provider.display_name, category=provider.category,
                sanctioned=effective_sanctioned(self.config, snap.overrides, provider.id),
                sanction_source=SanctionSource.OVERRIDE if provider.id in snap.overrides else SanctionSource.DEFAULT,
                seen=is_seen, confirmed=is_seen and stats["conf_rank"] < 2,
                event_count=stats["event_count"] if stats else 0, tool_count=stats["tool_count"] if stats else 0,
                last_seen=stats["last_seen"] if stats else None))
        rows.sort(key=lambda r: (not r.seen, -r.event_count))             # seen first, busiest first; catalog order after
        return rows

    def provider(self, provider_id: str) -> ProviderRow | None:
        return next((p for p in self.providers() if p.provider_id == provider_id), None)

    # ---- summary and time series --------------------------------------------

    def summary(self) -> Summary:
        # the scenario name can change without any database write, so it is added after the cache
        return self._cached("summary", self._build_summary).model_copy(update={"scenario": self._scenario()})

    def _build_summary(self) -> Summary:
        snap, db = self._snapshot(), self.db
        ai_events = db.count_events()
        dropped = db.get_counter(DROPPED_NON_AI)
        by_provider = [
            ProviderCount(provider_id=p.provider_id, display_name=p.display_name, count=p.event_count)
            for p in self.providers(seen=True)]
        by_provider.sort(key=lambda p: (-p.count, p.display_name))
        severities = db.alert_counts_by_severity("open")
        categories = db.finding_counts_by_category()
        egress = db.egress_summary()
        full = sum(t.visibility.full for t in snap.tools)
        meta = sum(t.visibility.metadata_only for t in snap.tools)
        return Summary(
            risk=self.risk(),
            totals=SummaryTotals(events=ai_events + dropped, ai_events=ai_events, dropped_non_ai=dropped,
                                 tools=len(snap.tools), providers=len(by_provider),
                                 alerts_open=db.count_open_alerts(), findings=db.count_findings()),
            alerts_by_severity=AlertsBySeverity(**{k: severities.get(k, 0) for k in ("critical", "high", "medium", "low")}),
            findings_by_category=FindingsByCategory(**{k: categories.get(k, 0) for k in ("secret", "pii", "code", "agent", "policy")}),
            events_by_provider=by_provider,
            unsanctioned_tools=sum(1 for t in snap.tools if not t.sanctioned and not t.unconfirmed),
            coverage=VisibilityCounts(full=full, metadata_only=meta),
            top_tools=self.top_tools(),
            llm=LlmSummary(mode=LlmMode(self.config.llm_mode), sent=egress.sent, blocked=egress.blocked,
                           failed=egress.failed),
            scenario=None,
            last_event_at=db.last_event_at())

    def timeseries(self, bucket_s: int = 60, since: str | None = None) -> Timeseries:
        """Events and alerts per time bucket. Alerts are placed at the time of the event behind them."""
        if bucket_s <= 0:
            raise ValueError("bucket_s must be positive")
        return self._cached(f"timeseries:{bucket_s}:{since}", lambda: self._build_timeseries(bucket_s, since))

    def _build_timeseries(self, bucket_s: int, since: str | None) -> Timeseries:
        def bucket_of(ts: str) -> int:
            return int(parse_ts(ts).timestamp() // bucket_s)

        events: dict[int, int] = defaultdict(int)
        alerts: dict[int, int] = defaultdict(int)
        for ts in self.db.event_times(since):
            events[bucket_of(ts)] += 1
        for ts in self.db.alert_event_times(since):
            alerts[bucket_of(ts)] += 1
        keys = set(events) | set(alerts)
        if not keys:
            return Timeseries(bucket_s=bucket_s, buckets=[])
        first, last = min(keys), max(keys)
        first = max(first, last - MAX_BUCKETS + 1)                       # never more than MAX_BUCKETS points
        buckets = [
            TimeBucket(t=format_ts(datetime.fromtimestamp(k * bucket_s, timezone.utc)),
                       events=events.get(k, 0), alerts=alerts.get(k, 0))
            for k in range(first, last + 1)]                             # empty buckets included: a continuous chart
        return Timeseries(bucket_s=bucket_s, buckets=buckets)

    # ---- why this score? ----------------------------------------------------

    def compliance(self) -> "Compliance":
        """Which controls have an open finding (SOT 7.6). The mapping is ``config/compliance.yaml``."""
        def build():
            rows = [compliance_map.OpenFinding(i, r) for i, r in self.db.open_finding_refs()]
            return compliance_map.build(self._controls(), rows, self.risk())
        return self._cached("compliance", build)

    def _controls(self) -> list:
        if self._control_defs is None:
            self._control_defs = compliance_map.load_controls()
        return self._control_defs

    def score_explain(self, tool_id: str | None = None) -> ScoreExplain | None:
        """Every finding's contribution to a tool's score, then the organisation score.

        With no ``tool_id`` the highest-risk tool is explained; with no tools at all the
        answer is empty (``tool_id`` ""). Returns None for a tool that does not exist.
        """
        snap = self._snapshot()
        org = ScoreOrg(max_tool_score=snap.org.max_tool_score, mean_top3=snap.org.mean_top3,
                       org_risk=snap.org.org_risk, compliance_score=snap.org.compliance_score, band=snap.org.band)
        if tool_id is None:
            if not snap.tools:
                return ScoreExplain(tool_id="", S=0.0, score=0, items=[], org=org)
            tool_id = snap.tools[0].tool_id                              # tools are sorted, riskiest first
        result = snap.scores.get(tool_id)
        if result is None:
            return None
        items = [ScoreItem(finding_id=i.finding_id, rule_id=i.rule_id, severity=i.severity, w_sev=i.w_sev,
                           confidence=i.confidence, m_exposure=i.m_exposure, m_sanction=i.m_sanction,
                           count_factor=i.count_factor, points=i.points) for i in result.items]
        return ScoreExplain(tool_id=tool_id, S=result.s, score=result.score, items=items, org=org)

    # ---- the exposure graph -------------------------------------------------

    def graph(self) -> Graph:
        return self._cached("graph", self._build_graph)

    def _build_graph(self) -> Graph:
        snap = self._snapshot()
        process_risk: dict[str, int] = defaultdict(int)
        provider_risk: dict[str, int] = defaultdict(int)
        edges: list[GraphEdge] = []
        for tool in snap.tools:
            process_risk[tool.process] = max(process_risk[tool.process], tool.risk)
            provider_risk[tool.provider_id] = max(provider_risk[tool.provider_id], tool.risk)
            severity = snap.max_real_severity.get(tool.tool_id)          # policy findings do not turn an edge red
            edges.append(GraphEdge(
                source=f"proc:{tool.process}", target=f"prov:{tool.provider_id}", tool_id=tool.tool_id,
                event_count=tool.event_count, bytes_out=tool.bytes_out, max_severity=severity,
                has_finding=severity is not None))
        nodes = [GraphNode(id=f"proc:{p}", kind=NodeKind.PROCESS, label=p, risk=r, risk_band=band_for_score(r),
                           sanctioned=None) for p, r in sorted(process_risk.items())]
        for provider_id, r in sorted(provider_risk.items()):
            provider = self.catalog.get(provider_id)
            nodes.append(GraphNode(
                id=f"prov:{provider_id}", kind=NodeKind.PROVIDER, label=provider.display_name if provider else provider_id,
                risk=r, risk_band=band_for_score(r),
                sanctioned=effective_sanctioned(self.config, snap.overrides, provider_id)))
        return Graph(nodes=nodes, edges=edges)

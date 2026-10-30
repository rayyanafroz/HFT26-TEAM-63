"""Data models for ShadowLens: the frozen contracts in SOT section 6.

Field names and allowed values are exactly the ones in the SOT. Changing one
here means changing the SOT in the same PR (SOT 0.3).

Conventions (SOT 6.1): JSON names are snake_case; timestamps are ISO-8601 UTC
ending in ``Z``; ids are lowercase UUID4 strings; ``null`` only where a type
says ``| null``.

This file is built in parts:
  A. vocabulary, ``NetEvent``, ``ProviderMatch``, ``Finding``
  B. ``Remediation``, ``Alert``, capabilities, ``AgentActivity``, ``Tool``
  C. API response shapes and the small request bodies
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from datetime import datetime, timezone
from enum import StrEnum
from typing import Annotated, Any, Generic, Literal, TypeVar

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    computed_field,
    field_validator,
    model_validator,
)

# --------------------------------------------------------------------------
# Small reusable types and helpers
# --------------------------------------------------------------------------

Uuid4 = Annotated[
    str,
    StringConstraints(pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"),
]
Timestamp = Annotated[
    str,
    StringConstraints(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$"),
]
Hash12 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{12}$")]
Sha256Hex = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]


def new_id() -> str:
    """A new lowercase UUID4 string."""
    return str(uuid.uuid4())


def utc_now_iso() -> str:
    """Now, as ISO-8601 UTC with milliseconds and a trailing ``Z``."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def make_tool_id(process: str | None, provider_id: str) -> str:
    """``"<process lowercased or unknown>|<provider_id>"``, e.g. ``python3|openai`` (SOT 6.4)."""
    return f"{(process or 'unknown').strip().lower() or 'unknown'}|{provider_id}"


class ShadowModel(BaseModel):
    """Base for every model: unknown fields are errors, assignments are validated."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)


# --------------------------------------------------------------------------
# Vocabulary (the allowed values in SOT 6.2 to 6.7)
# --------------------------------------------------------------------------

class Source(StrEnum):
    CONN_SCAN = "conn_scan"
    HTTP_LOG = "http_log"
    HAR = "har"
    PCAP = "pcap"
    LIVE_LOG = "live_log"
    TRANSCRIPT = "transcript"
    PROXY = "proxy"
    SCENARIO = "scenario"


class HostBasis(StrEnum):
    SNI = "sni"
    HOST_HEADER = "host_header"
    URL = "url"
    RESOLVED_IP = "resolved_ip"
    DNS_QUERY = "dns_query"
    PORT_ONLY = "port_only"
    TRANSCRIPT = "transcript"


class Visibility(StrEnum):
    FULL = "full"
    METADATA_ONLY = "metadata_only"


class AuthScheme(StrEnum):
    BEARER = "bearer"
    X_API_KEY = "x-api-key"
    X_GOOG_API_KEY = "x-goog-api-key"
    BASIC = "basic"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """0 (info) to 4 (critical), for sorting and comparisons."""
        return _SEVERITY_RANK[self.value]


_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class Band(StrEnum):
    """Risk band for a tool or the whole organization (SOT 6.7)."""

    LOW = "low"            # 0-24
    MODERATE = "moderate"  # 25-49
    HIGH = "high"          # 50-74
    CRITICAL = "critical"  # 75-100


class Category(StrEnum):
    """Provider category (SOT 6.4)."""

    CLOUD_LLM = "cloud_llm"
    LOCAL_LLM = "local_llm"
    MODEL_HUB = "model_hub"
    AI_APP = "ai_app"


class MatchConfidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class MatchBasis(StrEnum):
    HOST = "host"
    PORT = "port"
    RESOLVED_IP = "resolved_ip"


class FindingCategory(StrEnum):
    SECRET = "secret"
    PII = "pii"
    CODE = "code"
    AGENT = "agent"
    POLICY = "policy"


class LocationField(StrEnum):
    BODY = "body"
    PATH = "path"
    HEADER_AUTHORIZATION = "header:authorization"
    HEADER_X_API_KEY = "header:x-api-key"
    TOOL_CALL = "tool_call"
    TOOL_DECLARATION = "tool_declaration"
    TOOL_RESULT = "tool_result"


# Rule ids from the catalog in SOT 6.5 (IDs are frozen). The prefix decides the
# finding category.
RULE_IDS: frozenset[str] = frozenset({
    # secrets
    "SEC_PRIVATE_KEY", "SEC_AWS_SECRET_KEY", "SEC_GITHUB_TOKEN", "SEC_STRIPE_KEY", "SEC_DB_URL",
    "SEC_AWS_ACCESS_KEY", "SEC_OPENAI_KEY", "SEC_ANTHROPIC_KEY", "SEC_SLACK_TOKEN",
    "SEC_GOOGLE_API_KEY", "SEC_HF_TOKEN", "SEC_JWT", "SEC_GENERIC_ASSIGNMENT", "SEC_HIGH_ENTROPY",
    # personal data
    "PII_CREDIT_CARD", "PII_AADHAAR", "PII_IBAN", "PII_SSN", "PII_BULK", "PII_PAN",
    "PII_EMAIL", "PII_PHONE", "PII_INTERNAL_HOST",
    # code
    "CODE_CONFIDENTIAL_MARKER", "CODE_POSSIBLE_SOURCE",
    # agents
    "AGENT_DANGEROUS_CMD", "AGENT_SENSITIVE_FILE_READ", "AGENT_SHELL_EXEC", "AGENT_EGRESS_COMMAND",
    "AGENT_MCP_TOOL_CALL", "AGENT_FS_READ_OUTSIDE_WORKSPACE", "AGENT_SHELL_TOOL_DECLARED",
    "AGENT_EXCESSIVE_AGENCY", "AGENT_INJECTION_CHAIN", "AGENT_NETWORK_TOOL",
    # policy (created by the pipeline, not by analysis)
    "POLICY_UNSANCTIONED_TOOL", "POLICY_LOCAL_LLM",
})

_RULE_PREFIX_CATEGORY = {
    "SEC_": FindingCategory.SECRET,
    "PII_": FindingCategory.PII,
    "CODE_": FindingCategory.CODE,
    "AGENT_": FindingCategory.AGENT,
    "POLICY_": FindingCategory.POLICY,
}


def category_for_rule(rule_id: str) -> FindingCategory:
    """The category implied by a rule id's prefix (``SEC_`` to secret, and so on)."""
    for prefix, category in _RULE_PREFIX_CATEGORY.items():
        if rule_id.startswith(prefix):
            return category
    raise ValueError(f"unknown rule id prefix: {rule_id!r}")


# --------------------------------------------------------------------------
# NetEvent (SOT 6.2): one observed network event, produced by ingest
# --------------------------------------------------------------------------

# Only these headers are ever kept (SOT 6.2). Everything else (cookies, etc.) is dropped.
HEADER_WHITELIST: frozenset[str] = frozenset({
    "host", "content-type", "user-agent", "authorization",
    "x-api-key", "x-goog-api-key", "x-shadow-client",
})


class NetEvent(ShadowModel):
    """Body and headers live in memory only; they are never stored (SOT 6.9)."""

    id: Uuid4
    ts: Timestamp
    source: Source
    process: str | None = None           # lowercased; "unknown" when ingest cannot tell
    pid: int | None = Field(default=None, ge=0)
    dst_ip: str
    dst_port: int = Field(ge=0, le=65535)
    host: str | None = None
    host_basis: HostBasis
    method: str | None = None
    path: str | None = None              # WITHOUT the query string
    query: str | None = None             # memory only, scanned for secrets, never stored
    headers: dict[str, str] = Field(default_factory=dict)
    body_text: str | None = None         # memory only, already truncated by ingest
    body_bytes: int = Field(default=0, ge=0)
    body_sha256: Sha256Hex | None = None
    body_truncated: bool = False
    bytes_out: int | None = Field(default=None, ge=0)
    bytes_in: int | None = Field(default=None, ge=0)
    auth_scheme: AuthScheme | None = None
    auth_hint: Hash12 | None = None      # hash12 of the credential, never the credential

    @field_validator("process")
    @classmethod
    def _normalize_process(cls, value: str | None) -> str | None:
        """Lowercase, and drop a trailing ``.exe`` so Windows names match everywhere
        (``Claude.EXE`` becomes ``claude``, SOT 1.2)."""
        if value is None:
            return None
        name = value.strip().lower()
        if name.endswith(".exe") and len(name) > 4:
            name = name[:-4]
        return name or None

    @field_validator("host")
    @classmethod
    def _normalize_host(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip().lower().rstrip(".")
        return value or None

    @field_validator("dst_ip")
    @classmethod
    def _valid_ip(cls, value: str) -> str:
        try:
            ipaddress.ip_address(value)
        except ValueError:
            # The standard message repeats the value, and a bad value in a log can be anything
            # (even a secret). Never echo it.
            raise ValueError("not a valid IP address") from None
        return value

    @field_validator("path")
    @classmethod
    def _path_has_no_query(cls, value: str | None) -> str | None:
        if value is not None and "?" in value:
            raise ValueError("path must not contain a query string; put it in 'query'")
        return value

    @field_validator("headers", mode="before")
    @classmethod
    def _keep_only_whitelisted_headers(cls, value: Any) -> Any:
        if value is None:
            return {}
        if not isinstance(value, dict):
            return value
        kept: dict[str, str] = {}
        for key, val in value.items():
            name = str(key).strip().lower()
            if name in HEADER_WHITELIST:
                kept[name] = ", ".join(map(str, val)) if isinstance(val, (list, tuple)) else str(val)
        return kept

    @computed_field  # type: ignore[prop-decorator]
    @property
    def visibility(self) -> Visibility:
        """``full`` exactly when ``body_text`` is a non-empty string (SOT 6.2)."""
        return Visibility.FULL if self.body_text else Visibility.METADATA_ONLY


# --------------------------------------------------------------------------
# ProviderMatch (SOT 6.4): which AI provider an event talks to
# --------------------------------------------------------------------------

class ProviderMatch(ShadowModel):
    provider_id: str
    display_name: str
    category: Category
    confidence: MatchConfidence
    match_basis: MatchBasis
    tool_id: str  # "<process>|<provider_id>"

    @model_validator(mode="after")
    def _tool_id_matches_provider(self) -> "ProviderMatch":
        process, sep, provider = self.tool_id.rpartition("|")
        if not sep or not process or provider != self.provider_id:
            raise ValueError("tool_id must be '<process>|<provider_id>' for this provider")
        return self


# --------------------------------------------------------------------------
# Finding (SOT 6.5): one thing a rule found
# --------------------------------------------------------------------------

class Location(ShadowModel):
    field: LocationField
    offset: int | None = Field(default=None, ge=0)


class FindingMeta(ShadowModel):
    hash12: Hash12                              # HMAC of the matched value or call; never the value
    spans: list[tuple[int, int]] = Field(default_factory=list)
    context: str = Field(default="", max_length=200)   # surrounding text, every span redacted
    in_tool_args: bool = False
    count: int | None = Field(default=None, ge=1)
    tool_name: str | None = None
    argument: str | None = Field(default=None, max_length=200)  # redacted

    @field_validator("spans")
    @classmethod
    def _spans_are_ordered_pairs(cls, spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
        for start, end in spans:
            if start < 0 or end < start:
                raise ValueError("each span must be [start, end] with 0 <= start <= end")
        return spans


class Finding(ShadowModel):
    """Points are never stored; they are computed at read time (SOT 7.5)."""

    id: Uuid4
    event_id: Uuid4
    tool_id: str
    rule_id: str
    category: FindingCategory
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    masked_preview: str
    location: Location
    owasp: list[str] = Field(default_factory=list)      # e.g. ["LLM02"]
    controls: list[str] = Field(default_factory=list)   # ids from config/compliance.yaml
    meta: FindingMeta
    created_at: Timestamp

    @field_validator("rule_id")
    @classmethod
    def _known_rule(cls, value: str) -> str:
        if value not in RULE_IDS:
            raise ValueError(f"unknown rule_id {value!r}")
        return value

    @model_validator(mode="after")
    def _category_matches_rule(self) -> "Finding":
        expected = category_for_rule(self.rule_id)
        if self.category != expected:
            raise ValueError(f"rule {self.rule_id} belongs to category {expected.value!r}, not {self.category.value!r}")
        return self


# --------------------------------------------------------------------------
# Part B vocabulary
# --------------------------------------------------------------------------

class AlertStatus(StrEnum):
    OPEN = "open"
    ACKED = "acked"


class Sensitivity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Verdict(StrEnum):
    TRUE_POSITIVE = "true_positive"
    LIKELY_FALSE_POSITIVE = "likely_false_positive"
    NEEDS_REVIEW = "needs_review"


class RemediationSource(StrEnum):
    LLM = "llm"
    TEMPLATE = "template"


class RedactionCheck(StrEnum):
    PASSED = "passed"
    BLOCKED = "blocked"
    NOT_APPLICABLE = "not_applicable"


class CapabilityName(StrEnum):
    SHELL = "shell"
    FS_READ = "fs_read"
    FS_WRITE = "fs_write"
    NETWORK = "network"
    MCP = "mcp"
    SENSITIVE_FILE = "sensitive_file"


class ActivityKind(StrEnum):
    GRANTED = "granted"
    USED = "used"


def band_for_score(score: int) -> Band:
    """The risk band for a 0-100 score (SOT 6.7): 0-24 low, 25-49 moderate, 50-74 high, 75-100 critical."""
    if not 0 <= score <= 100:
        raise ValueError("score must be between 0 and 100")
    if score < 25:
        return Band.LOW
    if score < 50:
        return Band.MODERATE
    if score < 75:
        return Band.HIGH
    return Band.CRITICAL


def _parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


# --------------------------------------------------------------------------
# Remediation (SOT 6.6): advice for one alert, from the AI model or a template
# --------------------------------------------------------------------------

class Remediation(ShadowModel):
    id: Uuid4
    alert_id: Uuid4
    summary: str = Field(max_length=300)
    steps: list[Annotated[str, StringConstraints(max_length=200)]] = Field(default_factory=list, max_length=5)
    sensitivity: Sensitivity
    verdict: Verdict
    data_classes: list[str] = Field(default_factory=list)  # e.g. ["credential", "pii"]
    source: RemediationSource
    model: str | None = None
    latency_ms: int | None = Field(default=None, ge=0)
    redaction_check: RedactionCheck
    prompt_text: str | None = None  # the exact redacted text sent; null if blocked or template
    created_at: Timestamp

    @model_validator(mode="after")
    def _consistent_source(self) -> "Remediation":
        if self.source is RemediationSource.TEMPLATE:
            if self.prompt_text is not None or self.model is not None:
                raise ValueError("a template remediation has no model and no prompt_text")
        if self.redaction_check is RedactionCheck.BLOCKED:
            if self.source is not RemediationSource.TEMPLATE:
                raise ValueError("a blocked remediation must be a template (nothing was sent)")
        if self.source is RemediationSource.LLM and self.redaction_check is not RedactionCheck.PASSED:
            raise ValueError("an llm remediation must have passed the redaction check")
        return self


# --------------------------------------------------------------------------
# Alert (SOT 6.6): a finding worth showing the admin
# --------------------------------------------------------------------------

class Alert(ShadowModel):
    id: Uuid4
    finding_id: Uuid4
    tool_id: str
    provider_id: str
    rule_id: str
    severity: Severity
    title: str = Field(min_length=1)
    status: AlertStatus = AlertStatus.OPEN
    created_at: Timestamp
    acked_at: Timestamp | None = None
    finding: Finding
    remediation: Remediation | None = None

    @model_validator(mode="after")
    def _consistent(self) -> "Alert":
        if self.finding_id != self.finding.id:
            raise ValueError("finding_id does not match the embedded finding")
        if self.tool_id != self.finding.tool_id or self.rule_id != self.finding.rule_id:
            raise ValueError("tool_id/rule_id do not match the embedded finding")
        if (self.status is AlertStatus.ACKED) != (self.acked_at is not None):
            raise ValueError("acked_at must be set exactly when status is 'acked'")
        if self.remediation is not None and self.remediation.alert_id != self.id:
            raise ValueError("remediation belongs to a different alert")
        return self

    def acknowledge(self, at: str | None = None) -> "Alert":
        """A copy of this alert marked acknowledged (idempotent).

        Status and ``acked_at`` must change together, so setting them one by one
        is rejected; use this instead.
        """
        if self.status is AlertStatus.ACKED:
            return self
        data = self.model_dump()
        data.update(status=AlertStatus.ACKED, acked_at=at or utc_now_iso())
        return Alert.model_validate(data)


# --------------------------------------------------------------------------
# Agent capabilities and activity (SOT 6.6)
# --------------------------------------------------------------------------

class Capability(ShadowModel):
    """granted: a declared tool maps to it. used: a tool call executed it. risky: a risky finding is attached."""

    granted: bool = False
    used: bool = False
    risky: bool = False


class Capabilities(ShadowModel):
    shell: Capability = Field(default_factory=Capability)
    fs_read: Capability = Field(default_factory=Capability)
    fs_write: Capability = Field(default_factory=Capability)
    network: Capability = Field(default_factory=Capability)
    mcp: Capability = Field(default_factory=Capability)
    sensitive_file: Capability = Field(default_factory=Capability)


class AgentActivity(ShadowModel):
    ts: Timestamp
    capability: CapabilityName
    kind: ActivityKind
    risky: bool = False
    name: str                                   # the tool name
    rule_id: str | None = None
    finding_id: Uuid4 | None = None
    argument: str | None = Field(default=None, max_length=200)  # redacted

    @field_validator("rule_id")
    @classmethod
    def _known_rule(cls, value: str | None) -> str | None:
        if value is not None and value not in RULE_IDS:
            raise ValueError(f"unknown rule_id {value!r}")
        return value


# --------------------------------------------------------------------------
# Tool (SOT 6.6): one (process, provider) pair, with its computed risk
# --------------------------------------------------------------------------

class FindingCounts(ShadowModel):
    critical: int = Field(default=0, ge=0)
    high: int = Field(default=0, ge=0)
    medium: int = Field(default=0, ge=0)
    low: int = Field(default=0, ge=0)
    info: int = Field(default=0, ge=0)


class VisibilityCounts(ShadowModel):
    full: int = Field(default=0, ge=0)
    metadata_only: int = Field(default=0, ge=0)


class Tool(ShadowModel):
    tool_id: str
    process: str
    provider_id: str
    display_name: str
    category: Category
    sanctioned: bool
    confidence: MatchConfidence
    event_count: int = Field(ge=0)
    bytes_out: int | None = Field(default=None, ge=0)
    first_seen: Timestamp
    last_seen: Timestamp
    risk: int = Field(ge=0, le=100)
    risk_band: Band
    finding_counts: FindingCounts = Field(default_factory=FindingCounts)
    capabilities: Capabilities = Field(default_factory=Capabilities)
    visibility: VisibilityCounts = Field(default_factory=VisibilityCounts)
    unconfirmed: bool  # true if the match confidence is "low"

    @model_validator(mode="after")
    def _consistent(self) -> "Tool":
        if self.tool_id != make_tool_id(self.process, self.provider_id):
            raise ValueError("tool_id must be '<process>|<provider_id>'")
        if self.risk_band != band_for_score(self.risk):
            raise ValueError(f"risk_band {self.risk_band.value!r} does not match risk {self.risk}")
        if self.unconfirmed != (self.confidence is MatchConfidence.LOW):
            raise ValueError("unconfirmed must be true exactly when confidence is 'low'")
        if _parse_ts(self.first_seen) > _parse_ts(self.last_seen):
            raise ValueError("first_seen is after last_seen")
        return self


# ==========================================================================
# Part C: API response shapes (SOT 6.7) and the small request bodies
# ==========================================================================

T = TypeVar("T")


def _check_risk_triplet(org_risk: int, compliance_score: int, band: Band) -> None:
    """Shared rule: compliance = 100 - org_risk, and the band follows org_risk (SOT 7.5)."""
    if compliance_score != 100 - org_risk:
        raise ValueError("compliance_score must equal 100 - org_risk")
    if band != band_for_score(org_risk):
        raise ValueError(f"band {band.value!r} does not match org_risk {org_risk}")


class Page(ShadowModel, Generic[T]):
    """List envelope used by every list route: ``{"items": [...], "total": N}`` (SOT 6.1)."""

    items: list[T]
    total: int = Field(ge=0)

    @model_validator(mode="after")
    def _total_covers_items(self) -> "Page[T]":
        if self.total < len(self.items):
            raise ValueError("total cannot be smaller than the number of items")
        return self


class ErrorResponse(ShadowModel):
    error: str


class OkResponse(ShadowModel):
    ok: Literal[True] = True


# ---- health ------------------------------------------------------------------

class LlmMode(StrEnum):
    LLM = "llm"
    TEMPLATE = "template"


class HealthLlm(ShadowModel):
    enabled: bool
    key_present: bool
    model: str | None = None
    mode: LlmMode


class Health(ShadowModel):
    status: Literal["ok"] = "ok"
    version: str
    llm: HealthLlm
    db: Literal[True] = True


# ---- ingest and events -------------------------------------------------------

class IngestSummary(ShadowModel):
    source: str
    accepted: int = Field(default=0, ge=0)
    skipped: int = Field(default=0, ge=0)
    dropped_non_ai: int = Field(default=0, ge=0)
    findings: int = Field(default=0, ge=0)
    alerts: int = Field(default=0, ge=0)
    errors: list[str] = Field(default_factory=list, max_length=20)


class EventLite(ShadowModel):
    id: Uuid4
    ts: Timestamp
    source: Source
    tool_id: str
    process: str | None = None
    provider_id: str
    host: str | None = None
    dst_ip: str
    dst_port: int = Field(ge=0, le=65535)
    method: str | None = None
    path: str | None = None
    visibility: Visibility
    bytes_out: int | None = Field(default=None, ge=0)
    body_bytes: int = Field(default=0, ge=0)
    finding_count: int = Field(default=0, ge=0)


# ---- agents and providers ----------------------------------------------------

class AgentRow(ShadowModel):
    tool_id: str
    display_name: str
    process: str
    risk: int = Field(ge=0, le=100)
    risk_band: Band
    capabilities: Capabilities
    activity: list[AgentActivity] = Field(default_factory=list, max_length=100)  # oldest to newest

    @model_validator(mode="after")
    def _band_matches_risk(self) -> "AgentRow":
        if self.risk_band != band_for_score(self.risk):
            raise ValueError(f"risk_band {self.risk_band.value!r} does not match risk {self.risk}")
        return self


class SanctionSource(StrEnum):
    DEFAULT = "default"
    OVERRIDE = "override"


class ProviderRow(ShadowModel):
    provider_id: str
    display_name: str
    category: Category
    sanctioned: bool
    sanction_source: SanctionSource
    seen: bool
    confirmed: bool
    event_count: int = Field(default=0, ge=0)
    tool_count: int = Field(default=0, ge=0)
    last_seen: Timestamp | None = None


# ---- risk and summary --------------------------------------------------------

class RiskBlock(ShadowModel):
    org_risk: int = Field(ge=0, le=100)
    band: Band
    compliance_score: int = Field(ge=0, le=100)

    @model_validator(mode="after")
    def _consistent(self) -> "RiskBlock":
        _check_risk_triplet(self.org_risk, self.compliance_score, self.band)
        return self


class SummaryTotals(ShadowModel):
    events: int = Field(default=0, ge=0)
    ai_events: int = Field(default=0, ge=0)
    dropped_non_ai: int = Field(default=0, ge=0)
    tools: int = Field(default=0, ge=0)
    providers: int = Field(default=0, ge=0)
    alerts_open: int = Field(default=0, ge=0)
    findings: int = Field(default=0, ge=0)


class AlertsBySeverity(ShadowModel):
    critical: int = Field(default=0, ge=0)
    high: int = Field(default=0, ge=0)
    medium: int = Field(default=0, ge=0)
    low: int = Field(default=0, ge=0)


class FindingsByCategory(ShadowModel):
    secret: int = Field(default=0, ge=0)
    pii: int = Field(default=0, ge=0)
    code: int = Field(default=0, ge=0)
    agent: int = Field(default=0, ge=0)
    policy: int = Field(default=0, ge=0)


class ProviderCount(ShadowModel):
    provider_id: str
    display_name: str
    count: int = Field(ge=0)


class TopTool(ShadowModel):
    tool_id: str
    risk: int = Field(ge=0, le=100)
    risk_band: Band

    @model_validator(mode="after")
    def _band_matches_risk(self) -> "TopTool":
        if self.risk_band != band_for_score(self.risk):
            raise ValueError(f"risk_band {self.risk_band.value!r} does not match risk {self.risk}")
        return self


class LlmSummary(ShadowModel):
    mode: LlmMode
    sent: int = Field(default=0, ge=0)
    blocked: int = Field(default=0, ge=0)
    failed: int = Field(default=0, ge=0)


class Summary(ShadowModel):
    risk: RiskBlock
    totals: SummaryTotals = Field(default_factory=SummaryTotals)
    alerts_by_severity: AlertsBySeverity = Field(default_factory=AlertsBySeverity)
    findings_by_category: FindingsByCategory = Field(default_factory=FindingsByCategory)
    events_by_provider: list[ProviderCount] = Field(default_factory=list)
    unsanctioned_tools: int = Field(default=0, ge=0)
    coverage: VisibilityCounts = Field(default_factory=VisibilityCounts)
    top_tools: list[TopTool] = Field(default_factory=list)
    llm: LlmSummary
    scenario: str | None = None
    last_event_at: Timestamp | None = None


class TimeBucket(ShadowModel):
    t: Timestamp
    events: int = Field(ge=0)
    alerts: int = Field(ge=0)


class Timeseries(ShadowModel):
    bucket_s: int = Field(gt=0)
    buckets: list[TimeBucket] = Field(default_factory=list)


# ---- score explanation -------------------------------------------------------

class ScoreItem(ShadowModel):
    finding_id: Uuid4
    rule_id: str
    severity: Severity
    w_sev: float = Field(ge=0)
    confidence: float = Field(ge=0, le=1)
    m_exposure: float = Field(ge=0)
    m_sanction: float = Field(ge=0)
    count_factor: float = Field(ge=0)
    points: float = Field(ge=0)

    @field_validator("rule_id")
    @classmethod
    def _known_rule(cls, value: str) -> str:
        if value not in RULE_IDS:
            raise ValueError(f"unknown rule_id {value!r}")
        return value


class ScoreOrg(ShadowModel):
    max_tool_score: int = Field(ge=0, le=100)
    mean_top3: float = Field(ge=0, le=100)
    org_risk: int = Field(ge=0, le=100)
    compliance_score: int = Field(ge=0, le=100)
    band: Band

    @model_validator(mode="after")
    def _consistent(self) -> "ScoreOrg":
        _check_risk_triplet(self.org_risk, self.compliance_score, self.band)
        return self


class ScoreExplain(ShadowModel):
    tool_id: str
    S: float = Field(ge=0)
    score: int = Field(ge=0, le=100)
    items: list[ScoreItem] = Field(default_factory=list)  # sorted by points, highest first
    org: ScoreOrg

    @model_validator(mode="after")
    def _items_sorted(self) -> "ScoreExplain":
        points = [item.points for item in self.items]
        if points != sorted(points, reverse=True):
            raise ValueError("items must be sorted by points, highest first")
        return self


# ---- exposure graph ----------------------------------------------------------

class NodeKind(StrEnum):
    PROCESS = "process"
    PROVIDER = "provider"


class GraphNode(ShadowModel):
    id: str  # "proc:<process>" or "prov:<provider_id>"
    kind: NodeKind
    label: str
    risk: int = Field(ge=0, le=100)
    risk_band: Band
    sanctioned: bool | None = None

    @model_validator(mode="after")
    def _consistent(self) -> "GraphNode":
        prefix = "proc:" if self.kind is NodeKind.PROCESS else "prov:"
        if not self.id.startswith(prefix) or len(self.id) == len(prefix):
            raise ValueError(f"a {self.kind.value} node id must look like '{prefix}<name>'")
        if self.risk_band != band_for_score(self.risk):
            raise ValueError(f"risk_band {self.risk_band.value!r} does not match risk {self.risk}")
        return self


class GraphEdge(ShadowModel):
    source: str
    target: str
    tool_id: str
    event_count: int = Field(ge=0)
    bytes_out: int | None = Field(default=None, ge=0)
    max_severity: Severity | None = None
    has_finding: bool = False

    @model_validator(mode="after")
    def _finding_flag_matches_severity(self) -> "GraphEdge":
        if self.has_finding != (self.max_severity is not None):
            raise ValueError("has_finding must be true exactly when max_severity is set")
        return self


class Graph(ShadowModel):
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)

    @model_validator(mode="after")
    def _edges_point_at_nodes(self) -> "Graph":
        ids = {node.id for node in self.nodes}
        if len(ids) != len(self.nodes):
            raise ValueError("node ids must be unique")
        for edge in self.edges:
            if edge.source not in ids or edge.target not in ids:
                raise ValueError("every edge must connect two existing nodes")
        return self


# ---- compliance --------------------------------------------------------------

COMPLIANCE_DISCLAIMER = "This is an interpretation of risk, not an audit."


class ControlStatus(StrEnum):
    GAP = "gap"
    OK = "ok"


class Control(ShadowModel):
    id: str
    framework: str
    title: str
    status: ControlStatus
    finding_count: int = Field(ge=0)
    finding_ids: list[Uuid4] = Field(default_factory=list)

    @model_validator(mode="after")
    def _count_matches_ids(self) -> "Control":
        if self.finding_count != len(self.finding_ids):
            raise ValueError("finding_count must equal the number of finding_ids")
        return self


class Compliance(ShadowModel):
    compliance_score: int = Field(ge=0, le=100)
    org_risk: int = Field(ge=0, le=100)
    band: Band
    controls: list[Control] = Field(default_factory=list)
    disclaimer: Literal["This is an interpretation of risk, not an audit."] = COMPLIANCE_DISCLAIMER

    @model_validator(mode="after")
    def _consistent(self) -> "Compliance":
        _check_risk_triplet(self.org_risk, self.compliance_score, self.band)
        return self


# ---- AI egress ledger --------------------------------------------------------

class LlmStatus(StrEnum):
    SENT = "sent"
    BLOCKED = "blocked"
    FAILED = "failed"


class LlmCall(ShadowModel):
    id: Uuid4
    ts: Timestamp
    alert_id: Uuid4
    model: str | None = None
    bytes: int = Field(ge=0)
    status: LlmStatus
    prompt_sha256: Sha256Hex
    latency_ms: int | None = Field(default=None, ge=0)


class EgressSummary(ShadowModel):
    sent: int = Field(default=0, ge=0)
    blocked: int = Field(default=0, ge=0)
    failed: int = Field(default=0, ge=0)
    template_fallbacks: int = Field(default=0, ge=0)


class EgressResponse(ShadowModel):
    summary: EgressSummary
    items: list[LlmCall] = Field(default_factory=list)
    total: int = Field(default=0, ge=0)


# ---- evidence ----------------------------------------------------------------

class EvidenceMetric(ShadowModel):
    """``pass`` is a Python keyword, so the field is ``passed`` and serializes as ``pass``.

    Always build API output with ``by_alias=True`` (FastAPI does this by default).
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True, populate_by_name=True)

    id: str
    label: str
    value: float
    target: float
    unit: str
    passed: bool = Field(alias="pass")
    fixture: str
    command: str


class Evidence(ShadowModel):
    available: bool
    generated_at: Timestamp | None = None
    metrics: list[EvidenceMetric] = Field(default_factory=list)


# ---- capture status and sources ----------------------------------------------

class CaptureMode(StrEnum):
    IDLE = "idle"
    SCANNING = "scanning"
    WATCHING = "watching"
    PLAYING = "playing"


class ScanScope(StrEnum):
    OWN_USER = "own_user"
    ALL_USERS = "all_users"
    UNKNOWN = "unknown"


class Platform(StrEnum):
    LINUX = "linux"
    DARWIN = "darwin"
    WINDOWS = "windows"


class ScanStatus(ShadowModel):
    enabled: bool
    interval_s: float = Field(ge=0)
    last_scan_at: Timestamp | None = None
    scope: ScanScope
    privileged: bool
    psutil_ok: bool


class LiveTailStatus(ShadowModel):
    enabled: bool
    dir: str
    lines_ingested: int = Field(default=0, ge=0)


class TranscriptsStatus(ShadowModel):
    enabled: bool
    sources_active: int = Field(default=0, ge=0)
    files_watched: int = Field(default=0, ge=0)
    lines_ingested: int = Field(default=0, ge=0)


class ProxyStatus(ShadowModel):
    enabled: bool
    listen_port: int = Field(ge=1, le=65535)
    upstream: str
    upstream_ok: bool
    requests_ingested: int = Field(default=0, ge=0)
    error: str | None = None


class ScenarioStatus(ShadowModel):
    name: str | None = None
    played: int = Field(default=0, ge=0)
    total: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def _played_within_total(self) -> "ScenarioStatus":
        if self.played > self.total:
            raise ValueError("played cannot exceed total")
        return self


class CaptureStatus(ShadowModel):
    mode: CaptureMode
    scan: ScanStatus
    live_tail: LiveTailStatus
    transcripts: TranscriptsStatus
    proxy: ProxyStatus
    platform: Platform
    scenario: ScenarioStatus = Field(default_factory=ScenarioStatus)


class SourceKind(StrEnum):
    LIVE_LOG = "live_log"
    TRANSCRIPT = "transcript"
    PROXY = "proxy"


class SourceRow(ShadowModel):
    id: str
    display_name: str
    kind: SourceKind
    found: bool
    enabled: bool
    supported: bool
    error: str | None = None
    paths: list[str] = Field(default_factory=list)  # display only; the home folder is shown as "~"
    files_watched: int = Field(default=0, ge=0)
    lines_ingested: int = Field(default=0, ge=0)
    last_event_at: Timestamp | None = None
    reads: str
    stores: str


class VisibilityRow(ShadowModel):
    source: str
    can_see: str
    cannot_see: str
    visibility: str


class VisibilityResponse(ShadowModel):
    statement: str
    rows: list[VisibilityRow] = Field(default_factory=list)


# ---- Leak Lab preview --------------------------------------------------------

class PreviewFinding(ShadowModel):
    rule_id: str
    category: FindingCategory
    severity: Severity
    title: str
    masked_preview: str
    confidence: float = Field(ge=0, le=1)
    span: tuple[int, int]  # position in the submitted text

    @model_validator(mode="after")
    def _consistent(self) -> "PreviewFinding":
        if self.rule_id not in RULE_IDS:
            raise ValueError(f"unknown rule_id {self.rule_id!r}")
        if self.category != category_for_rule(self.rule_id):
            raise ValueError("category does not match the rule")
        start, end = self.span
        if start < 0 or end < start:
            raise ValueError("span must be [start, end] with 0 <= start <= end")
        return self


class PointsPreview(ShadowModel):
    S: float = Field(ge=0)
    tool_score: int = Field(ge=0, le=100)


class Preview(ShadowModel):
    findings: list[PreviewFinding] = Field(default_factory=list)
    redacted_text: str            # the exact text the AI model would receive
    would_block: bool             # true if the egress guard finds a hit in redacted_text
    points_preview: PointsPreview


class SamplesResponse(ShadowModel):
    key: str
    pii: str
    agent: str


# ---- small request bodies ----------------------------------------------------

class SanctionRequest(ShadowModel):
    sanctioned: bool


class SanctionResponse(ShadowModel):
    provider: ProviderRow
    risk: RiskBlock


class AnalyzeMode(StrEnum):
    TEXT = "text"
    AGENT_JSON = "agent_json"


class AnalyzePreviewRequest(ShadowModel):
    text: str = Field(max_length=20000)
    mode: AnalyzeMode = AnalyzeMode.TEXT


class ScenarioName(StrEnum):
    CLEAN_BASELINE = "clean_baseline"
    FULL_DEMO = "full_demo"
    AGENT_ATTACK = "agent_attack"
    QUICK_LEAK = "quick_leak"


class LoadScenarioRequest(ShadowModel):
    name: ScenarioName


class PlayScenarioRequest(ShadowModel):
    name: ScenarioName
    speed: float = Field(default=1.0, gt=0)


class PlayScenarioResponse(ShadowModel):
    name: ScenarioName
    total: int = Field(ge=0)
    duration_s: float = Field(ge=0)


class CaptureControlRequest(ShadowModel):
    scan: bool | None = None
    tail: bool | None = None


class SourceUpdateRequest(ShadowModel):
    enabled: bool
    backfill: bool = False

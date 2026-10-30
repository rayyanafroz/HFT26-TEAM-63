"""SQLite storage for ShadowLens (SOT section 6.9).

What is stored: events (metadata only), findings (masked), alerts, remediations,
agent activity, the AI call ledger, provider sanction overrides, the transcript
read offsets and a few counters.

What is NEVER stored (SOT 6.9): request bodies, headers, query strings, raw
secrets, command lines. This is enforced two ways:

  * no table has a column that could hold them (checked by a test), and
  * every insert method copies explicit fields from the model, so even if a
    caller hands over a ``NetEvent`` that still carries its body in memory,
    the body never reaches this module's SQL.

Tools, scores, the graph and the summary are computed on read (later modules);
this module only stores and fetches rows.

One ``Database`` holds one connection, shared between threads and serialized by
a re-entrant lock. Use ``with db.transaction():`` to make several writes atomic.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

from .config import Config
from .models import (
    AgentActivity,
    Alert,
    AlertStatus,
    EgressSummary,
    EventLite,
    Finding,
    FindingMeta,
    LlmCall,
    Location,
    NetEvent,
    Page,
    ProviderMatch,
    Remediation,
    Severity,
    utc_now_iso,
)

SCHEMA_VERSION = 1
DEFAULT_LIMIT = 100
MAX_LIMIT = 1000

# Counter names (rows in the ``counters`` table).
DROPPED_NON_AI = "dropped_non_ai"

# Column names that must never exist in any table (checked by a test).
FORBIDDEN_COLUMNS = frozenset({
    "body", "body_text", "headers", "header", "query", "cmdline", "secret", "raw",
    "raw_value", "value", "authorization", "cookie", "api_key", "token", "password",
})

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id                  TEXT PRIMARY KEY,
    ts                  TEXT NOT NULL,
    source              TEXT NOT NULL,
    tool_id             TEXT NOT NULL,
    process             TEXT,
    provider_id         TEXT NOT NULL,
    provider_confidence TEXT NOT NULL,
    match_basis         TEXT NOT NULL,
    host                TEXT,
    dst_ip              TEXT NOT NULL,
    dst_port            INTEGER NOT NULL,
    method              TEXT,
    path                TEXT,
    visibility          TEXT NOT NULL,
    bytes_out           INTEGER,
    bytes_in            INTEGER,
    body_bytes          INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_events_ts       ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_tool     ON events(tool_id);
CREATE INDEX IF NOT EXISTS idx_events_provider ON events(provider_id);

CREATE TABLE IF NOT EXISTS findings (
    id              TEXT PRIMARY KEY,
    event_id        TEXT NOT NULL REFERENCES events(id),
    tool_id         TEXT NOT NULL,
    rule_id         TEXT NOT NULL,
    category        TEXT NOT NULL,
    severity        TEXT NOT NULL,
    confidence      REAL NOT NULL,
    masked_preview  TEXT NOT NULL,
    location_field  TEXT NOT NULL,
    location_offset INTEGER,
    owasp           TEXT NOT NULL DEFAULT '[]',
    controls        TEXT NOT NULL DEFAULT '[]',
    hash12          TEXT NOT NULL,
    spans           TEXT NOT NULL DEFAULT '[]',
    context         TEXT NOT NULL DEFAULT '',
    in_tool_args    INTEGER NOT NULL DEFAULT 0,
    occurrences     INTEGER,
    tool_name       TEXT,
    argument        TEXT,
    created_at      TEXT NOT NULL
);
-- A finding exists at most once per (tool, rule, matched value) (SOT 6.5).
CREATE UNIQUE INDEX IF NOT EXISTS uq_findings_dedupe ON findings(tool_id, rule_id, hash12);
CREATE INDEX IF NOT EXISTS idx_findings_event ON findings(event_id);
CREATE INDEX IF NOT EXISTS idx_findings_tool  ON findings(tool_id);

CREATE TABLE IF NOT EXISTS alerts (
    id          TEXT PRIMARY KEY,
    finding_id  TEXT NOT NULL UNIQUE REFERENCES findings(id),
    tool_id     TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    rule_id     TEXT NOT NULL,
    severity    TEXT NOT NULL,
    title       TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'open',
    created_at  TEXT NOT NULL,
    acked_at    TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);

CREATE TABLE IF NOT EXISTS remediations (
    id              TEXT PRIMARY KEY,
    alert_id        TEXT NOT NULL UNIQUE REFERENCES alerts(id),
    summary         TEXT NOT NULL,
    steps           TEXT NOT NULL DEFAULT '[]',
    sensitivity     TEXT NOT NULL,
    verdict         TEXT NOT NULL,
    data_classes    TEXT NOT NULL DEFAULT '[]',
    source          TEXT NOT NULL,
    model           TEXT,
    latency_ms      INTEGER,
    redaction_check TEXT NOT NULL,
    prompt_text     TEXT,
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_activity (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    tool_id    TEXT NOT NULL,
    ts         TEXT NOT NULL,
    capability TEXT NOT NULL,
    kind       TEXT NOT NULL,
    risky      INTEGER NOT NULL DEFAULT 0,
    name       TEXT NOT NULL,
    rule_id    TEXT,
    finding_id TEXT REFERENCES findings(id),
    argument   TEXT
);
CREATE INDEX IF NOT EXISTS idx_activity_tool ON agent_activity(tool_id, id);

CREATE TABLE IF NOT EXISTS llm_calls (
    id            TEXT PRIMARY KEY,
    ts            TEXT NOT NULL,
    alert_id      TEXT NOT NULL REFERENCES alerts(id),
    model         TEXT,
    bytes         INTEGER NOT NULL,
    status        TEXT NOT NULL,
    prompt_sha256 TEXT NOT NULL,
    latency_ms    INTEGER
);

CREATE TABLE IF NOT EXISTS provider_overrides (
    provider_id TEXT PRIMARY KEY,
    sanctioned  INTEGER NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS source_offsets (
    path       TEXT PRIMARY KEY,
    inode      INTEGER,
    offset     INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS counters (
    name   TEXT PRIMARY KEY,
    amount INTEGER NOT NULL DEFAULT 0
);
"""

# Tables cleared by reset(), children first. source_offsets is kept on purpose so a
# reset does not make the transcript reader re-read old history (SOT 6.8, 7.2.1).
_RESET_ORDER = (
    "llm_calls", "agent_activity", "remediations", "alerts", "findings", "events",
    "provider_overrides", "counters",
)


class DatabaseError(RuntimeError):
    pass


def clamp_page(limit: int | None, offset: int | None) -> tuple[int, int]:
    """Apply the list rules from SOT 6.1: ``limit`` default 100, max 1000; ``offset`` at least 0."""
    lim = DEFAULT_LIMIT if limit is None else max(1, min(int(limit), MAX_LIMIT))
    off = 0 if offset is None else max(0, int(offset))
    return lim, off


def _dumps(items: Iterable[Any]) -> str:
    return json.dumps(list(items), separators=(",", ":"))


class Database:
    def __init__(self, path: Path | str):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._depth = 0
        # Autocommit mode: we open and close transactions explicitly (see transaction()).
        self._conn = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA busy_timeout = 5000")
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.execute("PRAGMA synchronous = NORMAL")
        self.init_schema()

    # ---- lifecycle -------------------------------------------------------

    def init_schema(self) -> None:
        """Create the tables if they do not exist (safe to call repeatedly)."""
        with self._lock:
            version = self._conn.execute("PRAGMA user_version").fetchone()[0]
            if version > SCHEMA_VERSION:
                raise DatabaseError(
                    f"database schema version {version} is newer than this app ({SCHEMA_VERSION})"
                )
            self._conn.executescript(_SCHEMA)
            self._conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ---- low-level helpers ----------------------------------------------

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """Run several writes atomically. Nested use joins the outer transaction."""
        with self._lock:
            if self._depth:
                self._depth += 1
                try:
                    yield
                finally:
                    self._depth -= 1
                return
            self._conn.execute("BEGIN IMMEDIATE")
            self._depth = 1
            try:
                yield
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            else:
                self._conn.execute("COMMIT")
            finally:
                self._depth = 0

    def _run(self, sql: str, params: Sequence[Any] = ()) -> int:
        with self._lock:
            return self._conn.execute(sql, params).rowcount

    def _all(self, sql: str, params: Sequence[Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    def _one(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(sql, params).fetchone()

    def _count(self, sql: str, params: Sequence[Any] = ()) -> int:
        row = self._one(sql, params)
        return int(row[0]) if row else 0

    def table_columns(self) -> dict[str, list[str]]:
        """``{table: [column, ...]}`` for every table (used by the no-secrets test)."""
        tables = [r["name"] for r in self._all(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
        return {t: [c["name"] for c in self._all(f"PRAGMA table_info({t})")] for t in tables}

    # ---- events ----------------------------------------------------------

    def insert_event(self, event: NetEvent, match: ProviderMatch) -> None:
        """Store an event's METADATA. Body, headers and query never reach this SQL."""
        self._run(
            """INSERT INTO events (id, ts, source, tool_id, process, provider_id, provider_confidence,
                                   match_basis, host, dst_ip, dst_port, method, path, visibility,
                                   bytes_out, bytes_in, body_bytes)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (event.id, event.ts, event.source.value, match.tool_id, event.process, match.provider_id,
             match.confidence.value, match.match_basis.value, event.host, event.dst_ip, event.dst_port,
             event.method, event.path, event.visibility.value, event.bytes_out, event.bytes_in,
             event.body_bytes),
        )

    def list_events(
        self,
        provider_id: str | None = None,
        tool_id: str | None = None,
        visibility: str | None = None,
        since: str | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> Page[EventLite]:
        where, params = [], []
        for column, value in (("provider_id", provider_id), ("tool_id", tool_id), ("visibility", visibility)):
            if value is not None:
                where.append(f"e.{column} = ?")
                params.append(value)
        if since is not None:
            where.append("e.ts >= ?")
            params.append(since)
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        lim, off = clamp_page(limit, offset)
        total = self._count(f"SELECT COUNT(*) FROM events e {clause}", params)
        rows = self._all(
            f"""SELECT e.*, (SELECT COUNT(*) FROM findings f WHERE f.event_id = e.id) AS finding_count
                FROM events e {clause} ORDER BY e.ts DESC, e.rowid DESC LIMIT ? OFFSET ?""",
            [*params, lim, off],
        )
        items = [EventLite(
            id=r["id"], ts=r["ts"], source=r["source"], tool_id=r["tool_id"], process=r["process"],
            provider_id=r["provider_id"], host=r["host"], dst_ip=r["dst_ip"], dst_port=r["dst_port"],
            method=r["method"], path=r["path"], visibility=r["visibility"], bytes_out=r["bytes_out"],
            body_bytes=r["body_bytes"], finding_count=r["finding_count"]) for r in rows]
        return Page[EventLite](items=items, total=total)

    def count_events(self) -> int:
        return self._count("SELECT COUNT(*) FROM events")

    # ---- findings --------------------------------------------------------

    def insert_finding(self, finding: Finding) -> bool:
        """Store a finding. Returns False (and stores nothing) if the same
        (tool, rule, matched value) was already recorded (SOT 6.5)."""
        meta, loc = finding.meta, finding.location
        changed = self._run(
            """INSERT OR IGNORE INTO findings
               (id, event_id, tool_id, rule_id, category, severity, confidence, masked_preview,
                location_field, location_offset, owasp, controls, hash12, spans, context,
                in_tool_args, occurrences, tool_name, argument, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (finding.id, finding.event_id, finding.tool_id, finding.rule_id, finding.category.value,
             finding.severity.value, finding.confidence, finding.masked_preview, loc.field.value,
             loc.offset, _dumps(finding.owasp), _dumps(finding.controls), meta.hash12,
             _dumps([list(s) for s in meta.spans]), meta.context, int(meta.in_tool_args), meta.count,
             meta.tool_name, meta.argument, finding.created_at),
        )
        return changed == 1

    @staticmethod
    def _finding_from_row(r: sqlite3.Row) -> Finding:
        return Finding(
            id=r["id"], event_id=r["event_id"], tool_id=r["tool_id"], rule_id=r["rule_id"],
            category=r["category"], severity=r["severity"], confidence=r["confidence"],
            masked_preview=r["masked_preview"],
            location=Location(field=r["location_field"], offset=r["location_offset"]),
            owasp=json.loads(r["owasp"]), controls=json.loads(r["controls"]),
            meta=FindingMeta(
                hash12=r["hash12"], spans=[tuple(s) for s in json.loads(r["spans"])], context=r["context"],
                in_tool_args=bool(r["in_tool_args"]), count=r["occurrences"], tool_name=r["tool_name"],
                argument=r["argument"]),
            created_at=r["created_at"])

    def get_finding(self, finding_id: str) -> Finding | None:
        row = self._one("SELECT * FROM findings WHERE id = ?", (finding_id,))
        return self._finding_from_row(row) if row else None

    def list_findings(
        self,
        event_id: str | None = None,
        rule_id: str | None = None,
        category: str | None = None,
        tool_id: str | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> Page[Finding]:
        where, params = [], []
        for column, value in (("event_id", event_id), ("rule_id", rule_id),
                              ("category", category), ("tool_id", tool_id)):
            if value is not None:
                where.append(f"{column} = ?")
                params.append(value)
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        lim, off = clamp_page(limit, offset)
        total = self._count(f"SELECT COUNT(*) FROM findings {clause}", params)
        rows = self._all(
            f"SELECT * FROM findings {clause} ORDER BY created_at DESC, rowid DESC LIMIT ? OFFSET ?",
            [*params, lim, off])
        return Page[Finding](items=[self._finding_from_row(r) for r in rows], total=total)

    def count_findings(self) -> int:
        return self._count("SELECT COUNT(*) FROM findings")

    # ---- remediations ----------------------------------------------------

    def save_remediation(self, remediation: Remediation) -> Remediation:
        """Store a remediation for an alert. Idempotent: if the alert already has one,
        the existing one is kept and returned (SOT 6.7)."""
        self._run(
            """INSERT OR IGNORE INTO remediations
               (id, alert_id, summary, steps, sensitivity, verdict, data_classes, source, model,
                latency_ms, redaction_check, prompt_text, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (remediation.id, remediation.alert_id, remediation.summary, _dumps(remediation.steps),
             remediation.sensitivity.value, remediation.verdict.value, _dumps(remediation.data_classes),
             remediation.source.value, remediation.model, remediation.latency_ms,
             remediation.redaction_check.value, remediation.prompt_text, remediation.created_at),
        )
        stored = self.get_remediation(remediation.alert_id)
        assert stored is not None
        return stored

    @staticmethod
    def _remediation_from_row(r: sqlite3.Row) -> Remediation:
        return Remediation(
            id=r["id"], alert_id=r["alert_id"], summary=r["summary"], steps=json.loads(r["steps"]),
            sensitivity=r["sensitivity"], verdict=r["verdict"], data_classes=json.loads(r["data_classes"]),
            source=r["source"], model=r["model"], latency_ms=r["latency_ms"],
            redaction_check=r["redaction_check"], prompt_text=r["prompt_text"], created_at=r["created_at"])

    def get_remediation(self, alert_id: str) -> Remediation | None:
        row = self._one("SELECT * FROM remediations WHERE alert_id = ?", (alert_id,))
        return self._remediation_from_row(row) if row else None

    def count_remediations_by_source(self) -> dict[str, int]:
        rows = self._all("SELECT source, COUNT(*) AS n FROM remediations GROUP BY source")
        return {r["source"]: r["n"] for r in rows}

    # ---- alerts ----------------------------------------------------------

    def insert_alert(self, alert: Alert) -> None:
        """Store an alert (and its remediation, if it has one). The alert's finding must
        already be stored."""
        with self.transaction():
            self._run(
                """INSERT INTO alerts (id, finding_id, tool_id, provider_id, rule_id, severity, title,
                                       status, created_at, acked_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (alert.id, alert.finding_id, alert.tool_id, alert.provider_id, alert.rule_id,
                 alert.severity.value, alert.title, alert.status.value, alert.created_at, alert.acked_at),
            )
            if alert.remediation is not None:
                self.save_remediation(alert.remediation)

    def _alerts_from_rows(self, rows: list[sqlite3.Row]) -> list[Alert]:
        if not rows:
            return []
        findings = self._by_ids("findings", "id", [r["finding_id"] for r in rows])
        remediations = self._by_ids("remediations", "alert_id", [r["id"] for r in rows])
        out = []
        for r in rows:
            rem = remediations.get(r["id"])
            out.append(Alert(
                id=r["id"], finding_id=r["finding_id"], tool_id=r["tool_id"], provider_id=r["provider_id"],
                rule_id=r["rule_id"], severity=r["severity"], title=r["title"], status=r["status"],
                created_at=r["created_at"], acked_at=r["acked_at"],
                finding=self._finding_from_row(findings[r["finding_id"]]),
                remediation=self._remediation_from_row(rem) if rem else None))
        return out

    def _by_ids(self, table: str, column: str, ids: list[str]) -> dict[str, sqlite3.Row]:
        found: dict[str, sqlite3.Row] = {}
        for start in range(0, len(ids), 400):  # stay far below SQLite's parameter limit
            chunk = ids[start:start + 400]
            marks = ",".join("?" * len(chunk))
            for row in self._all(f"SELECT * FROM {table} WHERE {column} IN ({marks})", chunk):
                found[row[column]] = row
        return found

    def get_alert(self, alert_id: str) -> Alert | None:
        row = self._one("SELECT * FROM alerts WHERE id = ?", (alert_id,))
        return self._alerts_from_rows([row])[0] if row else None

    def list_alerts(
        self,
        severity: Sequence[str] | None = None,
        status: str | None = None,
        tool_id: str | None = None,
        rule_id: str | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> Page[Alert]:
        where, params = [], []
        if severity:
            levels = [Severity(s).value for s in severity]  # ValueError on an unknown level
            where.append(f"severity IN ({','.join('?' * len(levels))})")
            params.extend(levels)
        if status is not None:
            where.append("status = ?")
            params.append(AlertStatus(status).value)
        for column, value in (("tool_id", tool_id), ("rule_id", rule_id)):
            if value is not None:
                where.append(f"{column} = ?")
                params.append(value)
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        lim, off = clamp_page(limit, offset)
        total = self._count(f"SELECT COUNT(*) FROM alerts {clause}", params)
        rows = self._all(
            f"SELECT * FROM alerts {clause} ORDER BY created_at DESC, rowid DESC LIMIT ? OFFSET ?",
            [*params, lim, off])
        return Page[Alert](items=self._alerts_from_rows(rows), total=total)

    def ack_alert(self, alert_id: str, at: str | None = None) -> Alert | None:
        """Acknowledge an alert (idempotent). Returns None if there is no such alert."""
        with self.transaction():
            alert = self.get_alert(alert_id)
            if alert is None:
                return None
            if alert.status is AlertStatus.ACKED:
                return alert
            acked = alert.acknowledge(at)
            self._run("UPDATE alerts SET status = 'acked', acked_at = ? WHERE id = ? AND status = 'open'",
                      (acked.acked_at, alert_id))
            return acked

    def count_open_alerts(self) -> int:
        return self._count("SELECT COUNT(*) FROM alerts WHERE status = 'open'")

    # ---- agent activity --------------------------------------------------

    def add_agent_activity(self, tool_id: str, activity: AgentActivity) -> None:
        self._run(
            """INSERT INTO agent_activity (tool_id, ts, capability, kind, risky, name, rule_id, finding_id, argument)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (tool_id, activity.ts, activity.capability.value, activity.kind.value, int(activity.risky),
             activity.name, activity.rule_id, activity.finding_id, activity.argument),
        )

    def list_agent_activity(self, tool_id: str, limit: int = 100) -> list[AgentActivity]:
        """The last ``limit`` (max 100) actions of a tool, oldest first."""
        rows = self._all(
            "SELECT * FROM agent_activity WHERE tool_id = ? ORDER BY id DESC LIMIT ?",
            (tool_id, max(1, min(limit, 100))))
        return [AgentActivity(
            ts=r["ts"], capability=r["capability"], kind=r["kind"], risky=bool(r["risky"]), name=r["name"],
            rule_id=r["rule_id"], finding_id=r["finding_id"], argument=r["argument"]) for r in reversed(rows)]

    # ---- AI call ledger --------------------------------------------------

    def add_llm_call(self, call: LlmCall) -> None:
        self._run(
            "INSERT INTO llm_calls (id, ts, alert_id, model, bytes, status, prompt_sha256, latency_ms) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (call.id, call.ts, call.alert_id, call.model, call.bytes, call.status.value,
             call.prompt_sha256, call.latency_ms))

    def list_llm_calls(self, limit: int | None = None, offset: int | None = None) -> Page[LlmCall]:
        lim, off = clamp_page(limit, offset)
        total = self._count("SELECT COUNT(*) FROM llm_calls")
        rows = self._all("SELECT * FROM llm_calls ORDER BY ts DESC, rowid DESC LIMIT ? OFFSET ?", (lim, off))
        items = [LlmCall(id=r["id"], ts=r["ts"], alert_id=r["alert_id"], model=r["model"], bytes=r["bytes"],
                         status=r["status"], prompt_sha256=r["prompt_sha256"], latency_ms=r["latency_ms"])
                 for r in rows]
        return Page[LlmCall](items=items, total=total)

    def egress_summary(self) -> EgressSummary:
        by_status = {r["status"]: r["n"] for r in self._all(
            "SELECT status, COUNT(*) AS n FROM llm_calls GROUP BY status")}
        return EgressSummary(
            sent=by_status.get("sent", 0), blocked=by_status.get("blocked", 0),
            failed=by_status.get("failed", 0),
            template_fallbacks=self.count_remediations_by_source().get("template", 0))

    # ---- provider sanction overrides ------------------------------------

    def set_provider_override(self, provider_id: str, sanctioned: bool) -> None:
        self._run(
            """INSERT INTO provider_overrides (provider_id, sanctioned, updated_at) VALUES (?,?,?)
               ON CONFLICT(provider_id) DO UPDATE SET sanctioned = excluded.sanctioned,
                                                      updated_at = excluded.updated_at""",
            (provider_id, int(sanctioned), utc_now_iso()))

    def get_provider_overrides(self) -> dict[str, bool]:
        return {r["provider_id"]: bool(r["sanctioned"])
                for r in self._all("SELECT provider_id, sanctioned FROM provider_overrides")}

    # ---- transcript read offsets ----------------------------------------

    def set_offset(self, path: str, inode: int | None, offset: int) -> None:
        self._run(
            """INSERT INTO source_offsets (path, inode, offset, updated_at) VALUES (?,?,?,?)
               ON CONFLICT(path) DO UPDATE SET inode = excluded.inode, offset = excluded.offset,
                                               updated_at = excluded.updated_at""",
            (path, inode, offset, utc_now_iso()))

    def get_offset(self, path: str) -> tuple[int | None, int] | None:
        """``(inode, offset)`` for a file, or None if it was never read."""
        row = self._one("SELECT inode, offset FROM source_offsets WHERE path = ?", (path,))
        return (row["inode"], row["offset"]) if row else None

    # ---- counters --------------------------------------------------------

    def bump_counter(self, name: str, amount: int = 1) -> None:
        self._run(
            """INSERT INTO counters (name, amount) VALUES (?, ?)
               ON CONFLICT(name) DO UPDATE SET amount = amount + excluded.amount""",
            (name, amount))

    def get_counter(self, name: str) -> int:
        return self._count("SELECT amount FROM counters WHERE name = ?", (name,))

    # ---- reset -----------------------------------------------------------

    def reset(self) -> None:
        """Clear everything the Reset button clears (SOT 6.7). Offsets are kept."""
        with self.transaction():
            for table in _RESET_ORDER:
                self._run(f"DELETE FROM {table}")


def open_database(config: Config) -> Database:
    """Open the database at ``config.db_path``, creating its folder if needed."""
    return Database(config.db_path)

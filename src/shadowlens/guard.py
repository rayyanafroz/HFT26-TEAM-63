"""Guard events: what the prevention side of Shadow Lens stopped, redacted or let through.

The browser extension (through the native messaging host), the Claude Code hooks, the clipboard watcher
and the ``scan`` command all report here. An event holds what happened and masks of what was found
(``sk-p... (len 56)``) with keyed hashes; never the text itself. ``clean_event`` enforces that on the way
in, whatever the sender claims to send.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any

SOURCES = frozenset({"browser", "claude_code", "clipboard", "cli"})
ACTIONS = frozenset({
    "redacted", "cleaned", "cancelled", "blocked", "sent_anyway", "pasted_anyway", "uploaded_anyway",
    "sent_unchecked", "noted", "warned", "allowed",
})
# Actions where something sensitive was kept from leaving, and where it left anyway.
STOPPED = frozenset({"redacted", "cleaned", "cancelled", "blocked"})
LET_THROUGH = frozenset({"sent_anyway", "pasted_anyway", "uploaded_anyway", "sent_unchecked"})

_HASH12 = re.compile(r"^[0-9a-f]{12}$")
_RULE = re.compile(r"^[A-Z][A-Z0-9_]{1,39}$")
_SEVERITIES = frozenset({"critical", "high", "medium", "low", "none"})
# The shapes a mask can have (masking.py): four characters then "...", "****" and the last four, or
# "j***@domain". The browser puts a file name in front for files ("notes.txt: ****1111").
_MASK = re.compile(r"^(?:[^\n:]{1,80}: )?(?:\S{0,4}\.\.\. \(len \d+\)|\*{4}\S{0,4}|\S\*\*\*@[A-Za-z0-9.-]{1,253})$")
# Rules whose "mask" is a description (what hidden characters spell, the phrase aimed at the AI).
_DESCRIBED_RULES = frozenset({"HIDDEN_TEXT", "INJECTION_PHRASE"})
# A run this long of key-like characters is a value, not a mask or a description.
_TOKEN_RUN = re.compile(r"[A-Za-z0-9_+/=-]{20,}")


def _safe_mask(rule_id: str, mask: str) -> str:
    """The mask if it has a mask's shape (or is a harmless description); otherwise nothing."""
    if not mask:
        return ""
    if rule_id in _DESCRIBED_RULES:
        return "" if _TOKEN_RUN.search(mask) else mask
    prefix = mask.split(": ", 1)[0] if ": " in mask else ""
    return mask if _MASK.match(mask) and not _TOKEN_RUN.search(prefix) else ""


def _iso(value: Any) -> str:
    """Milliseconds since the epoch (the extension's clock) or an ISO string, as UTC ISO."""
    if isinstance(value, (int, float)) and value > 0:
        return datetime.fromtimestamp(value / 1000, tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        except ValueError:
            pass
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _text(value: Any, limit: int) -> str:
    return re.sub(r"[\x00-\x1f\x7f]", " ", str(value))[:limit] if value is not None else ""


def clean_finding(raw: Any) -> dict[str, str] | None:
    if not isinstance(raw, dict) or not _RULE.match(str(raw.get("rule_id", ""))):
        return None
    rule_id = str(raw["rule_id"])
    # Anything not shaped like a mask is dropped rather than stored: it could be a raw value.
    mask = _safe_mask(rule_id, _text(raw.get("masked_preview"), 160))
    hash12 = str(raw.get("hash12", ""))
    severity = str(raw.get("severity", "")).lower()
    return {
        "rule_id": rule_id,
        "hash12": hash12 if _HASH12.match(hash12) else "",
        "masked_preview": mask,
        "severity": severity if severity in _SEVERITIES else "",
    }


def clean_event(raw: Any, source: str) -> dict[str, Any] | None:
    """A guard event as it may be stored, or ``None`` if it is not one."""
    if not isinstance(raw, dict) or source not in SOURCES:
        return None
    action = str(raw.get("action", ""))
    if action not in ACTIONS:
        return None
    raw_id = str(raw.get("id", ""))
    event_id = raw_id if re.fullmatch(r"[A-Za-z0-9_-]{4,64}", raw_id) else uuid.uuid4().hex
    severity = str(raw.get("severity", "none")).lower()
    findings = [f for f in map(clean_finding, raw.get("findings") or []) if f][:50]
    return {
        "id": f"{source}:{event_id}",
        "at": _iso(raw.get("at")),
        "source": source,
        "site": _text(raw.get("site") or "unknown", 60),
        "action": action,
        "kind": _text(raw.get("kind") or "submit", 20),
        "severity": severity if severity in _SEVERITIES else "none",
        "reason": _text(raw.get("reason"), 300) or None,
        "findings": findings,
    }


def record(db: Any, raw: Any, source: str) -> dict[str, Any] | None:
    """Store one event (once: the same id twice is stored once). Returns what was stored."""
    event = clean_event(raw, source)
    if event is None:
        return None
    db.insert_guard_event(event)
    return event


class GuardWatcher:
    """Tells the dashboard when guard events arrive. They are written by other processes (the native
    messaging host, the hooks), so the server notices them by watching the table, every ``interval_s``."""

    def __init__(self, db: Any, publish: Any, interval_s: float = 1.5):
        import threading  # noqa: PLC0415 - only the server needs it

        self._db, self._publish, self._interval = db, publish, interval_s
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="shadowlens-guard-watch", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=5)

    def _run(self) -> None:
        try:
            last = self._db.guard_cursor()
        except Exception:  # noqa: BLE001 - the database may be closing; nothing to watch
            return
        while not self._stop.wait(self._interval):
            try:
                cursor = self._db.guard_cursor()
            except Exception:  # noqa: BLE001
                continue
            if cursor > last:
                last = cursor
                self._publish("guard.new", {"cursor": cursor})

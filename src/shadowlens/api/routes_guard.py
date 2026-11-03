"""What the guard stopped: ``GET /api/guard/summary`` and ``GET /api/guard/events``.

Guard events come from the browser extension (through the native messaging host), the Claude Code hooks,
the clipboard watcher and the ``scan`` command. They hold masks and keyed hashes, never text.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Query

from .. import native_host
from ..core.rule_titles import title_for
from ..db import Database
from ..guard import LET_THROUGH, STOPPED
from .deps import get_db

router = APIRouter(prefix="/api/guard")


def _title(rule_id: str) -> str:
    return title_for(rule_id).removesuffix(" sent to an AI tool")


def _companion_installed() -> bool:
    try:
        return any(line.endswith(": installed") for line in native_host.status(Path.home()))
    except Exception:  # noqa: BLE001 - only a hint for the screen
        return False


@router.get("/summary")
def summary(days: int = Query(30, ge=1, le=365), db: Database = Depends(get_db)) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    since = (now - timedelta(days=days - 1)).replace(hour=0, minute=0, second=0, microsecond=0)
    events = db.guard_events_since(since.isoformat(timespec="milliseconds").replace("+00:00", "Z"))
    totals = Counter(e["action"] for e in events)
    stopped = sum(n for a, n in totals.items() if a in STOPPED)
    let_through = sum(n for a, n in totals.items() if a in LET_THROUGH)

    sites: dict[str, Counter] = defaultdict(Counter)
    rules: Counter = Counter()
    rule_severity: dict[str, str] = {}
    sources: Counter = Counter()
    daily: dict[str, Counter] = {(since + timedelta(days=i)).date().isoformat(): Counter() for i in range(days)}
    for e in events:
        group = "stopped" if e["action"] in STOPPED else "let_through" if e["action"] in LET_THROUGH else "noted"
        sites[e["site"]][group] += 1
        sources[e["source"]] += 1
        day = e["at"][:10]
        if day in daily:
            daily[day][group] += 1
        if group != "noted":
            for f in e["findings"]:
                rules[f["rule_id"]] += 1
                rule_severity.setdefault(f["rule_id"], f.get("severity") or "")
    return {
        "days": days,
        "totals": {"events": len(events), "stopped": stopped, "let_through": let_through,
                   "noted": totals.get("noted", 0), "by_action": dict(totals)},
        "sites": sorted(({"site": s, **{k: c.get(k, 0) for k in ("stopped", "let_through", "noted")}} for s, c in sites.items()),
                        key=lambda r: -(r["stopped"] + r["let_through"])),
        "rules": [{"rule_id": r, "title": _title(r), "severity": rule_severity.get(r, ""), "count": n} for r, n in rules.most_common()],
        "sources": dict(sources),
        "daily": [{"day": d, "stopped": c.get("stopped", 0), "let_through": c.get("let_through", 0)} for d, c in daily.items()],
        "last_event_at": db.last_guard_event_at(),
        "last_browser_event_at": db.last_guard_event_at("browser"),
        "companion_installed": _companion_installed(),
    }


@router.get("/events")
def events(limit: int | None = None, offset: int | None = None, db: Database = Depends(get_db)) -> dict[str, Any]:
    items, total = db.list_guard_events(limit, offset)
    for item in items:
        for f in item["findings"]:
            f["title"] = _title(f["rule_id"])
    return {"items": items, "total": total}

"""Reads a scenario template and gives each line a real timestamp (SOT 7.2).

The returned lines are in the HTTP log format (SOT 6.3), ready for the log parser.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from shadowlens.fakes import expand

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
SCENARIO_NAMES = ("clean_baseline", "full_demo", "agent_attack", "quick_leak")


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def read_lines(name: str) -> list[dict[str, Any]]:
    """The scenario's lines with fakes expanded, still using ``t_ms``. An unknown name is a ``ValueError``."""
    if name not in SCENARIO_NAMES:
        raise ValueError(f"unknown scenario: {name!r}")
    lines = []
    for raw in (TEMPLATE_DIR / f"{name}.jsonl").read_text(encoding="utf-8").splitlines():
        if raw.strip():
            lines.append(json.loads(expand(raw)))
    return lines


def duration_s(name: str, speed: float = 1.0) -> float:
    """How long ``/api/demo/play`` takes at this speed."""
    return max(line["t_ms"] for line in read_lines(name)) / 1000 / _valid_speed(speed)


def _valid_speed(speed: float) -> float:
    return speed if speed > 0 else 1.0


def schedule(name: str, now: datetime | None = None, speed: float | None = None) -> list[dict[str, Any]]:
    """Lines with ``ts`` in place of ``t_ms``.

    Without ``speed`` (load-scenario): the run ends at ``now``, so it appears to have
    just happened. With ``speed`` (play): it starts at ``now`` and each line's ``ts``
    is when to send it.
    """
    start = now or datetime.now(timezone.utc)
    lines = read_lines(name)
    last = max(line["t_ms"] for line in lines)
    timed = []
    for line in lines:
        t_ms = line.pop("t_ms")
        if speed is None:
            moment = start - timedelta(milliseconds=last - t_ms)
        else:
            moment = start + timedelta(milliseconds=t_ms / _valid_speed(speed))
        timed.append({"ts": _iso(moment), **line})
    return timed

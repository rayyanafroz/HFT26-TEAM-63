"""Read a demo scenario file and turn it into timed events (SOT 7.2, "scenario loader").

A scenario is ``scenarios/templates/<name>.jsonl``: log lines (SOT 6.3) whose time is a
``t_ms`` offset from the start. This module only reads them; the files themselves, and the
fake secrets in them, are written by the analysis side.

Two ways to use one:
  * load: every event at once, with times shifted so the LAST event is "now";
  * play: events arrive in real time (``t_ms / speed`` seconds after the start).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ..models import NetEvent
from .http_log import DEFAULT_MAX_BODY_BYTES, Expander, LogLineError, event_from_record, split_lines

# <repo>/scenarios/templates, found relative to this file (src/shadowlens/ingest/scenarios.py).
DEFAULT_TEMPLATES_DIR = Path(__file__).resolve().parents[3] / "scenarios" / "templates"
_NAME = re.compile(r"^[a-z0-9_]{1,64}$")


class ScenarioNotFound(LookupError):
    """There is no template with that name."""


class ScenarioError(ValueError):
    """A template exists but cannot be used. The message holds no file content."""


@dataclass(frozen=True)
class TimedEvent:
    delay_s: float          # seconds after the start at which it should be ingested (0 for "load")
    event: NetEvent


def template_path(name: str, templates_dir: Path = DEFAULT_TEMPLATES_DIR) -> Path:
    if not _NAME.fullmatch(name):                            # no slashes, dots or ".."
        raise ScenarioNotFound(name)
    path = Path(templates_dir) / f"{name}.jsonl"
    if not path.is_file():
        raise ScenarioNotFound(name)
    return path


def read_records(name: str, templates_dir: Path = DEFAULT_TEMPLATES_DIR) -> list[dict[str, Any]]:
    path = template_path(name, templates_dir)
    records: list[dict[str, Any]] = []
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        raise ScenarioError(f"scenario '{name}' cannot be read") from exc
    for number, line in enumerate(split_lines(text), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ScenarioError(f"scenario '{name}' line {number} is not valid JSON") from exc
        if not isinstance(record, dict) or not isinstance(record.get("t_ms"), int) or record["t_ms"] < 0:
            raise ScenarioError(f"scenario '{name}' line {number} needs an integer 't_ms' of 0 or more")
        records.append(record)
    if not records:
        raise ScenarioError(f"scenario '{name}' is empty")
    return records


def build_events(
    name: str,
    *,
    play: bool,
    speed: float = 1.0,
    templates_dir: Path = DEFAULT_TEMPLATES_DIR,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    expand: Expander | None = None,
    now: datetime | None = None,
) -> list[TimedEvent]:
    """The scenario's events, in time order.

    ``play=False`` (load): all delays are 0 and timestamps end at ``now``.
    ``play=True``: delays are ``t_ms / speed`` and timestamps start at ``now`` and match the delays.
    """
    if speed <= 0:
        raise ScenarioError("speed must be above 0")
    now = now or datetime.now(timezone.utc)
    records = read_records(name, templates_dir)
    last_ms = max(r["t_ms"] for r in records)
    out: list[TimedEvent] = []
    for number, record in enumerate(sorted(records, key=lambda r: r["t_ms"]), start=1):
        record = {**record, "source": record.get("source", "scenario")}      # a line may say pcap, conn_scan...
        if play:
            record["t_ms"] = int(record["t_ms"] / speed)
            base = now
        else:
            base = now - timedelta(milliseconds=last_ms)
        try:
            event = event_from_record(record, base_time=base, max_body_bytes=max_body_bytes, expand=expand)
        except LogLineError as exc:
            raise ScenarioError(f"scenario '{name}' event {number}: {exc}") from exc
        out.append(TimedEvent(delay_s=record["t_ms"] / 1000 if play else 0.0, event=event))
    return out


def duration_s(name: str, speed: float = 1.0, templates_dir: Path = DEFAULT_TEMPLATES_DIR) -> float:
    """How long playing the scenario takes at this speed."""
    records = read_records(name, templates_dir)
    return max(r["t_ms"] for r in records) / 1000 / speed

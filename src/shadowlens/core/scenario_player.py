"""Load or play a demo scenario (SOT 6.7, ``/api/demo/*``).

``load`` puts all of a scenario's events in at once. ``play`` feeds them in over time,
telling the dashboard how far along it is (``scenario.progress``), so the 10-second leak
demo happens live. Only one scenario plays at a time; starting another stops the first.
"""

from __future__ import annotations

import logging
import threading
import time
from pathlib import Path
from typing import Any, Callable

from ..models import IngestSummary, PlayScenarioResponse, ScenarioStatus
from ..ingest import scenarios
from ..ingest.http_log import Expander
from .pipeline import Pipeline

log = logging.getLogger("shadowlens.scenario")

Publish = Callable[[str, "dict[str, Any]"], None]


class ScenarioPlayer:
    def __init__(
        self,
        pipeline: Pipeline,
        publish: Publish,
        *,
        templates_dir: Path = scenarios.DEFAULT_TEMPLATES_DIR,
        max_body_bytes: int,
        expand: Callable[[], Expander | None] | None = None,
    ):
        self._pipeline = pipeline
        self._publish = publish
        self._templates_dir = Path(templates_dir)
        self._max_body = max_body_bytes
        self._expand = expand or (lambda: None)
        self._lock = threading.RLock()          # guards the state below
        self._ops = threading.Lock()            # one load / play / stop at a time (see _halt)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._name: str | None = None
        self._played = 0
        self._total = 0

    # ---- state -----------------------------------------------------------

    @property
    def playing(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def name(self) -> str | None:
        return self._name

    def status(self) -> ScenarioStatus:
        with self._lock:
            played = min(self._played, self._total)              # the status endpoint must never fail on a number
            return ScenarioStatus(name=self._name, played=played, total=self._total)

    def _progress(self) -> None:
        self._publish("scenario.progress", {"name": self._name, "played": self._played, "total": self._total})

    def _build(self, name: str, *, play: bool, speed: float = 1.0):
        return scenarios.build_events(
            name, play=play, speed=speed, templates_dir=self._templates_dir,
            max_body_bytes=self._max_body, expand=self._expand())

    # ---- load: everything now ---------------------------------------------

    def load(self, name: str) -> IngestSummary:
        """Add all of a scenario's events at once, timed so the last one is 'now'."""
        with self._ops:
            self._halt()                                 # before taking the state lock: the old thread needs it to finish
            with self._lock:
                timed = self._build(name, play=False)
                self._name, self._played, self._total = name, len(timed), len(timed)
                summary = self._pipeline.ingest([t.event for t in timed], source="scenario")
                self._progress()
                return summary

    # ---- play: events over time -------------------------------------------

    def play(self, name: str, speed: float = 1.0) -> PlayScenarioResponse:
        """Start feeding a scenario in real time. Returns at once; playback runs in the background."""
        with self._ops:                                  # two requests at once must not both think the way is clear
            self._halt()
            with self._lock:
                timed = self._build(name, play=True, speed=speed)
                self._name, self._played, self._total = name, 0, len(timed)
                self._stop = stop = threading.Event()    # a fresh flag: an old thread keeps seeing its own
                self._thread = threading.Thread(
                    target=self._run, args=(timed, stop), name="shadowlens-scenario", daemon=True)
                self._thread.start()
                self._progress()
                return PlayScenarioResponse(name=name, total=len(timed), duration_s=timed[-1].delay_s if timed else 0.0)

    def _run(self, timed: list[scenarios.TimedEvent], stop: threading.Event) -> None:
        started = time.monotonic()
        try:
            for item in timed:
                wait = started + item.delay_s - time.monotonic()      # on schedule, however long ingesting took
                if wait > 0 and stop.wait(wait):
                    return                                            # stopped while waiting
                if stop.is_set():
                    return
                self._pipeline.ingest([item.event], source="scenario")
                with self._lock:
                    if stop.is_set():
                        return
                    self._played += 1
                    self._progress()
        except Exception:  # noqa: BLE001 - playback must never take the app down
            log.exception("scenario playback failed")

    def stop(self) -> None:
        """Stop a playing scenario (what has been played stays)."""
        with self._ops:
            self._halt()

    def _halt(self) -> None:
        """Stop the playback thread and wait for it. Only called while holding ``_ops``."""
        with self._lock:
            self._stop.set()
            thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=5)
        with self._lock:
            self._thread = None

    def clear(self) -> None:
        """Forget which scenario was shown (after a reset)."""
        with self._lock:
            self._name, self._played, self._total = None, 0, 0

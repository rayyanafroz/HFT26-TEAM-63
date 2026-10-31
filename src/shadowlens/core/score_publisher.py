"""Tell the dashboard when the score changes, at most 4 times a second (SOT 4.2, 6.8).

Live sources call ``notify`` after every batch of events. If the last message was sent
less than 250 ms ago, one message is scheduled for when that time is up, so a burst of
events produces a few updates and the last word is never lost.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Callable

from pydantic import BaseModel

from ..models import ScoreUpdate
from .views import Insights

log = logging.getLogger("shadowlens.score")

MIN_INTERVAL_S = 0.25


class ScorePublisher:
    def __init__(
        self,
        insights: Insights,
        publish: Callable[[str, BaseModel], None],
        *,
        min_interval_s: float = MIN_INTERVAL_S,
        clock: Callable[[], float] = time.monotonic,
    ):
        self._insights = insights
        self._publish = publish
        self._min_interval = min_interval_s
        self._clock = clock
        self._lock = threading.Lock()
        self._last = float("-inf")
        self._timer: threading.Timer | None = None
        self._closed = False

    def notify(self) -> None:
        """Something may have changed: send an update now, or schedule one if we just sent one."""
        with self._lock:
            if self._closed:
                return
            wait = self._last + self._min_interval - self._clock()
            if wait > 0:
                if self._timer is None:                      # one pending update is enough
                    self._timer = threading.Timer(wait, self._fire)
                    self._timer.daemon = True
                    self._timer.start()
                return
            self._last = self._clock()
        self._send()

    def publish_now(self) -> None:
        """Send an update immediately (used after approving a provider)."""
        with self._lock:
            if self._closed:
                return
            self._last = self._clock()
        self._send()

    def close(self) -> None:
        with self._lock:
            self._closed = True
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None

    def _fire(self) -> None:
        with self._lock:
            self._timer = None
            if self._closed:
                return
            self._last = self._clock()
        self._send()

    def _send(self) -> None:
        try:
            top = self._insights.top_tools(1)
            self._publish("score.update", ScoreUpdate(risk=self._insights.risk(), tool=top[0] if top else None))
        except Exception:  # noqa: BLE001 - a scoring problem must never break ingest
            log.exception("could not publish a score update")

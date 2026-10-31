"""Control of what is being watched right now, and the status the Capture screen shows (SOT 6.7).

Three live inputs are managed here:
  * the process scan (looks at open connections every few seconds; off unless asked for),
  * the live log tail (watches ``data/live/``; on by default),
  * demo scenarios (load or play).
The transcript reader and the Ollama tap are added in later steps; their status blocks are
already in the answer so the screen does not change shape when they arrive.
"""

from __future__ import annotations

import logging
import sys
import threading
from typing import Callable

from ..config import Config
from ..ingest.conn_scan import ConnectionScanner, is_privileged, scan_scope
from ..ingest.live_tail import LiveTail
from ..models import (
    CaptureMode,
    CaptureStatus,
    IngestSummary,
    LiveTailStatus,
    Platform,
    ProxyStatus,
    ScanStatus,
    TranscriptsStatus,
    utc_now_iso,
)
from .pipeline import Pipeline
from .scenario_player import ScenarioPlayer

log = logging.getLogger("shadowlens.capture")

DEFAULT_SCAN_INTERVAL_S = 2.0         # used when the scan is switched on but the config says 0


def current_platform() -> Platform:
    if sys.platform.startswith("win"):
        return Platform.WINDOWS
    if sys.platform == "darwin":
        return Platform.DARWIN
    return Platform.LINUX


class CaptureManager:
    def __init__(
        self,
        config: Config,
        pipeline: Pipeline,
        scanner: ConnectionScanner,
        tail: LiveTail,
        player: ScenarioPlayer,
        *,
        privileged: Callable[[], bool] = is_privileged,
    ):
        self.config = config
        self.pipeline = pipeline
        self.scanner = scanner
        self.tail = tail
        self.player = player
        self._privileged = privileged
        self._lock = threading.RLock()
        self._scan_stop = threading.Event()
        self._scan_thread: threading.Thread | None = None
        self._scan_interval = config.scan_interval_s or DEFAULT_SCAN_INTERVAL_S
        self._last_scan_at: str | None = None
        self._psutil_ok = True

    # ---- process scan ----------------------------------------------------

    @property
    def scan_running(self) -> bool:
        return self._scan_thread is not None and self._scan_thread.is_alive()

    def scan_once(self) -> IngestSummary:
        """Look at the open connections now (``POST /api/scan/connections``)."""
        with self._lock:
            result = self.scanner.scan()
            self._psutil_ok = result.psutil_ok
            self._last_scan_at = utc_now_iso()
            errors = [result.error] if result.error else []
            return self.pipeline.ingest(result.events, source="conn_scan", errors=errors)

    def _scan_loop(self, stop: threading.Event) -> None:
        while not stop.is_set():
            try:
                self.scan_once()
            except Exception:  # noqa: BLE001 - the scan must never die
                log.exception("connection scan failed")
            stop.wait(self._scan_interval)

    def start_scan(self) -> None:
        with self._lock:
            if self.scan_running:
                return
            self._scan_stop = threading.Event()
            self._scan_thread = threading.Thread(
                target=self._scan_loop, args=(self._scan_stop,), name="shadowlens-scan", daemon=True)
            self._scan_thread.start()

    def stop_scan(self) -> None:
        with self._lock:
            self._scan_stop.set()
            thread, self._scan_thread = self._scan_thread, None
        if thread is not None:
            thread.join(timeout=5)

    # ---- on/off from the dashboard ---------------------------------------

    def start(self, scan: bool | None = None, tail: bool | None = None) -> CaptureStatus:
        """Switch on the scan and/or the tail. Naming neither switches on both."""
        both = scan is None and tail is None
        if scan or both:
            self.start_scan()
        if tail or both:
            self.tail.start()
        return self.status()

    def stop(self, scan: bool | None = None, tail: bool | None = None) -> CaptureStatus:
        """Switch off the scan and/or the tail. Naming neither switches off both."""
        both = scan is None and tail is None
        if scan or both:
            self.stop_scan()
        if tail or both:
            self.tail.stop()
        return self.status()

    def start_defaults(self) -> None:
        """What happens when the app starts: the tail is on; the scan only if the config asks for it."""
        self.tail.start()
        if self.config.scan_interval_s > 0:
            self.start_scan()

    def shutdown(self) -> None:
        self.player.stop()
        self.stop_scan()
        self.tail.stop()

    def reset(self) -> None:
        """The Reset button: stop playback, clear all results and forget the scenario."""
        self.player.stop()
        self.pipeline.reset()
        self.player.clear()
        with self._lock:                                 # the next scan must see everything again
            self.scanner.forget()

    # ---- the answer for the Capture screen --------------------------------

    def status(self) -> CaptureStatus:
        scanning, watching, playing = self.scan_running, self.tail.running, self.player.playing
        mode = (CaptureMode.PLAYING if playing else CaptureMode.SCANNING if scanning
                else CaptureMode.WATCHING if watching else CaptureMode.IDLE)
        privileged = self._privileged()
        cfg = self.config
        return CaptureStatus(
            mode=mode,
            scan=ScanStatus(enabled=scanning, interval_s=self._scan_interval, last_scan_at=self._last_scan_at,
                            scope=scan_scope(privileged, self._psutil_ok), privileged=privileged,
                            psutil_ok=self._psutil_ok),
            live_tail=LiveTailStatus(enabled=watching, dir=str(self.tail.directory),
                                     lines_ingested=self.tail.lines_ingested),
            transcripts=TranscriptsStatus(enabled=False),                  # filled in with the transcript reader
            proxy=ProxyStatus(enabled=False, listen_port=cfg.proxy_port, upstream=cfg.proxy_upstream,
                              upstream_ok=False),                          # filled in with the Ollama tap
            platform=current_platform(),
            scenario=self.player.status())

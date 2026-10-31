"""Which AI websites are open in the browser (SOT 2.8: browser traffic is HTTPS, so this is metadata only).

Browsers keep a local history database of every page visited: address and time. We read a COPY of it (the
browser keeps the original locked) and turn each visit to an AI site into a ``metadata_only`` event whose
host is known, so the tool shows up with its provider, is policy-checked and scored like any other.

What this cannot see: anything typed on the page. The conversation itself travels encrypted; only a HAR export
or an extension could expose it. Page titles are never read, and only the address without its query string is kept.
"""

from __future__ import annotations

import logging
import os
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

from ..models import NetEvent, Source, utc_now_iso
from .http_log import event_from_record

log = logging.getLogger("shadowlens.browser")

POLL_S = 3.0
BACKFILL_S = 30 * 60                      # "Scan existing history": the last half hour
REPEAT_S = 30.0                           # one event per (browser, site) at most this often
_CHROMIUM_EPOCH_US = 11_644_473_600 * 1_000_000   # 1601-01-01 to 1970-01-01

IngestFn = Callable[..., object]


@dataclass(frozen=True)
class HistoryFile:
    browser: str                          # becomes the event's process name
    path: Path
    engine: str                           # "chromium" | "firefox"


def _roots(home: Path) -> list[tuple[str, str, Path]]:
    """(browser, engine, folder that holds the profiles) for this platform."""
    local = Path(os.environ.get("LOCALAPPDATA", home / "AppData" / "Local"))
    roaming = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
    if sys.platform.startswith("win"):
        return [("chrome", "chromium", local / "Google" / "Chrome" / "User Data"),
                ("msedge", "chromium", local / "Microsoft" / "Edge" / "User Data"),
                ("brave", "chromium", local / "BraveSoftware" / "Brave-Browser" / "User Data"),
                ("chromium", "chromium", local / "Chromium" / "User Data"),
                ("firefox", "firefox", roaming / "Mozilla" / "Firefox" / "Profiles")]
    if sys.platform == "darwin":
        app = home / "Library" / "Application Support"
        return [("chrome", "chromium", app / "Google" / "Chrome"),
                ("msedge", "chromium", app / "Microsoft Edge"),
                ("brave", "chromium", app / "BraveSoftware" / "Brave-Browser"),
                ("firefox", "firefox", app / "Firefox" / "Profiles")]
    cfg = home / ".config"
    return [("chrome", "chromium", cfg / "google-chrome"),
            ("msedge", "chromium", cfg / "microsoft-edge"),
            ("brave", "chromium", cfg / "BraveSoftware" / "Brave-Browser"),
            ("chromium", "chromium", cfg / "chromium"),
            ("firefox", "firefox", home / ".mozilla" / "firefox")]


def find_history_files(home: Path | None = None) -> list[HistoryFile]:
    home = home or Path.home()
    found: list[HistoryFile] = []
    for browser, engine, root in _roots(home):
        try:
            if not root.is_dir():
                continue
            if engine == "chromium":
                names = [root / "Default" / "History", *sorted(root.glob("Profile */History"))]
            else:
                names = sorted(root.glob("*/places.sqlite"))
            found += [HistoryFile(browser, p, engine) for p in names if p.is_file()]
        except OSError:
            continue
    return found


def _query(engine: str) -> str:
    """SQL for visits after a time given in the browser's own clock."""
    if engine == "chromium":
        return ("SELECT u.url, v.visit_time FROM visits v JOIN urls u ON u.id = v.url "
                "WHERE v.visit_time > ? ORDER BY v.visit_time LIMIT 500")
    return ("SELECT p.url, v.visit_date FROM moz_historyvisits v JOIN moz_places p ON p.id = v.place_id "
            "WHERE v.visit_date > ? ORDER BY v.visit_date LIMIT 500")


def offset_of(engine: str) -> int:
    """The browser clock's offset to the Unix epoch, in microseconds."""
    return _CHROMIUM_EPOCH_US if engine == "chromium" else 0


def read_visits(item: HistoryFile, since_unix: float) -> list[tuple[str, float]]:
    """(url, unix time) of visits after ``since_unix``, read from a copy of the history file."""
    sql, offset = _query(item.engine), offset_of(item.engine)
    with tempfile.TemporaryDirectory(prefix="shadowlens_hist_") as tmp:
        copy = Path(tmp) / "h.sqlite"
        shutil.copy2(item.path, copy)
        for suffix in ("-wal",):                       # Firefox keeps recent visits in the write-ahead log
            side = item.path.with_name(item.path.name + suffix)
            if side.is_file():
                try:
                    shutil.copy2(side, copy.with_name(copy.name + suffix))
                except OSError:
                    pass
        conn = sqlite3.connect(f"file:{copy.as_posix()}?mode=ro", uri=True, timeout=2)
        try:
            rows = conn.execute(sql, (int(since_unix * 1_000_000) + offset,)).fetchall()
        finally:
            conn.close()
    return [(str(url), (stamp - offset) / 1_000_000) for url, stamp in rows if isinstance(stamp, int)]


def event_for_visit(browser: str, url: str, unix: float) -> NetEvent | None:
    """One visit as an event (no title, no query string), or ``None`` for a page without a host."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(unix)) + f".{int((unix % 1) * 1000):03d}Z"
    return event_from_record(
        {"ts": stamp, "host": parts.hostname, "method": "GET", "path": (parts.path or "/")[:120],
         "process_name": browser}, source=Source.BROWSER)


class BrowserWatcher:
    """Polls the browsers' history for visits to AI sites and ingests them."""

    def __init__(self, ingest: IngestFn, is_ai_host: Callable[[str], bool], *, home: Path | None = None,
                 poll_s: float = POLL_S, clock: Callable[[], float] = time.time):
        self._ingest, self._is_ai_host = ingest, is_ai_host
        self._home, self._poll_s, self._clock = home, poll_s, clock
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._cursor: dict[str, float] = {}
        self._last_sent: dict[tuple[str, str], float] = {}
        self.visits_ingested = 0
        self.error: str | None = None
        self.files: list[HistoryFile] = []

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self, backfill: bool = False) -> None:
        if self.running:
            if backfill:
                self.poll_once(since=self._clock() - BACKFILL_S)
            return
        now = self._clock()
        self.files = find_history_files(self._home)
        self._cursor = {str(f.path): now for f in self.files}        # starts at "now": only what happens next
        self._stop.clear()
        if backfill:
            self.poll_once(since=now - BACKFILL_S)
        self._thread = threading.Thread(target=self._run, name="shadowlens-browser", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        thread, self._thread = self._thread, None
        if thread is not None:
            thread.join(timeout=3)

    def _run(self) -> None:
        while not self._stop.wait(self._poll_s):
            try:
                self.poll_once()
            except Exception:  # noqa: BLE001 - never die
                log.exception("browser history poll failed")

    def poll_once(self, since: float | None = None) -> int:
        self.files = find_history_files(self._home)
        events: list[NetEvent] = []
        skipped, errors, failed = 0, [], 0
        for item in self.files:
            key = str(item.path)
            start = since if since is not None else self._cursor.setdefault(key, self._clock())
            try:
                visits = read_visits(item, start)
            except (OSError, sqlite3.Error):
                failed += 1
                continue
            if visits and since is None:
                self._cursor[key] = max(t for _, t in visits)
            for url, unix in visits:
                event = event_for_visit(item.browser, url, unix)
                if event is None or not self._is_ai_host(event.host or ""):
                    continue
                gate = (item.browser, event.host or "")
                if unix - self._last_sent.get(gate, 0.0) < REPEAT_S:
                    continue
                self._last_sent[gate] = unix
                events.append(event)
        self.error = "A browser history file is locked right now; it is retried." if failed and not events else None
        if events:
            self._ingest(events, source="browser", skipped=skipped, errors=errors)
            self.visits_ingested += len(events)
        return len(events)

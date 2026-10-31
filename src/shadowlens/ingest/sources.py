"""The registry of automatic sources and what is being read from each (SOT 7.2.1, 4.5).

``config/sources.yaml`` lists the places AI tools keep readable text. Every few seconds we check which of
them exist on this machine, show them on the Capture screen, and, for the ones switched on, read what is
added to their files and ingest it.

Reading a person's own conversations is opt-in. When a source is switched on, it starts at the END of each
file, so only what happens from now on is seen. ``backfill`` also reads the recent past once (the last 20 MB
of at most 50 files). Switching it off and on again starts from the end again: nothing typed while it was
off is read afterwards.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

import yaml
from pydantic import Field, ValidationError, model_validator

from ..config import Config
from ..db import Database
from ..models import ProxyStatus, ShadowModel, SourceKind, SourceRow, TranscriptsStatus, utc_now_iso
from .browser_history import BrowserWatcher, find_history_files
from .live_tail import LiveTail
from .ollama_proxy import OllamaTap
from .transcripts import READERS, make_parser

log = logging.getLogger("shadowlens.sources")

PROJECT_DIR = Path(__file__).resolve().parents[3]
DEFAULT_REGISTRY_PATH = PROJECT_DIR / "config" / "sources.yaml"

DISCOVERY_INTERVAL_S = 5.0
BACKFILL_BYTES = 20 * 1024 * 1024
BACKFILL_MAX_FILES = 50
TAIL_MAX_READ = 32 * 1024 * 1024        # real transcript lines can be tens of megabytes; read them whole, then drop them


class RegistryError(ValueError):
    """The registry file is missing or invalid."""


class SourceDef(ShadowModel):
    id: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    display_name: str = Field(min_length=1)
    kind: SourceKind
    paths: list[str] = Field(default_factory=list)
    reader: str | None = None
    provider_id: str | None = None
    host: str | None = None
    process: str | None = None
    enabled_default: bool = False
    max_files: int = Field(default=200, ge=1)
    max_age_h: float = Field(default=24.0, gt=0)
    reads: str = ""
    stores: str = ""

    @model_validator(mode="after")
    def _transcripts_are_complete(self) -> "SourceDef":
        if self.kind is SourceKind.TRANSCRIPT:
            if self.reader not in READERS:
                raise ValueError(f"unknown reader {self.reader!r}")
            if not (self.paths and self.host and self.process):
                raise ValueError("a transcript source needs paths, host and process")
        return self


def load_registry(path: Path | str | None = None) -> list[SourceDef]:
    file = Path(path) if path is not None else DEFAULT_REGISTRY_PATH
    try:
        raw = yaml.safe_load(file.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RegistryError(f"source registry not found: {file}") from exc
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise RegistryError(f"cannot read source registry {file}: {type(exc).__name__}") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("sources"), list):
        raise RegistryError(f"{file}: expected a mapping with a 'sources' list")
    if set(raw) != {"sources"}:
        raise RegistryError(f"{file}: unknown top-level keys {sorted(set(raw) - {'sources'})}")
    sources: list[SourceDef] = []
    for index, entry in enumerate(raw["sources"]):
        try:
            sources.append(SourceDef.model_validate(entry))
        except ValidationError as exc:
            label = entry.get("id", f"#{index}") if isinstance(entry, dict) else f"#{index}"
            first = exc.errors()[0]
            raise RegistryError(f"{file}: source {label}: {'.'.join(str(p) for p in first['loc'])}: {first['msg']}") from exc
    ids = [s.id for s in sources]
    if len(set(ids)) != len(ids):
        raise RegistryError(f"{file}: duplicate source ids")
    return sources


# ---- finding files -----------------------------------------------------------

_GLOB_CHARS = set("*?[")


def expand_glob(pattern: str, project_dir: Path = PROJECT_DIR, home: Path | None = None) -> list[Path]:
    """The files a registry glob matches. ``~`` is the home folder, a relative path is relative to the project
    folder. These are our own configuration paths, never paths found inside an AI payload."""
    home = home or Path.home()
    if pattern.startswith("~"):
        pattern = str(home / pattern[1:].lstrip("/\\"))
    path = Path(pattern)
    if not path.is_absolute():
        path = project_dir / path
    parts = path.parts
    fixed = len(parts)
    for index, part in enumerate(parts):
        if _GLOB_CHARS & set(part):
            fixed = index
            break
    root = Path(*parts[:fixed]) if fixed else Path(".")
    rest = parts[fixed:]
    try:
        if not rest:
            return [root] if root.is_file() else []
        return [p for p in root.glob(str(Path(*rest))) if p.is_file()]
    except (OSError, ValueError, NotImplementedError):
        return []


def _shown(path: str, home: Path) -> str:
    """A path for display: the home folder as ``~``."""
    text = str(path)
    prefix = str(home)
    return "~" + text[len(prefix):] if text.startswith(prefix) else text


@dataclass
class _State:
    definition: SourceDef
    default_on: bool = False
    enabled: bool = False
    enabled_at: float = 0.0
    found: bool = False
    files: list[Path] = field(default_factory=list)
    known: set[str] = field(default_factory=set)       # files already given a starting point since it was enabled
    tail: LiveTail | None = None
    last_event_at: str | None = None
    lines_before: int = 0                               # lines read by tails that were stopped since the app started
    error: str | None = None


class SourceManager:
    def __init__(
        self,
        config: Config,
        db: Database,
        ingest: Callable[..., object],
        *,
        registry: Iterable[SourceDef] | None = None,
        project_dir: Path = PROJECT_DIR,
        home: Path | None = None,
        clock: Callable[[], float] = time.time,
        poll_s: float = 0.5,
        discovery_s: float = DISCOVERY_INTERVAL_S,
        is_ai_host: Callable[[str], bool] | None = None,
    ):
        self._config = config
        self._db = db
        self._ingest = ingest
        self._project_dir = project_dir
        self._home = home or Path.home()
        self._clock = clock
        self._poll_s = poll_s
        self._discovery_s = discovery_s
        self._lock = threading.RLock()
        self._is_ai_host = is_ai_host or (lambda host: False)
        self._browsers: dict[str, BrowserWatcher] = {}
        self._tap: OllamaTap | None = None
        self._capture = None                            # set by attach_capture: the live log folder lives there
        definitions = list(registry) if registry is not None else load_registry()
        self._states = {}
        for d in definitions:
            default_on = d.enabled_default or (d.id == "claude_code" and config.transcripts_enabled) \
                or (d.id == "ollama_proxy" and config.proxy_enabled)
            self._states[d.id] = _State(self._restricted(d), default_on=default_on)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # ---- configuration -----------------------------------------------------

    def _restricted(self, d: SourceDef) -> SourceDef:
        """``SHADOWLENS_TRANSCRIPT_DIRS`` limits the Claude Code source to those folders."""
        if d.id == "claude_code" and self._config.transcript_dirs:
            return d.model_copy(update={"paths": [f"{folder}/**/*.jsonl" for folder in self._config.transcript_dirs]})
        return d

    def attach_capture(self, capture: object) -> None:
        self._capture = capture

    # ---- discovery ---------------------------------------------------------

    def discover_once(self) -> None:
        with self._lock:
            now = self._clock()
            for state in self._states.values():
                d = state.definition
                if d.kind is SourceKind.BROWSER:
                    state.files = [f.path for f in find_history_files(self._home)]
                    state.found = bool(state.files)
                    continue
                if d.kind is not SourceKind.TRANSCRIPT:
                    continue
                matches: dict[str, tuple[float, Path]] = {}
                for pattern in d.paths:
                    for path in expand_glob(pattern, self._project_dir, self._home):
                        try:
                            matches[str(path)] = (path.stat().st_mtime, path)
                        except OSError:
                            continue
                state.found = bool(matches)
                recent = sorted((m for m in matches.values() if now - m[0] <= d.max_age_h * 3600),
                                key=lambda m: m[0], reverse=True)[:d.max_files]
                state.files = [path for _, path in recent]

    # ---- turning a source on and off ----------------------------------------

    def start_defaults(self) -> None:
        with self._lock:
            self.discover_once()
            for state in self._states.values():
                d = state.definition
                if d.kind is SourceKind.TRANSCRIPT and state.default_on:
                    self._enable(state, backfill=False)
                elif d.kind is SourceKind.BROWSER and state.default_on and state.found:
                    self._set_browser(state, True, False)
                elif d.kind is SourceKind.PROXY and state.default_on:
                    self._set_proxy(state, True)

    def set_enabled(self, source_id: str, enabled: bool, backfill: bool = False) -> SourceRow:
        """``PUT /api/sources/{id}``. Raises ``KeyError`` for an unknown id and ``ValueError`` when the source cannot
        be switched."""
        with self._lock:
            state = self._states[source_id]
            kind = state.definition.kind
            if kind is SourceKind.TRANSCRIPT:
                self.discover_once()
                if enabled:
                    self._enable(state, backfill=backfill)
                else:
                    self._disable(state)
            elif kind is SourceKind.PROXY:
                self._set_proxy(state, enabled)
            elif kind is SourceKind.BROWSER:
                self.discover_once()
                self._set_browser(state, enabled, backfill)
            elif kind is SourceKind.LIVE_LOG:
                if self._capture is None:
                    raise ValueError("the live log folder is not available")
                (self._capture.start if enabled else self._capture.stop)(tail=True)
            else:
                raise ValueError("this source is not available yet")
            return self._row(state)

    def _set_proxy(self, state: _State, enabled: bool) -> None:
        """Start or stop the opt-in Ollama tap (SOT 7.2.2). A tap that cannot start is reported on its row."""
        if not enabled:
            tap, self._tap, state.enabled = self._tap, None, False
            if tap is not None:
                state.lines_before += tap.app.requests_ingested
                tap.stop()
            return
        if self._tap is not None and self._tap.running:
            state.enabled = True
            return

        def on_event(event) -> None:
            self._ingest([event], source="proxy", skipped=0, errors=[])
            state.last_event_at = utc_now_iso()

        tap = OllamaTap.from_config(self._config, on_event)
        if tap.start():
            self._tap, state.enabled, state.enabled_at, state.error = tap, True, self._clock(), None
        else:
            self._tap, state.enabled, state.error = None, False, tap.error

    def proxy_status(self) -> ProxyStatus:
        """The ``proxy`` block of ``CaptureStatus``."""
        with self._lock:
            if self._tap is not None:
                return ProxyStatus(**self._tap.status())
            state = self._states.get("ollama_proxy")
            return ProxyStatus(enabled=False, listen_port=self._config.proxy_port,
                               upstream=self._config.proxy_upstream, upstream_ok=False,
                               requests_ingested=0, error=state.error if state else None)

    def _set_browser(self, state: _State, enabled: bool, backfill: bool) -> None:
        watcher = self._browsers.get(state.definition.id)
        if not enabled:
            if watcher is not None:
                watcher.stop()
                state.lines_before += watcher.visits_ingested
            state.enabled = False
            self._browsers.pop(state.definition.id, None)
            return
        if not state.found:
            raise ValueError("no browser history was found on this machine")
        if watcher is None:
            def ingest(events, **kw):
                self._ingest(events, **kw)
                state.last_event_at = utc_now_iso()
            watcher = self._browsers[state.definition.id] = BrowserWatcher(ingest, self._is_ai_host, home=self._home)
        watcher.start(backfill=backfill)
        state.enabled, state.enabled_at, state.error = True, self._clock(), None

    def _enable(self, state: _State, backfill: bool) -> None:
        d = state.definition
        if state.tail is not None and state.enabled:
            if backfill:
                self._start_at(state, state.files, backfill=True)
            return
        state.enabled, state.enabled_at, state.known, state.error = True, self._clock(), set(), None
        parse = make_parser(d.reader, host=d.host, process=d.process, max_body_bytes=self._config.max_body_bytes)

        def ingest(events, skipped, errors):
            self._ingest(events, source="transcript", skipped=skipped, errors=errors)
            if events:
                state.last_event_at = utc_now_iso()

        def files() -> list[Path]:
            current = list(state.files)             # no lock: this runs on the tail's thread, which stop() waits for
            self._give_starting_points(state, current)
            return current

        state.tail = LiveTail(self._project_dir, self._db, ingest, max_body_bytes=self._config.max_body_bytes,
                              poll_s=self._poll_s, max_read=TAIL_MAX_READ, files=files, parse=parse)
        self._start_at(state, state.files, backfill=backfill)
        state.known.update(str(p) for p in state.files)
        state.tail.start()

    def _disable(self, state: _State) -> None:
        tail, state.tail, state.enabled = state.tail, None, False
        if tail is not None:
            tail.stop()
            state.lines_before += tail.lines_ingested

    def _start_at(self, state: _State, files: list[Path], backfill: bool) -> None:
        """Where reading begins for ``files`` that are there now: their end, or (``backfill``) the recent past."""
        for index, path in enumerate(files):
            try:
                info = path.stat()
            except OSError:
                continue
            start = info.st_size
            if backfill and index < BACKFILL_MAX_FILES:
                start = self._line_start(path, max(0, info.st_size - BACKFILL_BYTES))
            self._db.set_offset(str(path.resolve()), info.st_ino or None, start)

    @staticmethod
    def _line_start(path: Path, position: int) -> int:
        """``position`` moved forward to the start of the next line (so reading never begins mid-line)."""
        if position == 0:
            return 0
        try:
            with open(path, "rb") as handle:
                handle.seek(position - 1)
                tail = handle.read(1 << 20)
        except OSError:
            return position
        newline = tail.find(b"\n")
        return position + newline if newline >= 0 else position

    def _give_starting_points(self, state: _State, files: list[Path]) -> None:
        """A file that appears while the source is on: a brand new session is read from its start; an older file
        that merely came into range is read from its end."""
        for path in files:
            key = str(path)
            if key in state.known:
                continue
            state.known.add(key)
            try:
                info = path.stat()
            except OSError:
                continue
            if self._db.get_offset(str(path.resolve())) is None and info.st_mtime < state.enabled_at:
                self._db.set_offset(str(path.resolve()), info.st_ino or None, info.st_size)

    # ---- the answers --------------------------------------------------------

    def rows(self) -> list[SourceRow]:
        with self._lock:
            return [self._row(state) for state in self._states.values()]

    def _row(self, state: _State) -> SourceRow:
        d = state.definition
        shown = [_shown(p, self._home) for p in d.paths]
        base = dict(id=d.id, display_name=d.display_name, kind=d.kind, reads=d.reads, stores=d.stores, paths=shown)
        if d.kind is SourceKind.TRANSCRIPT:
            lines = state.lines_before + (state.tail.lines_ingested if state.tail else 0)
            return SourceRow(found=state.found, enabled=state.enabled, supported=True, error=state.error,
                             files_watched=len(state.files) if state.enabled else 0, lines_ingested=lines,
                             last_event_at=state.last_event_at, **base)
        if d.kind is SourceKind.BROWSER:
            watcher = self._browsers.get(d.id)
            shown_files = [_shown(str(p), self._home) for p in state.files]
            return SourceRow(found=state.found, enabled=state.enabled, supported=True,
                             error=(watcher.error if watcher else None) or state.error,
                             files_watched=len(state.files) if state.enabled else 0,
                             lines_ingested=state.lines_before + (watcher.visits_ingested if watcher else 0),
                             last_event_at=state.last_event_at, **{**base, "paths": shown_files or base["paths"]})
        if d.kind is SourceKind.LIVE_LOG:
            tail = getattr(self._capture, "tail", None)
            folder = self._config.live_dir
            files = len(list(folder.glob("*.jsonl"))) if folder.is_dir() else 0
            return SourceRow(found=folder.is_dir(), enabled=bool(tail and tail.running), supported=True,
                             files_watched=files, lines_ingested=tail.lines_ingested if tail else 0,
                             **{**base, "paths": [_shown(str(folder / "*.jsonl"), self._home)]})
        status = self.proxy_status()
        return SourceRow(found=True, enabled=state.enabled, supported=True, error=state.error or status.error,
                         files_watched=0, lines_ingested=state.lines_before + status.requests_ingested,
                         last_event_at=state.last_event_at,
                         **{**base, "paths": [f"127.0.0.1:{status.listen_port} \u2192 {status.upstream}"]})

    def status(self) -> TranscriptsStatus:
        with self._lock:
            active = [s for s in self._states.values() if s.definition.kind is SourceKind.TRANSCRIPT and s.enabled]
            lines = sum(s.lines_before + (s.tail.lines_ingested if s.tail else 0)
                        for s in self._states.values() if s.definition.kind is SourceKind.TRANSCRIPT)
            return TranscriptsStatus(enabled=bool(active), sources_active=len(active),
                                     files_watched=sum(len(s.files) for s in active), lines_ingested=lines)

    # ---- background discovery ------------------------------------------------

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self.start_defaults()
        self._thread = threading.Thread(target=self._run, name="shadowlens-sources", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.wait(self._discovery_s):
            try:
                self.discover_once()
            except Exception:  # noqa: BLE001 - discovery must never die
                log.exception("source discovery failed")

    def stop(self) -> None:
        self._stop.set()
        thread, self._thread = self._thread, None
        if thread is not None:
            thread.join(timeout=2)
        with self._lock:
            for state in self._states.values():
                self._disable(state)
            for watcher in self._browsers.values():
                watcher.stop()
            if self._tap is not None:
                self._set_proxy(self._states["ollama_proxy"], False)
            self._browsers.clear()

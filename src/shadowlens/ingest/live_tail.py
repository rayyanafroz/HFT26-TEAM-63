"""Watch the live log folder and ingest new lines as they appear (SOT 7.2, ``live_log``).

A local AI server (or our mock) appends one JSON request per line to a ``*.jsonl`` file in
``data/live/``. Every half second we read what was added since last time and ingest it.

What this has to get right:
  * a line that is only half written is left alone until its newline arrives;
  * a file that shrinks (truncated) or is replaced is read again from the start;
  * we remember how far we got (in the database), so a restart neither loses nor repeats lines;
  * Windows: another program may be writing the file, so it is opened read-only and a
    ``PermissionError`` just means "try again next time".
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Callable, Iterable

from ..db import Database
from ..models import NetEvent, Source
from .http_log import DEFAULT_MAX_BODY_BYTES, Expander, LogLineError, parse_jsonl_line, split_lines

log = logging.getLogger("shadowlens.live_tail")

POLL_INTERVAL_S = 0.5
HEAD_BYTES = 256                        # the start of each file is remembered, to notice it being rewritten in place
MAX_ATTEMPTS = 3                        # a batch that keeps failing is given up on, so it cannot block the lines behind it
MAX_READ_BYTES = 4 * 1024 * 1024        # per file per poll, so one huge file cannot stall everything
BATCH_LINES = 200                       # the bookmark moves at least this often, so a crash repeats at most one batch

# What is done with new events: (events, number of bad lines, their error messages)
Ingest = Callable[[list[NetEvent], int, list[str]], None]

# Turns one line of text into an event. It may return None for a line that is fine but of no interest (not
# counted as bad), or raise LogLineError for a bad one. Arguments: the line, and the placeholder expander.
ParseLine = Callable[[str, Expander | None], NetEvent | None]


class LiveTail:
    def __init__(
        self,
        directory: Path,
        db: Database,
        ingest: Ingest,
        *,
        max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
        expand: Callable[[], Expander | None] | None = None,
        poll_s: float = POLL_INTERVAL_S,
        max_read: int = MAX_READ_BYTES,
        batch_lines: int = BATCH_LINES,
        files: Callable[[], Iterable[Path]] | None = None,
        parse: ParseLine | None = None,
    ):
        """Normally this watches ``directory/*.jsonl`` for lines in the HTTP log format. The transcript reader
        reuses it all (partial lines, truncation, bookmarks, batching) by passing its own ``files`` (which files
        to read) and ``parse`` (what a line means)."""
        self.directory = Path(directory)
        self._files = files
        self._parse = parse or (lambda text, expand: parse_jsonl_line(
            text, source=Source.LIVE_LOG, max_body_bytes=max_body_bytes, expand=expand))
        self._db = db
        self._ingest = ingest
        self._max_body = max_body_bytes
        self._expand = expand or (lambda: None)
        self._poll_s = poll_s
        self._max_read = max_read
        self._batch_lines = batch_lines
        self._lock = threading.RLock()
        self._failures: dict[str, int] = {}
        self._heads: dict[str, bytes] = {}      # the first bytes of each file when we last read it (in memory only)
        self._mtimes: dict[str, int] = {}       # when each file was last modified, as we last saw it
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.lines_ingested = 0

    # ---- one pass --------------------------------------------------------

    def poll_once(self) -> int:
        """Read whatever was added to every ``*.jsonl`` file. Returns how many lines were ingested."""
        with self._lock:
            try:
                files = sorted(self._files()) if self._files else sorted(self.directory.glob("*.jsonl"))
            except OSError:
                return 0
            return sum(self._read_new(path) for path in files)

    def _read_new(self, path: Path) -> int:
        try:
            info = path.stat()
        except OSError:
            return 0
        key, inode = str(path.resolve()), (info.st_ino or None)
        stored = self._db.get_offset(key)
        offset = stored[1] if stored else 0
        if stored and stored[0] and inode and stored[0] != inode:
            offset = 0                                          # the file was replaced
        if info.st_size < offset:
            offset = 0                                          # the file was shrunk

        # A file emptied and refilled in place can end up as long as before, so size alone proves nothing.
        # When the modification time moved, look at the start of the file too.
        touched = info.st_mtime_ns != self._mtimes.get(key)
        self._mtimes[key] = info.st_mtime_ns
        if info.st_size == offset and not (touched and offset > 0 and key in self._heads):
            if stored is None or stored[1] != offset:
                self._db.set_offset(key, inode, offset)
            return 0

        try:
            with open(path, "rb") as handle:                    # read-only; fine while another program writes
                head = handle.read(HEAD_BYTES)
                if offset > 0 and self._rewritten(key, head):
                    offset = 0                                  # emptied and refilled: read it all again
                if info.st_size == offset:
                    return 0                                    # touched, but nothing new
                handle.seek(offset)
                chunk = handle.read(min(info.st_size - offset, self._max_read))
        except OSError:
            return 0                                            # locked or gone for now: try again next time
        self._heads.setdefault(key, head)

        cut = chunk.rfind(b"\n")
        errors: list[str] = []
        if cut < 0:
            if len(chunk) < self._max_read:
                return 0                                        # a half-written line: wait for its newline
            # one endless line: skip it, do not loop forever
            self._deliver(key, inode, offset + len(chunk), path, [], 1, [f"{path.name}: line is too long"])
            return 0
        complete = chunk[:cut + 1]

        # Work through the complete lines in batches. The bookmark moves after each batch, so if the app dies
        # part way through a big file only the batch in progress is repeated, not everything since the read began.
        delivered = 0
        events: list[NetEvent] = []
        skipped, in_batch, batch_end = 0, 0, 0
        for raw in complete.split(b"\n")[:-1]:                  # the last piece is empty: `complete` ends with a newline
            first_line_of_file = offset == 0 and batch_end == 0
            batch_end += len(raw) + 1
            text = raw.decode("utf-8", errors="replace")
            if text.endswith("\r"):
                text = text[:-1]
            if first_line_of_file:
                text = text.lstrip("\ufeff")                    # a UTF-8 byte-order mark at the start (Notepad, PowerShell)
            in_batch += 1
            if text.strip():
                try:
                    event = self._parse(text, self._expand())
                    if event is not None:
                        events.append(event)
                except LogLineError as exc:
                    skipped += 1
                    if len(errors) < 20:
                        errors.append(f"{path.name}: {exc}")
            if in_batch >= self._batch_lines:
                if not self._deliver(key, inode, offset + batch_end, path, events, skipped, errors):
                    return delivered                            # try this batch again next pass; earlier ones are done
                delivered += len(events)
                self.lines_ingested += len(events)
                events, skipped, in_batch, errors = [], 0, 0, []
        if in_batch:
            if not self._deliver(key, inode, offset + batch_end, path, events, skipped, errors):
                return delivered
            delivered += len(events)
            self.lines_ingested += len(events)
        self._heads[key] = head                                  # remember how this file starts now
        return delivered

    def _rewritten(self, key: str, head: bytes) -> bool:
        """Does the start of the file differ from what we saw before? Then it is a different file's worth of
        lines even though the name and size look the same (the size check alone misses a refill that is
        at least as long as the old content)."""
        known = self._heads.get(key)
        if known is None:
            return False                                        # first time we look (e.g. after a restart)
        shared = min(len(known), len(head))
        return len(head) < len(known) or head[:shared] != known[:shared]

    def _deliver(self, key: str, inode: int | None, new_offset: int, path: Path,
                 events: list[NetEvent], skipped: int, errors: list[str]) -> bool:
        """Hand the lines on, and only then move the bookmark.

        If handing them on fails, the bookmark stays and the same lines are tried again next pass, so a
        brief failure (a busy database) loses nothing. After ``MAX_ATTEMPTS`` the batch is dropped, with
        an error in the log, so one permanently broken batch cannot block everything behind it.
        """
        try:
            if events or skipped:
                self._ingest(events, skipped, errors)
        except Exception:  # noqa: BLE001
            attempts = self._failures[key] = self._failures.get(key, 0) + 1
            if attempts < MAX_ATTEMPTS:
                log.warning("could not ingest lines from %s (attempt %d of %d), will retry", path.name, attempts, MAX_ATTEMPTS)
                return False
            log.error("giving up on a batch from %s after %d attempts", path.name, attempts)
        self._failures.pop(key, None)
        self._db.set_offset(key, inode, new_offset)
        return True

    # ---- background thread ----------------------------------------------

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="shadowlens-live-tail", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.poll_once()
            except Exception:  # noqa: BLE001 - the watcher must never die
                log.exception("live tail pass failed")
            self._stop.wait(self._poll_s)

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

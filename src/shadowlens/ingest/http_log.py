"""Read HTTP request logs (JSONL) and browser HAR files into ``NetEvent``s (SOT 6.3, 7.2).

The same record-to-event code serves every file-like source: uploads, the live
log tail and the scenario loader all call ``event_from_record``.

Rules this module keeps:
  * Bad input never raises for a single line or entry: it is counted in
    ``skipped`` and described in ``errors`` (first 20). Only a whole file over
    the size limit raises (``LogTooLargeError``).
  * Error messages never contain request content (a bad line may hold a secret).
  * The query string is split off the path. The body is truncated for analysis,
    but its true size and a SHA-256 of the whole body are recorded.
  * The auth credential is not hashed here (that needs the secret salt and
    happens in the pipeline); only its scheme is noted.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable
from urllib.parse import urlsplit

from pydantic import ValidationError

from ..models import AuthScheme, HostBasis, NetEvent, Source, new_id

MAX_LOG_BYTES = 20 * 1024 * 1024     # SOT 6.3
MAX_ERRORS = 20                       # SOT 6.3
DEFAULT_MAX_BODY_BYTES = 262144      # most large pastes and long conversations fit whole; see keep_head_and_tail

# Sources a log line may name for itself (SOT 6.3).
_LINE_SOURCES = {s.value: s for s in (Source.HTTP_LOG, Source.PCAP, Source.CONN_SCAN, Source.SCENARIO)}
_HOST_PORT = re.compile(r"^(?P<host>[^:\[\]]+):(?P<port>\d{1,5})$")

Expander = Callable[[str], str]


class LogTooLargeError(ValueError):
    """The whole file is bigger than the allowed size."""


class LogLineError(ValueError):
    """One line or entry cannot be used. The message is safe to show (it holds no content)."""


@dataclass
class ParseResult:
    events: list[NetEvent] = field(default_factory=list)
    skipped: int = 0
    errors: list[str] = field(default_factory=list)   # at most MAX_ERRORS
    format: str = "jsonl"                              # "jsonl" or "har"

    @property
    def source(self) -> str:
        """The ``IngestSummary.source`` label for this file."""
        return "har" if self.format == "har" else "http_log"

    def fail(self, label: str, message: str) -> None:
        self.skipped += 1
        if len(self.errors) < MAX_ERRORS:
            self.errors.append(f"{label}: {message}")


# --------------------------------------------------------------------------
# small value helpers
# --------------------------------------------------------------------------

def split_lines(text: str) -> list[str]:
    """Split a JSONL file into lines at real line ends only (``\\n`` or ``\\r\\n``).

    Not ``str.splitlines()``: that also breaks at U+2028, U+0085, form feed, vertical tab and a few
    more, all of which JSON allows INSIDE a string (text copied from a web page often has U+2028).
    Using it would tear a valid request in half and silently drop it, so anything with such a
    character in it would escape analysis.
    """
    return [line[:-1] if line.endswith("\r") else line for line in text.split("\n")]


def format_ts(moment: datetime) -> str:
    """ISO-8601 UTC with milliseconds and a trailing Z (SOT 6.1)."""
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def parse_ts(value: object) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise LogLineError("invalid timestamp")
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        moment = datetime.fromisoformat(text)
    except ValueError as exc:
        raise LogLineError("invalid timestamp") from exc
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)   # no zone means UTC


def _int(record: dict[str, Any], key: str, *, minimum: int = 0, maximum: int | None = None) -> int | None:
    value = record.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise LogLineError(f"{key} must be an integer")
    if value < minimum or (maximum is not None and value > maximum):
        raise LogLineError(f"{key} is out of range")
    return value


def _required_str(record: dict[str, Any], key: str) -> str:
    value = record.get(key)
    if not isinstance(value, str) or not value.strip():
        raise LogLineError(f"missing or invalid '{key}'")
    return value.strip()


CUT_MARKER = "\n"


def keep_head_and_tail(data: bytes, max_bytes: int) -> str:
    """A body too big to read whole, as text: its start and its end, joined by a line break.

    The end matters as much as the start: in a chat request the newest message, the one being sent now, is
    last, and a long conversation (or a lot of padding) would otherwise push it out of view. Each half is cut
    on a character boundary, so the text stays valid UTF-8.
    """
    half = max(1, max_bytes // 2)
    head = data[:half].decode("utf-8", errors="ignore")
    tail = data[-half:].decode("utf-8", errors="ignore")
    return head + CUT_MARKER + tail


def _prepare_body(raw: object, max_bytes: int, expand: Expander | None) -> tuple[str | None, int, str | None, bool]:
    """``(text kept for analysis, true size in bytes, sha256 of the whole body, truncated)``."""
    if raw is None:
        return None, 0, None, False
    if isinstance(raw, (dict, list)):
        raw = json.dumps(raw, separators=(",", ":"), ensure_ascii=False)
    if not isinstance(raw, str):
        raise LogLineError("body must be a string or null")
    if expand is not None:
        raw = _expand(expand, raw)
    if raw == "":
        return None, 0, None, False
    data = raw.encode("utf-8", errors="replace")
    sha = hashlib.sha256(data).hexdigest()
    if len(data) > max_bytes:
        return keep_head_and_tail(data, max_bytes), len(data), sha, True
    return raw, len(data), sha, False


def _expand(expand: Expander, text: str) -> str:
    try:
        return expand(text)
    except Exception as exc:  # noqa: BLE001
        raise LogLineError("placeholder expansion failed") from exc


def _prepare_headers(raw: object, expand: Expander | None) -> dict[str, str]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise LogLineError("headers must be an object")
    out: dict[str, str] = {}
    for key, value in raw.items():
        text = value if isinstance(value, str) else str(value)
        out[str(key)] = _expand(expand, text) if expand is not None else text
    return out


def detect_auth_scheme(headers: dict[str, str]) -> AuthScheme | None:
    """Which kind of credential the request carries (the credential itself is never read here)."""
    lower = {k.lower(): v for k, v in headers.items()}
    auth = lower.get("authorization", "").strip().lower()
    if auth.startswith("bearer "):
        return AuthScheme.BEARER
    if auth.startswith("basic "):
        return AuthScheme.BASIC
    if "x-api-key" in lower:
        return AuthScheme.X_API_KEY
    if "x-goog-api-key" in lower:
        return AuthScheme.X_GOOG_API_KEY
    return None


def _error_text(exc: ValidationError) -> str:
    """The first problem in a pydantic error, without echoing the offending value."""
    first = exc.errors()[0]
    where = ".".join(str(p) for p in first.get("loc", ()))
    return f"{where}: {first.get('msg', 'invalid value')}" if where else str(first.get("msg", "invalid value"))


# --------------------------------------------------------------------------
# one record -> one event
# --------------------------------------------------------------------------

def event_from_record(
    record: object,
    *,
    source: Source | None = None,
    host_basis: HostBasis = HostBasis.HOST_HEADER,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    expand: Expander | None = None,
    base_time: datetime | None = None,
) -> NetEvent:
    """Build a ``NetEvent`` from one log record (SOT 6.3).

    ``source`` forces the event's source (the live tail uses ``live_log``); if None the
    record's own ``source`` is used, defaulting to ``http_log``. ``expand`` turns
    ``{{fake:...}}`` placeholders into test values in the body, path and header values.
    ``base_time`` is the zero point for ``t_ms`` offsets (default: now).
    """
    if not isinstance(record, dict):
        raise LogLineError("not a JSON object")

    host = _required_str(record, "host")
    method = _required_str(record, "method").upper()
    path = _required_str(record, "path")
    if expand is not None:
        path = _expand(expand, path)

    # when: an ISO timestamp, or a millisecond offset (scenario files)
    if record.get("ts") is not None:
        moment = parse_ts(record["ts"])
    elif record.get("t_ms") is not None:
        offset = _int(record, "t_ms", minimum=0)
        moment = (base_time or datetime.now(timezone.utc)) + timedelta(milliseconds=offset or 0)
    else:
        raise LogLineError("needs 'ts' or 't_ms'")

    # where to: port and address, inferred from the host when not given
    tls = record.get("tls", True)
    if not isinstance(tls, bool):
        raise LogLineError("tls must be true or false")
    host_part = _HOST_PORT.match(host)
    port = _int(record, "dst_port", maximum=65535)
    if port is None:
        port = int(host_part["port"]) if host_part and int(host_part["port"]) <= 65535 else (443 if tls else 80)
    bare_host = host_part["host"] if host_part else host
    dst_ip = record.get("dst_ip")
    if dst_ip is None:
        try:
            dst_ip = str(ipaddress.ip_address(bare_host.strip("[]")))     # host is itself an address
        except ValueError:
            dst_ip = "0.0.0.0"                                           # unknown (SOT 6.3)
    elif not isinstance(dst_ip, str):
        raise LogLineError("dst_ip must be a string")

    # the request itself
    path, _, query = path.partition("?")
    path = path.split("#", 1)[0] or "/"
    query = query.split("#", 1)[0] or None
    headers = _prepare_headers(record.get("headers"), expand)
    body_text, body_bytes, body_sha, truncated = _prepare_body(record.get("body"), max_body_bytes, expand)

    process = record.get("process_name")
    if process is not None and not isinstance(process, str):
        raise LogLineError("process_name must be a string")

    if source is None:
        named = record.get("source")
        if named is None:
            source = Source.HTTP_LOG
        elif isinstance(named, str) and named in _LINE_SOURCES:
            source = _LINE_SOURCES[named]
        else:
            raise LogLineError("unknown source")

    try:
        return NetEvent(
            id=new_id(),
            ts=format_ts(moment),
            source=source,
            process=process or "unknown",
            pid=_int(record, "pid"),
            dst_ip=dst_ip,
            dst_port=port,
            host=host,
            host_basis=host_basis,
            method=method,
            path=path,
            query=query,
            headers=headers,
            body_text=body_text,
            body_bytes=body_bytes,
            body_sha256=body_sha,
            body_truncated=truncated,
            bytes_out=_int(record, "bytes_out"),
            auth_scheme=detect_auth_scheme(headers),
        )
    except ValidationError as exc:
        raise LogLineError(_error_text(exc)) from exc


# --------------------------------------------------------------------------
# JSONL and HAR
# --------------------------------------------------------------------------

def parse_jsonl_line(text: str, **options: Any) -> NetEvent:
    """One JSONL line to one event (used by the live tail). Raises ``LogLineError``."""
    try:
        record = json.loads(text)
    except json.JSONDecodeError as exc:
        raise LogLineError(f"not valid JSON ({exc.msg})") from exc
    return event_from_record(record, **options)


def _parse_jsonl(text: str, result: ParseResult, **options: Any) -> None:
    for number, line in enumerate(split_lines(text), start=1):
        if not line.strip():
            continue
        try:
            result.events.append(parse_jsonl_line(line, **options))
        except LogLineError as exc:
            result.fail(f"line {number}", str(exc))


def _har_record(entry: object) -> dict[str, Any]:
    """Translate one HAR 1.2 entry into the record format of SOT 6.3."""
    if not isinstance(entry, dict) or not isinstance(entry.get("request"), dict):
        raise LogLineError("entry has no request")
    request = entry["request"]
    url = request.get("url")
    if not isinstance(url, str):
        raise LogLineError("request has no url")
    parts = urlsplit(url)
    if not parts.hostname:
        raise LogLineError("request url has no host")
    try:
        explicit_port = parts.port
    except ValueError as exc:
        raise LogLineError("request url has a bad port") from exc
    secure = parts.scheme in ("https", "wss")

    headers: dict[str, str] = {}
    raw_headers = request.get("headers")
    if isinstance(raw_headers, list):
        for item in raw_headers:
            if isinstance(item, dict) and isinstance(item.get("name"), str):
                headers[item["name"]] = str(item.get("value", ""))

    body: str | None = None
    post = request.get("postData")
    if isinstance(post, dict):
        if isinstance(post.get("text"), str):
            body = post["text"]
        elif isinstance(post.get("params"), list):
            body = "&".join(f"{p.get('name', '')}={p.get('value', '')}" for p in post["params"] if isinstance(p, dict))

    def size(container: object, key: str) -> int | None:
        value = container.get(key) if isinstance(container, dict) else None
        return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None

    record: dict[str, Any] = {
        "ts": entry.get("startedDateTime"),
        "host": parts.hostname,
        "method": request.get("method"),
        "path": parts.path + (f"?{parts.query}" if parts.query else ""),
        "dst_port": explicit_port or (443 if secure else 80),
        "headers": headers,
        "body": body,
        "process_name": "browser",
        "bytes_out": size(request, "bodySize"),
    }
    server_ip = entry.get("serverIPAddress")
    if isinstance(server_ip, str) and server_ip.strip():
        record["dst_ip"] = server_ip.strip().strip("[]")
    return record


def _parse_har(doc: dict[str, Any], result: ParseResult, **options: Any) -> None:
    result.format = "har"
    entries = doc.get("log", {}).get("entries") if isinstance(doc.get("log"), dict) else None
    if not isinstance(entries, list):
        result.fail("har", "no log.entries list")
        return
    source = options.pop("source", None) or Source.HAR
    for number, entry in enumerate(entries, start=1):
        try:
            result.events.append(event_from_record(
                _har_record(entry), source=source, host_basis=HostBasis.URL, **options))
        except LogLineError as exc:
            result.fail(f"entry {number}", str(exc))


def parse_log(
    data: bytes | str,
    filename: str | None = None,
    *,
    max_log_bytes: int = MAX_LOG_BYTES,
    **options: Any,
) -> ParseResult:
    """Parse an uploaded log. The format is detected from the content: a JSON object with a
    ``log`` key is a HAR file; anything else is JSONL.

    ``options`` are passed to ``event_from_record`` (``source``, ``max_body_bytes``,
    ``expand``, ``base_time``).
    """
    size = len(data) if isinstance(data, bytes) else len(data.encode("utf-8", errors="replace"))
    if size > max_log_bytes:
        raise LogTooLargeError(f"log is larger than {max_log_bytes // (1024 * 1024)} MB")
    text = data.decode("utf-8-sig", errors="replace") if isinstance(data, bytes) else data.lstrip("﻿")

    result = ParseResult()
    document: object = None
    if text.lstrip().startswith("{"):
        try:
            document = json.loads(text)
        except json.JSONDecodeError:
            document = None            # several JSON objects, one per line: JSONL

    if isinstance(document, dict) and "log" in document:
        _parse_har(document, result, **options)
    elif filename and filename.lower().endswith(".har"):
        result.format = "har"
        result.fail("har", "not a valid HAR file")
    else:
        _parse_jsonl(text, result, **options)
    return result

"""Read what an AI tool saved about its conversations (SOT 7.2.1, ``transcript`` source).

Claude Code writes every session to ``~/.claude/projects/<project>/<session>.jsonl``, one JSON object per
line. A line is a message the user typed, a file or command output handed back to the model, or something
the model decided to do. All of that has been SENT to the provider, so it is exactly what we want to
inspect, and it is saved in plain text on this machine.

This module turns one such line into one event that looks like the request that was sent
(``POST /v1/messages`` with an Anthropic-shaped body), so the normal analysis, scoring and alerting
handle it unchanged. Which lines count:

  * user lines: the typed text, and tool results (file contents and command output the agent read);
  * assistant lines: only the ``tool_use`` blocks, which are the agent's actions;
  * nothing else. The model's own prose and its hidden reasoning are not inspected, and neither are the
    bookkeeping lines (file snapshots, titles, saved copies of requests) that make up most of a real file.

Only masked findings are stored. The text itself lives in memory while it is analysed, like any request.
"""

from __future__ import annotations

import json
import re
from typing import Any, Callable

from ..models import NetEvent, Source, utc_now_iso
from .http_log import Expander, LogLineError, event_from_record, parse_ts

ParseLine = Callable[[str, Expander | None], NetEvent | None]

# Real files are mostly other kinds of line (some of them tens of megabytes). The kind is the first field,
# so we can drop those without parsing them.
_FIRST_TYPE = re.compile(r'\s*\{\s*"type"\s*:\s*"([^"]*)"')
_WANTED_TYPES = frozenset({"user", "assistant"})

# Per piece of text kept in one event. The analysis only looks at the first `max_body_bytes` of a body,
# so a huge file read is cut to fit instead of cutting the JSON in half (which would hide the tool calls).
MIN_PIECE_CHARS = 512
OVERHEAD_CHARS = 2048


def _cap(value: Any, limit: int) -> Any:
    """``value`` with every string cut to ``limit`` characters (lists and objects are followed)."""
    if isinstance(value, str):
        return value if len(value) <= limit else value[:limit]
    if isinstance(value, list):
        return [_cap(item, limit) for item in value]
    if isinstance(value, dict):
        return {key: _cap(item, limit) for key, item in value.items()}
    return value


def _result_text(content: Any) -> Any:
    """A tool result's content as the plain string or list of text blocks the model was given."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text" and isinstance(item.get("text"), str):
                parts.append({"type": "text", "text": item["text"]})
            elif isinstance(item, str):
                parts.append({"type": "text", "text": item})
        return parts
    return ""


def _kept_blocks(role: str, content: Any) -> list[dict[str, Any]]:
    """The blocks of one message that are worth inspecting (see the module notes)."""
    if isinstance(content, str):
        content = [{"type": "text", "text": content}]
    if not isinstance(content, list):
        return []
    kept: list[dict[str, Any]] = []
    for block in content:
        if isinstance(block, str):
            block = {"type": "text", "text": block}
        if not isinstance(block, dict):
            continue
        kind = block.get("type")
        if role == "user" and kind == "text" and isinstance(block.get("text"), str) and block["text"].strip():
            kept.append({"type": "text", "text": block["text"]})
        elif role == "user" and kind == "tool_result":
            result = _result_text(block.get("content"))
            if result:
                kept.append({"type": "tool_result", "content": result})
        elif role == "assistant" and kind == "tool_use" and isinstance(block.get("name"), str):
            kept.append({"type": "tool_use", "name": block["name"],
                         "input": block["input"] if isinstance(block.get("input"), dict) else {}})
    return kept


def claude_code_jsonl(text: str, *, host: str, process: str, max_body_bytes: int,
                      expand: Expander | None = None) -> NetEvent | None:
    """One transcript line to one event, or ``None`` when the line holds nothing to inspect.

    Raises ``LogLineError`` for a line that is not a JSON object.
    """
    head = _FIRST_TYPE.match(text)
    if head and head.group(1) not in _WANTED_TYPES:
        return None                                              # bookkeeping: skipped without parsing
    try:
        line = json.loads(text)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise LogLineError("not valid JSON") from exc
    if not isinstance(line, dict):
        raise LogLineError("not a JSON object")

    message = line.get("message")
    if not isinstance(message, dict):
        return None
    role = message.get("role") if isinstance(message.get("role"), str) else line.get("type")
    kept = _kept_blocks(role, message.get("content")) if role in _WANTED_TYPES else []
    if not kept:
        return None

    limit = max(MIN_PIECE_CHARS, (max_body_bytes - OVERHEAD_CHARS) // len(kept))
    model = message.get("model") if isinstance(message.get("model"), str) and message.get("model") else "unknown"
    body = {"model": model, "messages": [{"role": role, "content": _cap(kept, limit)}]}

    stamp = line.get("timestamp")
    try:
        parse_ts(stamp)
    except Exception:  # noqa: BLE001 - the field is not guaranteed: fall back to "now"
        stamp = utc_now_iso()
    return event_from_record(
        {"ts": stamp, "host": host, "method": "POST", "path": "/v1/messages", "process_name": process,
         "body": json.dumps(body, separators=(",", ":"), ensure_ascii=False)},
        source=Source.TRANSCRIPT, max_body_bytes=max_body_bytes, expand=expand)


READERS: dict[str, Callable[..., NetEvent | None]] = {"claude_code_jsonl": claude_code_jsonl}


def make_parser(reader: str, *, host: str, process: str, max_body_bytes: int) -> ParseLine:
    """The line parser for a registry entry's ``reader`` name."""
    function = READERS[reader]
    return lambda text, expand: function(text, host=host, process=process, max_body_bytes=max_body_bytes, expand=expand)

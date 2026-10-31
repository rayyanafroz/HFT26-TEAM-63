"""What an AI model may be sent, and the check before anything is sent (SOT 7.7).

The model sees one redacted finding and nothing else: rule, title, severity, category, process, provider,
whether the provider is approved, and (if switched on) at most 120 characters of already-redacted context.
Never the masked preview, raw values, headers, host names or bodies. Before sending, the whole outgoing text
goes through the detectors; any hit blocks the call.
"""

from __future__ import annotations

import hashlib
from typing import Any, Callable

from ..models import Alert

CONTEXT_CHARS = 120

SYSTEM_PROMPT = (
    "You are a security analyst assistant. You receive one redacted finding from a scanner of AI-tool traffic. "
    "Reply with ONLY a JSON object with keys: summary (max 300 chars: what happened and why it matters), "
    "steps (array of at most 5 strings, each max 200 chars, concrete actions in priority order), "
    "sensitivity (critical|high|medium|low, judged in context), "
    "verdict (true_positive|likely_false_positive|needs_review), data_classes (array of strings). "
    "Placeholders such as [REDACTED:...] stand for removed values; never ask for them."
)


def cut_context(text: str, limit: int = CONTEXT_CHARS) -> str:
    """At most ``limit`` characters, never ending inside a ``[...]`` placeholder."""
    if len(text) <= limit:
        return text
    cut = text[:limit]
    if cut.rfind("[") > cut.rfind("]"):
        cut = cut[:cut.rfind("[")]
    return cut


def user_prompt(alert: Alert, *, provider_name: str, sanctioned: bool, send_context: bool) -> str:
    """The whole user message. One field per line."""
    f = alert.finding
    process = alert.tool_id.split("|", 1)[0]
    lines = [
        f"rule_id: {f.rule_id}",
        f"title: {alert.title}",
        f"severity: {f.severity.value}",
        f"category: {f.category.value}",
        f"process: {process}",
        f"provider: {provider_name}",
        f"provider_sanctioned: {'yes' if sanctioned else 'no'}",
    ]
    if send_context and f.meta.context:
        lines.append(f"context: {cut_context(f.meta.context)}")
    if f.meta.tool_name:
        lines.append(f"tool_name: {f.meta.tool_name}")
    if f.meta.argument:
        lines.append(f"argument: {f.meta.argument}")
    return "\n".join(lines)


def outgoing_text(prompt: str) -> str:
    """Everything that leaves the machine in the request body."""
    return f"{SYSTEM_PROMPT}\n{prompt}"


def sha256_of(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def is_allowed(prompt: str, config: Any, check: Callable[[str, Any], bool] | None) -> bool:
    """May this prompt leave the machine? Fails closed: with no checker the answer is no."""
    if check is None:
        return False
    try:
        return bool(check(outgoing_text(prompt), config))
    except Exception:  # noqa: BLE001 - an unchecked prompt is not a safe prompt
        return False

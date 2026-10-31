"""Optional pieces that Saleha's modules provide, found by name at the moment they are needed.

Looking them up when needed means the app still starts if one is missing, and the feature that
needs it answers "not installed yet" instead of crashing. The contracts (see
docs/ANALYSIS_INTEGRATION.md):

    shadowlens.analysis.analyze(event, config, ctx)      -> findings + agent activity
    shadowlens.analysis.preview(text, mode, config)      -> {findings, redacted_text, would_block}   (Leak Lab)
    shadowlens.analysis.analyze_text(text, settings)     -> findings + redacted_text      (settings = settings_for(config))
    shadowlens.fakes.samples()                           -> {key, pii, agent}              (Leak Lab buttons)
    shadowlens.fakes.expand(text)                        -> text with every {{fake:kind#n}} replaced
    shadowlens.analysis.engine.is_safe_to_send(text, cfg) -> bool                       (egress guard before an AI call)
"""

from __future__ import annotations

import importlib
from typing import Any, Callable


def _attr(module: str, name: str) -> Any | None:
    try:
        return getattr(importlib.import_module(module), name, None)
    except ImportError:
        return None


def event_analyzer() -> Callable[..., Any] | None:
    return _attr("shadowlens.analysis", "analyze")


def preview_function() -> Callable[..., Any] | None:
    return _attr("shadowlens.analysis", "preview")


def placeholder_expander() -> Callable[[str], str] | None:
    return _attr("shadowlens.fakes", "expand")


def samples_function() -> Callable[[], dict[str, str]] | None:
    return _attr("shadowlens.fakes", "samples")


def egress_guard() -> Callable[[str, Any], bool] | None:
    """``is_safe_to_send(text, config)``: False when the text still contains anything a detector recognizes."""
    return _attr("shadowlens.analysis.engine", "is_safe_to_send")

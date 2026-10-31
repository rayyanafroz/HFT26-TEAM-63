"""Payload analysis: secrets, personal data, code and agent behavior (SOT 7.3, 7.4)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from shadowlens.analysis.engine import AnalysisResult, analyze, preview, redact_path
    from shadowlens.analysis.settings import AnalysisSettings, settings_for
    from shadowlens.analysis.text import TextResult, analyze_text

__all__ = ["AnalysisResult", "AnalysisSettings", "TextResult", "analyze", "analyze_text", "preview",
           "redact_path", "settings_for"]

_LOCATIONS = {
    "AnalysisResult": "engine", "analyze": "engine", "preview": "engine", "redact_path": "engine",
    "AnalysisSettings": "settings", "settings_for": "settings", "TextResult": "text", "analyze_text": "text",
}


def __getattr__(name: str) -> Any:
    # Loaded on first use, so `shadowlens.analysis.checksums` (used by fakes.py) stays light.
    module = _LOCATIONS.get(name)
    if module is None:
        raise AttributeError(name)
    from importlib import import_module
    return getattr(import_module(f"shadowlens.analysis.{module}"), name)

"""Payload analysis: secrets, personal data, code and agent behavior (SOT 7.3, 7.4).

See ``docs/DETECTORS.md``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from shadowlens.analysis.engine import AnalysisResult, DetectorFailure, analyze, is_safe_to_send, preview, redact_path
    from shadowlens.analysis.settings import AnalysisSettings, settings_for
    from shadowlens.analysis.text import TextResult, analyze_text

__all__ = ["AnalysisResult", "AnalysisSettings", "DetectorFailure", "TextResult", "analyze", "analyze_text",
           "is_safe_to_send", "preview", "redact_path", "settings_for"]

_LOCATIONS = {
    "AnalysisResult": "engine", "DetectorFailure": "engine", "analyze": "engine", "is_safe_to_send": "engine",
    "preview": "engine", "redact_path": "engine",
    "AnalysisSettings": "settings", "settings_for": "settings", "TextResult": "text", "analyze_text": "text",
}


def __getattr__(name: str) -> Any:
    # Loaded on first use, so `shadowlens.analysis.checksums` (used by fakes.py) stays light.
    module = _LOCATIONS.get(name)
    if module is None:
        raise AttributeError(name)
    from importlib import import_module
    return getattr(import_module(f"shadowlens.analysis.{module}"), name)

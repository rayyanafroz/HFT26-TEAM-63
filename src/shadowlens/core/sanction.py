"""Is a provider approved? One rule, used everywhere (pipeline and scoring)."""

from __future__ import annotations

from typing import Mapping

from ..config import Config


def effective_sanctioned(config: Config, overrides: Mapping[str, bool], provider_id: str) -> bool:
    """A choice made in the dashboard (``overrides``) beats the default list in the config."""
    if provider_id in overrides:
        return overrides[provider_id]
    return provider_id in config.sanctioned

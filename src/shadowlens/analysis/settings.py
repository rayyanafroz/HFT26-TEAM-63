"""What the analysis needs from the outside, loaded once at startup.

``analyze`` must not touch the disk (SOT 7.3), so the salt and the YAML files are read here and
the result is passed in.

Nothing here may stop detection. A missing, damaged or out-of-range setting falls back to its
default, an unusable salt file falls back to a salt kept in memory, and every fallback is logged
and listed in ``AnalysisSettings.warnings``. Values from the files are never logged.
"""

from __future__ import annotations

import logging
import re
import secrets
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from shadowlens.analysis.masking import SALT_BYTES, load_or_create_salt

log = logging.getLogger("shadowlens.analysis")

_REPO_CONFIG = Path(__file__).resolve().parents[3] / "config"
_DEFAULT_AGENT_RULES_PATH = _REPO_CONFIG / "agent_rules.yaml"
_RULES_FILE = "rules.yaml"


@dataclass(frozen=True)
class AgentRules:
    capabilities: dict[str, re.Pattern[str]]
    dangerous_commands: tuple[re.Pattern[str], ...]
    egress_commands: tuple[re.Pattern[str], ...]
    network_commands: tuple[re.Pattern[str], ...]
    sensitive_paths: tuple[re.Pattern[str], ...]
    read_only_commands: frozenset[str]
    read_only_git: frozenset[str]


def _compile_all(patterns: object) -> tuple[re.Pattern[str], ...]:
    compiled = []
    for pattern in patterns if isinstance(patterns, list) else []:
        try:
            compiled.append(re.compile(pattern, re.IGNORECASE))
        except (re.error, TypeError):
            log.error("skipping a bad pattern in agent_rules.yaml")
    return tuple(compiled)


@lru_cache(maxsize=4)
def load_agent_rules(path: Path = _DEFAULT_AGENT_RULES_PATH) -> AgentRules:
    """Read ``agent_rules.yaml``. If it cannot be read the agent rules simply find nothing, loudly."""
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        log.error("agent rules are OFF, could not read %s: %s", path, type(exc).__name__)
        raw = None
    raw = raw if isinstance(raw, dict) else {}
    capabilities = {}
    for name, pattern in (raw.get("capabilities") or {}).items():
        compiled = _compile_all([pattern])
        if compiled:
            capabilities[name] = compiled[0]
    return AgentRules(
        capabilities=capabilities,
        dangerous_commands=_compile_all(raw.get("dangerous_commands")),
        egress_commands=_compile_all(raw.get("egress_commands")),
        network_commands=_compile_all(raw.get("network_commands")),
        sensitive_paths=_compile_all(raw.get("sensitive_paths")),
        read_only_commands=frozenset(str(item).lower() for item in raw.get("read_only_commands") or ()),
        read_only_git=frozenset(str(item).lower() for item in raw.get("read_only_git") or ()),
    )


@dataclass(frozen=True)
class AnalysisSettings:
    """The defaults here are the fallback, and match ``config/rules.yaml`` (a test checks that)."""

    salt: bytes = field(repr=False)
    internal_markers: tuple[str, ...] = ()
    workspace_roots: tuple[str, ...] = ("~/projects", "~/source", "/workspace")

    entropy_alnum: float = 4.2
    entropy_hex: float = 3.3
    entropy_min_len: int = 24
    entropy_length_ratio: float = 0.88
    max_entropy_findings_per_event: int = 3
    entropy_digest_lengths: tuple[int, ...] = (32, 40, 64)

    generic_min_entropy: float = 3.0
    generic_min_len: int = 12
    generic_password_min_len: int = 8
    generic_placeholder_words: tuple[str, ...] = ("your_", "xxx", "changeme", "example", "<", "${", "{{")

    email_skip_domains: tuple[str, ...] = ("example.com", "example.org", "test.com", "localhost")

    marker_window: int = 200
    code_min_lines: int = 20
    code_min_distinct_tokens: int = 3
    code_min_shaped_lines: int = 3

    agent_rules: AgentRules = field(default_factory=load_agent_rules, repr=False)
    warnings: tuple[str, ...] = ()

    @classmethod
    def from_config(cls, config: Any) -> "AnalysisSettings":
        """Build from a ``shadowlens.config.Config``. This never raises because of a bad file."""
        warnings: list[str] = []
        values = _load_rules_file(Path(config.base_dir), warnings)
        return cls(
            salt=_load_salt(Path(config.salt_path), warnings),
            internal_markers=tuple(config.internal_markers),
            workspace_roots=tuple(config.workspace_roots),
            warnings=tuple(warnings),
            **values,
        )


# name -> (type, smallest allowed, largest allowed). Lists hold items of that type.
_NUMBERS: dict[str, tuple[type, float, float]] = {
    "entropy_alnum": (float, 1.0, 8.0),
    "entropy_hex": (float, 1.0, 4.0),
    "entropy_min_len": (int, 8, 512),
    "entropy_length_ratio": (float, 0.1, 1.0),
    "max_entropy_findings_per_event": (int, 0, 1000),
    "generic_min_entropy": (float, 0.0, 8.0),
    "generic_min_len": (int, 1, 512),
    "generic_password_min_len": (int, 1, 512),
    "marker_window": (int, 1, 100_000),
    "code_min_lines": (int, 1, 1_000_000),
    "code_min_distinct_tokens": (int, 1, 11),
    "code_min_shaped_lines": (int, 0, 1_000_000),
}
_LISTS: dict[str, type] = {
    "entropy_digest_lengths": int,
    "generic_placeholder_words": str,
    "email_skip_domains": str,
}


def _warn(warnings: list[str], message: str) -> None:
    warnings.append(message)
    log.warning("analysis settings: %s", message)


def _valid_number(value: Any, kind: type, low: float, high: float) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    if kind is int and not isinstance(value, int):
        return False
    return low <= value <= high


def _clean_rules(loaded: dict[Any, Any], warnings: list[str]) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for name, value in loaded.items():
        if name in _NUMBERS:
            kind, low, high = _NUMBERS[name]
            if _valid_number(value, kind, low, high):
                values[name] = kind(value)
            else:
                _warn(warnings, f"{name} is not a {kind.__name__} from {low} to {high}; using the default")
        elif name in _LISTS:
            kind = _LISTS[name]
            if isinstance(value, list) and value and all(isinstance(i, kind) and not isinstance(i, bool) for i in value):
                values[name] = tuple(value)
            else:
                _warn(warnings, f"{name} is not a list of {kind.__name__}; using the default")
        else:
            _warn(warnings, f"unknown setting {name!r} ignored (misspelled?)")
    return values


def _load_rules_file(base_dir: Path, warnings: list[str]) -> dict[str, Any]:
    """The project's ``config/rules.yaml``, or the one next to this code when run from elsewhere."""
    path = base_dir / "config" / _RULES_FILE
    if not path.exists():
        path = _REPO_CONFIG / _RULES_FILE
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        _warn(warnings, f"{_RULES_FILE} not found; using the default settings")
        return {}
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        _warn(warnings, f"could not read {_RULES_FILE} ({type(exc).__name__}); using the default settings")
        return {}
    if not isinstance(loaded, dict):
        _warn(warnings, f"{_RULES_FILE} is not a list of settings; using the default settings")
        return {}
    return _clean_rules(loaded, warnings)


def _load_salt(path: Path, warnings: list[str]) -> bytes:
    """A salt that cannot be saved only means hashes change on restart, so the same finding could
    be stored again after one. That is far better than no detection at all."""
    try:
        return load_or_create_salt(path)
    except OSError as exc:
        _warn(warnings, f"could not use the salt file ({type(exc).__name__}); using a temporary salt for this run")
        return secrets.token_bytes(SALT_BYTES)


@lru_cache(maxsize=8)
def _settings_from_config(config: Any) -> AnalysisSettings:
    return AnalysisSettings.from_config(config)


def settings_for(cfg: Any) -> AnalysisSettings:
    """Ready settings for the app's ``Config``, read once. ``AnalysisSettings`` pass straight through."""
    return cfg if isinstance(cfg, AnalysisSettings) else _settings_from_config(cfg)

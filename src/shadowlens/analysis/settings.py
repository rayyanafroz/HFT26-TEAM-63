"""What the analysis needs from the outside, loaded once at startup.

``analyze`` must not touch the disk (SOT 7.3), so the salt and the YAML files are
read here and the result is passed in.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import yaml

from shadowlens.analysis.masking import load_or_create_salt

log = logging.getLogger("shadowlens.analysis")

_DEFAULT_RULES_PATH = Path(__file__).resolve().parents[3] / "config" / "agent_rules.yaml"


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
def load_agent_rules(path: Path = _DEFAULT_RULES_PATH) -> AgentRules:
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
    salt: bytes = field(repr=False)
    internal_markers: tuple[str, ...] = ()
    workspace_roots: tuple[str, ...] = ("~/projects", "~/source", "/workspace")
    # config/rules.yaml (SOT 6.11)
    entropy_alnum: float = 4.2
    entropy_hex: float = 3.3
    entropy_min_len: int = 24
    max_entropy_findings_per_event: int = 3
    agent_rules: AgentRules = field(default_factory=load_agent_rules, repr=False)

    @classmethod
    def from_config(cls, config) -> "AnalysisSettings":
        """Build from a ``shadowlens.config.Config``. A missing or bad ``rules.yaml`` means defaults."""
        values = {}
        path = Path(config.base_dir) / "config" / "rules.yaml"
        try:
            loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                values = {key: loaded[key] for key in (
                    "entropy_alnum", "entropy_hex", "entropy_min_len", "max_entropy_findings_per_event",
                ) if key in loaded}
        except FileNotFoundError:
            pass
        except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
            log.warning("could not read %s: %s", path, type(exc).__name__)
        return cls(
            salt=load_or_create_salt(config.salt_path),
            internal_markers=config.internal_markers,
            workspace_roots=config.workspace_roots,
            **values,
        )


@lru_cache(maxsize=8)
def _settings_from_config(config) -> AnalysisSettings:
    return AnalysisSettings.from_config(config)


def settings_for(cfg) -> AnalysisSettings:
    """Ready settings for the app's ``Config``, read once. ``AnalysisSettings`` pass straight through."""
    return cfg if isinstance(cfg, AnalysisSettings) else _settings_from_config(cfg)

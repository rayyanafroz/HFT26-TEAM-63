"""Runtime configuration for ShadowLens (SOT section 5.4).

Everything the app can be configured with is read here, once, into one
immutable ``Config`` object. Other modules receive the object; they never read
environment variables themselves.

Sources, lowest to highest priority:
  1. the defaults in this file (identical to ``.env.example``)
  2. a ``.env`` file in the project folder (optional, git-ignored)
  3. real environment variables

Bad values never crash the app. They fall back to the default and the reason is
recorded in ``Config.warnings`` (and logged), so the problem is visible.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

log = logging.getLogger("shadowlens.config")

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}

# The server binds to loopback only (SOT 2.5 principle 4, AT-21).
LOOPBACK_HOST = "127.0.0.1"


def parse_dotenv(text: str) -> dict[str, str]:
    """Parse the contents of a ``.env`` file.

    Supports ``KEY=value`` lines, blank lines, full-line ``#`` comments and
    values wrapped in matching single or double quotes. Inline comments are not
    supported (a ``#`` inside a value is kept). A leading BOM (Windows Notepad)
    and ``\\r\\n`` line endings are handled.
    """
    out: dict[str, str] = {}
    for raw in text.lstrip("﻿").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key:
            out[key] = value
    return out


class _Reader:
    """Reads typed values from a mapping and collects warnings."""

    def __init__(self, values: Mapping[str, str]):
        self.values = values
        self.warnings: list[str] = []

    def _raw(self, name: str) -> str | None:
        value = self.values.get(name)
        if value is None:
            return None
        value = value.strip()
        return value if value != "" else None

    def _warn(self, name: str, problem: str, default: object) -> None:
        # Never include the value: it could be a secret.
        msg = f"{name}: {problem}; using default {default!r}"
        self.warnings.append(msg)
        log.warning(msg)

    def string(self, name: str, default: str) -> str:
        raw = self._raw(name)
        return default if raw is None else raw

    def optional_string(self, name: str) -> str | None:
        return self._raw(name)

    def boolean(self, name: str, default: bool) -> bool:
        raw = self._raw(name)
        if raw is None:
            return default
        low = raw.lower()
        if low in _TRUE:
            return True
        if low in _FALSE:
            return False
        self._warn(name, "not a boolean (use true/false)", default)
        return default

    def integer(self, name: str, default: int, minimum: int, maximum: int | None = None) -> int:
        raw = self._raw(name)
        if raw is None:
            return default
        try:
            value = int(raw)
        except ValueError:
            self._warn(name, "not an integer", default)
            return default
        if value < minimum or (maximum is not None and value > maximum):
            self._warn(name, "out of range", default)
            return default
        return value

    def number(self, name: str, default: float, minimum: float, allow_equal: bool = True) -> float:
        raw = self._raw(name)
        if raw is None:
            return default
        try:
            value = float(raw)
        except ValueError:
            self._warn(name, "not a number", default)
            return default
        bad = value < minimum if allow_equal else value <= minimum
        if bad:
            self._warn(name, "out of range", default)
            return default
        return value

    def csv(self, name: str, default: str, lower: bool = False) -> tuple[str, ...]:
        raw = self._raw(name)
        text = default if raw is None else raw
        items = [part.strip() for part in text.split(",")]
        if lower:
            items = [item.lower() for item in items]
        return tuple(item for item in items if item)


def _resolve_path(value: str, base_dir: Path) -> Path:
    """Resolve one of OUR OWN config paths.

    ``~`` expands to the user's home folder; relative paths are relative to the
    project folder. (Paths found inside AI payloads are different: they are only
    ever strings and never go through here, SOT 1.2.)
    """
    path = Path(value).expanduser()
    return path if path.is_absolute() else (base_dir / path)


def _valid_upstream(value: str) -> bool:
    host, sep, port = value.rpartition(":")
    return bool(sep) and bool(host) and port.isdigit() and 1 <= int(port) <= 65535


@dataclass(frozen=True)
class Config:
    # Server
    host: str
    port: int
    desktop: bool

    # Storage
    db_path: Path
    salt_path: Path

    # Analysis
    max_body_bytes: int
    workspace_roots: tuple[str, ...]  # kept as strings: normalized like payload paths (SOT 7.4)
    internal_markers: tuple[str, ...]
    sanctioned: tuple[str, ...]

    # Capture
    scan_interval_s: float
    resolve: bool
    live_dir: Path
    transcripts_enabled: bool
    transcript_dirs: tuple[Path, ...]
    proxy_enabled: bool
    proxy_port: int
    proxy_upstream: str

    # AI triage
    llm_enabled: bool
    llm_timeout_s: float
    llm_send_context: bool
    llm_max_auto: int
    featherless_api_key: str | None = field(repr=False)  # secret: never printed
    featherless_base_url: str = ""
    featherless_model: str | None = None

    base_dir: Path = field(default_factory=Path.cwd)
    warnings: tuple[str, ...] = ()

    # ---- derived values -------------------------------------------------

    @property
    def key_present(self) -> bool:
        return bool(self.featherless_api_key)

    @property
    def llm_mode(self) -> str:
        """``"llm"`` only when enabled AND a key AND a model are set (SOT 5.4)."""
        if self.llm_enabled and self.key_present and self.featherless_model:
            return "llm"
        return "template"

    @property
    def server_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def ensure_dirs(self) -> None:
        """Create the folders the app writes into (idempotent)."""
        for folder in (self.db_path.parent, self.salt_path.parent, self.live_dir):
            folder.mkdir(parents=True, exist_ok=True)

    # ---- loading --------------------------------------------------------

    @classmethod
    def load(
        cls,
        env: Mapping[str, str] | None = None,
        env_file: Path | None = None,
        base_dir: Path | None = None,
        use_dotenv: bool = True,
    ) -> "Config":
        """Build the configuration.

        ``env`` defaults to ``os.environ``. ``base_dir`` (default: current
        folder) is where relative paths and the ``.env`` file are looked up.
        """
        base = Path(base_dir) if base_dir is not None else Path.cwd()
        merged: dict[str, str] = {}

        if use_dotenv:
            dotenv_path = Path(env_file) if env_file is not None else base / ".env"
            try:
                merged.update(parse_dotenv(dotenv_path.read_text(encoding="utf-8")))
            except FileNotFoundError:
                pass
            except (OSError, UnicodeDecodeError) as exc:
                log.warning("could not read %s: %s", dotenv_path, type(exc).__name__)

        merged.update(os.environ if env is None else env)
        r = _Reader(merged)

        host = r.string("SHADOWLENS_HOST", LOOPBACK_HOST)
        if host != LOOPBACK_HOST:
            r._warn("SHADOWLENS_HOST", "only 127.0.0.1 is allowed", LOOPBACK_HOST)
            host = LOOPBACK_HOST

        proxy_upstream = r.string("SHADOWLENS_PROXY_UPSTREAM", "127.0.0.1:11434")
        if not _valid_upstream(proxy_upstream):
            r._warn("SHADOWLENS_PROXY_UPSTREAM", "expected host:port", "127.0.0.1:11434")
            proxy_upstream = "127.0.0.1:11434"

        transcript_dirs = tuple(
            _resolve_path(item, base)
            for item in r.csv("SHADOWLENS_TRANSCRIPT_DIRS", "")
        )

        return cls(
            host=host,
            port=r.integer("SHADOWLENS_PORT", 8787, 1, 65535),
            desktop=r.boolean("SHADOWLENS_DESKTOP", True),
            db_path=_resolve_path(r.string("SHADOWLENS_DB_PATH", "data/shadow.db"), base),
            salt_path=_resolve_path(r.string("SHADOWLENS_SALT_PATH", "data/salt"), base),
            max_body_bytes=r.integer("SHADOWLENS_MAX_BODY_BYTES", 262144, 1),
            workspace_roots=r.csv("SHADOWLENS_WORKSPACE_ROOTS", "~/projects,~/source,/workspace"),
            internal_markers=r.csv("SHADOWLENS_INTERNAL_MARKERS", ""),
            sanctioned=r.csv("SHADOWLENS_SANCTIONED", "ollama", lower=True),
            scan_interval_s=r.number("SHADOWLENS_SCAN_INTERVAL_S", 0.0, 0.0),
            resolve=r.boolean("SHADOWLENS_RESOLVE", True),
            live_dir=_resolve_path(r.string("SHADOWLENS_LIVE_DIR", "data/live"), base),
            transcripts_enabled=r.boolean("SHADOWLENS_TRANSCRIPTS_ENABLED", False),
            transcript_dirs=transcript_dirs,
            proxy_enabled=r.boolean("SHADOWLENS_PROXY_ENABLED", False),
            proxy_port=r.integer("SHADOWLENS_PROXY_PORT", 11436, 1, 65535),
            proxy_upstream=proxy_upstream,
            llm_enabled=r.boolean("SHADOWLENS_LLM_ENABLED", True),
            llm_timeout_s=r.number("SHADOWLENS_LLM_TIMEOUT_S", 15.0, 0.0, allow_equal=False),
            llm_send_context=r.boolean("SHADOWLENS_LLM_SEND_CONTEXT", True),
            llm_max_auto=r.integer("SHADOWLENS_LLM_MAX_AUTO", 12, 0),
            featherless_api_key=r.optional_string("FEATHERLESS_API_KEY"),
            featherless_base_url=r.string("FEATHERLESS_BASE_URL", "https://api.featherless.ai/v1"),
            featherless_model=r.optional_string("FEATHERLESS_MODEL"),
            base_dir=base,
            warnings=tuple(r.warnings),
        )

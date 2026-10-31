"""The AI provider catalog (SOT 7.1), loaded from ``config/providers.yaml``.

Every entry is validated when the file is loaded, so a typo (unknown category,
bad regex, unknown rule id, duplicate id) fails at startup with a clear message.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated

import yaml
from pydantic import Field, StringConstraints, ValidationError, field_validator, model_validator

from ..models import RULE_IDS, Category, ShadowModel

# <repo>/config/providers.yaml, found relative to this file (src/shadowlens/providers/catalog.py).
DEFAULT_CATALOG_PATH = Path(__file__).resolve().parents[3] / "config" / "providers.yaml"

ProviderId = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]*$")]


class CatalogError(ValueError):
    """The catalog file is missing, unreadable or invalid."""


class Provider(ShadowModel):
    id: ProviderId
    display_name: str = Field(min_length=1)
    category: Category
    hosts: list[str] = Field(default_factory=list)
    host_regex: str | None = None
    ports: list[Annotated[int, Field(ge=1, le=65535)]] = Field(default_factory=list)
    path_hints: list[str] = Field(default_factory=list)
    ports_need_path_hint: bool = False
    native_key_rules: list[str] = Field(default_factory=list)
    sanctioned_default: bool = False
    unverified: bool = False
    # Providers of one vendor share a family (api.anthropic.com and claude.ai are both Anthropic's and
    # sit on the same address). An address shared only within a family belongs to the first of them.
    family: str | None = None
    # False for providers whose host names point at generic shared servers (GitHub, Google, a CDN), where
    # an address alone says nothing about AI. They are still recognised by host name.
    ip_match: bool = True
    # Program names that are this provider's own client (e.g. "claude" for Anthropic). A program with one
    # of these names connecting to the provider's address is a confident match, not a guess.
    clients: list[str] = Field(default_factory=list)

    @field_validator("hosts")
    @classmethod
    def _clean_hosts(cls, hosts: list[str]) -> list[str]:
        cleaned = [h.strip().lower().strip(".") for h in hosts]
        if any(not h or "/" in h or " " in h for h in cleaned):
            raise ValueError("hosts must be plain host names")
        return cleaned

    @field_validator("host_regex")
    @classmethod
    def _regex_compiles(cls, pattern: str | None) -> str | None:
        if pattern is not None:
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(f"invalid host_regex: {exc}") from exc
        return pattern

    @field_validator("clients")
    @classmethod
    def _clean_clients(cls, clients: list[str]) -> list[str]:
        return [c.strip().lower().removesuffix(".exe") for c in clients if c.strip()]

    @field_validator("path_hints")
    @classmethod
    def _hints_start_with_slash(cls, hints: list[str]) -> list[str]:
        if any(not h.startswith("/") for h in hints):
            raise ValueError("path_hints must start with '/'")
        return [h.lower() for h in hints]

    @field_validator("native_key_rules")
    @classmethod
    def _known_rules(cls, rules: list[str]) -> list[str]:
        unknown = [r for r in rules if r not in RULE_IDS]
        if unknown:
            raise ValueError(f"unknown rule ids: {unknown}")
        return rules

    @model_validator(mode="after")
    def _has_a_way_to_match(self) -> "Provider":
        if not (self.hosts or self.host_regex or self.ports):
            raise ValueError("a provider needs hosts, host_regex or ports")
        if self.ports_need_path_hint and not (self.ports and self.path_hints):
            raise ValueError("ports_need_path_hint requires both ports and path_hints")
        return self

    @property
    def is_local(self) -> bool:
        return self.category is Category.LOCAL_LLM

    def matches_host(self, hostname: str) -> int:
        """How specifically ``hostname`` matches this provider: 0 = no match, higher = more
        specific (the longest matching host entry wins; a regex match counts as 1)."""
        best = 0
        for h in self.hosts:
            if hostname == h or hostname.endswith("." + h):
                best = max(best, len(h))
        if self.host_regex and re.fullmatch(self.host_regex, hostname, re.IGNORECASE):
            best = max(best, 1)
        return best


@dataclass(frozen=True)
class Catalog:
    providers: tuple[Provider, ...]
    category_exposure: dict[Category, float]

    # ---- loading --------------------------------------------------------

    @classmethod
    def load(cls, path: Path | str | None = None) -> "Catalog":
        file = Path(path) if path is not None else DEFAULT_CATALOG_PATH
        try:
            raw = yaml.safe_load(file.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise CatalogError(f"provider catalog not found: {file}") from exc
        except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
            raise CatalogError(f"cannot read provider catalog {file}: {type(exc).__name__}") from exc
        return cls.from_dict(raw, source=str(file))

    @classmethod
    def from_dict(cls, raw: object, source: str = "<catalog>") -> "Catalog":
        if not isinstance(raw, dict) or not isinstance(raw.get("providers"), list):
            raise CatalogError(f"{source}: expected a mapping with a 'providers' list")
        unknown_keys = set(raw) - {"providers", "category_exposure"}
        if unknown_keys:
            raise CatalogError(f"{source}: unknown top-level keys {sorted(unknown_keys)}")

        providers: list[Provider] = []
        for index, entry in enumerate(raw["providers"]):
            try:
                providers.append(Provider.model_validate(entry))
            except ValidationError as exc:
                label = entry.get("id", f"#{index}") if isinstance(entry, dict) else f"#{index}"
                first = exc.errors()[0]
                where = ".".join(str(p) for p in first["loc"])
                raise CatalogError(f"{source}: provider {label}: {where}: {first['msg']}") from exc

        ids = [p.id for p in providers]
        duplicates = sorted({i for i in ids if ids.count(i) > 1})
        if duplicates:
            raise CatalogError(f"{source}: duplicate provider ids {duplicates}")

        exposure_raw = raw.get("category_exposure")
        if not isinstance(exposure_raw, dict):
            raise CatalogError(f"{source}: 'category_exposure' is required")
        try:
            exposure = {Category(k): float(v) for k, v in exposure_raw.items()}
        except (ValueError, TypeError) as exc:
            raise CatalogError(f"{source}: bad category_exposure: {exc}") from exc
        missing = [c.value for c in Category if c not in exposure]
        if missing or any(v <= 0 for v in exposure.values()):
            raise CatalogError(f"{source}: category_exposure must cover every category with a value > 0 "
                               f"(missing: {missing})")
        return cls(providers=tuple(providers), category_exposure=exposure)

    # ---- lookups --------------------------------------------------------

    def get(self, provider_id: str) -> Provider | None:
        for provider in self.providers:
            if provider.id == provider_id:
                return provider
        return None

    def exposure(self, category: Category) -> float:
        return self.category_exposure[category]

    def native_key_ok(self, provider_id: str, rule_id: str) -> bool:
        """True when a credential of kind ``rule_id`` is normal use for this provider."""
        provider = self.get(provider_id)
        return provider is not None and rule_id in provider.native_key_rules

    def sanctioned_by_default(self) -> frozenset[str]:
        return frozenset(p.id for p in self.providers if p.sanctioned_default)

    def resolvable_hosts(self) -> dict[str, str]:
        """``{host name: provider_id}`` for every literal host of a cloud provider.

        These are the names the resolver looks up (SOT 7.1). Regex providers and local
        servers have nothing to look up.
        """
        return {h: p.id for p in self.providers if not p.is_local for h in p.hosts}

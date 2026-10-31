"""Decide which AI provider (if any) a network event is talking to (SOT 7.1).

Match order, strongest evidence first:

  1. the host name  (``match_basis: host``, confidence ``high``)
  2. a local LLM server port on a loopback/private destination
     (``match_basis: port``; ``high`` for dedicated ports such as Ollama's 11434,
     ``medium`` for ambiguous ports that also need an LLM-looking path)
  3. the destination IP in the resolver map  (``match_basis: resolved_ip``,
     confidence ``low``: shared CDN addresses make this a guess; ``medium`` when the program is
     that provider's own client, e.g. ``claude`` talking to Anthropic). Never for a web browser:
     it talks to every site, so an address alone cannot say it was an AI one.

No match returns ``None``; the caller drops the event and counts it.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Mapping

from ..models import (
    MatchBasis,
    MatchConfidence,
    NetEvent,
    ProviderMatch,
    make_tool_id,
)
from .catalog import Catalog, Provider

_PORT_SUFFIX = re.compile(r":\d+$")

_BROWSER_PREFIXES = ("chrome", "chromium", "brave", "firefox", "msedge", "microsoftedge", "iexplore",
                     "opera", "vivaldi", "safari", "librewolf", "waterfox", "tor-browser", "webkit")


def is_browser(process: str | None) -> bool:
    """A web browser (or one of its helper processes), judged by program name."""
    name = (process or "").strip().lower().removesuffix(".exe")
    return name.startswith(_BROWSER_PREFIXES)


def hostname_of(host: str | None) -> str | None:
    """A lowercase host name with any ``:port`` or IPv6 brackets removed."""
    if not host:
        return None
    host = host.strip().lower()
    if host.startswith("["):                       # [::1]:8080
        end = host.find("]")
        return host[1:end] if end > 0 else None
    if host.count(":") == 1:                       # example.com:8080 (a bare IPv6 has several colons)
        host = _PORT_SUFFIX.sub("", host)
    return host.rstrip(".") or None


# Real private networks only. Python's ``is_private`` also covers the documentation
# ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) that our fixtures use as
# stand-ins for public addresses, so it cannot be used here.
_PRIVATE_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",   # RFC 1918
    "169.254.0.0/16",                                    # IPv4 link-local
    "fc00::/7", "fe80::/10",                             # IPv6 unique-local and link-local
))


def _is_local_address(value: str) -> bool:
    """Loopback or a private network address.

    The unspecified address (0.0.0.0) is NOT local: our logs use it for 'address unknown'.
    """
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if ip.is_unspecified:
        return False
    return ip.is_loopback or any(ip.version == net.version and ip in net for net in _PRIVATE_NETWORKS)


def is_local_destination(event: NetEvent, hostname: str | None) -> bool:
    """True if the event went to this machine or a private network (SOT 7.1, step 2)."""
    if hostname == "localhost" or (hostname or "").endswith(".localhost"):
        return True
    if hostname and _is_local_address(hostname):
        return True
    return _is_local_address(event.dst_ip)


def _match(provider: Provider, event: NetEvent, confidence: MatchConfidence, basis: MatchBasis) -> ProviderMatch:
    return ProviderMatch(
        provider_id=provider.id,
        display_name=provider.display_name,
        category=provider.category,
        confidence=confidence,
        match_basis=basis,
        tool_id=make_tool_id(event.process, provider.id),
    )


def _by_host(catalog: Catalog, hostname: str) -> Provider | None:
    best: Provider | None = None
    best_score = 0
    for provider in catalog.providers:           # catalog order breaks ties
        score = provider.matches_host(hostname)
        if score > best_score:
            best, best_score = provider, score
    return best


def _by_local_port(catalog: Catalog, event: NetEvent) -> tuple[Provider, MatchConfidence] | None:
    path = (event.path or "").lower()
    candidates = [p for p in catalog.providers if p.is_local and event.dst_port in p.ports]
    for provider in candidates:                    # dedicated ports first: no path needed
        if not provider.ports_need_path_hint:
            return provider, MatchConfidence.HIGH
    for provider in candidates:                    # ambiguous ports: the path must look like an LLM API
        if provider.ports_need_path_hint and any(path.startswith(hint) for hint in provider.path_hints):
            return provider, MatchConfidence.MEDIUM
    return None


def classify(
    event: NetEvent,
    catalog: Catalog,
    resolved_ips: Mapping[str, str] | None = None,
) -> ProviderMatch | None:
    """The provider this event talks to, or ``None`` if it is not AI traffic.

    ``resolved_ips`` maps an IP address to a provider id (built by the resolver,
    only for IPs that belong to exactly one provider).
    """
    hostname = hostname_of(event.host)

    # 1. host name
    if hostname:
        provider = _by_host(catalog, hostname)
        if provider is not None:
            return _match(provider, event, MatchConfidence.HIGH, MatchBasis.HOST)

    # 2. local LLM server port
    if is_local_destination(event, hostname):
        found = _by_local_port(catalog, event)
        if found is not None:
            provider, confidence = found
            return _match(provider, event, confidence, MatchBasis.PORT)

    # 3. resolved IP (a guess: shared addresses are common)
    if resolved_ips and not is_browser(event.process):
        provider_id = resolved_ips.get(event.dst_ip)
        provider = catalog.get(provider_id) if provider_id else None
        if provider is not None:
            own_client = (event.process or "").lower() in provider.clients
            return _match(provider, event, MatchConfidence.MEDIUM if own_client else MatchConfidence.LOW,
                          MatchBasis.RESOLVED_IP)

    return None

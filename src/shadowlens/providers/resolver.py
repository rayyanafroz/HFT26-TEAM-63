"""Turn provider host names into IP addresses, so a bare connection can be recognised (SOT 7.1).

The live process scan only sees an IP address, never a host name. To still say
"this connection goes to OpenAI", we look up the catalog's host names ourselves
and remember which IPs they point to.

Safety rule: an IP is only used if it belongs to EXACTLY ONE provider. Many AI
services sit behind the same shared (CDN) addresses; guessing between them would
mislabel traffic. Matches made this way are low confidence anyway ("unconfirmed").

The resolver makes DNS lookups for the catalog's ~28 public host names and
nothing else (SOT 4.4). Turn it off with ``SHADOWLENS_RESOLVE=false``.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import threading
import time
from types import MappingProxyType
from typing import Callable, Mapping, Sequence

from .catalog import Catalog

log = logging.getLogger("shadowlens.resolver")

REFRESH_INTERVAL_S = 300.0   # SOT 7.1: at start and every 300 s
LOOKUP_TIMEOUT_S = 2.0       # SOT 7.1: per host

Lookup = Callable[[str], Sequence[str]]


def system_lookup(host: str) -> list[str]:
    """Ask the operating system's resolver for a host's addresses (IPv4 and IPv6)."""
    found: list[str] = []
    for *_, sockaddr in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM):
        found.append(str(sockaddr[0]))
    return found


def _usable(address: str) -> str | None:
    """A canonical IP string, or None if it must not be used as a provider marker.

    Loopback, unspecified, link-local and multicast addresses are skipped: a DNS
    sinkhole or hosts-file entry pointing a provider at 127.0.0.1 must not make
    all local traffic look like that provider.
    """
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])    # drop an IPv6 scope id (fe80::1%eth0)
    except ValueError:
        return None
    if ip.is_loopback or ip.is_unspecified or ip.is_link_local or ip.is_multicast:
        return None
    return str(ip)


class Resolver:
    def __init__(
        self,
        catalog: Catalog,
        *,
        enabled: bool = True,
        interval_s: float = REFRESH_INTERVAL_S,
        timeout_s: float = LOOKUP_TIMEOUT_S,
        lookup: Lookup = system_lookup,
    ):
        self._hosts = catalog.resolvable_hosts()       # {host name: provider_id}
        self.enabled = enabled
        self.interval_s = interval_s
        self.timeout_s = timeout_s
        self._lookup = lookup
        self._lock = threading.Lock()
        self._host_ips: dict[str, frozenset[str]] = {}  # last good answer per host
        self._ip_map: Mapping[str, str] = MappingProxyType({})
        self._last_refresh: float | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # ---- the answer ------------------------------------------------------

    @property
    def ip_map(self) -> Mapping[str, str]:
        """``{ip: provider_id}`` for IPs that belong to exactly one provider (a read-only snapshot)."""
        return self._ip_map

    def status(self) -> dict[str, object]:
        with self._lock:
            return {
                "enabled": self.enabled,
                "hosts_total": len(self._hosts),
                "hosts_resolved": len(self._host_ips),
                "ips": len(self._ip_map),
                "last_refresh_age_s": None if self._last_refresh is None
                else round(time.monotonic() - self._last_refresh, 1),
            }

    # ---- one pass --------------------------------------------------------

    def refresh(self) -> None:
        """Look up every host once (in parallel, each with its own timeout) and rebuild the map.

        A host whose lookup fails or times out keeps its previous answer, so a brief
        network problem does not wipe what we know.
        """
        if not self.enabled:
            return
        answers = self._lookup_all()
        with self._lock:
            for host, ips in answers.items():
                if ips:
                    self._host_ips[host] = ips
            owners: dict[str, set[str]] = {}
            for host, ips in self._host_ips.items():
                for ip in ips:
                    owners.setdefault(ip, set()).add(self._hosts[host])
            self._ip_map = MappingProxyType(
                {ip: next(iter(providers)) for ip, providers in owners.items() if len(providers) == 1})
            self._last_refresh = time.monotonic()

    def _lookup_all(self) -> dict[str, frozenset[str]]:
        results: dict[str, frozenset[str]] = {}

        def worker(host: str) -> None:
            try:
                ips = {u for a in self._lookup(host) if (u := _usable(a))}
            except Exception as exc:  # noqa: BLE001 - any resolver failure just means "no answer"
                log.debug("lookup failed for %s (%s)", host, type(exc).__name__)
                return
            results[host] = frozenset(ips)

        threads = [threading.Thread(target=worker, args=(h,), daemon=True) for h in self._hosts]
        for t in threads:
            t.start()
        deadline = time.monotonic() + self.timeout_s
        for t in threads:
            t.join(max(0.0, deadline - time.monotonic()))      # a stuck lookup is abandoned, never waited on
        return dict(results)                                   # copy: late workers cannot change it

    # ---- background thread ----------------------------------------------

    def start(self) -> None:
        """Start refreshing in the background (once now, then every ``interval_s``). Safe to call twice."""
        if not self.enabled or (self._thread is not None and self._thread.is_alive()):
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="shadowlens-resolver", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.refresh()
            except Exception:  # noqa: BLE001 - the thread must never die
                log.exception("resolver pass failed")
            self._stop.wait(self.interval_s)

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self.timeout_s + 1)
            self._thread = None

"""The live process scan: which programs are talking to which servers right now (SOT 7.2).

``psutil`` gives the operating system's list of open network connections. For each new
one we emit an event with the program name, the other end's address and port, and
nothing else: no payload (``metadata_only``). The classifier then decides whether the
other end is an AI service (by port for local model servers, by the resolver's IP map
for cloud ones).

Only the REMOTE address is used. That way the server side of a connection on this machine
(whose "remote" is the client's random port) can never be mistaken for an AI service.

Known limits, stated on the Capture screen: a connection shorter than the scan interval
is missed, and other users' processes are only visible with administrator rights.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from ..models import HostBasis, NetEvent, ScanScope, Source, new_id, utc_now_iso

log = logging.getLogger("shadowlens.conn_scan")

FORGET_AFTER_S = 60.0       # SOT 7.2: a connection not seen for this long counts as new if it returns
ESTABLISHED = "ESTABLISHED"


def is_privileged() -> bool:
    """Are we running with administrator (Windows) or root rights?"""
    try:
        if os.name == "nt":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())          # type: ignore[attr-defined]
        return os.geteuid() == 0
    except Exception:  # noqa: BLE001 - when unsure, say no
        return False


def scan_scope(privileged: bool, psutil_ok: bool) -> ScanScope:
    """Whose connections the scan can see (shown to the user)."""
    if not psutil_ok:
        return ScanScope.UNKNOWN
    return ScanScope.ALL_USERS if privileged else ScanScope.OWN_USER


def _clean_ip(value: str) -> str | None:
    """A plain IP string: no IPv6 scope id, IPv4-mapped IPv6 turned back into IPv4."""
    try:
        ip = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return str(ip)


def _default_connections() -> Iterable[Any]:
    import psutil
    return psutil.net_connections(kind="inet")


def _default_process_name(pid: int) -> str:
    import psutil
    return psutil.Process(pid).name()


@dataclass
class ScanResult:
    events: list[NetEvent] = field(default_factory=list)
    psutil_ok: bool = True
    error: str | None = None            # why the scan could not run, if it could not


class ConnectionScanner:
    def __init__(
        self,
        *,
        list_connections: Callable[[], Iterable[Any]] = _default_connections,
        process_name: Callable[[int], str] = _default_process_name,
        clock: Callable[[], float] = time.monotonic,
        forget_after_s: float = FORGET_AFTER_S,
    ):
        self._list = list_connections
        self._process_name = process_name
        self._clock = clock
        self._forget_after = forget_after_s
        self._seen: dict[tuple[int, str, int], float] = {}      # (pid, ip, port) -> last time we saw it

    def scan(self) -> ScanResult:
        """One look at the open connections. Returns events for the ones not seen before."""
        try:
            connections = list(self._list())
        except Exception as exc:  # noqa: BLE001 - e.g. AccessDenied on macOS without root, or no psutil
            log.warning("connection scan unavailable (%s)", type(exc).__name__)
            return ScanResult(psutil_ok=False, error=f"cannot list connections ({type(exc).__name__})")

        now = self._clock()
        events: list[NetEvent] = []
        names: dict[int, str | None] = {}                        # one process lookup per pid per scan
        for conn in connections:
            if getattr(conn, "status", None) != ESTABLISHED or not getattr(conn, "raddr", None):
                continue
            pid = getattr(conn, "pid", None)
            ip = _clean_ip(str(conn.raddr[0]))
            port = int(conn.raddr[1])
            if pid is None or ip is None:
                continue
            key = (pid, ip, port)
            known = key in self._seen
            self._seen[key] = now
            if known:
                continue
            if pid not in names:
                try:
                    names[pid] = self._process_name(pid)
                except Exception:  # noqa: BLE001 - process gone, or access denied: skip it (SOT 7.2)
                    names[pid] = None
            if names[pid] is None:
                del self._seen[key]                              # try again next scan
                continue
            events.append(NetEvent(
                id=new_id(), ts=utc_now_iso(), source=Source.CONN_SCAN, process=names[pid], pid=pid,
                dst_ip=ip, dst_port=port, host=None, host_basis=HostBasis.PORT_ONLY))

        cutoff = now - self._forget_after
        for key in [k for k, seen_at in self._seen.items() if seen_at < cutoff]:
            del self._seen[key]
        return ScanResult(events=events)

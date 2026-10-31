import os
import socket
import threading
from types import SimpleNamespace

import pytest

from shadowlens.ingest import conn_scan
from shadowlens.ingest.conn_scan import ConnectionScanner, ScanResult, is_privileged, scan_scope
from shadowlens.models import HostBasis, ScanScope, Source, Visibility


def conn(ip="203.0.113.7", port=443, pid=100, status="ESTABLISHED"):
    raddr = (ip, port) if ip is not None else ()
    return SimpleNamespace(status=status, raddr=raddr, pid=pid, laddr=("192.168.1.5", 50000))


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def scanner(connections, names=None, clock=None):
    state = {"connections": connections}
    names = names if names is not None else {}
    lookups = []

    def process_name(pid):
        lookups.append(pid)
        value = names.get(pid, f"proc{pid}")
        if isinstance(value, Exception):
            raise value
        return value

    s = ConnectionScanner(list_connections=lambda: state["connections"], process_name=process_name,
                          clock=clock or Clock())
    s.state, s.lookups = state, lookups
    return s


# ---- which connections count ----------------------------------------------------

def test_only_established_connections_with_a_remote_end_become_events():
    s = scanner([conn(), conn(status="LISTEN", ip=None), conn(status="TIME_WAIT", port=444),
                 conn(status="CLOSE_WAIT", port=445), conn(status="SYN_SENT", port=446),
                 conn(ip=None), conn(pid=None, port=447)])
    result = s.scan()
    assert [(e.dst_ip, e.dst_port, e.pid) for e in result.events] == [("203.0.113.7", 443, 100)]


def test_an_event_is_metadata_only_and_names_the_program_and_the_other_end():
    event = scanner([conn(pid=4123)], names={4123: "Python.EXE"}).scan().events[0]
    assert (event.source, event.process, event.pid) == (Source.CONN_SCAN, "python", 4123)   # .exe dropped, lowercased
    assert (event.dst_ip, event.dst_port) == ("203.0.113.7", 443)
    assert (event.host, event.host_basis, event.visibility) == (None, HostBasis.PORT_ONLY, Visibility.METADATA_ONLY)
    assert (event.body_text, event.bytes_out, event.method, event.path) == (None, None, None, None)
    assert event.ts.endswith("Z")


def test_the_ids_are_unique():
    events = scanner([conn(port=1), conn(port=2), conn(port=3)]).scan().events
    assert len({e.id for e in events}) == 3


# ---- new versus already seen ----------------------------------------------------

def test_a_connection_is_reported_once_however_often_it_is_seen():
    s = scanner([conn()])
    assert len(s.scan().events) == 1
    assert s.scan().events == [] and s.scan().events == []


def test_a_new_port_pid_or_address_is_a_new_connection():
    s = scanner([conn()])
    s.scan()
    s.state["connections"] = [conn(), conn(port=444), conn(pid=101), conn(ip="203.0.113.8")]
    found = sorted((e.dst_ip, e.dst_port, e.pid) for e in s.scan().events)
    assert found == sorted([("203.0.113.7", 444, 100), ("203.0.113.7", 443, 101), ("203.0.113.8", 443, 100)])
    assert s.scan().events == []                                  # and now they are known too


def test_a_connection_that_comes_back_within_a_minute_is_not_new_but_after_a_minute_it_is():
    clock = Clock()
    s = scanner([conn()], clock=clock)
    assert len(s.scan().events) == 1
    s.state["connections"] = []
    clock.now += 30
    s.scan()
    s.state["connections"] = [conn()]
    clock.now += 20                                   # gone for 50 s in total: still remembered
    assert s.scan().events == []
    s.state["connections"] = []
    clock.now += 70                                   # gone for more than 60 s: forgotten
    s.scan()
    s.state["connections"] = [conn()]
    assert len(s.scan().events) == 1


def test_a_connection_that_stays_open_is_never_forgotten():
    clock = Clock()
    s = scanner([conn()], clock=clock)
    s.scan()
    for _ in range(10):
        clock.now += 30                               # 5 minutes, always present
        assert s.scan().events == []


def test_memory_of_old_connections_is_released():
    clock = Clock()
    s = scanner([conn(port=p) for p in range(1, 51)], clock=clock)
    s.scan()
    assert len(s._seen) == 50
    s.state["connections"] = []
    clock.now += 61
    s.scan()
    assert s._seen == {}


# ---- process lookups --------------------------------------------------------------

def test_a_process_that_cannot_be_read_is_skipped_and_tried_again_next_time():
    s = scanner([conn(pid=7)], names={7: PermissionError("access denied")})
    assert s.scan().events == []
    s.state["connections"] = [conn(pid=7)]
    del s.lookups[:]
    s._process_name = lambda pid: "recovered"
    events = s.scan().events
    assert [e.process for e in events] == ["recovered"]


def test_each_process_is_looked_up_once_per_scan():
    s = scanner([conn(port=1, pid=5), conn(port=2, pid=5), conn(port=3, pid=5), conn(port=4, pid=6)])
    s.scan()
    assert sorted(s.lookups) == [5, 6]


def test_a_process_that_vanished_mid_scan_is_skipped():
    s = scanner([conn(pid=8), conn(pid=9)], names={8: ProcessLookupError("gone")})
    assert [e.pid for e in s.scan().events] == [9]


# ---- addresses --------------------------------------------------------------------

@pytest.mark.parametrize("given,expected", [
    ("2001:db8::1", "2001:db8::1"), ("fe80::1%eth0", "fe80::1"), ("::ffff:203.0.113.9", "203.0.113.9"),
    ("203.0.113.7", "203.0.113.7"), ("::1", "::1"),
])
def test_addresses_are_cleaned(given, expected):
    assert scanner([conn(ip=given)]).scan().events[0].dst_ip == expected


def test_an_unreadable_address_is_skipped():
    assert scanner([conn(ip="not-an-ip"), conn(ip="")]).scan().events == []


# ---- when the scan cannot run -----------------------------------------------------

def test_a_failing_connection_list_is_reported_not_raised():
    def broken():
        raise PermissionError("needs root")

    result = ConnectionScanner(list_connections=broken).scan()
    assert result == ScanResult(events=[], psutil_ok=False, error="cannot list connections (PermissionError)")


# ---- who can be seen ---------------------------------------------------------------

@pytest.mark.parametrize("privileged,ok,scope", [
    (False, True, ScanScope.OWN_USER), (True, True, ScanScope.ALL_USERS),
    (False, False, ScanScope.UNKNOWN), (True, False, ScanScope.UNKNOWN),
])
def test_scope(privileged, ok, scope):
    assert scan_scope(privileged, ok) is scope


@pytest.mark.skipif(os.name == "nt", reason="geteuid does not exist on Windows")
def test_privileged_on_posix(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    assert is_privileged() is True
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    assert is_privileged() is False


def test_privileged_never_raises(monkeypatch):
    def boom():
        raise OSError("no")
    monkeypatch.setattr(conn_scan.os, "name", "posix")
    monkeypatch.setattr(os, "geteuid", boom, raising=False)
    assert is_privileged() is False


# ---- the real thing ------------------------------------------------------------------

def test_the_real_scan_sees_a_real_connection_on_this_machine():
    """Open a real TCP connection and check psutil really reports it (the heart of AT-01)."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen()
    port = server.getsockname()[1]
    kept = []                                                       # keep the accepted socket OPEN, as a real server does
    accepted = threading.Thread(target=lambda: kept.append(server.accept()[0]), daemon=True)
    accepted.start()
    client = socket.create_connection(("127.0.0.1", port))
    accepted.join(2)
    assert kept, "the test server did not accept the connection"
    try:
        result = ConnectionScanner().scan()
        assert result.psutil_ok, result.error
        mine = [e for e in result.events if e.pid == os.getpid() and e.dst_port == port]
        assert len(mine) == 1                                     # the client side, once
        assert mine[0].dst_ip == "127.0.0.1" and mine[0].process
    finally:
        client.close()
        kept[0].close()
        server.close()

import threading
import time

import pytest

from shadowlens.models import MatchBasis, MatchConfidence, NetEvent, new_id
from shadowlens.providers import resolver as resolver_module
from shadowlens.providers.catalog import Catalog
from shadowlens.providers.classify import classify
from shadowlens.providers.resolver import Resolver, _usable, system_lookup

CATALOG = Catalog.load()


def fake_dns(table):
    """A lookup function backed by a dict; a missing host raises like a failed DNS query."""
    def lookup(host):
        if host not in table:
            raise OSError("no such host")
        return table[host]
    return lookup


def resolver(table, **kwargs):
    return Resolver(CATALOG, lookup=fake_dns(table), **kwargs)


# ---- building the map ----------------------------------------------------------

def test_unique_ips_map_to_their_provider():
    r = resolver({"api.openai.com": ["198.51.100.1"], "api.anthropic.com": ["198.51.100.2", "198.51.100.3"]})
    r.refresh()
    assert dict(r.ip_map) == {"198.51.100.1": "openai", "198.51.100.2": "anthropic", "198.51.100.3": "anthropic"}


def test_an_ip_shared_by_two_providers_is_not_used():
    r = resolver({"api.openai.com": ["198.51.100.1", "198.51.100.9"], "api.anthropic.com": ["198.51.100.9"]})
    r.refresh()
    assert dict(r.ip_map) == {"198.51.100.1": "openai"}          # .9 belongs to two providers: dropped


def test_an_ip_shared_by_two_hosts_of_the_same_provider_is_used():
    r = resolver({"chatgpt.com": ["198.51.100.5"], "chat.openai.com": ["198.51.100.5"]})
    r.refresh()
    assert dict(r.ip_map) == {"198.51.100.5": "chatgpt_web"}


def test_unusable_addresses_are_ignored():
    r = resolver({"api.openai.com": ["127.0.0.1", "0.0.0.0", "169.254.1.1", "224.0.0.1", "::1", "not-an-ip", "198.51.100.1"]})
    r.refresh()
    assert dict(r.ip_map) == {"198.51.100.1": "openai"}


@pytest.mark.parametrize("raw,expected", [
    ("198.51.100.1", "198.51.100.1"), ("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
    ("fe80::1%eth0", None), ("2001:db8::1%12", "2001:db8::1"), ("127.0.0.1", None), ("::", None),
    ("224.0.0.251", None), ("garbage", None), ("", None),
])
def test_usable_normalizes_or_rejects(raw, expected):
    assert _usable(raw) == expected


def test_only_catalog_hosts_are_looked_up():
    asked = []
    r = Resolver(CATALOG, lookup=lambda h: asked.append(h) or [])
    r.refresh()
    assert set(asked) == set(CATALOG.resolvable_hosts())
    assert len(asked) == 28
    assert not any(h in asked for h in ("localhost", "github.com"))


def test_the_map_is_a_read_only_snapshot():
    r = resolver({"api.openai.com": ["198.51.100.1"]})
    r.refresh()
    snapshot = r.ip_map
    with pytest.raises(TypeError):
        snapshot["203.0.113.1"] = "openai"                     # type: ignore[index]
    r2 = resolver({"api.openai.com": ["198.51.100.1"]})
    assert r2.ip_map == {}                                      # empty before the first pass


# ---- failures and timeouts -----------------------------------------------------

def test_a_failed_lookup_keeps_the_previous_answer():
    state = {"fail": False}

    def lookup(host):
        if host != "api.openai.com":
            return []
        if state["fail"]:
            raise OSError("network down")
        return ["198.51.100.1"]

    r = Resolver(CATALOG, lookup=lookup)
    r.refresh()
    assert dict(r.ip_map) == {"198.51.100.1": "openai"}
    state["fail"] = True
    r.refresh()
    assert dict(r.ip_map) == {"198.51.100.1": "openai"}          # still known


def test_a_first_time_failure_leaves_the_map_empty():
    r = resolver({})
    r.refresh()
    assert dict(r.ip_map) == {}
    assert r.status()["hosts_resolved"] == 0


def test_an_empty_answer_does_not_erase_a_known_one():
    answers = {"api.openai.com": ["198.51.100.1"]}
    r = Resolver(CATALOG, lookup=lambda h: answers.get(h, []))
    r.refresh()
    answers["api.openai.com"] = []
    r.refresh()
    assert dict(r.ip_map) == {"198.51.100.1": "openai"}


def test_a_hanging_lookup_cannot_hold_up_the_pass():
    release = threading.Event()

    def lookup(host):
        if host == "api.openai.com":
            release.wait(10)                                   # hangs, like a dead DNS server
            return ["198.51.100.99"]
        return ["198.51.100.2"] if host == "api.anthropic.com" else []

    r = Resolver(CATALOG, lookup=lookup, timeout_s=0.3)
    started = time.monotonic()
    try:
        r.refresh()
        elapsed = time.monotonic() - started
        assert elapsed < 2.0                                    # the hung host was abandoned after ~0.3 s
        assert dict(r.ip_map) == {"198.51.100.2": "anthropic"}
    finally:
        release.set()                                           # let the stuck thread finish
    time.sleep(0.1)
    assert "198.51.100.99" not in r.ip_map                      # a late answer is ignored for this pass


# ---- on/off and the background thread -------------------------------------------

def test_disabled_resolver_does_nothing():
    calls = []
    r = Resolver(CATALOG, enabled=False, lookup=lambda h: calls.append(h) or ["198.51.100.1"])
    r.refresh()
    r.start()
    time.sleep(0.05)
    assert calls == [] and dict(r.ip_map) == {} and r._thread is None
    r.stop()                                                    # harmless


def test_background_thread_refreshes_repeatedly_and_stops():
    count = {"n": 0}
    lock = threading.Lock()

    def lookup(host):
        if host == "api.openai.com":
            with lock:
                count["n"] += 1
            return ["198.51.100.1"]
        return []

    r = Resolver(CATALOG, lookup=lookup, interval_s=0.05)
    r.start()
    r.start()                                                   # second start is ignored
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline and count["n"] < 3:
        time.sleep(0.02)
    assert count["n"] >= 3 and dict(r.ip_map) == {"198.51.100.1": "openai"}
    r.stop()
    seen = count["n"]
    time.sleep(0.2)
    assert count["n"] == seen                                   # no more passes after stop()
    assert not any(t.name == "shadowlens-resolver" for t in threading.enumerate())


def test_a_crashing_pass_does_not_kill_the_thread(monkeypatch):
    r = resolver({"api.openai.com": ["198.51.100.1"]}, interval_s=0.05)
    real = r.refresh
    state = {"calls": 0}

    def flaky():
        state["calls"] += 1
        if state["calls"] == 1:
            raise RuntimeError("boom")
        real()

    monkeypatch.setattr(r, "refresh", flaky)
    r.start()
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline and not r.ip_map:
        time.sleep(0.02)
    r.stop()
    assert state["calls"] >= 2 and dict(r.ip_map) == {"198.51.100.1": "openai"}


def test_status_reports_progress():
    r = resolver({"api.openai.com": ["198.51.100.1"]})
    assert r.status()["last_refresh_age_s"] is None
    r.refresh()
    status = r.status()
    assert status["enabled"] is True and status["hosts_total"] == 28
    assert status["hosts_resolved"] == 1 and status["ips"] == 1
    assert status["last_refresh_age_s"] is not None


# ---- system lookup and use with the classifier ---------------------------------

def test_system_lookup_returns_the_addresses_from_getaddrinfo(monkeypatch):
    def fake_getaddrinfo(host, port, type=0):                   # noqa: A002 - mirrors the real signature
        return [(2, 1, 6, "", ("198.51.100.1", 0)), (10, 1, 6, "", ("2001:db8::1", 0, 0, 0))]

    monkeypatch.setattr(resolver_module.socket, "getaddrinfo", fake_getaddrinfo)
    assert system_lookup("api.openai.com") == ["198.51.100.1", "2001:db8::1"]


def test_resolver_map_drives_a_low_confidence_match():
    r = resolver({"api.anthropic.com": ["198.51.100.2"]})
    r.refresh()
    event = NetEvent(id=new_id(), ts="2026-10-31T10:00:00.000Z", source="conn_scan", process="claude", pid=1,
                     dst_ip="198.51.100.2", dst_port=443, host_basis="port_only")
    match = classify(event, CATALOG, r.ip_map)
    assert (match.tool_id, match.match_basis, match.confidence) == (
        "claude|anthropic", MatchBasis.RESOLVED_IP, MatchConfidence.LOW)

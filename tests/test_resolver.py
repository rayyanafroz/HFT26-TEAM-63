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
    event = NetEvent(id=new_id(), ts="2026-10-31T10:00:00.000Z", source="conn_scan", process="somescript", pid=1,
                     dst_ip="198.51.100.2", dst_port=443, host_basis="port_only")
    match = classify(event, CATALOG, r.ip_map)
    assert (match.tool_id, match.match_basis, match.confidence) == (
        "somescript|anthropic", MatchBasis.RESOLVED_IP, MatchConfidence.LOW)


# ---- vendors that share an address, shared servers, browsers, own clients ---------------------------

def _scan_event(process, ip, port=443):
    return NetEvent(id=new_id(), ts="2026-10-31T10:00:00.000Z", source="conn_scan", process=process, pid=1,
                    dst_ip=ip, dst_port=port, host_basis="port_only")


def test_two_providers_of_one_vendor_may_share_an_address():
    # api.anthropic.com and claude.ai really do share 160.79.104.10
    r = resolver({"api.anthropic.com": ["198.51.100.20"], "claude.ai": ["198.51.100.20"]})
    r.refresh()
    assert dict(r.ip_map) == {"198.51.100.20": "anthropic"}          # the vendor's first provider, not dropped


def test_vendors_sharing_an_address_are_still_dropped():
    r = resolver({"api.anthropic.com": ["198.51.100.21"], "api.openai.com": ["198.51.100.21"]})
    r.refresh()
    assert dict(r.ip_map) == {}


def test_providers_on_generic_shared_servers_are_never_matched_by_address():
    r = resolver({"api.githubcopilot.com": ["198.51.100.30"], "gemini.google.com": ["198.51.100.31"],
                  "generativelanguage.googleapis.com": ["198.51.100.32"], "huggingface.co": ["198.51.100.33"],
                  "api.openai.com": ["198.51.100.34"]})
    r.refresh()
    assert dict(r.ip_map) == {"198.51.100.34": "openai"}
    assert classify(_scan_event("python", "198.51.100.30"), CATALOG, r.ip_map) is None


@pytest.mark.parametrize("browser", ["brave", "chrome", "chrome.exe", "firefox", "msedge.exe", "Chromium", "vivaldi-bin"])
def test_a_browser_is_never_matched_by_address_alone(browser):
    r = resolver({"api.featherless.ai": ["198.51.100.40"]})
    r.refresh()
    assert classify(_scan_event(browser, "198.51.100.40"), CATALOG, r.ip_map) is None
    assert classify(_scan_event("python", "198.51.100.40"), CATALOG, r.ip_map).provider_id == "featherless"


def test_a_browser_is_still_recognised_by_host_name():
    event = NetEvent(id=new_id(), ts="2026-10-31T10:00:00.000Z", source="http_log", process="chrome",
                     host="api.openai.com", dst_ip="198.51.100.41", dst_port=443, host_basis="host_header")
    assert classify(event, CATALOG, {}).provider_id == "openai"


def test_a_providers_own_client_is_a_confident_match():
    r = resolver({"api.anthropic.com": ["198.51.100.50"], "claude.ai": ["198.51.100.50"]})
    r.refresh()
    own = classify(_scan_event("claude", "198.51.100.50"), CATALOG, r.ip_map)
    assert (own.tool_id, own.confidence, own.match_basis) == ("claude|anthropic", MatchConfidence.MEDIUM, MatchBasis.RESOLVED_IP)
    assert classify(_scan_event("claude.exe", "198.51.100.50"), CATALOG, r.ip_map).confidence is MatchConfidence.MEDIUM
    other = classify(_scan_event("notes", "198.51.100.50"), CATALOG, r.ip_map)
    assert other.confidence is MatchConfidence.LOW                       # any other program stays a guess


def test_the_catalog_fields_are_validated():
    base = {"id": "x", "display_name": "X", "category": "cloud_llm", "hosts": ["x.example"]}
    from shadowlens.providers.catalog import Provider
    assert Provider.model_validate({**base, "clients": [" Claude.EXE ", ""]}).clients == ["claude"]
    with pytest.raises(Exception):
        Provider.model_validate({**base, "ip_match": "maybe"})


# ---- the scan waits for the first lookup round ------------------------------------------------------

def test_wait_ready_does_not_block_when_the_resolver_is_off_or_never_started():
    assert resolver({}).wait_ready(0.01) is True                        # never started
    assert resolver({}, enabled=False).wait_ready(0.01) is True


def test_wait_ready_waits_for_the_first_round_then_returns_at_once():
    gate = threading.Event()

    def slow(host):
        gate.wait(5)
        return ["198.51.100.60"]

    r = Resolver(CATALOG, lookup=slow, timeout_s=5)
    r.start()
    try:
        assert r.wait_ready(0.2) is False                               # still looking up
        gate.set()
        assert r.wait_ready(5) is True
        started = time.monotonic()
        assert r.wait_ready(5) is True and time.monotonic() - started < 0.1
    finally:
        gate.set()
        r.stop()


def test_the_scan_waits_for_the_first_lookup_round(tmp_path):
    """A scan that runs first judges the connections already open before any provider address is known,
    and the scanner never looks at those again (found with a real Claude Code process)."""
    import dataclasses

    from fastapi.testclient import TestClient

    from shadowlens.api.app import create_app
    from shadowlens.config import Config
    from shadowlens.ingest.conn_scan import ScanResult

    order = []

    def slow_lookup(host):
        time.sleep(0.4)
        order.append("lookup done")
        return ["198.51.100.70"]

    class Scanner:
        def scan(self):
            order.append("scan")
            return ScanResult()

        def forget(self):
            pass

    config = dataclasses.replace(Config.load(), db_path=tmp_path / "t.db", live_dir=tmp_path / "live", scan_interval_s=5.0)
    app = create_app(config, resolver=Resolver(CATALOG, lookup=slow_lookup, timeout_s=3), scanner=Scanner())
    with TestClient(app):
        deadline = time.monotonic() + 5
        while "scan" not in order and time.monotonic() < deadline:
            time.sleep(0.05)
    assert "scan" in order and order.index("lookup done") < order.index("scan")

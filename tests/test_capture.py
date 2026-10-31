import json
import threading
import time
from types import SimpleNamespace

import pytest

from shadowlens.config import Config
from shadowlens.core.capture import DEFAULT_SCAN_INTERVAL_S, CaptureManager, current_platform
from shadowlens.core.pipeline import Pipeline
from shadowlens.core.scenario_player import ScenarioPlayer
from shadowlens.db import Database
from shadowlens.ingest.conn_scan import ConnectionScanner
from shadowlens.ingest.live_tail import LiveTail
from shadowlens.models import CaptureMode, Platform, ScanScope
from shadowlens.providers.catalog import Catalog


def conn(ip="127.0.0.1", port=11434, pid=100):
    return SimpleNamespace(status="ESTABLISHED", raddr=(ip, port), pid=pid)


@pytest.fixture
def db(tmp_path):
    database = Database(tmp_path / "shadow.db")
    yield database
    database.close()


class Rig:
    def __init__(self, tmp_path, db, connections=None, privileged=False, **env):
        self.config = Config.load(env={"SHADOWLENS_RESOLVE": "false", **env}, base_dir=tmp_path, use_dotenv=False)
        self.db = db
        self.pipeline = Pipeline(self.config, db, Catalog.load())
        self.live = tmp_path / "live"
        self.live.mkdir(exist_ok=True)
        self.connections = connections if connections is not None else []
        self.scanner = ConnectionScanner(list_connections=lambda: self.connections, process_name=lambda pid: f"proc{pid}.exe")
        self.tail = LiveTail(self.live, db, lambda ev, sk, er: self.pipeline.ingest(ev, source="live_log", skipped=sk, errors=er),
                             poll_s=0.05)
        templates = tmp_path / "templates"
        templates.mkdir(exist_ok=True)
        self.templates = templates
        self.player = ScenarioPlayer(self.pipeline, lambda k, p: None, templates_dir=templates, max_body_bytes=65536)
        self.capture = CaptureManager(self.config, self.pipeline, self.scanner, self.tail, self.player,
                                      privileged=lambda: privileged)

    def close(self):
        self.capture.shutdown()


@pytest.fixture
def rig(tmp_path, db):
    made = []

    def build(**kw):
        r = Rig(tmp_path, db, **kw)
        made.append(r)
        return r

    yield build
    for r in made:
        r.close()


def wait_for(predicate, timeout=4.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return False


# ---- scanning once ------------------------------------------------------------------

def test_scan_once_stores_what_it_finds_and_names_the_ollama_server(rig):
    r = rig(connections=[conn(), conn(ip="203.0.113.7", port=443, pid=101)])
    summary = r.capture.scan_once()
    assert (summary.source, summary.accepted, summary.dropped_non_ai) == ("conn_scan", 1, 1)
    event = r.db.list_events().items[0]
    assert (event.tool_id, event.provider_id, event.visibility.value, event.source.value) == (
        "proc100|ollama", "ollama", "metadata_only", "conn_scan")           # ".exe" gone, found by its port
    assert r.capture.scan_once().accepted == 0                               # the same connections are not new
    r.connections.append(conn(port=11434, pid=102))
    assert r.capture.scan_once().accepted == 1


def test_a_scan_that_cannot_run_says_so(rig):
    r = rig()
    r.scanner._list = lambda: (_ for _ in ()).throw(PermissionError("needs root"))
    summary = r.capture.scan_once()
    assert summary.accepted == 0 and "cannot list connections" in summary.errors[0]
    status = r.capture.status()
    assert status.scan.psutil_ok is False and status.scan.scope is ScanScope.UNKNOWN


# ---- the status -----------------------------------------------------------------------

def test_a_fresh_manager_is_idle_and_describes_itself(rig):
    r = rig()
    s = r.capture.status()
    assert s.mode is CaptureMode.IDLE
    assert (s.scan.enabled, s.scan.interval_s, s.scan.last_scan_at) == (False, DEFAULT_SCAN_INTERVAL_S, None)
    assert (s.scan.scope, s.scan.privileged, s.scan.psutil_ok) == (ScanScope.OWN_USER, False, True)
    assert (s.live_tail.enabled, s.live_tail.dir, s.live_tail.lines_ingested) == (False, str(r.live), 0)
    assert s.transcripts.enabled is False and s.proxy.listen_port == 11436 and s.proxy.upstream == "127.0.0.1:11434"
    assert s.platform is current_platform() and isinstance(s.platform, Platform)
    assert (s.scenario.name, s.scenario.played, s.scenario.total) == (None, 0, 0)


def test_an_administrator_can_see_everyones_connections(rig):
    assert rig(privileged=True).capture.status().scan.scope is ScanScope.ALL_USERS
    assert rig(privileged=False).capture.status().scan.scope is ScanScope.OWN_USER


def test_last_scan_time_is_recorded(rig):
    r = rig()
    r.capture.scan_once()
    assert r.capture.status().scan.last_scan_at.endswith("Z")


def test_the_mode_follows_what_is_running(rig):
    r = rig(connections=[])
    assert r.capture.status().mode is CaptureMode.IDLE
    r.capture.start(tail=True)
    assert r.capture.status().mode is CaptureMode.WATCHING
    r.capture.start(scan=True)
    assert r.capture.status().mode is CaptureMode.SCANNING                 # scanning is the more active state
    (r.templates / "quick_leak.jsonl").write_text(
        json.dumps({"t_ms": 0, "host": "api.openai.com", "method": "POST", "path": "/"}) + "\n"
        + json.dumps({"t_ms": 30000, "host": "api.openai.com", "method": "POST", "path": "/"}) + "\n", encoding="utf-8")
    r.player.play("quick_leak")
    assert r.capture.status().mode is CaptureMode.PLAYING                  # and playing beats both
    r.player.stop()
    assert r.capture.status().mode is CaptureMode.SCANNING


# ---- switching on and off --------------------------------------------------------------

def test_naming_neither_switch_means_both(rig):
    r = rig()
    s = r.capture.start()
    assert (s.scan.enabled, s.live_tail.enabled) == (True, True)
    s = r.capture.stop()
    assert (s.scan.enabled, s.live_tail.enabled) == (False, False)


def test_each_switch_works_on_its_own(rig):
    r = rig()
    assert r.capture.start(scan=True).scan.enabled and not r.capture.status().live_tail.enabled
    assert r.capture.start(tail=True).live_tail.enabled
    assert not r.capture.stop(scan=True).scan.enabled and r.capture.status().live_tail.enabled
    assert not r.capture.stop(tail=True).live_tail.enabled


def test_false_does_not_switch_anything(rig):
    r = rig()
    s = r.capture.start(scan=False, tail=False)
    assert (s.scan.enabled, s.live_tail.enabled) == (False, False)


def test_starting_twice_is_harmless(rig):
    r = rig()
    r.capture.start_scan()
    thread = r.capture._scan_thread
    r.capture.start_scan()
    assert r.capture._scan_thread is thread
    r.capture.stop_scan()
    r.capture.stop_scan()


def test_the_scan_loop_scans_again_and_again(rig):
    r = rig(connections=[conn()], SHADOWLENS_SCAN_INTERVAL_S="0.05")
    r.capture.start_scan()
    assert wait_for(lambda: r.db.count_events() == 1)
    r.connections.append(conn(port=11434, pid=555))
    assert wait_for(lambda: r.db.count_events() == 2)                       # picked up without being asked
    r.capture.stop_scan()
    r.connections.append(conn(port=11434, pid=556))
    time.sleep(0.3)
    assert r.db.count_events() == 2                                         # and it stops when told


def test_defaults_at_startup_are_tail_on_and_scan_only_if_configured(rig):
    quiet = rig()
    quiet.capture.start_defaults()
    assert (quiet.capture.status().live_tail.enabled, quiet.capture.status().scan.enabled) == (True, False)
    keen = rig(SHADOWLENS_SCAN_INTERVAL_S="3")
    keen.capture.start_defaults()
    assert keen.capture.status().scan.enabled and keen.capture.status().scan.interval_s == 3.0


def test_lines_appended_to_the_live_folder_arrive_after_start(rig):
    r = rig()
    r.capture.start(tail=True)
    line = json.dumps({"ts": "2026-10-31T10:00:00Z", "host": "api.openai.com", "method": "POST", "path": "/v1", "process_name": "x"})
    with open(r.live / "a.jsonl", "w", encoding="utf-8") as f:
        f.write(line + "\n")
    assert wait_for(lambda: r.db.count_events() == 1)
    assert r.db.list_events().items[0].source.value == "live_log"
    assert wait_for(lambda: r.capture.status().live_tail.lines_ingested == 1)


# ---- reset and shutdown ---------------------------------------------------------------------

def test_reset_clears_results_stops_playback_and_forgets_the_scenario(rig):
    r = rig(connections=[conn()])
    (r.templates / "quick_leak.jsonl").write_text(
        "\n".join(json.dumps({"t_ms": t, "host": "api.openai.com", "method": "POST", "path": "/"}) for t in (0, 40000)) + "\n",
        encoding="utf-8")
    r.capture.scan_once()
    r.player.play("quick_leak")
    assert wait_for(lambda: r.db.count_events() >= 2)
    r.db.set_provider_override("openai", True)
    r.capture.reset()
    assert r.db.count_events() == 0 and r.db.get_provider_overrides() == {}
    assert not r.player.playing and r.capture.status().scenario.name is None


def test_shutdown_stops_every_thread(rig):
    r = rig(connections=[conn()])
    r.capture.start()
    r.capture.shutdown()
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline and any(t.name.startswith("shadowlens-") for t in threading.enumerate()):
        time.sleep(0.02)
    assert not [t.name for t in threading.enumerate() if t.name.startswith("shadowlens-")]

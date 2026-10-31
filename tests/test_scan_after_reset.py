"""After Reset, the process scan must report the open connections again (not only new ones).

Found while building the guided demo: Reset cleared the results but not the scanner's memory, so a
scan right after it saw nothing for the next 60 seconds.
"""

from types import SimpleNamespace

from shadowlens.config import Config
from shadowlens.core.capture import CaptureManager
from shadowlens.core.pipeline import Pipeline
from shadowlens.core.scenario_player import ScenarioPlayer
from shadowlens.db import Database
from shadowlens.ingest.conn_scan import ConnectionScanner
from shadowlens.ingest.live_tail import LiveTail
from shadowlens.providers.catalog import Catalog


def conn(port=11434, pid=100):
    return SimpleNamespace(status="ESTABLISHED", raddr=("127.0.0.1", port), pid=pid)


def test_a_scanner_that_forgets_reports_known_connections_again():
    connections = [conn(), conn(pid=101)]
    scanner = ConnectionScanner(list_connections=lambda: connections, process_name=lambda pid: f"proc{pid}")
    assert len(scanner.scan().events) == 2
    assert scanner.scan().events == []                    # nothing is new
    scanner.forget()
    assert len(scanner.scan().events) == 2


def test_forgetting_an_empty_scanner_is_harmless():
    scanner = ConnectionScanner(list_connections=lambda: [])
    scanner.forget()
    assert scanner.scan().events == []


def test_reset_makes_the_next_scan_find_the_same_connection_again(tmp_path):
    config = Config.load(env={"SHADOWLENS_RESOLVE": "false"}, base_dir=tmp_path, use_dotenv=False)
    db = Database(tmp_path / "shadow.db")
    try:
        pipeline = Pipeline(config, db, Catalog.load())
        live = tmp_path / "live"
        live.mkdir()
        templates = tmp_path / "templates"
        templates.mkdir()
        scanner = ConnectionScanner(list_connections=lambda: [conn()], process_name=lambda pid: "ollama")
        tail = LiveTail(live, db, lambda ev, sk, er: pipeline.ingest(ev, source="live_log"), poll_s=0.05)
        player = ScenarioPlayer(pipeline, lambda k, p: None, templates_dir=templates, max_body_bytes=65536)
        capture = CaptureManager(config, pipeline, scanner, tail, player, privileged=lambda: False)

        assert capture.scan_once().accepted == 1
        assert capture.scan_once().accepted == 0          # already known
        capture.reset()
        assert db.count_events() == 0
        assert capture.scan_once().accepted == 1          # found again, as after a fresh start
        assert db.count_events() == 1
    finally:
        db.close()

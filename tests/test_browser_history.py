"""Browser history source: AI websites seen in a browser's history (metadata only)."""

import sqlite3
import sys
import time
from pathlib import Path

import pytest

from shadowlens.ingest import browser_history as bh
from shadowlens.models import Source, Visibility

CHROMIUM_EPOCH_US = 11_644_473_600 * 1_000_000
AI = {"chatgpt.com", "claude.ai", "gemini.google.com"}


def is_ai(host: str) -> bool:
    return host in AI


def chromium_profile(root: Path, visits: list[tuple[str, float]]) -> Path:
    folder = root / "Default"
    folder.mkdir(parents=True)
    db = folder / "History"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT)")
    conn.execute("CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER)")
    for index, (url, unix) in enumerate(visits, 1):
        conn.execute("INSERT INTO urls VALUES (?,?,?)", (index, url, "SECRET TITLE"))
        conn.execute("INSERT INTO visits VALUES (?,?,?)", (index, index, int(unix * 1_000_000) + CHROMIUM_EPOCH_US))
    conn.commit()
    conn.close()
    return db


def firefox_profile(root: Path, visits: list[tuple[str, float]]) -> Path:
    folder = root / "abc.default"
    folder.mkdir(parents=True)
    db = folder / "places.sqlite"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT)")
    conn.execute("CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, place_id INTEGER, visit_date INTEGER)")
    for index, (url, unix) in enumerate(visits, 1):
        conn.execute("INSERT INTO moz_places VALUES (?,?)", (index, url))
        conn.execute("INSERT INTO moz_historyvisits VALUES (?,?,?)", (index, index, int(unix * 1_000_000)))
    conn.commit()
    conn.close()
    return db


@pytest.fixture
def linux(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")


def watcher(home: Path, sink: list, clock=time.time) -> bh.BrowserWatcher:
    return bh.BrowserWatcher(lambda events, **kw: sink.extend(events), is_ai, home=home, clock=clock)


def test_chromium_visits_become_metadata_only_events(tmp_path, linux):
    now = time.time()
    chromium_profile(tmp_path / ".config" / "BraveSoftware" / "Brave-Browser", [
        ("https://chatgpt.com/c/abc?secret=1", now + 1), ("https://example.com/", now + 2),
        ("https://gemini.google.com/app", now + 3), ("https://claude.ai/new", now + 4)])
    sink: list = []
    w = watcher(tmp_path, sink, clock=lambda: now)
    w.start()
    w.stop()
    w.poll_once()
    hosts = sorted(e.host for e in sink)
    assert hosts == ["chatgpt.com", "claude.ai", "gemini.google.com"]
    assert all(e.process == "brave" and e.source is Source.BROWSER for e in sink)
    assert all(e.visibility is Visibility.METADATA_ONLY and not e.body_text for e in sink)
    assert all("?" not in (e.path or "") for e in sink)             # no query string kept


def test_only_new_visits_are_read_after_switching_on(tmp_path, linux):
    now = time.time()
    db = chromium_profile(tmp_path / ".config" / "chromium", [("https://chatgpt.com/old", now - 600)])
    sink: list = []
    w = watcher(tmp_path, sink, clock=lambda: now)
    w.start()
    w.stop()
    assert w.poll_once() == 0                                        # the old visit is history, not news
    conn = sqlite3.connect(db)
    conn.execute("INSERT INTO urls VALUES (9,'https://claude.ai/chat/1','t')")
    conn.execute("INSERT INTO visits VALUES (9,9,?)", (int((now + 5) * 1_000_000) + CHROMIUM_EPOCH_US,))
    conn.commit()
    conn.close()
    assert w.poll_once() == 1 and [e.host for e in sink] == ["claude.ai"]
    assert w.poll_once() == 0                                        # not read twice


def test_backfill_reads_the_recent_past(tmp_path, linux):
    now = time.time()
    chromium_profile(tmp_path / ".config" / "chromium", [
        ("https://chatgpt.com/", now - 300), ("https://claude.ai/", now - 7200)])
    sink: list = []
    w = watcher(tmp_path, sink, clock=lambda: now)
    w.start(backfill=True)
    w.stop()
    assert [e.host for e in sink] == ["chatgpt.com"]                 # 5 minutes ago yes, 2 hours ago no


def test_repeat_visits_to_one_site_are_collapsed(tmp_path, linux):
    now = time.time()
    chromium_profile(tmp_path / ".config" / "chromium", [
        ("https://chatgpt.com/c/1", now + 1), ("https://chatgpt.com/c/2", now + 5),
        ("https://chatgpt.com/c/3", now + 60)])
    sink: list = []
    w = watcher(tmp_path, sink, clock=lambda: now)
    w.start()
    w.stop()
    w.poll_once()
    assert len(sink) == 2                                            # the 5 s revisit is folded into the first


def test_firefox_history_is_read_too(tmp_path, linux):
    now = time.time()
    firefox_profile(tmp_path / ".mozilla" / "firefox", [("https://gemini.google.com/app", now + 2)])
    sink: list = []
    w = watcher(tmp_path, sink, clock=lambda: now)
    w.start()
    w.stop()
    w.poll_once()
    assert [(e.host, e.process) for e in sink] == [("gemini.google.com", "firefox")]


def test_a_missing_or_broken_history_never_raises(tmp_path, linux):
    broken = tmp_path / ".config" / "chromium" / "Default"
    broken.mkdir(parents=True)
    (broken / "History").write_bytes(b"not a database")
    sink: list = []
    w = watcher(tmp_path / "nowhere", sink)
    w.start()
    w.stop()
    assert w.poll_once() == 0 and w.files == []
    w2 = watcher(tmp_path, sink)
    w2.start()
    w2.stop()
    assert w2.poll_once() == 0 and w2.error


def test_the_page_title_is_never_stored(tmp_path, linux):
    now = time.time()
    chromium_profile(tmp_path / ".config" / "chromium", [("https://claude.ai/new", now + 1)])
    sink: list = []
    w = watcher(tmp_path, sink, clock=lambda: now)
    w.start()
    w.stop()
    w.poll_once()
    assert "SECRET TITLE" not in repr(sink[0].model_dump())


def test_switching_the_source_on_through_the_api_shows_the_tool(tmp_path, linux, monkeypatch):
    from fastapi.testclient import TestClient
    import dataclasses
    from shadowlens.api.app import create_app
    from shadowlens.config import Config

    now = time.time()
    monkeypatch.setenv("HOME", str(tmp_path))
    db = chromium_profile(tmp_path / ".config" / "chromium", [])
    config = dataclasses.replace(Config.load(), db_path=tmp_path / "t.db", salt_path=tmp_path / "salt",
                                 live_dir=tmp_path / "live", resolve=False, scan_interval_s=0.0)
    config.live_dir.mkdir()
    with TestClient(create_app(config)) as client:
        rows = {r["id"]: r for r in client.get("/api/sources").json()["items"]}
        assert rows["browser_history"]["kind"] == "browser" and rows["browser_history"]["enabled"] is False
        assert rows["browser_history"]["found"] is True
        row = client.put("/api/sources/browser_history", json={"enabled": True}).json()
        assert row["enabled"] is True and row["supported"] is True
        conn = sqlite3.connect(db)
        conn.execute("INSERT INTO urls VALUES (1,'https://chatgpt.com/c/1','t')")
        conn.execute("INSERT INTO visits VALUES (1,1,?)", (int((time.time() + 1) * 1_000_000) + CHROMIUM_EPOCH_US,))
        conn.commit()
        conn.close()
        deadline = time.time() + 10
        tools = []
        while time.time() < deadline and not tools:
            time.sleep(0.5)
            tools = [t for t in client.get("/api/tools").json()["items"] if "chatgpt" in t["tool_id"]]
        assert tools and tools[0]["tool_id"] == "chromium|chatgpt_web"
        alerts = client.get("/api/alerts").json()["items"]
        assert any(a["rule_id"] == "POLICY_UNSANCTIONED_TOOL" and a["tool_id"] == "chromium|chatgpt_web" for a in alerts)
        assert client.put("/api/sources/browser_history", json={"enabled": False}).json()["enabled"] is False

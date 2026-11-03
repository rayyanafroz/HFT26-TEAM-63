"""Guard events: cleaning, storage, the native messaging host, its installer, and the API."""

import io
import json
import os
import struct
import subprocess
import sys
import threading
import time

import pytest
from fastapi.testclient import TestClient

from shadowlens import guard, native_host
from shadowlens.api.app import create_app
from shadowlens.config import Config
from shadowlens.db import FORBIDDEN_COLUMNS, Database
from shadowlens.fakes import fake


def make_config(tmp_path, **env):
    env = {"SHADOWLENS_RESOLVE": "false", **env}
    return Config.load(env=env, base_dir=tmp_path, use_dotenv=False)


@pytest.fixture
def db(tmp_path):
    database = Database(tmp_path / "shadow.db")
    yield database
    database.close()


def browser_event(**over):
    event = {"id": "abc123", "at": 1762128000000, "site": "chatgpt", "action": "redacted", "kind": "submit", "severity": "high",
             "findings": [{"rule_id": "SEC_OPENAI_KEY", "hash12": "0123456789ab", "masked_preview": "sk-p... (len 56)", "severity": "high"}]}
    event.update(over)
    return event


# ---- cleaning ------------------------------------------------------------------------------------

def test_a_browser_event_is_cleaned_to_the_stored_shape():
    e = guard.clean_event(browser_event(), "browser")
    assert e["id"] == "browser:abc123"
    assert e["at"] == "2025-11-03T00:00:00.000Z"
    assert e["findings"] == [{"rule_id": "SEC_OPENAI_KEY", "hash12": "0123456789ab", "masked_preview": "sk-p... (len 56)", "severity": "high"}]


@pytest.mark.parametrize("bad", [None, [], {"action": "exploded"}, {"action": "redacted", "findings": "x"}])
def test_events_that_are_not_events_are_refused_or_emptied(bad):
    e = guard.clean_event(bad, "browser")
    assert e is None or e["findings"] == []


def test_an_unknown_source_is_refused():
    assert guard.clean_event(browser_event(), "somewhere") is None


def test_a_raw_value_disguised_as_a_mask_is_never_stored():
    key = fake("openai_key", 3)
    e = guard.clean_event(browser_event(findings=[{"rule_id": "SEC_OPENAI_KEY", "hash12": "nothex", "masked_preview": key}]), "browser")
    assert e["findings"][0]["masked_preview"] == ""
    assert e["findings"][0]["hash12"] == ""
    assert key not in json.dumps(e)


@pytest.mark.parametrize("rule, mask", [
    ("SEC_OPENAI_KEY", "sk-p... (len 56)"), ("SEC_GENERIC_ASSIGNMENT", "... (len 9)"), ("PII_CREDIT_CARD", "****1111"),
    ("PII_EMAIL", "j***@acme.invalid"), ("PII_SSN", "creds.txt: ****1120"),
    ("HIDDEN_TEXT", 'hidden message "IGNORE ALL"; 3 invisible characters in a row'),
    ("INJECTION_PHRASE", "\u201cignore previous instructions\u201d"),
])
def test_real_masks_are_kept(rule, mask):
    e = guard.clean_event(browser_event(findings=[{"rule_id": rule, "masked_preview": mask}]), "browser")
    assert e["findings"][0]["masked_preview"] == mask


@pytest.mark.parametrize("rule, mask", [
    ("SEC_OPENAI_KEY", "sk-proj-AAAA1111BBBB2222CCCC"), ("PII_EMAIL", "jordan.lee@acme.invalid"),
    ("PII_CREDIT_CARD", "4111 1111 1111 1111"), ("HIDDEN_TEXT", "hidden message sk-proj-AAAA1111BBBB2222CCCC3333"),
    ("SEC_OPENAI_KEY", "sk-proj-AAAA1111BBBB2222CCCC.txt: sk-p... (len 9)"),
])
def test_values_that_are_not_masks_are_dropped(rule, mask):
    e = guard.clean_event(browser_event(findings=[{"rule_id": rule, "masked_preview": mask}]), "browser")
    assert e["findings"][0]["masked_preview"] == ""


def test_long_fields_and_control_characters_are_cut():
    e = guard.clean_event(browser_event(site="x" * 500, reason="line\x00one\n" + "y" * 1000), "browser")
    assert len(e["site"]) == 60 and len(e["reason"]) == 300 and "\x00" not in e["reason"]


# ---- storage -------------------------------------------------------------------------------------

def test_the_same_event_is_stored_once_and_reads_back(db):
    assert guard.record(db, browser_event(), "browser")
    guard.record(db, browser_event(), "browser")
    items, total = db.list_guard_events()
    assert total == 1 and items[0]["findings"][0]["rule_id"] == "SEC_OPENAI_KEY"
    assert db.guard_cursor() == 1


def test_the_guard_table_has_no_column_that_could_hold_a_secret(db):
    assert set(db.table_columns()["guard_events"]).isdisjoint(FORBIDDEN_COLUMNS)


def test_reset_keeps_the_guard_history(db):
    guard.record(db, browser_event(), "browser")
    db.reset()
    assert db.list_guard_events()[1] == 1


# ---- the native messaging protocol -------------------------------------------------------------

def frame(message):
    body = json.dumps(message).encode()
    return struct.pack("=I", len(body)) + body


def unframe(data):
    out = []
    while data:
        (n,) = struct.unpack("=I", data[:4])
        out.append(json.loads(data[4:4 + n]))
        data = data[4 + n:]
    return out


def test_the_host_says_hello_and_stores_events(tmp_path):
    cfg = make_config(tmp_path)
    stdin = io.BytesIO(frame({"type": "hello", "version": "0.1.0"}) + frame({"type": "guard_event", "event": browser_event()}) + frame({"type": "nope"}))
    stdout = io.BytesIO()
    assert native_host.serve(stdin, stdout, cfg) == 0
    hello, ack, error = unframe(stdout.getvalue())
    assert hello["type"] == "hello" and hello["dashboard"].endswith("/#/guard")
    assert ack == {"type": "ack", "stored": True}
    assert error["type"] == "error"
    with Database(cfg.db_path) as check:
        assert check.list_guard_events()[1] == 1


def test_the_host_refuses_an_oversized_message(tmp_path):
    stdin = io.BytesIO(struct.pack("=I", native_host.MAX_MESSAGE + 1))
    assert native_host.serve(stdin, io.BytesIO(), make_config(tmp_path)) == 1


def test_installing_writes_a_manifest_for_each_browser_found(tmp_path):
    home = tmp_path / "home"
    (home / ".config" / "google-chrome").mkdir(parents=True)
    (home / ".config" / "BraveSoftware" / "Brave-Browser").mkdir(parents=True)
    root = tmp_path / "repo"
    done = native_host.install(home, platform="linux", ext_id="a" * 32, python="/usr/bin/python3", root=root)
    assert [line.split(":")[0] for line in done] == ["Chrome", "Brave"]
    target = home / ".config" / "google-chrome" / "NativeMessagingHosts" / "com.shadowlens.companion.json"
    manifest = json.loads(target.read_text())
    assert manifest["allowed_origins"] == [f"chrome-extension://{'a' * 32}/"]
    launcher = root / "data" / "shadowlens-host"
    assert manifest["path"] == str(launcher) and os.access(launcher, os.X_OK)
    assert f'cd "{root}"' in launcher.read_text()
    assert native_host.status(home, "linux") == ["Chrome: installed", "Brave: installed"]
    native_host.uninstall(home, "linux")
    assert not target.exists()


def test_the_default_extension_id_matches_the_extension_key():
    assert len(native_host.extension_id()) == 32 and set(native_host.extension_id()) <= set("abcdefghijklmnop")


def test_the_launcher_starts_a_working_host_the_way_chrome_does(tmp_path):
    """Install into a temporary home, then run the launcher like Chrome: origin as argument, framed stdio."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "src").symlink_to(native_host.ROOT / "src")
    native_host.install(tmp_path / "home", platform="linux", ext_id="b" * 32, python=sys.executable, root=root, all_browsers=True)
    env = {**os.environ, "PYTHONPATH": str(native_host.ROOT / "src"), "SHADOWLENS_RESOLVE": "false"}
    done = subprocess.run([str(root / "data" / "shadowlens-host"), f"chrome-extension://{'b' * 32}/"],
                          input=frame({"type": "hello"}) + frame({"type": "guard_event", "event": browser_event(id="viahost")}),
                          capture_output=True, env=env, timeout=60)
    assert done.returncode == 0, done.stderr.decode()
    replies = unframe(done.stdout)
    assert replies[0]["type"] == "hello" and replies[1]["stored"] is True
    with Database(root / "data" / "shadow.db") as check:
        assert check.list_guard_events()[0][0]["id"] == "browser:viahost"


# ---- the API and the live watcher --------------------------------------------------------------

def test_summary_and_events_routes(tmp_path, db):
    now = int(time.time() * 1000)
    guard.record(db, browser_event(id="e1", at=now), "browser")
    guard.record(db, browser_event(id="e2", at=now, action="sent_anyway", reason="test key"), "browser")
    guard.record(db, browser_event(id="e3", at=now, action="noted", site="claude"), "browser")
    guard.record(db, {"id": "e4", "at": now, "site": "claude-code", "action": "blocked", "kind": "prompt", "findings": []}, "claude_code")
    with TestClient(create_app(make_config(tmp_path), db=db, ui_dir=tmp_path / "no-ui")) as client:
        s = client.get("/api/guard/summary").json()
        assert s["totals"]["stopped"] == 2 and s["totals"]["let_through"] == 1 and s["totals"]["noted"] == 1
        assert s["sources"] == {"browser": 3, "claude_code": 1}
        assert s["sites"][0] == {"site": "chatgpt", "stopped": 1, "let_through": 1, "noted": 0}
        assert s["rules"] == [{"rule_id": "SEC_OPENAI_KEY", "title": "OpenAI-style API key", "severity": "high", "count": 2}]
        assert len(s["daily"]) == 30 and s["daily"][-1]["stopped"] == 2
        events = client.get("/api/guard/events?limit=2").json()
        assert events["total"] == 4 and len(events["items"]) == 2
        assert client.get("/api/guard/summary?days=0").status_code == 422


def test_the_watcher_announces_events_written_by_another_process(tmp_path):
    db = Database(tmp_path / "w.db")
    seen = []
    watcher = guard.GuardWatcher(db, lambda kind, payload: seen.append((kind, payload)), interval_s=0.05)
    watcher.start()
    with Database(tmp_path / "w.db") as other:          # a second connection, as the host has
        guard.record(other, browser_event(), "browser")
    deadline = time.time() + 3
    while not seen and time.time() < deadline:
        time.sleep(0.02)
    watcher.stop()
    db.close()
    assert seen == [("guard.new", {"cursor": 1})]

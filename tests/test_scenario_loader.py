import json
import re
import threading
import time
from datetime import datetime, timezone

import pytest

from shadowlens.config import Config
from shadowlens.core.pipeline import Pipeline
from shadowlens.core.scenario_player import ScenarioPlayer
from shadowlens.db import Database
from shadowlens.ingest import scenarios
from shadowlens.ingest.scenarios import ScenarioError, ScenarioNotFound, build_events, duration_s, read_records
from shadowlens.models import Source, Visibility
from shadowlens.providers.catalog import Catalog

NOW = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)


def record(t_ms, host="api.openai.com", **o):
    return {"t_ms": t_ms, "host": host, "method": "POST", "path": "/v1/chat/completions",
            "process_name": "python3", "body": "hello", **o}


@pytest.fixture
def templates(tmp_path):
    folder = tmp_path / "templates"
    folder.mkdir()
    return folder


def write(folder, name, records, raw=None):
    text = raw if raw is not None else "\n".join(json.dumps(r) for r in records) + "\n"
    (folder / f"{name}.jsonl").write_text(text, encoding="utf-8")


# ---- finding and reading templates --------------------------------------------------

@pytest.mark.parametrize("name", ["../secrets", "a/b", "a\\b", "..", "", "UPPER", "with space", "x" * 65, "evil.jsonl", "a.b"])
def test_unsafe_or_odd_names_are_never_looked_up(templates, name):
    write(templates, "quick_leak", [record(0)])
    with pytest.raises(ScenarioNotFound):
        scenarios.template_path(name, templates)


def test_a_missing_scenario_is_not_found(templates):
    with pytest.raises(ScenarioNotFound):
        read_records("quick_leak", templates)


@pytest.mark.parametrize("raw,fragment", [
    ("not json\n", "line 1 is not valid JSON"),
    ('["a"]\n', "line 1 needs an integer 't_ms'"),
    ('{"host": "x"}\n', "line 1 needs an integer 't_ms'"),
    ('{"t_ms": "5"}\n', "line 1 needs an integer 't_ms'"),
    ('{"t_ms": -1}\n', "line 1 needs an integer 't_ms'"),
    ('{"t_ms": 1.5}\n', "line 1 needs an integer 't_ms'"),
    ('{"t_ms": 0}\nnope\n', "line 2 is not valid JSON"),
    ("\n\n", "is empty"),
])
def test_a_broken_template_gives_a_clear_error_without_its_content(templates, raw, fragment):
    write(templates, "bad", [], raw=raw)
    with pytest.raises(ScenarioError) as err:
        read_records("bad", templates)
    assert fragment in str(err.value)


def test_a_byte_order_mark_is_tolerated(templates):
    write(templates, "bom", [], raw="﻿" + json.dumps(record(0)) + "\r\n")
    assert len(read_records("bom", templates)) == 1


# ---- load: all at once, ending now -----------------------------------------------------

def test_load_shifts_the_times_so_the_last_event_is_now(templates):
    write(templates, "s", [record(6000), record(0), record(3000)])                 # deliberately out of order
    timed = build_events("s", play=False, templates_dir=templates, now=NOW)
    stamps = [t.event.ts for t in timed]
    assert stamps == ["2026-10-31T11:59:54.000Z", "2026-10-31T11:59:57.000Z", "2026-10-31T12:00:00.000Z"]
    assert [t.delay_s for t in timed] == [0.0, 0.0, 0.0]


def test_events_are_marked_as_scenario_unless_the_line_says_otherwise(templates):
    write(templates, "s", [record(0), record(1, host="chatgpt.com", body=None, source="pcap")])
    first, second = (t.event for t in build_events("s", play=False, templates_dir=templates, now=NOW))
    assert first.source is Source.SCENARIO
    assert second.source is Source.PCAP and second.visibility is Visibility.METADATA_ONLY


def test_placeholders_and_the_body_limit_are_applied(templates):
    write(templates, "s", [record(0, body="key={{fake:openai_key#1}}" + "x" * 200)])
    expand = lambda t: re.sub(r"\{\{fake:([a-z_]+)#(\d+)\}\}", r"<\1-\2>", t)
    event = build_events("s", play=False, templates_dir=templates, now=NOW, expand=expand, max_body_bytes=30)[0].event
    assert event.body_text.startswith("key=<openai_key-1>") and event.body_truncated and len(event.body_text) == 30


# ---- play: spread over time ----------------------------------------------------------------

def test_play_delays_follow_the_template_and_the_speed(templates):
    write(templates, "s", [record(0), record(2000), record(6000)])
    normal = build_events("s", play=True, templates_dir=templates, now=NOW)
    assert [t.delay_s for t in normal] == [0.0, 2.0, 6.0]
    assert [t.event.ts for t in normal] == ["2026-10-31T12:00:00.000Z", "2026-10-31T12:00:02.000Z", "2026-10-31T12:00:06.000Z"]
    fast = build_events("s", play=True, speed=4, templates_dir=templates, now=NOW)
    assert [t.delay_s for t in fast] == [0.0, 0.5, 1.5]
    assert [t.event.ts[-7:] for t in fast] == ["00.000Z", "00.500Z", "01.500Z"]       # timestamps match the delays
    assert duration_s("s", templates_dir=templates) == 6.0 and duration_s("s", 2, templates) == 3.0


def test_speed_must_be_positive(templates):
    write(templates, "s", [record(0)])
    for speed in (0, -1):
        with pytest.raises(ScenarioError):
            build_events("s", play=True, speed=speed, templates_dir=templates)


def test_a_line_that_cannot_become_an_event_is_named_but_not_quoted(templates):
    write(templates, "s", [record(0), {"t_ms": 5, "host": "x", "method": "POST", "path": "/", "pid": "SECRETMARKER"}])
    with pytest.raises(ScenarioError) as err:
        build_events("s", play=False, templates_dir=templates, now=NOW)
    assert "event 2" in str(err.value) and "SECRETMARKER" not in str(err.value)


# ---- the player -----------------------------------------------------------------------------

class Published:
    def __init__(self):
        self.items = []
        self.lock = threading.Lock()

    def __call__(self, kind, payload):
        with self.lock:
            self.items.append((kind, payload))

    def progress(self):
        with self.lock:
            return [(p["played"], p["total"]) for k, p in self.items if k == "scenario.progress"]


@pytest.fixture
def db(tmp_path):
    database = Database(tmp_path / "shadow.db")
    yield database
    database.close()


def make_player(tmp_path, db, templates):
    config = Config.load(env={"SHADOWLENS_RESOLVE": "false"}, base_dir=tmp_path, use_dotenv=False)
    published = Published()
    pipeline = Pipeline(config, db, Catalog.load(), publish=published)
    player = ScenarioPlayer(pipeline, published, templates_dir=templates, max_body_bytes=65536)
    return player, pipeline, published


def wait_for(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return False


def test_load_adds_everything_at_once(tmp_path, db, templates):
    write(templates, "quick_leak", [record(0), record(1000, host="api.anthropic.com"), record(2000, host="github.com")])
    player, _, published = make_player(tmp_path, db, templates)
    summary = player.load("quick_leak")
    assert (summary.source, summary.accepted, summary.dropped_non_ai) == ("scenario", 2, 1)
    assert db.count_events() == 2
    status = player.status()
    assert (status.name, status.played, status.total) == ("quick_leak", 3, 3) and not player.playing
    assert published.progress()[-1] == (3, 3)
    newest = db.list_events().items[0].ts
    assert abs((datetime.fromisoformat(newest.replace("Z", "+00:00")) - datetime.now(timezone.utc)).total_seconds()) < 5


def test_load_of_an_unknown_scenario_changes_nothing(tmp_path, db, templates):
    player, _, _ = make_player(tmp_path, db, templates)
    with pytest.raises(ScenarioNotFound):
        player.load("nope")
    assert player.status().name is None and db.count_events() == 0


def test_play_returns_at_once_and_events_arrive_on_schedule(tmp_path, db, templates):
    write(templates, "quick_leak", [record(0), record(300), record(600)])
    player, _, published = make_player(tmp_path, db, templates)
    started = time.monotonic()
    response = player.play("quick_leak")
    assert time.monotonic() - started < 0.2                          # it did not wait for the scenario
    assert (response.name.value, response.total, response.duration_s) == ("quick_leak", 3, 0.6)
    assert player.playing and player.name == "quick_leak"
    assert wait_for(lambda: db.count_events() >= 1)
    first_at = time.monotonic() - started
    assert db.count_events() < 3                                     # the rest is still to come
    assert wait_for(lambda: db.count_events() == 3 and not player.playing)
    assert 0.5 <= time.monotonic() - started <= 2.0                  # took about 0.6 s, not instant, not slow
    assert first_at < 0.4
    assert published.progress() == [(0, 3), (1, 3), (2, 3), (3, 3)]
    assert player.status().played == 3


def test_speed_makes_play_shorter(tmp_path, db, templates):
    write(templates, "quick_leak", [record(0), record(2000)])
    player, _, _ = make_player(tmp_path, db, templates)
    started = time.monotonic()
    response = player.play("quick_leak", speed=10)
    assert response.duration_s == pytest.approx(0.2)
    assert wait_for(lambda: db.count_events() == 2) and time.monotonic() - started < 1.5


def test_stop_halts_playback_and_keeps_what_was_played(tmp_path, db, templates):
    write(templates, "quick_leak", [record(0), record(200), record(60000)])
    player, _, _ = make_player(tmp_path, db, templates)
    player.play("quick_leak")
    assert wait_for(lambda: db.count_events() == 2)
    started = time.monotonic()
    player.stop()
    assert time.monotonic() - started < 1.0 and not player.playing   # did not wait for the 60 s event
    time.sleep(0.2)
    assert db.count_events() == 2
    status = player.status()
    assert (status.name, status.played, status.total) == ("quick_leak", 2, 3)


def test_starting_another_scenario_while_one_plays_does_not_hang(tmp_path, db, templates):
    """The old playback needs the player's lock to report progress: stopping it must not hold that lock."""
    write(templates, "full_demo", [record(0), record(30000)])
    write(templates, "agent_attack", [record(0, host="api.groq.com")])
    player, _, _ = make_player(tmp_path, db, templates)
    player.play("full_demo")
    assert wait_for(lambda: db.count_events() == 1)
    started = time.monotonic()
    player.play("agent_attack")
    assert time.monotonic() - started < 2.0                          # a deadlock would take the 5 s join timeout
    assert wait_for(lambda: player.status().name == "agent_attack" and db.count_events() == 2)
    started = time.monotonic()
    player.load("agent_attack")
    assert time.monotonic() - started < 2.0 and not player.playing


def test_clear_forgets_the_scenario(tmp_path, db, templates):
    write(templates, "quick_leak", [record(0)])
    player, _, _ = make_player(tmp_path, db, templates)
    player.load("quick_leak")
    player.clear()
    assert (player.name, player.status().played, player.status().total) == (None, 0, 0)


def test_playback_survives_a_failing_ingest(tmp_path, db, templates, monkeypatch):
    write(templates, "quick_leak", [record(0), record(100), record(200)])
    player, pipeline, _ = make_player(tmp_path, db, templates)
    real = pipeline.ingest
    calls = {"n": 0}

    def flaky(events, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("boom")
        return real(events, **kw)

    monkeypatch.setattr(pipeline, "ingest", flaky)
    player.play("quick_leak")
    assert wait_for(lambda: not player.playing)                     # the thread ended cleanly instead of hanging


def test_a_scenario_line_with_a_line_separator_character_inside_a_string_is_read_whole(templates):
    text = json.dumps(record(0, body="a\u2028b"), ensure_ascii=False) + "\n"
    write(templates, "s", [], raw=text)
    assert read_records("s", templates)[0]["body"] == "a\u2028b"

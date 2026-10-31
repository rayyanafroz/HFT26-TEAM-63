import builtins
import json
import os
import re
import time

import pytest

from shadowlens.db import Database
from shadowlens.ingest.live_tail import LiveTail
from shadowlens.models import Source


def line(path="/v1", host="api.openai.com", **o):
    return json.dumps({"ts": "2026-10-31T10:00:00Z", "host": host, "method": "POST", "path": path, **o})


class Collector:
    def __init__(self):
        self.events, self.skipped, self.errors, self.calls = [], 0, [], 0

    def __call__(self, events, skipped, errors):
        self.calls += 1
        self.events += events
        self.skipped += skipped
        self.errors += errors

    def paths(self):
        return [e.path for e in self.events]


@pytest.fixture
def db(tmp_path):
    database = Database(tmp_path / "shadow.db")
    yield database
    database.close()


@pytest.fixture
def live(tmp_path):
    folder = tmp_path / "live"
    folder.mkdir()
    return folder


def make(live, db, **kwargs):
    sink = Collector()
    return LiveTail(live, db, sink, **kwargs), sink


def append(path, text, mode="a"):
    with open(path, mode, encoding="utf-8", newline="") as f:
        f.write(text)


# ---- reading new lines --------------------------------------------------------

def test_new_lines_are_ingested_once(live, db):
    tail, sink = make(live, db)
    assert tail.poll_once() == 0                                    # nothing there yet
    append(live / "ollama.jsonl", line("/a") + "\n" + line("/b") + "\n")
    assert tail.poll_once() == 2 and sink.paths() == ["/a", "/b"]
    assert tail.poll_once() == 0 and sink.paths() == ["/a", "/b"]   # not read again
    append(live / "ollama.jsonl", line("/c") + "\n")
    assert tail.poll_once() == 1 and sink.paths() == ["/a", "/b", "/c"]
    assert tail.lines_ingested == 3


def test_events_are_marked_as_coming_from_the_live_log(live, db):
    tail, sink = make(live, db)
    append(live / "x.jsonl", line(source="scenario") + "\n")        # the caller decides the source, not the line
    tail.poll_once()
    assert sink.events[0].source is Source.LIVE_LOG


def test_a_half_written_line_waits_for_its_end(live, db):
    tail, sink = make(live, db)
    full = line("/whole")
    append(live / "x.jsonl", line("/first") + "\n" + full[:20])
    assert tail.poll_once() == 1 and sink.paths() == ["/first"]
    assert tail.poll_once() == 0                                    # still incomplete: left alone
    append(live / "x.jsonl", full[20:] + "\n")
    assert tail.poll_once() == 1 and sink.paths() == ["/first", "/whole"]


def test_several_files_and_files_that_appear_later(live, db):
    tail, sink = make(live, db)
    append(live / "a.jsonl", line("/a1") + "\n")
    append(live / "b.jsonl", line("/b1") + "\n")
    append(live / "notes.txt", line("/ignored") + "\n")             # only *.jsonl
    assert tail.poll_once() == 2 and sorted(sink.paths()) == ["/a1", "/b1"]
    append(live / "c.jsonl", line("/c1") + "\n")                    # a new file starts from its first line
    append(live / "a.jsonl", line("/a2") + "\n")
    assert tail.poll_once() == 2 and sorted(sink.paths()[2:]) == ["/a2", "/c1"]


def test_windows_line_endings_blank_lines_and_a_byte_order_mark(live, db):
    tail, sink = make(live, db)
    append(live / "x.jsonl", "﻿" + line("/one") + "\r\n\r\n   \r\n" + line("/two") + "\r\n")
    assert tail.poll_once() == 2 and sink.paths() == ["/one", "/two"]


def test_bad_lines_are_counted_and_described(live, db):
    tail, sink = make(live, db)
    append(live / "x.jsonl", "garbage\n" + line("/ok") + "\n" + json.dumps({"host": "x"}) + "\n")
    assert tail.poll_once() == 1
    assert sink.skipped == 2 and sink.paths() == ["/ok"]
    assert sink.errors[0].startswith("x.jsonl: not valid JSON")
    assert sink.errors[1].startswith("x.jsonl:") and "method" in sink.errors[1]       # the first thing missing


def test_only_twenty_error_messages_are_kept_per_pass(live, db):
    tail, sink = make(live, db)
    append(live / "x.jsonl", "bad\n" * 50)
    tail.poll_once()
    assert sink.skipped == 50 and len(sink.errors) == 20


def test_placeholders_are_expanded_when_an_expander_exists(live, db):
    expander = lambda text: re.sub(r"\{\{fake:([a-z_]+)#(\d+)\}\}", r"<\1-\2>", text)
    tail, sink = make(live, db, expand=lambda: expander)
    append(live / "x.jsonl", line(body="key={{fake:openai_key#1}}") + "\n")
    tail.poll_once()
    assert sink.events[0].body_text == "key=<openai_key-1>"


def test_the_body_size_limit_is_applied(live, db):
    tail, sink = make(live, db, max_body_bytes=10)
    append(live / "x.jsonl", line(body="x" * 100) + "\n")
    tail.poll_once()
    assert sink.events[0].body_truncated and len(sink.events[0].body_text) == 10


# ---- files that change under us --------------------------------------------------

def test_a_truncated_file_is_read_again_from_the_start(live, db):
    tail, sink = make(live, db)
    append(live / "x.jsonl", line("/old1") + "\n" + line("/old2") + "\n")
    tail.poll_once()
    append(live / "x.jsonl", line("/new") + "\n", mode="w")         # the file was emptied and reused
    assert tail.poll_once() == 1 and sink.paths()[-1] == "/new"


def test_a_replaced_file_is_read_from_the_start(live, db):
    tail, sink = make(live, db)
    path = live / "x.jsonl"
    append(path, line("/a") + "\n" + line("/b") + "\n" + line("/c") + "\n")
    tail.poll_once()
    key = str(path.resolve())
    inode, offset = db.get_offset(key)
    assert inode
    db.set_offset(key, inode + 12345, offset)                       # as if the file had been swapped for another
    assert tail.poll_once() == 3 and sink.paths()[3:] == ["/a", "/b", "/c"]


def test_a_restart_neither_repeats_nor_loses_lines(live, db):
    first, sink1 = make(live, db)
    append(live / "x.jsonl", line("/before") + "\n")
    first.poll_once()
    append(live / "x.jsonl", line("/while-down") + "\n")            # written while ShadowLens was not running
    second, sink2 = make(live, db)                                  # a new instance, same database
    assert second.poll_once() == 1 and sink2.paths() == ["/while-down"]


def test_offsets_are_stored_in_the_database(live, db):
    tail, _ = make(live, db)
    path = live / "x.jsonl"
    append(path, line() + "\n")
    tail.poll_once()
    inode, offset = db.get_offset(str(path.resolve()))
    assert offset == path.stat().st_size


def test_polling_without_new_data_does_not_touch_the_database(live, db):
    tail, _ = make(live, db)
    append(live / "x.jsonl", line() + "\n")
    tail.poll_once()
    version = db.version
    for _ in range(5):
        tail.poll_once()
    assert db.version == version                                    # so cached views are not thrown away for nothing


def test_a_locked_file_is_skipped_and_read_next_time(live, db, monkeypatch):
    tail, sink = make(live, db)
    path = live / "x.jsonl"
    append(path, line("/a") + "\n")
    real_open = builtins.open
    locked = {"on": True}

    def flaky_open(file, mode="r", *args, **kwargs):
        if locked["on"] and str(file).endswith("x.jsonl") and "b" in mode and "r" in mode:
            raise PermissionError("another program has it locked")
        return real_open(file, mode, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", flaky_open)
    assert tail.poll_once() == 0
    locked["on"] = False
    assert tail.poll_once() == 1 and sink.paths() == ["/a"]


def test_a_missing_folder_is_fine(tmp_path, db):
    sink = Collector()
    tail = LiveTail(tmp_path / "does-not-exist", db, sink)
    assert tail.poll_once() == 0


def test_one_endless_line_is_skipped_instead_of_blocking_everything(live, db):
    tail, sink = make(live, db, max_read=512)
    append(live / "x.jsonl", "x" * 2000)                             # no newline, longer than one read
    tail.poll_once()
    assert sink.skipped == 1 and "too long" in sink.errors[0]
    for _ in range(5):                                              # the rest of it is skipped, piece by piece
        tail.poll_once()
    append(live / "x.jsonl", "\n" + line("/after") + "\n")
    for _ in range(3):
        tail.poll_once()
    assert "/after" in sink.paths()                                 # and normal lines after it still arrive


def test_big_files_are_read_in_pieces(live, db):
    tail, sink = make(live, db, max_read=300)
    append(live / "x.jsonl", "".join(line(f"/{i}") + "\n" for i in range(20)))
    total = 0
    for _ in range(30):
        total += tail.poll_once()
    assert total == 20 and sink.paths() == [f"/{i}" for i in range(20)]


# ---- the background thread --------------------------------------------------------

def test_the_watcher_notices_new_lines_by_itself_and_stops(live, db):
    tail, sink = make(live, db, poll_s=0.05)
    tail.start()
    tail.start()                                                    # a second start does nothing
    assert tail.running
    append(live / "x.jsonl", line("/live") + "\n")
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline and not sink.events:
        time.sleep(0.02)
    assert sink.paths() == ["/live"]
    tail.stop()
    assert not tail.running
    append(live / "x.jsonl", line("/after-stop") + "\n")
    time.sleep(0.2)
    assert sink.paths() == ["/live"]
    tail.start()                                                    # and it can be started again
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline and len(sink.events) < 2:
        time.sleep(0.02)
    tail.stop()
    assert sink.paths() == ["/live", "/after-stop"]


def test_an_error_in_one_pass_does_not_kill_the_watcher(live, db):
    calls = {"n": 0}

    def flaky(events, skipped, errors):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("downstream bug")

    tail = LiveTail(live, db, flaky, poll_s=0.05)
    tail.start()
    append(live / "x.jsonl", line("/one") + "\n")
    time.sleep(0.3)
    append(live / "x.jsonl", line("/two") + "\n")
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline and calls["n"] < 2:
        time.sleep(0.02)
    tail.stop()
    assert calls["n"] >= 2


# ---- a failure while ingesting must not lose lines -------------------------------------

def test_lines_are_not_lost_when_ingesting_fails_briefly(live, db):
    state = {"fail": True}
    got = []

    def ingest(events, skipped, errors):
        if state["fail"]:
            raise RuntimeError("database is busy")
        got.extend(e.path for e in events)

    tail = LiveTail(live, db, ingest)
    append(live / "x.jsonl", line("/one") + "\n" + line("/two") + "\n")
    assert tail.poll_once() == 0 and got == []                      # failed: nothing delivered, bookmark not moved
    state["fail"] = False
    append(live / "x.jsonl", line("/three") + "\n")
    assert tail.poll_once() == 3 and got == ["/one", "/two", "/three"]   # the failed lines came back, in order
    assert tail.poll_once() == 0 and got == ["/one", "/two", "/three"]   # and nothing is delivered twice


def test_a_batch_that_keeps_failing_is_given_up_on_so_later_lines_still_flow(live, db):
    got = []

    def ingest(events, skipped, errors):
        paths = [e.path for e in events]
        if "/poison" in paths:
            raise RuntimeError("always fails")
        got.extend(paths)

    tail = LiveTail(live, db, ingest)
    append(live / "x.jsonl", line("/poison") + "\n")
    assert [tail.poll_once() for _ in range(3)] == [0, 0, 1]        # two retries, then it is dropped
    append(live / "x.jsonl", line("/after") + "\n")
    assert tail.poll_once() == 1 and got == ["/after"]


def test_the_failure_count_is_forgotten_after_a_success(live, db):
    state = {"fail_next": 0}
    got = []

    def ingest(events, skipped, errors):
        if state["fail_next"] > 0:
            state["fail_next"] -= 1
            raise RuntimeError("blip")
        got.extend(e.path for e in events)

    tail = LiveTail(live, db, ingest)
    for name in ("/a", "/b", "/c"):                                 # each batch fails twice, then works
        state["fail_next"] = 2
        append(live / "x.jsonl", line(name) + "\n")
        for _ in range(3):
            tail.poll_once()
    assert got == ["/a", "/b", "/c"]                                # never reached the give-up limit


def test_a_crash_between_ingesting_and_saving_the_bookmark_repeats_rather_than_loses(live, db, monkeypatch):
    got = []
    tail = LiveTail(live, db, lambda ev, sk, er: got.extend(e.path for e in ev))
    append(live / "x.jsonl", line("/one") + "\n")
    real = db.set_offset
    monkeypatch.setattr(db, "set_offset", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("crash")))
    with pytest.raises(RuntimeError):
        tail.poll_once()
    monkeypatch.setattr(db, "set_offset", real)
    tail.poll_once()
    assert got == ["/one", "/one"]          # delivered twice (the pipeline's dedupe absorbs it), but never zero times


# ---- a file emptied and refilled in place -------------------------------------------------

def test_a_file_refilled_with_more_data_than_before_is_read_from_the_start(live, db):
    """The size check alone cannot see this: the new content is at least as long as the old."""
    tail, sink = make(live, db)
    path = live / "x.jsonl"
    append(path, "".join(line(f"/old{i}") + "\n" for i in range(5)))
    tail.poll_once()
    append(path, "".join(line(f"/newer{i}") + "\n" for i in range(8)), mode="w")      # same inode, now longer
    assert path.stat().st_size > len(sink.paths()) * 10
    tail.poll_once()
    assert sink.paths()[5:] == [f"/newer{i}" for i in range(8)]


def test_a_file_refilled_to_exactly_the_same_size_is_still_noticed(live, db):
    tail, sink = make(live, db)
    path = live / "x.jsonl"
    append(path, line("/aaa") + "\n" + line("/bbb") + "\n")
    tail.poll_once()
    time.sleep(0.02)                                                  # make sure the modification time differs
    append(path, line("/xxx") + "\n" + line("/yyy") + "\n", mode="w")        # identical length, different content
    tail.poll_once()
    assert sink.paths() == ["/aaa", "/bbb", "/xxx", "/yyy"]


def test_appending_is_not_mistaken_for_a_rewrite(live, db):
    tail, sink = make(live, db)
    path = live / "x.jsonl"
    for i in range(30):                                               # the file grows past the fingerprint length
        append(path, line(f"/n{i}") + "\n")
        tail.poll_once()
    assert sink.paths() == [f"/n{i}" for i in range(30)]              # each exactly once


def test_touching_a_file_without_changing_it_reads_nothing_new(live, db):
    tail, sink = make(live, db)
    path = live / "x.jsonl"
    append(path, line("/a") + "\n")
    tail.poll_once()
    for _ in range(3):
        os.utime(path, None)
        assert tail.poll_once() == 0
    assert sink.paths() == ["/a"]


def test_after_a_restart_the_first_look_does_not_assume_a_rewrite(live, db):
    first, sink1 = make(live, db)
    append(live / "x.jsonl", line("/before") + "\n")
    first.poll_once()
    second, sink2 = make(live, db)                                    # no fingerprints yet
    assert second.poll_once() == 0 and sink2.paths() == []            # nothing re-read
    append(live / "x.jsonl", line("/after") + "\n")
    assert second.poll_once() == 1 and sink2.paths() == ["/after"]


# ---- characters that str.splitlines() would break a line at --------------------------------

@pytest.mark.parametrize("char", ["\u2028", "\u2029", "\u0085"])      # the ones JSON allows raw inside a string
def test_a_request_containing_a_line_separator_character_arrives_whole(live, db, char):
    tail, sink = make(live, db)
    text = json.dumps({"ts": "2026-10-31T10:00:00Z", "host": "api.openai.com", "method": "POST", "path": "/ok",
                       "body": f"before{char}after"}, ensure_ascii=False)
    append(live / "x.jsonl", text + "\n" + line("/next") + "\n")
    assert tail.poll_once() == 2 and sink.skipped == 0
    assert sink.events[0].body_text == f"before{char}after" and sink.paths() == ["/ok", "/next"]


# ---- the bookmark moves in batches ----------------------------------------------------------

def test_a_crash_part_way_through_a_big_read_repeats_only_one_batch(live, db):
    got, state = [], {"calls": 0}

    def ingest(events, skipped, errors):
        state["calls"] += 1
        if state["calls"] == 3:                                       # the app "dies" while handling the third batch
            raise SystemExit("killed")
        got.extend(e.path for e in events)

    tail = LiveTail(live, db, ingest, batch_lines=5)
    append(live / "x.jsonl", "".join(line(f"/n{i}") + "\n" for i in range(23)))
    with pytest.raises(SystemExit):
        tail.poll_once()
    assert got == [f"/n{i}" for i in range(10)]                       # two whole batches were delivered and saved
    fresh = LiveTail(live, db, lambda ev, sk, er: got.extend(e.path for e in ev), batch_lines=5)   # "restart"
    fresh.poll_once()
    assert got[10:] == [f"/n{i}" for i in range(10, 23)]              # resumes at the third batch: no repeats, no gaps
    assert len(got) == len(set(got)) == 23


def test_batches_cover_every_line_exactly_once_whatever_the_size(live, db):
    for size in (1, 2, 7, 200):
        folder = live / f"b{size}"
        folder.mkdir()
        got = []
        tail = LiveTail(folder, db, lambda ev, sk, er, g=got: g.extend(e.path for e in ev), batch_lines=size)
        append(folder / "x.jsonl", "".join(line(f"/n{i}") + "\n" for i in range(50)))
        assert tail.poll_once() == 50 and got == [f"/n{i}" for i in range(50)]
        assert tail.poll_once() == 0


def test_a_failure_in_a_later_batch_retries_from_that_batch(live, db):
    got, state = [], {"fail": True}

    def ingest(events, skipped, errors):
        paths = [e.path for e in events]
        if state["fail"] and "/n7" in paths:
            raise RuntimeError("blip")
        got.extend(paths)

    tail = LiveTail(live, db, ingest, batch_lines=5)
    append(live / "x.jsonl", "".join(line(f"/n{i}") + "\n" for i in range(12)))
    assert tail.poll_once() == 5 and got == [f"/n{i}" for i in range(5)]        # batch 1 delivered, batch 2 failed
    state["fail"] = False
    assert tail.poll_once() == 7 and got == [f"/n{i}" for i in range(12)]        # batch 2 and 3, once each


def test_bad_lines_are_counted_in_the_batch_they_belong_to(live, db):
    seen = []
    tail = LiveTail(live, db, lambda ev, sk, er: seen.append((len(ev), sk, len(er))), batch_lines=3)
    append(live / "x.jsonl", line("/a") + "\nbad\n" + line("/b") + "\nbad\nbad\n" + line("/c") + "\n")
    tail.poll_once()
    assert seen == [(2, 1, 1), (1, 2, 2)]


def test_a_byte_order_mark_only_matters_at_the_very_start(live, db):
    tail, sink = make(live, db, batch_lines=2)
    append(live / "x.jsonl", "\ufeff" + line("/first") + "\n" + line("/second") + "\n" + line("/third") + "\n")
    assert tail.poll_once() == 3 and sink.paths() == ["/first", "/second", "/third"]

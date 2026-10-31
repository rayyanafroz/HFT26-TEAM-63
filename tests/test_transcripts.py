"""The transcript reader (SOT 7.2.1): AT-28 (the reader), AT-29 (the tail), AT-30 (the sources routes)."""

import json
import os
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from scenarios.transcript_sim import transcript_lines
from shadowlens.api.app import create_app
from shadowlens.config import Config
from shadowlens.core import hooks
from shadowlens.core.ctx import AgentContexts
from shadowlens.core.pipeline import Pipeline
from shadowlens.db import Database
from shadowlens.fakes import fake
from shadowlens.ingest.http_log import LogLineError
from shadowlens.ingest.sources import (RegistryError, SourceDef, SourceManager, expand_glob, load_registry)
from shadowlens.ingest.transcripts import claude_code_jsonl
from shadowlens.models import Source, SourceKind
from shadowlens.providers.catalog import Catalog

HOST, PROCESS = "api.anthropic.com", "claude"


def read(line, **kw):
    return claude_code_jsonl(line if isinstance(line, str) else json.dumps(line), host=HOST, process=PROCESS,
                             max_body_bytes=kw.pop("max_body_bytes", 65536), **kw)


def msg(role, content, **extra):
    return {"type": role, "timestamp": "2026-10-31T10:00:00.000Z", "message": {"role": role, "content": content, **extra}}


def body_of(event):
    return json.loads(event.body_text)


KEY = fake("openai_key", 3)


# ---- the reader ------------------------------------------------------------------------------------

def test_a_typed_message_becomes_the_request_that_was_sent():
    event = read(msg("user", [{"type": "text", "text": f"fix this {KEY}"}]))
    assert (event.source, event.process, event.host, event.method, event.path, event.dst_port) == (
        Source.TRANSCRIPT, "claude", "api.anthropic.com", "POST", "/v1/messages", 443)
    assert event.dst_ip == "0.0.0.0" and event.ts == "2026-10-31T10:00:00.000Z"
    assert body_of(event) == {"model": "unknown", "messages": [{"role": "user", "content": [{"type": "text", "text": f"fix this {KEY}"}]}]}


def test_a_plain_string_message_is_read_too():
    assert KEY in read(msg("user", f"my key is {KEY}")).body_text


def test_tool_results_are_kept_as_text_or_text_blocks():
    one = read(msg("user", [{"type": "tool_result", "tool_use_id": "t1", "content": f"API_KEY={KEY}"}]))
    two = read(msg("user", [{"type": "tool_result", "content": [{"type": "text", "text": "a"}, {"type": "image", "source": "x"},
                                                                 {"type": "text", "text": "b"}]}]))
    assert body_of(one)["messages"][0]["content"] == [{"type": "tool_result", "content": f"API_KEY={KEY}"}]
    assert body_of(two)["messages"][0]["content"][0]["content"] == [{"type": "text", "text": "a"}, {"type": "text", "text": "b"}]


def test_only_the_agents_actions_are_kept_from_the_assistant():
    event = read(msg("assistant", [{"type": "thinking", "thinking": f"secret plan {KEY}"}, {"type": "text", "text": f"here {KEY}"},
                                   {"type": "tool_use", "id": "x", "name": "Bash", "input": {"command": "ls"}}], model="claude-opus"))
    assert body_of(event) == {"model": "claude-opus", "messages": [{"role": "assistant", "content": [
        {"type": "tool_use", "name": "Bash", "input": {"command": "ls"}}]}]}
    assert KEY not in event.body_text


@pytest.mark.parametrize("line", [
    msg("assistant", [{"type": "text", "text": f"prose {KEY}"}]),            # assistant prose is not inspected
    msg("assistant", [{"type": "thinking", "thinking": KEY}]),
    msg("user", [{"type": "text", "text": "   "}]),
    msg("user", []),
    msg("user", [{"type": "image"}]),
    {"type": "user"},                                                          # no message
    {"type": "user", "message": "text"},
    {"type": "system", "message": {"role": "user", "content": "x"}},
])
def test_lines_with_nothing_to_inspect_make_no_event(line):
    assert read(line) is None


@pytest.mark.parametrize("kind", ["queue-operation", "file-history-snapshot", "api-request-blob", "ai-title", "attachment", "last-prompt"])
def test_bookkeeping_lines_are_skipped_without_even_being_parsed(kind):
    # not valid JSON after the type: parsing would raise, so a None proves it was never parsed
    assert read('{"type":"%s","payload":' % kind) is None
    assert read('{ "type" : "%s" }' % kind) is None


def test_a_line_that_is_not_json_is_an_error():
    with pytest.raises(LogLineError):
        read("this is not json")
    with pytest.raises(LogLineError):
        read('{"type":"user","message":{"role":')
    with pytest.raises(LogLineError):
        read("[1, 2]")


def test_timestamp_and_model_are_read_defensively():
    now = read({"type": "user", "message": {"role": "user", "content": "hi"}})
    assert now.ts.endswith("Z") and body_of(now)["model"] == "unknown"
    for bad in (None, 5, "yesterday", ""):
        line = msg("user", "hi")
        line["timestamp"] = bad
        assert read(line).ts.endswith("Z")
    assert body_of(read(msg("assistant", [{"type": "tool_use", "name": "Bash", "input": {}}], model=7)))["model"] == "unknown"


def test_the_role_inside_the_message_wins_over_the_line_type():
    line = {"type": "user", "message": {"role": "assistant", "content": [{"type": "text", "text": KEY}]}}
    assert read(line) is None


def test_a_huge_tool_result_is_cut_to_fit_and_the_json_stays_valid():
    huge = "A" * 5_000_000 + KEY
    event = read(msg("user", [{"type": "tool_result", "content": huge}]), max_body_bytes=65536)
    assert len(event.body_text) <= 65536 and not event.body_truncated
    assert json.loads(event.body_text)["messages"][0]["content"][0]["type"] == "tool_result"
    assert event.body_bytes == len(event.body_text.encode())          # the size is that of what we analyse


def test_unicode_and_odd_separators_survive():
    text = "naïve –   line \u0085 sep 🔑 " + KEY
    assert KEY in read(msg("user", [{"type": "text", "text": text}])).body_text


# ---- AT-28: what the real analysis makes of it ---------------------------------------------------------

@pytest.fixture
def db(tmp_path):
    database = Database(tmp_path / "shadow.db")
    yield database
    database.close()


def real_pipeline(tmp_path, db, **env):
    config = Config.load(env={"SHADOWLENS_RESOLVE": "false", **env}, base_dir=tmp_path, use_dotenv=False)
    return config, Pipeline(config, db, Catalog.load(), analyze=hooks.event_analyzer(), contexts=AgentContexts())


def test_the_simulated_session_yields_the_key_the_shell_and_the_sensitive_read(tmp_path, db):
    _, pipeline = real_pipeline(tmp_path, db)
    events = [read(line) for line in transcript_lines("s1")]
    summary = pipeline.ingest(events, source="transcript")
    rules = {f.rule_id for f in db.list_findings().items}
    assert {"SEC_OPENAI_KEY", "AGENT_DANGEROUS_CMD", "AGENT_SHELL_EXEC", "AGENT_SENSITIVE_FILE_READ"} <= rules
    assert summary.accepted == 3 and summary.skipped == 0
    key_finding = next(f for f in db.list_findings().items if f.rule_id == "SEC_OPENAI_KEY")
    assert key_finding.masked_preview.startswith("sk-p...") and key_finding.location.field == "body"


def test_assistant_prose_alone_creates_no_finding(tmp_path, db):
    _, pipeline = real_pipeline(tmp_path, db)
    assert read(msg("assistant", [{"type": "text", "text": f"the key is {KEY}"}])) is None
    assert pipeline.ingest([], source="transcript").accepted == 0 and db.count_findings() == 0


def test_the_secret_itself_is_never_stored(tmp_path, db):
    _, pipeline = real_pipeline(tmp_path, db)
    pipeline.ingest([read(msg("user", [{"type": "text", "text": f"use {KEY}"}]))], source="transcript")
    stored = json.dumps([f.model_dump(mode="json") for f in db.list_findings().items]) + json.dumps(
        [e.model_dump(mode="json") for e in db.list_events().items]) + json.dumps(
        [a.model_dump(mode="json") for a in db.list_alerts().items])
    longest = max(n for n in range(1, len(KEY) + 1) if any(KEY[i:i + n] in stored for i in range(len(KEY) - n + 1)))
    assert longest <= 4


# ---- the registry -----------------------------------------------------------------------------------

def test_the_shipped_registry_loads_and_is_opt_in():
    registry = {d.id: d for d in load_registry()}
    assert set(registry) == {"claude_code", "demo_transcripts", "live_log", "ollama_proxy", "browser_history"}
    assert registry["claude_code"].enabled_default is False and registry["ollama_proxy"].enabled_default is False
    assert registry["claude_code"].kind is SourceKind.TRANSCRIPT and registry["claude_code"].reader == "claude_code_jsonl"


@pytest.mark.parametrize("text, message", [
    ("sources: []\nextra: 1\nnot_sources: 2", "sources"),
    ("sources:\n  - {id: A, display_name: x, kind: transcript}", "id"),
    ("sources:\n  - {id: a, display_name: x, kind: transcript, paths: [x], reader: nope, host: h, process: p}", "reader"),
    ("sources:\n  - {id: a, display_name: x, kind: transcript, reader: claude_code_jsonl}", "paths"),
    ("sources:\n  - {id: a, display_name: x, kind: live_log, surprise: 1}", "surprise"),
    ("sources:\n  - {id: a, display_name: x, kind: live_log}\n  - {id: a, display_name: y, kind: live_log}", "duplicate"),
])
def test_a_broken_registry_fails_with_a_clear_message(tmp_path, text, message):
    path = tmp_path / "sources.yaml"
    path.write_text(text)
    with pytest.raises(RegistryError, match=message):
        load_registry(path)
    with pytest.raises(RegistryError):
        load_registry(tmp_path / "missing.yaml")


def test_globs_expand_home_relative_and_absolute_patterns(tmp_path):
    home, project = tmp_path / "home", tmp_path / "project"
    (home / ".tool" / "a" / "b").mkdir(parents=True)
    (home / ".tool" / "a" / "one.jsonl").write_text("x")
    (home / ".tool" / "a" / "b" / "two.jsonl").write_text("x")
    (home / ".tool" / "a" / "skip.txt").write_text("x")
    (project / "data").mkdir(parents=True)
    (project / "data" / "three.jsonl").write_text("x")
    names = lambda found: sorted(p.name for p in found)     # noqa: E731
    assert names(expand_glob("~/.tool/**/*.jsonl", project, home)) == ["one.jsonl", "three.jsonl"][:1] + ["two.jsonl"]
    assert names(expand_glob("data/*.jsonl", project, home)) == ["three.jsonl"]
    assert names(expand_glob(str(home / ".tool" / "a" / "*.jsonl"), project, home)) == ["one.jsonl"]
    assert expand_glob("~/nothing/**/*.jsonl", project, home) == []
    assert names(expand_glob(str(home / ".tool" / "a" / "one.jsonl"), project, home)) == ["one.jsonl"]


# ---- the manager and the tail (AT-29) ---------------------------------------------------------------------

def wait_for(condition, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.03)
    return False


def user_line(text, stamp="2026-10-31T10:00:00.000Z"):
    return json.dumps({"type": "user", "timestamp": stamp, "message": {"role": "user", "content": [{"type": "text", "text": text}]}}) + "\n"


class Rig:
    def __init__(self, tmp_path, db, **kw):
        self.home = tmp_path / "home"
        self.dir = self.home / ".claude" / "projects" / "demo"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.config, self.pipeline = real_pipeline(tmp_path, db, **kw.pop("env", {}))
        self.db = db
        self.batches = []

        def ingest(events, **kw2):
            self.batches.append((len(events), kw2.get("skipped", 0), list(kw2.get("errors", []))))
            return self.pipeline.ingest(events, **kw2)

        registry = [SourceDef(id="claude_code", display_name="Claude Code transcripts", kind=SourceKind.TRANSCRIPT,
                              paths=["~/.claude/projects/**/*.jsonl"], reader="claude_code_jsonl", provider_id="anthropic",
                              host=HOST, process=PROCESS, reads="r", stores="s", **kw)]
        self.manager = SourceManager(self.config, db, ingest, registry=registry, project_dir=tmp_path, home=self.home,
                                     poll_s=0.04, discovery_s=0.1)

    def session(self, name="s1.jsonl"):
        return self.dir / name

    def findings(self, rule="SEC_OPENAI_KEY"):
        return [f for f in self.db.list_findings().items if f.rule_id == rule]

    def skipped(self):
        return sum(b[1] for b in self.batches)


@pytest.fixture
def rig(tmp_path, db):
    made = []

    def build(**kw):
        r = Rig(tmp_path, db, **kw)
        made.append(r)
        return r

    yield build
    for r in made:
        r.manager.stop()


def append(path, text):
    with open(path, "ab") as handle:
        handle.write(text.encode("utf-8"))


def test_it_is_off_until_switched_on_and_reports_what_it_found(rig):
    r = rig()
    assert r.manager.rows()[0].found is False
    r.session().write_text(user_line(f"old {fake('openai_key', 0)}"))
    r.manager.start()
    row = r.manager.rows()[0]
    assert (row.found, row.enabled, row.files_watched) == (True, False, 0)
    time.sleep(0.3)
    assert r.findings() == []                                  # nothing is read while it is off
    assert r.manager.status().enabled is False


def test_switching_on_reads_only_what_happens_afterwards(rig):
    r = rig()
    r.session().write_text(user_line(f"history {fake('openai_key', 0)}"))
    r.manager.start()
    row = r.manager.set_enabled("claude_code", True)
    assert row.enabled and row.files_watched == 1
    time.sleep(0.3)
    assert r.findings() == []                                  # the history was not read
    append(r.session(), user_line(f"new {fake('openai_key', 1)}"))
    assert wait_for(lambda: len(r.findings()) == 1)
    assert r.manager.rows()[0].last_event_at is not None and r.manager.rows()[0].lines_ingested == 1


def test_a_new_session_file_is_read_from_its_first_line(rig):
    r = rig()
    r.manager.start()
    r.manager.set_enabled("claude_code", True)
    time.sleep(0.2)
    r.session("fresh.jsonl").write_text(user_line(f"hello {fake('openai_key', 2)}") + user_line(f"again {fake('openai_key', 4)}"))
    assert wait_for(lambda: len(r.findings()) == 2)


def test_a_half_written_line_waits_for_its_newline(rig):
    r = rig()
    r.session().write_text("")
    r.manager.start()
    r.manager.set_enabled("claude_code", True)
    line = user_line(f"split {fake('openai_key', 5)}")
    append(r.session(), line[:40])
    time.sleep(0.3)
    assert r.findings() == [] and r.skipped() == 0              # not an error: the rest has not arrived
    append(r.session(), line[40:])
    assert wait_for(lambda: len(r.findings()) == 1)
    assert r.skipped() == 0


def test_bad_lines_are_counted_and_the_good_ones_still_read(rig):
    r = rig()
    r.session().write_text("")
    r.manager.start()
    r.manager.set_enabled("claude_code", True)
    append(r.session(), "not json at all\n" + '{"type":"queue-operation","x":\n' + user_line(f"ok {fake('openai_key', 6)}") + "\n\n")
    assert wait_for(lambda: len(r.findings()) == 1)
    assert r.skipped() == 1                                     # the garbage line; the bookkeeping line is not an error


def test_windows_line_endings_and_a_byte_order_mark_are_fine(rig):
    r = rig()
    r.session().write_text("")
    r.manager.start()
    r.manager.set_enabled("claude_code", True)
    append(r.session(), "﻿" + user_line(f"crlf {fake('openai_key', 7)}").rstrip("\n") + "\r\n")
    assert wait_for(lambda: len(r.findings()) == 1) and r.skipped() == 0


def test_a_truncated_file_is_read_again_from_the_start(rig):
    r = rig()
    r.session().write_text(user_line("x" * 3000))
    r.manager.start()
    r.manager.set_enabled("claude_code", True)
    r.session().write_text(user_line(f"fresh {fake('openai_key', 8)}"))        # shorter than before
    assert wait_for(lambda: len(r.findings()) == 1)


def test_a_restart_does_not_read_the_same_lines_again(tmp_path, db):
    first = Rig(tmp_path, db)
    first.session().write_text("")
    first.manager.start()
    first.manager.set_enabled("claude_code", True)
    append(first.session(), user_line(f"once {fake('openai_key', 9)}"))
    assert wait_for(lambda: first.manager.rows()[0].lines_ingested == 1)
    first.manager.stop()
    events_before = db.list_events().total

    second = Rig(tmp_path, db)                                  # the same database: the bookmark is kept
    try:
        second.manager.start()
        second.manager.set_enabled("claude_code", True)
        time.sleep(0.4)
        assert db.list_events().total == events_before
        append(second.session(), user_line(f"twice {fake('openai_key', 10)}"))
        assert wait_for(lambda: db.list_events().total == events_before + 1)
    finally:
        second.manager.stop()


def test_switching_off_stops_reading_and_on_again_skips_what_was_missed(rig):
    r = rig()
    r.session().write_text("")
    r.manager.start()
    r.manager.set_enabled("claude_code", True)
    assert r.manager.set_enabled("claude_code", False).enabled is False
    append(r.session(), user_line(f"while off {fake('openai_key', 11)}"))
    time.sleep(0.3)
    assert r.findings() == []
    r.manager.set_enabled("claude_code", True)
    time.sleep(0.3)
    assert r.findings() == []                                   # what was typed while off stays unread
    append(r.session(), user_line(f"back on {fake('openai_key', 12)}"))
    assert wait_for(lambda: len(r.findings()) == 1)


def test_backfill_reads_the_recent_past_once(rig):
    r = rig()
    r.session().write_text(user_line(f"past {fake('openai_key', 13)}") + user_line("filler\n"))
    r.manager.start()
    r.manager.set_enabled("claude_code", True, backfill=True)
    assert wait_for(lambda: len(r.findings()) == 1)
    assert r.manager.rows()[0].enabled


def test_backfill_is_capped_to_the_last_20_mb_and_starts_on_a_line(rig, monkeypatch):
    from shadowlens.ingest import sources
    monkeypatch.setattr(sources, "BACKFILL_BYTES", 400)
    r = rig()
    old = user_line(f"too old {fake('openai_key', 14)}")
    recent = user_line(f"recent {fake('openai_key', 15)}")
    r.session().write_text(old * 20 + recent)
    assert len(old) * 20 > 400
    r.manager.start()
    r.manager.set_enabled("claude_code", True, backfill=True)
    assert wait_for(lambda: len(r.findings()) == 2)               # the last two lines fit in the window
    time.sleep(0.3)
    assert r.skipped() == 0                                       # never began in the middle of a line
    assert r.manager.rows()[0].lines_ingested == 2                # not the 21 lines in the file


def test_only_recent_files_and_at_most_max_files_are_read(rig):
    r = rig(max_files=2, max_age_h=1)
    now = time.time()
    for index, age_h in enumerate([0.1, 0.2, 0.3, 5.0]):
        path = r.session(f"f{index}.jsonl")
        path.write_text("")
        os.utime(path, (now - age_h * 3600, now - age_h * 3600))
    r.manager.start()
    row = r.manager.set_enabled("claude_code", True)
    assert row.found and row.files_watched == 2


def test_the_transcript_dirs_setting_restricts_where_it_reads(tmp_path, db):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    r = Rig(tmp_path, db, env={"SHADOWLENS_TRANSCRIPT_DIRS": str(allowed)})
    try:
        r.session().write_text("")
        (allowed / "only.jsonl").write_text("")
        r.manager.start()
        row = r.manager.set_enabled("claude_code", True)
        assert row.files_watched == 1 and str(allowed).replace(str(Path.home()), "~") in row.paths[0]
    finally:
        r.manager.stop()


def test_the_config_switch_turns_it_on_at_start(tmp_path, db):
    r = Rig(tmp_path, db, env={"SHADOWLENS_TRANSCRIPTS_ENABLED": "true"})
    try:
        r.session().write_text("")
        r.manager.start()
        assert r.manager.rows()[0].enabled and r.manager.status().sources_active == 1
    finally:
        r.manager.stop()


def test_paths_are_shown_with_the_home_folder_as_a_tilde(rig):
    assert rig().manager.rows()[0].paths == ["~/.claude/projects/**/*.jsonl"]


def test_a_source_that_cannot_be_switched_says_so(rig):
    r = rig()
    with pytest.raises(KeyError):
        r.manager.set_enabled("nope", True)


def test_a_failure_in_ingest_loses_nothing(rig):
    r = rig()
    r.session().write_text("")
    calls = {"n": 0}
    real = r.manager._ingest

    def flaky(events, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("database busy")
        return real(events, **kw)

    r.manager._ingest = flaky
    r.manager.start()
    r.manager.set_enabled("claude_code", True)
    append(r.session(), user_line(f"retry {fake('openai_key', 16)}"))
    assert wait_for(lambda: len(r.findings()) == 1) and calls["n"] >= 2


# ---- AT-30: the routes ---------------------------------------------------------------------------------

@pytest.fixture
def client(tmp_path):
    config = Config.load(env={"SHADOWLENS_RESOLVE": "false", "SHADOWLENS_DB_PATH": str(tmp_path / "t.db"),
                              "SHADOWLENS_LIVE_DIR": str(tmp_path / "live")}, base_dir=tmp_path, use_dotenv=False)
    with TestClient(create_app(config)) as c:
        yield c


def test_the_sources_list_has_the_registry_and_everything_opt_in_is_off(client):
    body = client.get("/api/sources").json()
    rows = {row["id"]: row for row in body["items"]}
    assert body["total"] == 5 and set(rows) == {"claude_code", "demo_transcripts", "live_log", "ollama_proxy", "browser_history"}
    assert rows["claude_code"]["enabled"] is False and rows["ollama_proxy"]["enabled"] is False
    assert rows["live_log"]["enabled"] is True and rows["live_log"]["supported"] is True
    assert rows["ollama_proxy"]["supported"] is True and rows["ollama_proxy"]["error"] is None
    assert "masked findings" in rows["claude_code"]["stores"].lower()
    assert set(rows["claude_code"]) == {"id", "display_name", "kind", "found", "enabled", "supported", "error", "paths",
                                         "files_watched", "lines_ingested", "last_event_at", "reads", "stores"}


def test_the_live_log_source_can_be_toggled_through_the_same_route(client):
    assert client.put("/api/sources/live_log", json={"enabled": False}).json()["enabled"] is False
    assert client.get("/api/capture/status").json()["live_tail"]["enabled"] is False
    assert client.put("/api/sources/live_log", json={"enabled": True}).json()["enabled"] is True


def test_unknown_unsupported_and_malformed_updates_are_refused(client):
    assert client.put("/api/sources/nope", json={"enabled": True}).status_code == 404
    assert client.put("/api/sources/claude_code", json={"enabled": "maybe"}).status_code == 422
    assert client.put("/api/sources/claude_code", json={"enabled": True, "extra": 1}).status_code == 422
    assert client.put("/api/sources/claude_code", json={}).status_code == 422


def test_switching_on_shows_in_the_capture_status(client):
    row = client.put("/api/sources/demo_transcripts", json={"enabled": True}).json()
    assert row["enabled"] is True
    status = client.get("/api/capture/status").json()["transcripts"]
    assert status["enabled"] is True and status["sources_active"] >= 1
    client.put("/api/sources/demo_transcripts", json={"enabled": False})
    assert client.get("/api/capture/status").json()["transcripts"]["sources_active"] == 0

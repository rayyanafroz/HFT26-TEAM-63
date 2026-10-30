import sqlite3
import threading
from pathlib import Path

import pytest

from shadowlens.config import Config
from shadowlens.db import (
    DROPPED_NON_AI, FORBIDDEN_COLUMNS, MAX_LIMIT, SCHEMA_VERSION, Database, DatabaseError, clamp_page,
    open_database,
)
from shadowlens.models import (
    AgentActivity, Alert, Finding, LlmCall, NetEvent, ProviderMatch, Remediation, new_id,
)


# ---- builders ----------------------------------------------------------------

def ts(n=0):
    return f"2026-10-31T10:{n // 60:02d}:{n % 60:02d}.000Z"


def make_event(n=0, **o):
    base = dict(id=new_id(), ts=ts(n), source="http_log", process="python3", dst_ip="203.0.113.7",
                dst_port=443, host="api.openai.com", host_basis="host_header", method="POST",
                path="/v1/chat/completions", body_bytes=10)
    base.update(o)
    return NetEvent(**base)


def make_match(tool_id="python3|openai", provider="openai", **o):
    base = dict(provider_id=provider, display_name="OpenAI", category="cloud_llm", confidence="high",
                match_basis="host", tool_id=tool_id)
    base.update(o)
    return ProviderMatch(**base)


def make_finding(event_id, n=0, rule="SEC_OPENAI_KEY", category="secret", severity="high",
                 tool_id="python3|openai", hash12="0123456789ab", **o):
    base = dict(id=new_id(), event_id=event_id, tool_id=tool_id, rule_id=rule, category=category,
                severity=severity, confidence=0.9, masked_preview="sk-p... (len 51)",
                location={"field": "body", "offset": 4}, owasp=["LLM02"], controls=["C1"],
                meta={"hash12": hash12, "spans": [[4, 55]], "context": "key [REDACTED:SEC_OPENAI_KEY:0123456789ab]"},
                created_at=ts(n))
    base.update(o)
    return Finding(**base)


def make_alert(finding, n=0, **o):
    base = dict(id=new_id(), finding_id=finding.id, tool_id=finding.tool_id, provider_id="openai",
                rule_id=finding.rule_id, severity=finding.severity.value, title="Key sent to an AI tool",
                created_at=ts(n), finding=finding)
    base.update(o)
    return Alert(**base)


def make_remediation(alert_id, **o):
    base = dict(id=new_id(), alert_id=alert_id, summary="Rotate the key.", steps=["Revoke it", "Make a new one"],
                sensitivity="high", verdict="true_positive", data_classes=["credential"], source="template",
                redaction_check="not_applicable", created_at=ts(5))
    base.update(o)
    return Remediation(**base)


@pytest.fixture
def db(tmp_path):
    database = Database(tmp_path / "data" / "shadow.db")
    yield database
    database.close()


def seed(db, n=0, **finding_overrides):
    """One event + one finding + one alert, all linked."""
    ev = make_event(n)
    db.insert_event(ev, make_match())
    f = make_finding(ev.id, n, **finding_overrides)
    db.insert_finding(f)
    a = make_alert(f, n)
    db.insert_alert(a)
    return ev, f, a


# ---- schema ------------------------------------------------------------------

def test_creates_the_expected_tables(db):
    assert set(db.table_columns()) == {
        "events", "findings", "alerts", "remediations", "agent_activity", "llm_calls",
        "provider_overrides", "source_offsets", "counters"}


def test_schema_is_idempotent_and_versioned(tmp_path):
    path = tmp_path / "x.db"
    Database(path).close()
    with Database(path) as again:           # opening twice must not fail or wipe anything
        again.init_schema()
        assert again._one("PRAGMA user_version")[0] == SCHEMA_VERSION


def test_refuses_a_newer_schema(tmp_path):
    path = tmp_path / "x.db"
    Database(path).close()
    raw = sqlite3.connect(path)
    raw.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
    raw.close()
    with pytest.raises(DatabaseError):
        Database(path)


def test_no_table_has_a_column_that_could_hold_secrets(db):
    for table, columns in db.table_columns().items():
        bad = FORBIDDEN_COLUMNS.intersection(columns)
        assert not bad, f"{table} has forbidden columns {bad}"


def test_creates_its_folder_and_opens_from_config(tmp_path):
    cfg = Config.load(env={"SHADOWLENS_DB_PATH": "deep/er/shadow.db"}, base_dir=tmp_path, use_dotenv=False)
    with open_database(cfg) as database:
        assert (tmp_path / "deep" / "er" / "shadow.db").exists()
        assert database.count_events() == 0


def test_wal_mode_and_foreign_keys_on(db):
    assert db._one("PRAGMA journal_mode")[0] == "wal"
    assert db._one("PRAGMA foreign_keys")[0] == 1


# ---- the privacy guarantee ---------------------------------------------------

def test_body_headers_and_query_never_reach_the_database_files(tmp_path):
    path = tmp_path / "shadow.db"
    database = Database(path)
    ev = make_event(
        body_text="BODYMARKER-top-secret-prompt with CARDMARKER-4111", headers={"Authorization": "Bearer HEADERMARKER-abc"},
        path="/v1/chat", query="key=QUERYMARKER-xyz", body_bytes=47, auth_hint="0123456789ab")
    database.insert_event(ev, make_match())
    database.insert_finding(make_finding(ev.id))
    database.close()
    for suffix in ("", "-wal", "-shm"):
        candidate = Path(str(path) + suffix)
        if candidate.exists():
            data = candidate.read_bytes()
            for marker in (b"BODYMARKER", b"CARDMARKER", b"HEADERMARKER", b"QUERYMARKER"):
                assert marker not in data, f"{marker!r} leaked into {candidate.name}"


def test_event_row_contains_only_metadata(db):
    ev = make_event(body_text="hello", query="a=b", headers={"authorization": "Bearer x"})
    db.insert_event(ev, make_match())
    row = db._one("SELECT * FROM events WHERE id = ?", (ev.id,))
    assert "hello" not in {str(v) for v in tuple(row)}
    assert set(row.keys()).isdisjoint(FORBIDDEN_COLUMNS)


# ---- paging helper -----------------------------------------------------------

@pytest.mark.parametrize("limit,offset,expected", [
    (None, None, (100, 0)), (5, 2, (5, 2)), (0, 0, (1, 0)), (-3, -9, (1, 0)),
    (5000, 0, (MAX_LIMIT, 0)), ("7", "3", (7, 3)),
])
def test_clamp_page(limit, offset, expected):
    assert clamp_page(limit, offset) == expected


# ---- events ------------------------------------------------------------------

def test_insert_and_list_events_newest_first_with_finding_count(db):
    old, new = make_event(1), make_event(5, process="curl")
    db.insert_event(old, make_match())
    db.insert_event(new, make_match(tool_id="curl|openai"))
    db.insert_finding(make_finding(new.id, tool_id="curl|openai"))
    page = db.list_events()
    assert page.total == 2
    assert [e.id for e in page.items] == [new.id, old.id]
    assert [e.finding_count for e in page.items] == [1, 0]
    assert page.items[0].tool_id == "curl|openai" and page.items[0].provider_id == "openai"
    assert page.items[0].visibility.value == "metadata_only"


def test_list_events_filters(db):
    a, b, c = make_event(1), make_event(2, body_text="x"), make_event(3)
    db.insert_event(a, make_match())
    db.insert_event(b, make_match(tool_id="curl|anthropic", provider="anthropic", display_name="Anthropic"))
    db.insert_event(c, make_match())
    assert db.list_events(provider_id="anthropic").total == 1
    assert db.list_events(tool_id="python3|openai").total == 2
    assert db.list_events(visibility="full").items[0].id == b.id
    assert db.list_events(since=ts(2)).total == 2          # events at or after the time
    assert db.list_events(provider_id="openai", visibility="full").total == 0


def test_list_events_paging(db):
    for n in range(7):
        db.insert_event(make_event(n), make_match())
    first = db.list_events(limit=3)
    second = db.list_events(limit=3, offset=3)
    assert first.total == 7 and len(first.items) == 3 and len(second.items) == 3
    assert {e.id for e in first.items}.isdisjoint({e.id for e in second.items})
    assert len(db.list_events(limit=3, offset=6).items) == 1


def test_duplicate_event_id_is_an_error(db):
    ev = make_event()
    db.insert_event(ev, make_match())
    with pytest.raises(sqlite3.IntegrityError):
        db.insert_event(ev, make_match())


# ---- findings ----------------------------------------------------------------

def test_finding_round_trip_is_lossless(db):
    ev = make_event()
    db.insert_event(ev, make_match())
    f = make_finding(ev.id, meta={"hash12": "0123456789ab", "spans": [[4, 55], [60, 70]], "context": "ctx",
                                  "in_tool_args": True, "count": 3, "tool_name": "bash", "argument": "curl x"})
    assert db.insert_finding(f) is True
    assert db.get_finding(f.id) == f


def test_same_tool_rule_value_is_stored_once(db):
    ev = make_event()
    db.insert_event(ev, make_match())
    first = make_finding(ev.id)
    again = make_finding(ev.id)                                    # new id, same (tool, rule, hash12)
    assert db.insert_finding(first) is True
    assert db.insert_finding(again) is False
    assert db.count_findings() == 1 and db.get_finding(again.id) is None
    other_value = make_finding(ev.id, hash12="ffffffffffff")       # same rule, different value
    other_tool = make_finding(ev.id, tool_id="curl|openai")        # same value, different tool
    assert db.insert_finding(other_value) and db.insert_finding(other_tool)
    assert db.count_findings() == 3


def test_finding_needs_an_existing_event(db):
    with pytest.raises(sqlite3.IntegrityError):
        db.insert_finding(make_finding(new_id()))


def test_list_findings_filters(db):
    ev = make_event()
    db.insert_event(ev, make_match())
    db.insert_finding(make_finding(ev.id, 1))
    db.insert_finding(make_finding(ev.id, 2, rule="PII_EMAIL", category="pii", severity="low", hash12="aaaaaaaaaaaa"))
    assert db.list_findings(category="pii").total == 1
    assert db.list_findings(rule_id="SEC_OPENAI_KEY").total == 1
    assert db.list_findings(event_id=ev.id).total == 2
    assert db.list_findings(tool_id="nobody|x").total == 0
    assert [f.rule_id for f in db.list_findings().items] == ["PII_EMAIL", "SEC_OPENAI_KEY"]   # newest first


# ---- alerts, ack, remediation ------------------------------------------------

def test_alert_round_trip_includes_the_finding(db):
    _, f, a = seed(db)
    got = db.get_alert(a.id)
    assert got == a and got.finding == f and got.remediation is None
    assert db.get_alert(new_id()) is None


def test_alert_requires_a_stored_finding(db):
    ev = make_event()
    db.insert_event(ev, make_match())
    unsaved = make_finding(ev.id)
    with pytest.raises(sqlite3.IntegrityError):
        db.insert_alert(make_alert(unsaved))


def test_one_alert_per_finding(db):
    _, f, _ = seed(db)
    with pytest.raises(sqlite3.IntegrityError):
        db.insert_alert(make_alert(f))


def test_failed_alert_insert_leaves_nothing_behind(db):
    ev = make_event()
    db.insert_event(ev, make_match())
    f = make_finding(ev.id)
    db.insert_finding(f)
    alert = make_alert(f)
    alert = alert.model_copy(update={"remediation": make_remediation(new_id())})   # wrong alert id inside
    with pytest.raises(sqlite3.IntegrityError):
        db.insert_alert(alert)
    assert db.get_alert(alert.id) is None            # the alert row was rolled back too


def test_list_alerts_filters_and_order(db):
    seed(db, 1, hash12="aaaaaaaaaaaa")
    seed(db, 2, hash12="bbbbbbbbbbbb", rule="SEC_PRIVATE_KEY", severity="critical")
    seed(db, 3, hash12="cccccccccccc", rule="PII_EMAIL", category="pii", severity="low")
    page = db.list_alerts()
    assert page.total == 3
    assert [a.rule_id for a in page.items] == ["PII_EMAIL", "SEC_PRIVATE_KEY", "SEC_OPENAI_KEY"]
    assert db.list_alerts(severity=["critical", "high"]).total == 2
    assert db.list_alerts(severity=["low"]).items[0].rule_id == "PII_EMAIL"
    assert db.list_alerts(rule_id="SEC_PRIVATE_KEY").total == 1
    assert db.list_alerts(status="open").total == 3 and db.list_alerts(status="acked").total == 0
    with pytest.raises(ValueError):
        db.list_alerts(severity=["catastrophic"])
    with pytest.raises(ValueError):
        db.list_alerts(status="snoozed")


def test_ack_alert_persists_and_is_idempotent(db):
    _, _, a = seed(db)
    first = db.ack_alert(a.id, "2026-10-31T11:00:00.000Z")
    assert first.status.value == "acked" and first.acked_at == "2026-10-31T11:00:00.000Z"
    second = db.ack_alert(a.id, "2030-01-01T00:00:00.000Z")
    assert second.acked_at == "2026-10-31T11:00:00.000Z"          # unchanged
    assert db.get_alert(a.id).status.value == "acked"
    assert db.count_open_alerts() == 0
    assert db.list_alerts(status="acked").total == 1
    assert db.ack_alert(new_id()) is None


def test_remediation_is_saved_once_and_attached_to_the_alert(db):
    _, _, a = seed(db)
    first = make_remediation(a.id, summary="First advice")
    stored = db.save_remediation(first)
    assert stored == first
    again = db.save_remediation(make_remediation(a.id, summary="Second advice"))
    assert again.summary == "First advice" and again.id == first.id       # idempotent: existing wins
    assert db.get_alert(a.id).remediation == first
    assert db.list_alerts().items[0].remediation == first


def test_alert_with_remediation_inserts_both(db):
    ev = make_event()
    db.insert_event(ev, make_match())
    f = make_finding(ev.id)
    db.insert_finding(f)
    a = make_alert(f)
    a = a.model_copy(update={"remediation": make_remediation(a.id)})
    db.insert_alert(a)
    assert db.get_alert(a.id).remediation.summary == "Rotate the key."


def test_remediation_needs_an_existing_alert(db):
    with pytest.raises(sqlite3.IntegrityError):
        db.save_remediation(make_remediation(new_id()))


# ---- agent activity ----------------------------------------------------------

def act(n, **o):
    base = dict(ts=ts(n), capability="shell", kind="used", risky=False, name=f"cmd{n}")
    base.update(o)
    return AgentActivity(**base)


def test_activity_is_returned_oldest_first_and_capped_at_100(db):
    for n in range(130):
        db.add_agent_activity("cursor|anthropic", act(n))
    db.add_agent_activity("other|openai", act(1))
    items = db.list_agent_activity("cursor|anthropic")
    assert len(items) == 100
    assert items[0].name == "cmd30" and items[-1].name == "cmd129"       # last 100, oldest to newest
    assert len(db.list_agent_activity("cursor|anthropic", limit=5)) == 5
    assert len(db.list_agent_activity("other|openai")) == 1
    assert db.list_agent_activity("nobody|x") == []


def test_activity_round_trip_and_finding_link(db):
    ev, f, _ = seed(db)
    original = act(1, risky=True, rule_id="AGENT_DANGEROUS_CMD", finding_id=f.id, argument="curl x | sh",
                   capability="shell", kind="used")
    db.add_agent_activity("python3|openai", original)
    assert db.list_agent_activity("python3|openai") == [original]
    with pytest.raises(sqlite3.IntegrityError):
        db.add_agent_activity("python3|openai", act(2, finding_id=new_id()))


# ---- AI call ledger ----------------------------------------------------------

def test_llm_ledger_and_egress_summary(db):
    _, _, a = seed(db)
    def call(n, status, model="m"):
        return LlmCall(id=new_id(), ts=ts(n), alert_id=a.id, model=model, bytes=100, status=status,
                       prompt_sha256="a" * 64, latency_ms=10)
    for c in (call(1, "sent"), call(2, "sent"), call(3, "blocked", None), call(4, "failed")):
        db.add_llm_call(c)
    db.save_remediation(make_remediation(a.id))                    # a template remediation
    summary = db.egress_summary()
    assert (summary.sent, summary.blocked, summary.failed, summary.template_fallbacks) == (2, 1, 1, 1)
    page = db.list_llm_calls(limit=3)
    assert page.total == 4 and [c.status.value for c in page.items] == ["failed", "blocked", "sent"]


def test_llm_call_needs_an_existing_alert(db):
    with pytest.raises(sqlite3.IntegrityError):
        db.add_llm_call(LlmCall(id=new_id(), ts=ts(), alert_id=new_id(), bytes=1, status="sent",
                                prompt_sha256="b" * 64))


# ---- overrides, offsets, counters --------------------------------------------

def test_provider_overrides_can_be_changed(db):
    assert db.get_provider_overrides() == {}
    db.set_provider_override("openai", True)
    db.set_provider_override("ollama", False)
    db.set_provider_override("openai", False)                      # update, not a duplicate
    assert db.get_provider_overrides() == {"openai": False, "ollama": False}


def test_offsets_round_trip_and_update(db):
    assert db.get_offset("C:/x/session.jsonl") is None
    db.set_offset("C:/x/session.jsonl", 42, 1000)
    assert db.get_offset("C:/x/session.jsonl") == (42, 1000)
    db.set_offset("C:/x/session.jsonl", None, 0)                   # e.g. truncated file, no inode
    assert db.get_offset("C:/x/session.jsonl") == (None, 0)


def test_counters(db):
    assert db.get_counter(DROPPED_NON_AI) == 0
    db.bump_counter(DROPPED_NON_AI)
    db.bump_counter(DROPPED_NON_AI, 4)
    assert db.get_counter(DROPPED_NON_AI) == 5


# ---- reset -------------------------------------------------------------------

def test_reset_clears_everything_except_offsets(db):
    _, _, a = seed(db)
    db.save_remediation(make_remediation(a.id))
    db.add_agent_activity("python3|openai", act(1))
    db.add_llm_call(LlmCall(id=new_id(), ts=ts(), alert_id=a.id, bytes=1, status="sent", prompt_sha256="c" * 64))
    db.set_provider_override("openai", True)
    db.bump_counter(DROPPED_NON_AI, 3)
    db.set_offset("f.jsonl", 1, 99)
    db.reset()
    assert db.count_events() == 0 and db.count_findings() == 0 and db.count_open_alerts() == 0
    assert db.list_llm_calls().total == 0 and db.list_agent_activity("python3|openai") == []
    assert db.get_provider_overrides() == {} and db.get_counter(DROPPED_NON_AI) == 0
    assert db.count_remediations_by_source() == {}
    assert db.get_offset("f.jsonl") == (1, 99)                     # kept on purpose
    seed(db)                                                       # and the db is usable again
    assert db.count_events() == 1


# ---- transactions and threads ------------------------------------------------

def test_transaction_commits_together(db):
    with db.transaction():
        db.bump_counter("a")
        db.bump_counter("b")
    assert (db.get_counter("a"), db.get_counter("b")) == (1, 1)


def test_transaction_rolls_back_on_error(db):
    with pytest.raises(RuntimeError):
        with db.transaction():
            db.bump_counter("a")
            raise RuntimeError("boom")
    assert db.get_counter("a") == 0


def test_nested_transactions_join_the_outer_one(db):
    with pytest.raises(RuntimeError):
        with db.transaction():
            db.bump_counter("outer")
            with db.transaction():
                db.bump_counter("inner")
            raise RuntimeError("late failure")
    assert (db.get_counter("outer"), db.get_counter("inner")) == (0, 0)   # both undone
    with db.transaction():
        with db.transaction():
            db.bump_counter("inner")
    assert db.get_counter("inner") == 1


def test_data_survives_closing_and_reopening(tmp_path):
    path = tmp_path / "shadow.db"
    with Database(path) as first:
        _, _, a = seed(first)
    with Database(path) as second:
        assert second.get_alert(a.id) == a


def test_concurrent_writers_do_not_lose_rows(db):
    errors = []

    def worker(offset):
        try:
            for n in range(25):
                db.insert_event(make_event(offset + n), make_match())
        except Exception as exc:                   # noqa: BLE001 - collected and asserted below
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i * 100,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert db.count_events() == 200

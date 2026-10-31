import asyncio
import json
import socket
import threading
import time

import httpx
import pytest

from shadowlens.api.app import create_app
from shadowlens.api.sse import EVENT_TYPES, EventBus, format_message
from shadowlens.config import Config
from shadowlens.core.rule_titles import RULE_TITLES, title_for
from shadowlens.models import RULE_IDS, Band, RiskBlock
from shadowlens import __main__ as entry


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ---- message format ----------------------------------------------------------

def test_message_format_for_dicts_and_models():
    assert format_message("reset", {}) == "event: reset\ndata: {}\n\n"
    assert format_message("scenario.progress", {"name": "quick_leak", "played": 1, "total": 12}) == (
        'event: scenario.progress\ndata: {"name":"quick_leak","played":1,"total":12}\n\n')
    risk = RiskBlock(org_risk=52, band=Band.HIGH, compliance_score=48)
    message = format_message("score.update", risk)
    assert message.startswith("event: score.update\ndata: ") and message.endswith("\n\n")
    assert json.loads(message.split("data: ", 1)[1]) == {"org_risk": 52, "band": "high", "compliance_score": 48}


def test_event_types_are_the_sot_list():
    assert EVENT_TYPES == {"event.new", "finding.new", "alert.new", "score.update",
                           "remediation.update", "scenario.progress", "reset"}


def test_unknown_event_types_are_refused():
    with pytest.raises(ValueError):
        EventBus().publish("made.up", {})


# ---- the bus -----------------------------------------------------------------

def test_published_messages_reach_every_subscriber_in_order():
    async def scenario():
        bus = EventBus()
        a, b = bus.subscribe(), bus.subscribe()
        assert bus.subscriber_count == 2
        await asyncio.to_thread(lambda: [bus.publish("reset", {}), bus.publish("scenario.progress", {"n": 2})])
        got = [[await asyncio.wait_for(q.get(), 2) for _ in range(2)] for q in (a, b)]
        assert got[0] == got[1] == ["event: reset\ndata: {}\n\n", 'event: scenario.progress\ndata: {"n":2}\n\n']
        bus.unsubscribe(a)
        assert bus.subscriber_count == 1
    asyncio.run(scenario())


def test_publishing_with_nobody_listening_is_fine():
    EventBus().publish("reset", {})


def test_a_slow_client_loses_its_oldest_messages_not_the_newest():
    async def scenario():
        bus = EventBus(queue_size=3)
        queue = bus.subscribe()
        await asyncio.to_thread(lambda: [bus.publish("scenario.progress", {"n": i}) for i in range(8)])
        await asyncio.sleep(0.05)
        seen = []
        while not queue.empty():
            seen.append(json.loads(queue.get_nowait().split("data: ")[1])["n"])
        assert seen == [5, 6, 7]
    asyncio.run(scenario())


def test_stream_sends_a_greeting_messages_and_pings():
    async def scenario():
        bus = EventBus(ping_s=0.05)
        stream = bus.stream()
        assert await stream.__anext__() == ": connected\n\n"
        assert await stream.__anext__() == ": ping\n\n"                       # nothing published: keep-alive
        await asyncio.to_thread(bus.publish, "reset", {})
        message = await stream.__anext__()
        while message == ": ping\n\n":
            message = await stream.__anext__()
        assert message == "event: reset\ndata: {}\n\n"
        await stream.aclose()
        assert bus.subscriber_count == 0                                      # leaving cleans up
    asyncio.run(scenario())


def test_stream_ends_when_the_client_disconnects():
    async def scenario():
        bus = EventBus(ping_s=0.05)

        async def gone():
            return True

        parts = [part async for part in bus.stream(is_disconnected=gone)]
        assert parts == [": connected\n\n"] and bus.subscriber_count == 0
    asyncio.run(scenario())


def test_close_ends_every_stream_and_later_streams_end_at_once():
    async def scenario():
        bus = EventBus(ping_s=5)
        stream = bus.stream()
        await stream.__anext__()
        closer = asyncio.get_running_loop().run_in_executor(None, bus.close)
        assert [part async for part in stream] == []                          # ended without waiting 5 s
        await closer
        assert [part async for part in bus.stream()] == [": connected\n\n"]   # a late client gets nothing more
    asyncio.run(scenario())


# ---- the real HTTP route -----------------------------------------------------

def start(tmp_path, bus):
    port = free_port()
    config = Config.load(env={"SHADOWLENS_PORT": str(port), "SHADOWLENS_DB_PATH": str(tmp_path / "s.db"),
                              "SHADOWLENS_RESOLVE": "false"}, base_dir=tmp_path, use_dotenv=False)
    app = create_app(config, bus=bus, ui_dir=tmp_path)
    server, thread = entry.start_server(app, config)
    assert entry.wait_until_healthy(config.server_url, thread)
    return config, app, server, thread


def test_the_stream_route_delivers_live_messages(tmp_path):
    bus = EventBus(ping_s=0.1)
    config, app, server, thread = start(tmp_path, bus)
    lines = []
    ready = threading.Event()

    def reader():
        with httpx.stream("GET", f"{config.server_url}/api/stream", timeout=10) as response:
            lines.append(("status", response.status_code, response.headers["content-type"],
                          response.headers.get("cache-control")))
            for line in response.iter_lines():
                lines.append(line)
                if line == ": connected":
                    ready.set()
                if line.startswith("data:"):
                    return

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    try:
        assert ready.wait(5)
        bus.publish("scenario.progress", {"name": "quick_leak", "played": 3, "total": 12})
        t.join(5)
        assert not t.is_alive()
        assert lines[0] == ("status", 200, "text/event-stream; charset=utf-8", "no-cache")
        assert "event: scenario.progress" in lines
        assert 'data: {"name":"quick_leak","played":3,"total":12}' in lines
    finally:
        entry.stop_server(server, thread)


def test_an_open_dashboard_tab_does_not_block_shutdown(tmp_path):
    """A connected live stream must not make Ctrl+C wait forever."""
    bus = EventBus(ping_s=30)
    config, app, server, thread = start(tmp_path, bus)
    connected = threading.Event()

    def hold_open():
        try:
            with httpx.stream("GET", f"{config.server_url}/api/stream", timeout=30) as response:
                for line in response.iter_lines():
                    if line == ": connected":
                        connected.set()
        except httpx.HTTPError:
            pass

    threading.Thread(target=hold_open, daemon=True).start()
    assert connected.wait(5)
    started = time.monotonic()
    entry.stop_server(server, thread)
    assert not thread.is_alive() and time.monotonic() - started < 8


def test_stopping_with_the_bus_closes_open_streams_quickly_and_quietly(tmp_path, caplog):
    """With the bus passed in, an open dashboard tab ends at once instead of being cancelled after the grace period."""
    bus = EventBus(ping_s=30)
    config, app, server, thread = start(tmp_path, bus)
    connected, ended = threading.Event(), threading.Event()

    def hold_open():
        try:
            with httpx.stream("GET", f"{config.server_url}/api/stream", timeout=30) as response:
                for line in response.iter_lines():
                    if line == ": connected":
                        connected.set()
        except httpx.HTTPError:
            pass
        ended.set()

    threading.Thread(target=hold_open, daemon=True).start()
    assert connected.wait(5)
    started = time.monotonic()
    with caplog.at_level("ERROR"):
        entry.stop_server(server, thread, bus)
    assert not thread.is_alive() and ended.wait(2)
    assert time.monotonic() - started < 1.5                                   # well inside the 2 s grace period
    assert not [r for r in caplog.records if "timeout graceful shutdown" in r.getMessage()]


# ---- titles ------------------------------------------------------------------

def test_every_rule_has_a_real_title():
    assert set(RULE_TITLES) == set(RULE_IDS) and len(RULE_TITLES) == 37
    assert all(isinstance(t, str) and len(t) > 8 for t in RULE_TITLES.values())
    assert len(set(RULE_TITLES.values())) == 37                              # no two rules read the same
    assert title_for("SEC_OPENAI_KEY") == "OpenAI-style API key sent to an AI tool"
    assert title_for("SOMETHING_NEW") == "SOMETHING_NEW"

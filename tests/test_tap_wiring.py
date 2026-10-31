"""The Ollama tap, switched on through the sources API and read by the pipeline (SOT 7.2.2, AT-30, AT-32)."""

import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx
import pytest
from fastapi.testclient import TestClient

from shadowlens.api.app import create_app
from shadowlens.config import Config
from shadowlens.fakes import fake

OLLAMA_PORT = 11434                      # the provider rule for local models is keyed to this port (SOT 7.1)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class FakeOllama(BaseHTTPRequestHandler):
    seen: list[bytes] = []

    def do_POST(self):
        FakeOllama.seen.append(self.rfile.read(int(self.headers.get("content-length", 0))))
        body = json.dumps({"message": {"content": "hi"}}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def upstream():
    FakeOllama.seen = []
    try:
        server = HTTPServer(("127.0.0.1", OLLAMA_PORT), FakeOllama)
    except OSError:
        pytest.skip("port 11434 is in use on this machine")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


@pytest.fixture
def client(tmp_path):
    config = Config.load(env={"SHADOWLENS_RESOLVE": "false", "SHADOWLENS_PROXY_PORT": str(free_port())},
                         base_dir=tmp_path, use_dotenv=False)
    with TestClient(create_app(config)) as c:
        c.config = config
        yield c


def row(client):
    return next(r for r in client.get("/api/sources").json()["items"] if r["id"] == "ollama_proxy")


def wait_for(check, seconds=8.0):
    end = time.time() + seconds
    while time.time() < end:
        if check():
            return True
        time.sleep(0.05)
    return False


def test_the_tap_is_off_by_default_and_supported(client):
    r = row(client)
    assert (r["kind"], r["enabled"], r["supported"], r["found"], r["error"]) == ("proxy", False, True, True, None)
    assert r["paths"] == [f"127.0.0.1:{client.config.proxy_port} → 127.0.0.1:11434"]
    proxy = client.get("/api/capture/status").json()["proxy"]
    assert proxy["enabled"] is False and proxy["listen_port"] == client.config.proxy_port


def test_a_request_through_the_tap_is_forwarded_once_and_found_once(client, upstream):
    key = fake("openai_key", 31)
    assert client.put("/api/sources/ollama_proxy", json={"enabled": True}).json()["enabled"] is True
    tap = f"http://127.0.0.1:{client.config.proxy_port}/api/chat"
    body = json.dumps({"model": "llama3", "messages": [{"role": "user", "content": f"my key is {key}"}]})
    for _ in range(2):                                                            # the same request twice
        reply = httpx.post(tap, content=body, headers={"content-type": "application/json"})
        assert reply.status_code == 200 and reply.json() == {"message": {"content": "hi"}}
    assert FakeOllama.seen == [body.encode()] * 2                               # forwarded byte for byte
    assert wait_for(lambda: client.get("/api/findings?rule_id=SEC_OPENAI_KEY").json()["total"] >= 1)
    findings = client.get("/api/findings?rule_id=SEC_OPENAI_KEY").json()
    assert findings["total"] == 1                                                  # one leak, one finding
    assert findings["items"][0]["tool_id"].endswith("|ollama")
    events = client.get("/api/events").json()["items"]
    assert {e["source"] for e in events} == {"proxy"} and {e["visibility"] for e in events} == {"full"}
    assert all(e["provider_id"] == "ollama" and e["host"] == "localhost:11434" for e in events)
    proxy = client.get("/api/capture/status").json()["proxy"]
    assert proxy["enabled"] is True and proxy["requests_ingested"] == 2 and proxy["upstream_ok"] is True
    assert row(client)["lines_ingested"] == 2 and row(client)["last_event_at"]
    assert key not in json.dumps(client.get("/api/findings").json()) + json.dumps(events)


def test_switching_it_off_stops_listening_and_frees_the_port(client, upstream):
    client.put("/api/sources/ollama_proxy", json={"enabled": True})
    assert client.put("/api/sources/ollama_proxy", json={"enabled": False}).json()["enabled"] is False
    with socket.socket() as s:
        s.bind(("127.0.0.1", client.config.proxy_port))                           # free again
    assert client.get("/api/capture/status").json()["proxy"]["enabled"] is False
    assert client.put("/api/sources/ollama_proxy", json={"enabled": True}).json()["enabled"] is True   # and back on
    client.put("/api/sources/ollama_proxy", json={"enabled": False})


def test_a_busy_port_is_reported_on_the_row_and_nothing_crashes(client):
    with socket.socket() as busy:
        busy.bind(("127.0.0.1", client.config.proxy_port))
        busy.listen()
        r = client.put("/api/sources/ollama_proxy", json={"enabled": True}).json()
        assert r["enabled"] is False and "busy" in r["error"]
        assert client.get("/api/capture/status").json()["proxy"]["enabled"] is False
        assert client.get("/api/sources").status_code == 200


def test_with_the_server_down_the_client_gets_502_and_the_request_is_still_recorded(client):
    client.put("/api/sources/ollama_proxy", json={"enabled": True})
    key = fake("openai_key", 32)
    reply = httpx.post(f"http://127.0.0.1:{client.config.proxy_port}/api/chat",
                       content=json.dumps({"model": "m", "messages": [{"role": "user", "content": key}]}))
    assert reply.status_code == 502
    assert wait_for(lambda: client.get("/api/events").json()["total"] >= 1)
    client.put("/api/sources/ollama_proxy", json={"enabled": False})


def test_the_environment_switch_turns_it_on_at_startup(tmp_path, upstream):
    port = free_port()
    config = Config.load(env={"SHADOWLENS_RESOLVE": "false", "SHADOWLENS_PROXY_ENABLED": "true",
                              "SHADOWLENS_PROXY_PORT": str(port)}, base_dir=tmp_path, use_dotenv=False)
    with TestClient(create_app(config)) as c:
        assert row(c)["enabled"] is True and c.get("/api/capture/status").json()["proxy"]["enabled"] is True
    with socket.socket() as s:
        s.bind(("127.0.0.1", port))                                                # stopping the app freed the port

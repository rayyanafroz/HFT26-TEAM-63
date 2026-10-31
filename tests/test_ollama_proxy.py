"""AT-31: the tap forwards unchanged, streaming stays streaming, and a dead upstream still records."""

import gzip
import http.client
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from scenarios import agent_sim
from scenarios.mock_ollama import MockOllamaServer
from shadowlens.analysis import analyze
from shadowlens.config import Config
from shadowlens.core.pipeline import Pipeline
from shadowlens.db import Database
from shadowlens.fakes import fake
from shadowlens.ingest.ollama_proxy import OllamaTap, build_event
from shadowlens.providers.catalog import Catalog

HOST = "127.0.0.1"
BINARY_REPLY = bytes(range(256)) * 40
GZIP_REPLY = gzip.compress(b"compressed reply, which must arrive still compressed")


def free_port():
    with socket.socket() as probe:
        probe.bind((HOST, 0))
        return probe.getsockname()[1]


class Upstream(ThreadingHTTPServer):
    allow_reuse_address = False
    daemon_threads = True

    def __init__(self):
        super().__init__((HOST, 0), UpstreamHandler)
        self.requests = []
        self.first_chunk_received = threading.Event()


class UpstreamHandler(BaseHTTPRequestHandler):
    """Records what arrived, and answers in ways that are easy to damage."""

    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        pass

    def _handle(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        self.server.requests.append({
            "method": self.command, "path": self.path, "body": body,
            "headers": {key.lower(): value for key, value in self.headers.items()},
        })
        if self.path.startswith("/binary"):
            self._reply(200, BINARY_REPLY, "application/octet-stream")
        elif self.path.startswith("/gzip"):
            self._reply(200, GZIP_REPLY, "text/plain", {"Content-Encoding": "gzip"})
        elif self.path.startswith("/teapot"):
            self._reply(418, b'{"error":"teapot"}', "application/json", {"X-Custom": "kept"})
        elif self.path.startswith("/slow"):
            self._slow_stream()
        elif self.path.startswith("/dies"):
            self.send_response(200)
            self.send_header("Content-Length", "1000")
            self.end_headers()
            self.wfile.write(b"partial")
            self.wfile.flush()
            self.close_connection = True
        else:
            self._reply(200, b'{"ok":true}', "application/json")

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = _handle

    def _reply(self, status, data, content_type, extra=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _slow_stream(self):
        """The second chunk is held back until the client confirms it got the first."""
        self.send_response(200)
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        for data, wait in ((b"first\n", True), (b"second\n", False)):
            self.wfile.write(f"{len(data):x}\r\n".encode() + data + b"\r\n")
            self.wfile.flush()
            if wait:
                self.server.first_chunk_received.wait(timeout=10)
        self.wfile.write(b"0\r\n\r\n")


@pytest.fixture
def upstream():
    server = Upstream()
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server
    server.first_chunk_received.set()
    server.shutdown()
    server.server_close()


@pytest.fixture
def events():
    return []


@pytest.fixture
def tap(upstream, events):
    instance = OllamaTap(events.append, free_port(), f"{HOST}:{upstream.server_address[1]}")
    assert instance.start(), instance.error
    yield instance
    instance.stop()


def call(port, method, target, body=None, headers=None):
    connection = http.client.HTTPConnection(HOST, port, timeout=15)
    connection.request(method, target, body=body, headers=headers or {})
    response = connection.getresponse()
    data = response.read()
    connection.close()
    return response, data


# ---- forwarding unchanged -----------------------------------------------------------------

def test_request_arrives_unchanged(tap, upstream):
    body = '{"model":"m",  "weird spacing":  true, "text":"café"}'.encode("utf-8")
    call(tap.listen_port, "POST", "/api/chat?a=1&b=%20x", body, {"Content-Type": "application/json", "X-Custom": "v"})
    seen = upstream.requests[0]
    assert seen["method"] == "POST" and seen["path"] == "/api/chat?a=1&b=%20x" and seen["body"] == body
    assert seen["headers"]["content-type"] == "application/json" and seen["headers"]["x-custom"] == "v"


def test_host_header_names_the_upstream(tap, upstream):
    call(tap.listen_port, "POST", "/x", b"{}")
    assert upstream.requests[0]["headers"]["host"] == f"{HOST}:{upstream.server_address[1]}"


def test_reply_is_byte_identical_to_asking_directly(tap, upstream):
    direct_response, direct = call(upstream.server_address[1], "GET", "/binary")
    tapped_response, tapped = call(tap.listen_port, "GET", "/binary")
    assert tapped == direct == BINARY_REPLY and tapped_response.status == direct_response.status
    assert tapped_response.getheader("Content-Type") == "application/octet-stream"
    assert tapped_response.getheader("Content-Length") == str(len(BINARY_REPLY))


def test_compressed_reply_is_not_decompressed(tap):
    response, data = call(tap.listen_port, "GET", "/gzip", headers={"Accept-Encoding": "gzip"})
    assert data == GZIP_REPLY and response.getheader("Content-Encoding") == "gzip"


def test_error_status_and_custom_headers_pass_through(tap):
    response, data = call(tap.listen_port, "POST", "/teapot", b"{}")
    assert response.status == 418 and data == b'{"error":"teapot"}' and response.getheader("X-Custom") == "kept"


def test_tap_adds_no_headers_of_its_own(tap):
    response, _ = call(tap.listen_port, "POST", "/x", b"{}")
    # The upstream's own Server header goes through; uvicorn must not add a second one.
    assert len(response.headers.get_all("Server") or []) <= 1
    assert "uvicorn" not in (response.getheader("Server") or "")


@pytest.mark.parametrize("method", ["GET", "PUT", "DELETE"])
def test_any_method_is_forwarded(tap, upstream, method):
    call(tap.listen_port, method, "/any/path")
    assert upstream.requests[0]["method"] == method and upstream.requests[0]["path"] == "/any/path"


def test_body_over_the_analysis_limit_is_still_forwarded_whole(upstream, events):
    instance = OllamaTap(events.append, free_port(), f"{HOST}:{upstream.server_address[1]}", max_body_bytes=10)
    assert instance.start()
    try:
        body = b"x" * 5000
        call(instance.listen_port, "POST", "/x", body)
    finally:
        instance.stop()
    assert upstream.requests[0]["body"] == body
    assert events[0].body_text == "x" * 5 + "\n" + "x" * 5       # its start and its end
    assert events[0].body_truncated and events[0].body_bytes == 5000


def test_one_client_connection_can_send_several_requests(tap, upstream):
    connection = http.client.HTTPConnection(HOST, tap.listen_port, timeout=10)
    for _ in range(3):
        connection.request("POST", "/x", b"{}")
        connection.getresponse().read()
    connection.close()
    assert len(upstream.requests) == 3


# ---- streaming ------------------------------------------------------------------------------

def test_streaming_reply_stays_streaming(tap, upstream):
    """The upstream will not send its second chunk until the client has the first."""
    connection = http.client.HTTPConnection(HOST, tap.listen_port, timeout=10)
    connection.request("POST", "/slow", b"{}")
    response = connection.getresponse()
    assert response.status == 200
    assert response.readline() == b"first\n"          # a buffering tap would time out here
    upstream.first_chunk_received.set()
    assert response.readline() == b"second\n"
    assert response.read() == b""
    connection.close()


def test_real_mock_ollama_stream_matches_direct(events):
    mock = MockOllamaServer(0, None)
    threading.Thread(target=mock.serve_forever, daemon=True).start()
    instance = OllamaTap(events.append, free_port(), f"{HOST}:{mock.server_address[1]}")
    assert instance.start()
    try:
        payload = json.dumps({"model": "m", "messages": []})
        _, direct = call(mock.server_address[1], "POST", "/api/chat", payload)
        _, tapped = call(instance.listen_port, "POST", "/api/chat", payload)
    finally:
        instance.stop()
        mock.shutdown()
        mock.server_close()

    def texts(raw):
        return [json.loads(line)["message"]["content"] for line in raw.decode().splitlines()]

    # Only created_at differs between two replies.
    assert texts(tapped) == texts(direct) and len(texts(tapped)) > 2


# ---- upstream trouble ------------------------------------------------------------------------

def test_dead_upstream_gives_502_and_still_records(events):
    instance = OllamaTap(events.append, free_port(), f"{HOST}:{free_port()}")
    assert instance.start()
    try:
        response, data = call(instance.listen_port, "POST", "/api/chat", b'{"model":"m"}')
        assert response.status == 502 and json.loads(data)["error"]
        assert instance.status()["upstream_ok"] is False
    finally:
        instance.stop()
    assert len(events) == 1 and events[0].body_text == '{"model":"m"}'


def test_upstream_dying_mid_reply_is_not_reported_as_complete(tap):
    connection = http.client.HTTPConnection(HOST, tap.listen_port, timeout=10)
    connection.request("GET", "/dies")
    response = connection.getresponse()
    with pytest.raises((http.client.IncompleteRead, ConnectionError)):
        response.read()
    connection.close()


def test_a_failing_pipeline_never_blocks_the_client(upstream):
    def broken(_event):
        raise RuntimeError("pipeline is down")

    instance = OllamaTap(broken, free_port(), f"{HOST}:{upstream.server_address[1]}")
    assert instance.start()
    try:
        response, data = call(instance.listen_port, "POST", "/x", b"{}")
    finally:
        instance.stop()
    assert response.status == 200 and data == b'{"ok":true}' and instance.app.requests_ingested == 0


# ---- the event ---------------------------------------------------------------------------------

def test_event_matches_the_sot(tap, events, upstream):
    port = upstream.server_address[1]
    call(tap.listen_port, "POST", "/api/chat?x=1", b'{"model":"m"}', {"Authorization": "Bearer a", "Cookie": "c=1"})
    event = events[0]
    assert event.source == "proxy" and event.host_basis == "host_header"
    assert event.host == f"localhost:{port}" and event.dst_ip == HOST and event.dst_port == port
    assert event.path == "/api/chat" and event.query == "x=1" and event.visibility == "full"
    assert event.body_bytes == 13 and len(event.body_sha256) == 64 and event.bytes_out == 13
    assert "cookie" not in event.headers and event.headers["authorization"] == "Bearer a"


def test_event_names_the_client_process(tap, events):
    import os
    call(tap.listen_port, "POST", "/x", b"{}")
    assert events[0].pid == os.getpid() and events[0].process.startswith("python")


def test_request_without_a_body_is_metadata_only(tap, events):
    call(tap.listen_port, "GET", "/api/tags")
    assert events[0].visibility == "metadata_only" and events[0].body_sha256 is None


def test_bad_utf8_body_does_not_break_the_event():
    event = build_event("POST", "/x", None, {}, b"\xff\xfe ok", f"{HOST}:11434", "p", None, 100)
    assert "ok" in event.body_text


def test_a_truncated_multibyte_character_is_harmless():
    event = build_event("POST", "/x", None, {}, "é".encode("utf-8") * 10, f"{HOST}:11434", "p", None, 5)
    assert event.body_truncated and event.body_text == "é\né"          # 5 bytes: 2 from each end, never half a character


# ---- starting and stopping ------------------------------------------------------------------------

def test_status_is_the_capture_status_block(tap, upstream):
    call(tap.listen_port, "POST", "/x", b"{}")
    assert tap.status() == {
        "enabled": True, "listen_port": tap.listen_port, "upstream": f"{HOST}:{upstream.server_address[1]}",
        "upstream_ok": True, "requests_ingested": 1, "error": None,
    }


def test_busy_port_is_reported_and_never_raises(events):
    with socket.socket() as holder:
        holder.bind((HOST, 0))
        holder.listen()
        instance = OllamaTap(events.append, holder.getsockname()[1], f"{HOST}:1")
        assert instance.start() is False
    assert "busy" in instance.error and instance.running is False


def test_stop_frees_the_port_and_it_can_start_again(upstream, events):
    instance = OllamaTap(events.append, free_port(), f"{HOST}:{upstream.server_address[1]}")
    assert instance.start()
    assert call(instance.listen_port, "POST", "/x", b"{}")[0].status == 200
    instance.stop()
    assert instance.running is False and instance.status()["enabled"] is False
    assert instance.start(), instance.error
    assert call(instance.listen_port, "POST", "/x", b"{}")[0].status == 200
    instance.stop()


def test_start_twice_is_harmless(tap):
    assert tap.start() is True


def test_listens_on_loopback_only(tap):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        try:
            probe.connect(("192.0.2.1", 1))
            own_ip = probe.getsockname()[0]
        except OSError:
            pytest.skip("no network address to test from")
    if own_ip.startswith("127."):
        pytest.skip("no network address to test from")
    with socket.socket() as other:
        other.settimeout(0.5)
        assert other.connect_ex((own_ip, tap.listen_port)) != 0


def test_from_config_uses_the_settings(tmp_path, events):
    config = Config.load(env={"SHADOWLENS_PROXY_PORT": "11999", "SHADOWLENS_PROXY_UPSTREAM": "127.0.0.1:11500",
                              "SHADOWLENS_MAX_BODY_BYTES": "99"}, base_dir=tmp_path, use_dotenv=False)
    instance = OllamaTap.from_config(config, events.append)
    assert (instance.listen_port, instance.upstream, instance.app.max_body_bytes) == (11999, "127.0.0.1:11500", 99)


# ---- AT-32: mock server + tap + agent_sim, end to end ------------------------------------------------

def test_at32_planted_key_gives_exactly_one_finding_through_the_real_pipeline(tmp_path):
    """mock_ollama --no-log, so the tap is the only path that sees the request."""
    try:
        mock = MockOllamaServer(11434, None)   # the real port, because that is what names Ollama
    except OSError:
        pytest.skip("port 11434 is in use (real Ollama?)")
    threading.Thread(target=mock.serve_forever, daemon=True).start()
    config = Config.load(env={"SHADOWLENS_RESOLVE": "false"}, base_dir=tmp_path, use_dotenv=False)
    database = Database(tmp_path / "shadow.db")
    pipeline = Pipeline(config, database, Catalog.load(), analyze=analyze)
    instance = OllamaTap(lambda event: pipeline.ingest([event], source="proxy"), free_port(), f"{HOST}:11434")
    assert instance.start()
    try:
        assert agent_sim.run(instance.listen_port, count=5, interval=0) == 5
    finally:
        instance.stop()
        mock.shutdown()
        mock.server_close()
    try:
        assert database.count_events() == 5
        found = database.list_findings(limit=100).items
        assert sorted(f.rule_id for f in found) == ["POLICY_LOCAL_LLM", "SEC_OPENAI_KEY"]
        assert found[0].tool_id.endswith("|ollama")
        assert fake("openai_key") not in json.dumps([f.model_dump(mode="json") for f in found])
    finally:
        database.close()

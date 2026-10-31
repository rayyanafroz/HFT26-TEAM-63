"""A tiny stand-in for a local Ollama server (SOT 8.3).

    python -m scenarios.mock_ollama [--port 11434] [--no-log]

Answers ``/api/chat``, ``/api/generate`` and ``/api/tags`` with a canned reply. Unless
``--no-log`` is given, each request is appended to ``data/live/ollama.jsonl`` in the HTTP log
format (SOT 6.3), which is where the live log tail reads it from.

That file holds request bodies as sent, so it is for fake demo traffic only: do not point a
real client with real prompts at this server.
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from shadowlens.config import LOOPBACK_HOST, Config
from shadowlens.ingest.ollama_proxy import resolve_client
from shadowlens.models import utc_now_iso

DEFAULT_PORT = 11434
LOG_FILE_NAME = "ollama.jsonl"
MAX_BODY_BYTES = 20 * 1024 * 1024
CANNED_REPLY = "This is a canned reply from the ShadowLens mock server."

_KEPT_HEADERS = ("content-type", "user-agent", "x-shadow-client")


def build_log_line(method: str, path: str, port: int, body: str | None, body_size: int,
                   headers: dict[str, str], process: str, pid: int | None) -> dict[str, Any]:
    return {
        "ts": utc_now_iso(),
        "host": "localhost",
        "method": method,
        "path": path,
        "headers": {name: headers[name] for name in _KEPT_HEADERS if name in headers},
        "body": body,
        "dst_ip": LOOPBACK_HOST,
        "dst_port": port,
        "tls": False,
        "process_name": process,
        "pid": pid,
        "source": "live_log",
        "bytes_out": body_size,
    }


def _reply_parts(path: str, model: str, text: str, done: bool) -> dict[str, Any]:
    part: dict[str, Any] = {"model": model, "created_at": utc_now_iso(), "done": done}
    if path == "/api/generate":
        part["response"] = text
    else:
        part["message"] = {"role": "assistant", "content": text}
    return part


class MockOllamaHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # keeps the connection open, so the live scan can see it

    def log_message(self, format: str, *args: Any) -> None:
        """Silent: nothing about a request is ever printed."""

    def _read_body(self) -> bytes | None:
        """The request body, or ``None`` if it is over the size limit."""
        try:
            length = max(0, int(self.headers.get("Content-Length", 0)))
        except ValueError:
            length = 0
        if length > MAX_BODY_BYTES:
            return None
        return self.rfile.read(length) if length else b""

    def _record(self, raw: bytes) -> None:
        log_path: Path | None = self.server.log_path  # type: ignore[attr-defined]
        if log_path is None:
            return
        headers = {name.lower(): value for name, value in self.headers.items()}
        process, pid = resolve_client(self.client_address[1], headers.get("x-shadow-client"))
        line = build_log_line(self.command, self.path.split("?", 1)[0], self.server.server_address[1],
                              raw.decode("utf-8", errors="replace") or None, len(raw), headers, process, pid)
        with self.server.log_lock:  # type: ignore[attr-defined]
            with open(log_path, "a", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(line) + "\n")

    def _send_json(self, status: int, payload: dict[str, Any], close: bool = False) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        if close:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        self.wfile.write(data)

    def _send_stream(self, path: str, model: str) -> None:
        """Newline-delimited JSON, sent in chunks, the way Ollama streams by default."""
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        words = CANNED_REPLY.split(" ")
        for index, word in enumerate(words):
            text = word if index == len(words) - 1 else word + " "
            self._write_chunk(_reply_parts(path, model, text, done=False))
        self._write_chunk(_reply_parts(path, model, "", done=True))
        self.wfile.write(b"0\r\n\r\n")

    def _write_chunk(self, part: dict[str, Any]) -> None:
        data = json.dumps(part).encode("utf-8") + b"\n"
        self.wfile.write(f"{len(data):x}\r\n".encode("ascii") + data + b"\r\n")
        self.wfile.flush()

    def do_POST(self) -> None:
        raw = self._read_body()
        if raw is None:
            self._send_json(413, {"error": "body too large"}, close=True)
            return
        self._record(raw)
        path = self.path.split("?", 1)[0]
        if path not in ("/api/chat", "/api/generate"):
            self._send_json(404, {"error": "not found"})
            return
        try:
            request = json.loads(raw) if raw else {}
        except ValueError:
            request = {}
        request = request if isinstance(request, dict) else {}
        model = request.get("model") if isinstance(request.get("model"), str) else "mock"
        if request.get("stream", True) is False:
            self._send_json(200, _reply_parts(path, model, CANNED_REPLY, done=True))
        else:
            self._send_stream(path, model)

    def do_GET(self) -> None:
        self._record(b"")
        if self.path.split("?", 1)[0] == "/api/tags":
            self._send_json(200, {"models": [{"name": "mock:latest", "model": "mock:latest"}]})
        else:
            self._send_json(404, {"error": "not found"})


class MockOllamaServer(ThreadingHTTPServer):
    # On Windows, address reuse would let a second program share the port (SOT 1.2).
    allow_reuse_address = False
    daemon_threads = True

    def __init__(self, port: int, log_path: Path | None):
        super().__init__((LOOPBACK_HOST, port), MockOllamaHandler)
        self.log_path = log_path
        self.log_lock = threading.Lock()


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description="A tiny stand-in for a local Ollama server.")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--no-log", action="store_true", help="write nothing to the live log")
    args = parser.parse_args(argv)

    log_path = None
    if not args.no_log:
        config = Config.load()
        config.live_dir.mkdir(parents=True, exist_ok=True)
        log_path = config.live_dir / LOG_FILE_NAME
    try:
        server = MockOllamaServer(args.port, log_path)
    except OSError:
        print(f"Port {args.port} is busy (real Ollama?). Try --port 11435 for both helpers.")
        return 1
    where = f"logging to {log_path}" if log_path else "not logging"
    print(f"mock_ollama on http://{LOOPBACK_HOST}:{args.port}, {where}. Ctrl+C stops it.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

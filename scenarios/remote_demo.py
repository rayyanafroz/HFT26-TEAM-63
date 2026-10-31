"""Two laptops for the live catch (W5): a Claude Code session on one, ShadowLens on the other.

ShadowLens reads what a tool writes on the machine it runs on. This demo helper carries a transcript
from a second laptop to the one running ShadowLens. It is a stand-in for running ShadowLens on that
machine, and the demo says so. Nothing here is a product feature.

    # laptop with ShadowLens (the server is already running on 127.0.0.1:8787)
    python -m scenarios.remote_demo relay

    # laptop with Claude Code (this file alone is enough; it needs only the standard library)
    python scenarios/remote_demo.py forward --to http://<address the relay printed>:8800 --token <token>

The forwarder is read-only. It starts at the end of each transcript, so only what is typed after it
starts is sent, and it sends the lines unchanged. The relay is the only part that listens on the
network, it needs the token, and it hands the lines to ShadowLens on 127.0.0.1 (the API itself stays
local). The relay keeps the same parts of a line that SOT 7.2.1 describes: what the user typed, tool
results, and the agent's actions. The agent's prose is dropped.
"""

from __future__ import annotations

import argparse
import hmac
import json
import os
import secrets
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Iterable

DEFAULT_RELAY_PORT = 8800
DEFAULT_SERVER = "http://127.0.0.1:8787"
DEFAULT_TRANSCRIPTS = "~/.claude/projects"
POLL_S = 0.5
DISCOVER_S = 2.0
MAX_AGE_S = 24 * 3600
MAX_FILES = 20
MAX_BATCH_BYTES = 5 * 1024 * 1024
MAX_LINE_BYTES = 4 * 1024 * 1024
HOST = "api.anthropic.com"
PROCESS = "claude-code"


# -- relay side: a transcript line becomes an HTTP-log line (SOT 6.3, 7.2.1) -----------------------

def _kept_content(role: str, content: Any) -> Any:
    """What of a message is inspected. None when nothing is."""
    if role == "user":
        if isinstance(content, str):
            return content if content.strip() else None
        if isinstance(content, list):
            blocks = [b for b in content if isinstance(b, dict) and b.get("type") in ("text", "tool_result")]
            return blocks or None
        return None
    if role == "assistant":
        if isinstance(content, list):
            blocks = [b for b in content if isinstance(b, dict) and b.get("type") == "tool_use"]
            return blocks or None
    return None


def _timestamp(value: Any) -> str:
    if isinstance(value, str):
        try:
            datetime.fromisoformat(value.replace("Z", "+00:00"))
            return value
        except ValueError:
            pass
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def convert(line: str) -> dict[str, Any] | None:
    """One Claude Code transcript line as an HTTP-log record, or None when it holds nothing to inspect."""
    try:
        entry = json.loads(line)
    except ValueError:
        return None
    message = entry.get("message") if isinstance(entry, dict) else None
    if not isinstance(message, dict):
        return None
    role = message.get("role")
    kept = _kept_content(role, message.get("content"))
    if kept is None:
        return None
    model = message.get("model")
    body = {"model": model if isinstance(model, str) else "unknown", "messages": [{"role": role, "content": kept}]}
    return {"ts": _timestamp(entry.get("timestamp")), "host": HOST, "method": "POST", "path": "/v1/messages",
            "body": json.dumps(body), "process_name": PROCESS}


def convert_all(lines: Iterable[str]) -> tuple[list[dict[str, Any]], int]:
    """(records, lines that held nothing to inspect or were not JSON)."""
    records, dropped = [], 0
    for line in lines:
        record = convert(line) if isinstance(line, str) and len(line) <= MAX_LINE_BYTES else None
        if record is None:
            dropped += 1
        else:
            records.append(record)
    return records, dropped


class Relay:
    """Receives lines from the forwarder and gives them to ShadowLens on this machine."""

    def __init__(self, server: str, token: str, post: Callable[[str, str, str, bytes], Any] | None = None,
                 write: Callable[[str], None] = print):
        self.server = server.rstrip("/")
        self.token = token
        self.write = write
        self._post = post
        self.received = 0
        self.sent = 0
        self.failures = 0

    def post(self, name: str, data: bytes) -> Any:
        if self._post is None:
            from scenarios.demo import post_file  # the relay runs from the project; the forwarder does not
            self._post = post_file
        return self._post(self.server, "/api/ingest/log", name, data)

    def accepts(self, given: str | None) -> bool:
        return given is not None and hmac.compare_digest(given.encode(), self.token.encode())

    def handle(self, payload: Any) -> dict[str, Any]:
        """Convert a batch and hand it to ShadowLens. Raises on a server failure so the caller can say 502."""
        lines = payload.get("lines") if isinstance(payload, dict) else None
        if not isinstance(lines, list):
            raise ValueError("expected {\"lines\": [...]}")
        records, dropped = convert_all(lines)
        self.received += len(lines)
        result: dict[str, Any] = {"received": len(lines), "inspected": len(records), "dropped": dropped}
        if records:
            data = ("\n".join(json.dumps(r) for r in records) + "\n").encode("utf-8")
            summary = self.post("claude_code_remote.jsonl", data)
            self.sent += len(records)
            if isinstance(summary, dict):
                result["findings"] = summary.get("findings", summary.get("findings_created"))
        return result


def _handler(relay: Relay) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args: Any) -> None:  # the relay prints its own, content-free lines
            return

        def _reply(self, status: int, body: dict[str, Any]) -> None:
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:
            if self.path == "/health":
                self._reply(200, {"ok": True})
            else:
                self._reply(404, {"error": "not found"})

        def do_POST(self) -> None:
            if self.path != "/lines":
                return self._reply(404, {"error": "not found"})
            if not relay.accepts(self.headers.get("X-Demo-Token")):
                relay.failures += 1
                return self._reply(401, {"error": "wrong token"})
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                return self._reply(411, {"error": "Content-Length required"})
            if length < 0 or length > MAX_BATCH_BYTES:
                return self._reply(413, {"error": "batch too large"})
            raw = self.rfile.read(length)
            try:
                result = relay.handle(json.loads(raw.decode("utf-8")))
            except (ValueError, UnicodeDecodeError) as exc:
                return self._reply(400, {"error": str(exc)})
            except Exception as exc:  # ShadowLens not reachable or it refused: the forwarder keeps the lines
                relay.failures += 1
                relay.write(f"  ! could not give {length} bytes to ShadowLens ({type(exc).__name__})")
                return self._reply(502, {"error": "ShadowLens did not accept the lines"})
            if result["inspected"]:
                relay.write(f"  received {result['received']} line(s), {result['inspected']} inspected "
                            f"-> ShadowLens findings: {result.get('findings')}")
            self._reply(200, result)

    return Handler


def lan_addresses() -> list[str]:
    """This machine's addresses on the network, for telling the other laptop where to connect."""
    found: list[str] = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            address = info[4][0]
            if not address.startswith("127.") and address not in found:
                found.append(address)
    except OSError:
        pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("192.0.2.1", 9))  # a reserved address; UDP connect sends nothing
            address = probe.getsockname()[0]
            if address not in found and not address.startswith("127."):
                found.insert(0, address)
    except OSError:
        pass
    return found


def serve_relay(server: str, port: int, token: str, host: str = "0.0.0.0",
                write: Callable[[str], None] = print) -> ThreadingHTTPServer:
    relay = Relay(server, token, write=write)
    httpd = ThreadingHTTPServer((host, port), _handler(relay))
    httpd.relay = relay  # type: ignore[attr-defined]
    return httpd


# -- forwarder side: tail the transcripts on this machine ---------------------------------------

class Forwarder:
    """Sends lines appended to transcript files after it started. Read-only."""

    def __init__(self, url: str, token: str, directory: Path, write: Callable[[str], None] = print,
                 backfill: bool = False):
        self.url = url.rstrip("/")
        self.token = token
        self.directory = directory
        self.write = write
        self.backfill = backfill
        self._offsets: dict[Path, int] = {}
        self._pending: list[str] = []
        self._first_pass = True
        self.sent = 0

    def files(self, now: float | None = None) -> list[Path]:
        now = time.time() if now is None else now
        found: list[tuple[float, Path]] = []
        try:
            for path in self.directory.rglob("*.jsonl"):
                try:
                    modified = path.stat().st_mtime
                except OSError:
                    continue
                if now - modified <= MAX_AGE_S:
                    found.append((modified, path))
        except OSError:
            return []
        found.sort(reverse=True)
        return [path for _, path in found[:MAX_FILES]]

    def read_new(self, path: Path) -> list[str]:
        """Complete new lines of a file. A partial last line waits; a shorter file starts over."""
        try:
            size = path.stat().st_size
        except OSError:
            return []
        if path not in self._offsets:
            self._offsets[path] = 0 if (self.backfill or not self._first_pass) else size
        offset = self._offsets[path]
        if size < offset:
            offset = 0
        if size == offset:
            self._offsets[path] = offset
            return []
        try:
            with open(path, "rb") as handle:
                handle.seek(offset)
                chunk = handle.read(size - offset)
        except OSError:
            return []
        end = chunk.rfind(b"\n")
        if end < 0:
            self._offsets[path] = offset
            return []
        self._offsets[path] = offset + end + 1
        return [piece.decode("utf-8", errors="replace").rstrip("\r")
                for piece in chunk[:end].split(b"\n") if piece.strip()]

    def send(self, lines: list[str]) -> bool:
        data = json.dumps({"lines": lines}).encode("utf-8")
        request = urllib.request.Request(self.url + "/lines", data=data, method="POST",
                                         headers={"Content-Type": "application/json", "X-Demo-Token": self.token})
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status == 200
        except urllib.error.HTTPError as exc:
            self.write(f"  ! the relay answered HTTP {exc.code}" + (" (wrong token?)" if exc.code == 401 else ""))
        except (urllib.error.URLError, OSError) as exc:
            self.write(f"  ! cannot reach the relay at {self.url} ({type(exc).__name__}); will retry")
        return False

    def step(self) -> int:
        """One pass: read what is new, send it (and anything that failed before). Returns lines sent."""
        for path in self.files():
            self._pending.extend(self.read_new(path))
        self._first_pass = False
        if not self._pending:
            return 0
        batch, size = [], 0
        for line in self._pending:
            size += len(line) + 1
            if size > MAX_BATCH_BYTES and batch:
                break
            batch.append(line)
        if self.send(batch):
            del self._pending[:len(batch)]
            self.sent += len(batch)
            self.write(f"  sent {len(batch)} new line(s) to the relay")
            return len(batch)
        return 0

    def run(self, stop: threading.Event | None = None) -> None:
        stop = stop or threading.Event()
        self.step()  # remembers where every transcript ends now
        while not stop.wait(POLL_S):
            self.step()


def check_relay(url: str, timeout: float = 5.0) -> bool:
    try:
        with urllib.request.urlopen(url.rstrip("/") + "/health", timeout=timeout) as response:
            return response.status == 200
    except (urllib.error.URLError, OSError):
        return False


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
    parser = argparse.ArgumentParser(description="Carry a Claude Code transcript from one laptop to another (demo).")
    commands = parser.add_subparsers(dest="command", required=True)
    relay = commands.add_parser("relay", help="on the laptop that runs ShadowLens")
    relay.add_argument("--port", type=int, default=DEFAULT_RELAY_PORT)
    relay.add_argument("--server", default=os.environ.get("SHADOWLENS_URL", DEFAULT_SERVER), help="ShadowLens API")
    relay.add_argument("--token", default=None, help="default: a new random token")
    forward = commands.add_parser("forward", help="on the laptop that runs Claude Code")
    forward.add_argument("--to", required=True, help="the relay, e.g. http://192.168.1.20:8800")
    forward.add_argument("--token", required=True)
    forward.add_argument("--dir", default=DEFAULT_TRANSCRIPTS)
    forward.add_argument("--backfill", action="store_true", help="also send what is already in the transcripts")
    args = parser.parse_args(argv)

    if args.command == "relay":
        token = args.token or secrets.token_urlsafe(9)
        try:
            httpd = serve_relay(args.server, args.port, token)
        except OSError as exc:
            print(f"Cannot listen on port {args.port}: {exc}")
            return 1
        print("Relay is up. It is the only part of ShadowLens listening on the network.")
        for address in lan_addresses() or ["<this laptop's address>"]:
            print(f"  on the other laptop:  python remote_demo.py forward --to http://{address}:{args.port} --token {token}")
        print(f"  giving lines to ShadowLens at {args.server}   (Ctrl+C to stop)")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nstopped")
        return 0

    directory = Path(os.path.expanduser(args.dir))
    if not check_relay(args.to):
        print(f"Cannot reach the relay at {args.to}. Same Wi-Fi? Is the firewall asking about Python? Is the relay running?")
        return 1
    forwarder = Forwarder(args.to, args.token, directory, backfill=args.backfill)
    print(f"Forwarding new lines of transcripts under {directory} to {args.to} (read-only; Ctrl+C to stop)")
    try:
        forwarder.run()
    except KeyboardInterrupt:
        print("\nstopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

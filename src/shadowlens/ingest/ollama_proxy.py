"""Opt-in tap for local model traffic (SOT 7.2.2).

A tiny forwarder: clients point at ``127.0.0.1:11436``, every request and reply passes through
to Ollama unchanged, and a copy of the request goes to the pipeline as a ``NetEvent``. It never
blocks or edits. It is NOT passive, because it sits in the request path, which is why it is off
by default and labelled on the Coverage card.

Reading loopback packets on Windows would need Npcap and Administrator; this needs neither.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import socket
import threading
import time
from typing import Any, Awaitable, Callable

import httpx
import psutil
import uvicorn

from shadowlens.config import LOOPBACK_HOST
from shadowlens.ingest.http_log import keep_head_and_tail
from shadowlens.models import NetEvent, new_id, utc_now_iso

log = logging.getLogger("shadowlens.ollama_proxy")

OnEvent = Callable[[NetEvent], None]
Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]

# Never forwarded: they describe one connection, not the message (RFC 9110).
_HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection",
    "te", "trailer", "transfer-encoding", "upgrade",
})
_UPSTREAM_CHECK_TIMEOUT_S = 0.5
_START_TIMEOUT_S = 10.0
_STOP_TIMEOUT_S = 5.0


def resolve_client(client_port: int, header_name: str | None) -> tuple[str, int | None]:
    """Which program is on the other end: ``(process name, pid)``.

    Found from the client's source port. Falls back to the ``x-shadow-client`` header, then
    ``unknown``, because psutil cannot always see other programs' connections on Windows.
    """
    try:
        for connection in psutil.net_connections(kind="inet"):
            if connection.laddr and connection.laddr.port == client_port and connection.pid:
                name = psutil.Process(connection.pid).name().lower().removesuffix(".exe")
                return name, connection.pid
    except (psutil.Error, OSError):
        pass
    return (header_name or "unknown").strip().lower() or "unknown", None


def split_upstream(upstream: str) -> tuple[str, int]:
    host, _, port = upstream.rpartition(":")
    return host, int(port)


def build_event(method: str, path: str, query: str | None, headers: dict[str, str], body: bytes,
                upstream: str, process: str, pid: int | None, max_body_bytes: int) -> NetEvent:
    """A body over ``max_body_bytes`` is analyzed by its start and its end. The whole body is still forwarded."""
    _, port = split_upstream(upstream)
    text = keep_head_and_tail(body, max_body_bytes) if len(body) > max_body_bytes else body.decode("utf-8", errors="replace")
    return NetEvent(
        id=new_id(), ts=utc_now_iso(), source="proxy", process=process, pid=pid,
        dst_ip=LOOPBACK_HOST, dst_port=port, host=f"localhost:{port}", host_basis="host_header",
        method=method, path=path, query=query or None,
        headers={**headers, "host": f"localhost:{port}"},
        body_text=text or None,
        body_bytes=len(body), body_sha256=hashlib.sha256(body).hexdigest() if body else None,
        body_truncated=len(body) > max_body_bytes, bytes_out=len(body),
    )


class TapApp:
    """A plain ASGI app. No framework, so nothing can rewrite a request or a reply on the way."""

    def __init__(self, upstream: str, on_event: OnEvent, max_body_bytes: int = 262144):
        self.upstream = upstream
        self.on_event = on_event
        self.max_body_bytes = max_body_bytes
        self.requests_ingested = 0
        self._client: httpx.AsyncClient | None = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            # trust_env=False: a system HTTP_PROXY setting must not send this traffic anywhere else.
            self._client = httpx.AsyncClient(
                base_url=f"http://{self.upstream}", trust_env=False,
                # Local models can think for minutes, so only connecting has a time limit.
                timeout=httpx.Timeout(None, connect=5.0),
            )
        return self._client

    async def __call__(self, scope: dict[str, Any], receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return
        body = await _read_body(receive)
        await self._record(scope, body)
        await self._forward(scope, body, send)

    async def _record(self, scope: dict[str, Any], body: bytes) -> None:
        """A failure here must never get in the way of the client's request."""
        try:
            headers = {key.decode("latin-1").lower(): value.decode("latin-1") for key, value in scope["headers"]}
            client = scope.get("client")
            process, pid = await asyncio.to_thread(
                resolve_client, client[1] if client else 0, headers.get("x-shadow-client"))
            event = build_event(scope["method"], scope["path"], scope["query_string"].decode("latin-1"),
                                headers, body, self.upstream, process, pid, self.max_body_bytes)
            await asyncio.to_thread(self.on_event, event)
            self.requests_ingested += 1
        except Exception as exc:  # noqa: BLE001 - the tap forwards whatever happens
            log.warning("could not record a request: %s", type(exc).__name__)

    async def _forward(self, scope: dict[str, Any], body: bytes, send: Send) -> None:
        target = (scope.get("raw_path") or scope["path"].encode("ascii", "replace")).decode("latin-1")
        if scope["query_string"]:
            target += "?" + scope["query_string"].decode("latin-1")
        # Host and Content-Length are set again for the upstream by httpx.
        headers = [
            (key, value) for key, value in scope["headers"]
            if key.lower().decode("latin-1") not in _HOP_BY_HOP | {"host", "content-length"}
        ]
        client = self._get_client()
        started = False
        try:
            request = client.build_request(scope["method"], target, headers=headers, content=body)
            response = await client.send(request, stream=True)
            try:
                await send({
                    "type": "http.response.start",
                    "status": response.status_code,
                    "headers": [(key, value) for key, value in response.headers.raw
                                if key.lower().decode("latin-1") not in _HOP_BY_HOP],
                })
                started = True
                # aiter_raw: no decompression and no buffering, so streaming replies stay streaming.
                async for chunk in response.aiter_raw():
                    await send({"type": "http.response.body", "body": chunk, "more_body": True})
                await send({"type": "http.response.body", "body": b"", "more_body": False})
            finally:
                await response.aclose()
        except httpx.TransportError as exc:
            log.warning("upstream %s failed: %s", self.upstream, type(exc).__name__)
            if not started:
                await _send_bad_gateway(send)
            # Otherwise the reply is already underway: returning makes the server drop the
            # connection, so the client sees a broken reply and not a falsely complete one.


async def _read_body(receive: Receive) -> bytes:
    parts: list[bytes] = []
    while True:
        message = await receive()
        if message["type"] != "http.request":
            break
        parts.append(message.get("body", b""))
        if not message.get("more_body"):
            break
    return b"".join(parts)


async def _send_bad_gateway(send: Send) -> None:
    payload = json.dumps({"error": "upstream unreachable"}).encode("utf-8")
    await send({
        "type": "http.response.start",
        "status": 502,
        "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(payload)).encode("ascii"))],
    })
    await send({"type": "http.response.body", "body": payload, "more_body": False})


class OllamaTap:
    """Starts and stops the tap on its own thread. A failure is reported in ``error``, never raised."""

    def __init__(self, on_event: OnEvent, listen_port: int = 11436, upstream: str = "127.0.0.1:11434",
                 max_body_bytes: int = 262144):
        self.listen_port = listen_port
        self.upstream = upstream
        self.app = TapApp(upstream, on_event, max_body_bytes)
        self.error: str | None = None
        self._server: uvicorn.Server | None = None
        self._thread: threading.Thread | None = None

    @classmethod
    def from_config(cls, config, on_event: OnEvent) -> "OllamaTap":
        return cls(on_event, config.proxy_port, config.proxy_upstream, config.max_body_bytes)

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def upstream_ok(self) -> bool:
        host, port = split_upstream(self.upstream)
        try:
            with socket.create_connection((host, port), timeout=_UPSTREAM_CHECK_TIMEOUT_S):
                return True
        except OSError:
            return False

    def start(self) -> bool:
        """True once the tap is listening. Otherwise the reason is in ``error``."""
        if self.running:
            return True
        self.error = None
        # Bound here, not by uvicorn, because uvicorn exits the whole process on a busy port.
        # No SO_REUSEADDR: on Windows it would let a second program share the port (SOT 1.2).
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.bind((LOOPBACK_HOST, self.listen_port))
        except OSError:
            listener.close()
            self.error = f"Port {self.listen_port} is busy."
            return False
        config = uvicorn.Config(
            self.app, log_level="warning", access_log=False, lifespan="off",
            # Otherwise uvicorn adds headers of its own to replies that must pass through unchanged.
            server_header=False, date_header=False,
        )
        self._server = uvicorn.Server(config)
        self._thread = threading.Thread(target=self._serve, args=(self._server, listener),
                                        name="ollama-tap", daemon=True)
        self._thread.start()
        deadline = time.monotonic() + _START_TIMEOUT_S
        while not self._server.started and self._thread.is_alive() and time.monotonic() < deadline:
            time.sleep(0.02)
        if not self._server.started:
            self.error = "The tap could not start."
            self.stop()
            return False
        return True

    def _serve(self, server: uvicorn.Server, listener: socket.socket) -> None:
        try:
            server.run(sockets=[listener])
        except Exception as exc:  # noqa: BLE001 - reported on the Sources panel
            self.error = f"The tap stopped: {type(exc).__name__}"
        finally:
            listener.close()

    def stop(self) -> None:
        if self._server is not None:
            self._server.should_exit = True
        if self._thread is not None:
            self._thread.join(timeout=_STOP_TIMEOUT_S)
        self._server = None
        self._thread = None
        # The next start opens a new event loop, which needs a new HTTP client.
        self.app._client = None

    def status(self) -> dict[str, Any]:
        """The ``proxy`` block of ``CaptureStatus`` (SOT 6.7)."""
        return {
            "enabled": self.running,
            "listen_port": self.listen_port,
            "upstream": self.upstream,
            "upstream_ok": self.upstream_ok(),
            "requests_ingested": self.app.requests_ingested,
            "error": self.error,
        }

"""Only this machine may talk to the API (SOT 5.5, 7.3 AT-21).

The server already listens on 127.0.0.1 only. This closes the other door: a web page the person has open can
make their browser send requests to 127.0.0.1, and a hostile site can point its own name at 127.0.0.1
(DNS rebinding). Both arrive with a ``Host`` or ``Origin`` that is not this machine, so both are refused.
"""

from __future__ import annotations

import json
from typing import Any, Awaitable, Callable, Iterable
from urllib.parse import urlsplit

Scope = dict[str, Any]
Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]

LOCAL_NAMES = frozenset({"127.0.0.1", "localhost", "::1"})


def host_of(value: str) -> str | None:
    """The host name in a ``Host`` header value (port and IPv6 brackets removed), lowercase."""
    try:
        return (urlsplit("//" + value.strip()).hostname or "").lower() or None
    except ValueError:
        return None


class LocalOnly:
    def __init__(self, app: Callable[..., Awaitable[None]], allowed: Iterable[str] = ()):
        self.app = app
        self.allowed = LOCAL_NAMES | {a.lower() for a in allowed}

    def _refusal(self, headers: dict[bytes, bytes]) -> str | None:
        host = headers.get(b"host")
        if host is None or host_of(host.decode("latin-1")) not in self.allowed:
            return "requests must be addressed to this machine"
        origin = headers.get(b"origin")
        if origin is not None:
            text = origin.decode("latin-1")
            try:
                name = (urlsplit(text).hostname or "").lower()
            except ValueError:
                name = ""
            if name not in self.allowed:
                return "requests from other websites are not allowed"
        return None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        reason = self._refusal({k.lower(): v for k, v in scope["headers"]})
        if reason is None:
            await self.app(scope, receive, send)
        elif scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
        else:
            body = json.dumps({"error": reason}).encode()
            await send({"type": "http.response.start", "status": 403,
                        "headers": [(b"content-type", b"application/json"),
                                    (b"content-length", str(len(body)).encode())]})
            await send({"type": "http.response.body", "body": body})

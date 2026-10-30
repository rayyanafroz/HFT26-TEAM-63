"""Server-Sent Events: the live stream to the dashboard (SOT 6.8).

``EventBus.publish`` can be called from any thread (the pipeline, the live tail, the
scenario player). Every connected dashboard gets its own small queue; slow clients
lose their oldest messages instead of slowing everyone down (the dashboard re-fetches
on reconnect, and polls while disconnected).
"""

from __future__ import annotations

import asyncio
import json
import threading
from typing import Any, AsyncIterator

from pydantic import BaseModel

PING_INTERVAL_S = 15.0       # SOT 6.8: a comment line every 15 s keeps the connection alive
QUEUE_SIZE = 1000

# The message types the dashboard understands (SOT 6.8).
EVENT_TYPES = frozenset({
    "event.new", "finding.new", "alert.new", "score.update",
    "remediation.update", "scenario.progress", "reset",
})

_CLOSED = object()           # put in every queue to end the streams on shutdown


def format_message(event_type: str, payload: "BaseModel | dict[str, Any]") -> str:
    """One SSE message: ``event: <type>`` and one ``data:`` line of JSON."""
    if isinstance(payload, BaseModel):
        data = payload.model_dump_json(by_alias=True)
    else:
        data = json.dumps(payload, separators=(",", ":"), default=str)
    return f"event: {event_type}\ndata: {data}\n\n"


class EventBus:
    def __init__(self, ping_s: float = PING_INTERVAL_S, queue_size: int = QUEUE_SIZE):
        self.ping_s = ping_s
        self._queue_size = queue_size
        self._lock = threading.Lock()
        self._subscribers: list[tuple[asyncio.AbstractEventLoop, asyncio.Queue]] = []
        self._closed = False

    @property
    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subscribers)

    # ---- publishing (any thread) ----------------------------------------

    def publish(self, event_type: str, payload: "BaseModel | dict[str, Any]") -> None:
        """Send a message to every connected dashboard. Never blocks, never raises for a gone client."""
        if event_type not in EVENT_TYPES:
            raise ValueError(f"unknown event type {event_type!r}")
        message = format_message(event_type, payload)
        with self._lock:
            targets = list(self._subscribers)
        for loop, queue in targets:
            try:
                loop.call_soon_threadsafe(self._offer, queue, message)
            except RuntimeError:                  # that client's loop has already shut down
                self._drop(queue)

    @staticmethod
    def _offer(queue: asyncio.Queue, message: object) -> None:
        if queue.full():                          # a slow client: discard its oldest message
            try:
                queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
        queue.put_nowait(message)

    # ---- subscribing (event loop) ---------------------------------------

    def subscribe(self) -> asyncio.Queue:
        """Register the calling coroutine's loop; returns the queue to read messages from."""
        queue: asyncio.Queue = asyncio.Queue(maxsize=self._queue_size)
        loop = asyncio.get_running_loop()
        with self._lock:
            if self._closed:
                queue.put_nowait(_CLOSED)
            else:
                self._subscribers.append((loop, queue))
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        self._drop(queue)

    def _drop(self, queue: asyncio.Queue) -> None:
        with self._lock:
            self._subscribers = [(l, q) for (l, q) in self._subscribers if q is not queue]

    def close(self) -> None:
        """End every stream (called when the app shuts down)."""
        with self._lock:
            self._closed = True
            targets = list(self._subscribers)
            self._subscribers.clear()
        for loop, queue in targets:
            try:
                loop.call_soon_threadsafe(self._offer, queue, _CLOSED)
            except RuntimeError:
                pass

    # ---- the stream a client reads --------------------------------------

    async def stream(self, is_disconnected=None) -> AsyncIterator[str]:
        """Yield SSE text until the client leaves or the bus closes."""
        queue = self.subscribe()
        try:
            yield ": connected\n\n"
            while True:
                try:
                    message = await asyncio.wait_for(queue.get(), timeout=self.ping_s)
                except asyncio.TimeoutError:
                    if is_disconnected is not None and await is_disconnected():
                        return
                    yield ": ping\n\n"
                    continue
                if message is _CLOSED:
                    return
                yield message
        finally:
            self.unsubscribe(queue)

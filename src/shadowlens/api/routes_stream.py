"""``GET /api/stream``: the live event stream (SOT 6.8)."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

router = APIRouter(prefix="/api")


@router.get("/stream")
async def stream(request: Request) -> StreamingResponse:
    bus = request.app.state.bus
    return StreamingResponse(
        bus.stream(is_disconnected=request.is_disconnected),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )

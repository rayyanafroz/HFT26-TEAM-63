"""Routes for the automatic sources (SOT 6.7): ``GET /api/sources``, ``PUT /api/sources/{id}``."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from ..ingest.sources import SourceManager
from ..models import Page, SourceRow, SourceUpdateRequest

router = APIRouter(prefix="/api")


def get_sources(request: Request) -> SourceManager:
    return request.app.state.sources


@router.get("/sources", response_model=Page[SourceRow])
def list_sources(sources: SourceManager = Depends(get_sources)) -> Page[SourceRow]:
    rows = sources.rows()
    return Page[SourceRow](items=rows, total=len(rows))


@router.put("/sources/{source_id}", response_model=SourceRow)
def update_source(source_id: str, body: SourceUpdateRequest,
                  sources: SourceManager = Depends(get_sources)) -> SourceRow:
    try:
        return sources.set_enabled(source_id, body.enabled, body.backfill)
    except KeyError:
        raise HTTPException(status_code=404, detail="source not found") from None
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

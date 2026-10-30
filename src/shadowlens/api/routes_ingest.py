"""Routes for getting data in and reading it back (SOT 6.7):

``POST /api/ingest/log``, ``GET /api/events``, ``GET /api/findings``,
``GET /api/alerts``, ``POST /api/alerts/{id}/ack``.
"""

from __future__ import annotations

import importlib
from typing import Callable

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile

from ..config import Config
from ..core.pipeline import Pipeline
from ..db import Database
from ..ingest import http_log
from ..models import (
    Alert,
    AlertStatus,
    EventLite,
    Finding,
    FindingCategory,
    IngestSummary,
    Page,
    Timestamp,
    Uuid4,
    Visibility,
)
from .deps import get_config, get_db, get_pipeline

router = APIRouter(prefix="/api")


def _placeholder_expander() -> Callable[[str], str] | None:
    """``fakes.expand`` (turns ``{{fake:...}}`` into test values) once that module exists.

    It lets the bundled sample file carry only placeholders. Real logs contain none, so
    expanding them is harmless.
    """
    try:
        return importlib.import_module("shadowlens.fakes").expand
    except (ImportError, AttributeError):
        return None


@router.post("/ingest/log", response_model=IngestSummary)
def ingest_log(
    file: UploadFile = File(...),
    config: Config = Depends(get_config),
    pipeline: Pipeline = Depends(get_pipeline),
) -> IngestSummary:
    limit = http_log.MAX_LOG_BYTES
    data = file.file.read(limit + 1)
    if len(data) > limit:
        raise HTTPException(status_code=413, detail=f"log is larger than {limit // (1024 * 1024)} MB")
    try:
        result = http_log.parse_log(
            data, file.filename, max_log_bytes=limit, max_body_bytes=config.max_body_bytes,
            expand=_placeholder_expander())
    except http_log.LogTooLargeError as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    return pipeline.ingest_log(result)


@router.get("/events", response_model=Page[EventLite])
def list_events(
    provider_id: str | None = None,
    tool_id: str | None = None,
    visibility: Visibility | None = None,
    since: Timestamp | None = None,
    limit: int | None = None,
    offset: int | None = None,
    db: Database = Depends(get_db),
) -> Page[EventLite]:
    return db.list_events(provider_id=provider_id, tool_id=tool_id,
                          visibility=visibility.value if visibility else None,
                          since=since, limit=limit, offset=offset)


@router.get("/findings", response_model=Page[Finding])
def list_findings(
    event_id: Uuid4 | None = None,
    rule_id: str | None = None,
    category: FindingCategory | None = None,
    tool_id: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
    db: Database = Depends(get_db),
) -> Page[Finding]:
    return db.list_findings(event_id=event_id, rule_id=rule_id,
                            category=category.value if category else None,
                            tool_id=tool_id, limit=limit, offset=offset)


@router.get("/alerts", response_model=Page[Alert])
def list_alerts(
    severity: str | None = None,          # comma list, e.g. "critical,high"
    status: AlertStatus | None = None,
    tool_id: str | None = None,
    rule_id: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
    db: Database = Depends(get_db),
) -> Page[Alert]:
    levels = [part.strip() for part in severity.split(",") if part.strip()] if severity else None
    try:
        return db.list_alerts(severity=levels, status=status.value if status else None,
                              tool_id=tool_id, rule_id=rule_id, limit=limit, offset=offset)
    except ValueError as exc:             # an unknown severity name
        raise HTTPException(status_code=422, detail="invalid request: severity must be a comma list of "
                                                     "info, low, medium, high, critical") from exc


@router.post("/alerts/{alert_id}/ack", response_model=Alert)
def ack_alert(alert_id: Uuid4, db: Database = Depends(get_db)) -> Alert:
    alert = db.ack_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="alert not found")
    return alert

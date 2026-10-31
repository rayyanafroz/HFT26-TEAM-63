"""Advice for alerts and the AI egress ledger (SOT 6.7): ``POST /api/alerts/{id}/remediate``, ``GET /api/egress``."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from ..db import Database
from ..llm.triage import Triage
from ..models import EgressResponse, Remediation, Uuid4
from .deps import get_db, get_triage

router = APIRouter(prefix="/api")


@router.post("/alerts/{alert_id}/remediate", response_model=Remediation)
def remediate(alert_id: Uuid4, db: Database = Depends(get_db), triage: Triage = Depends(get_triage)) -> Remediation:
    """Advice for one alert. Idempotent: an alert that already has some returns it."""
    alert = db.get_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="alert not found")
    return triage.remediate(alert)


@router.get("/egress", response_model=EgressResponse)
def egress(limit: int | None = None, offset: int | None = None, db: Database = Depends(get_db)) -> EgressResponse:
    """Every call made, or refused, to an AI model for advice."""
    page = db.list_llm_calls(limit=limit, offset=offset)
    return EgressResponse(summary=db.egress_summary(), items=page.items, total=page.total)

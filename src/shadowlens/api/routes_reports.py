"""Compliance and evidence (SOT 6.7): ``GET /api/compliance``, ``GET /api/evidence``."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from fastapi import APIRouter, Depends
from pydantic import ValidationError

from ..config import Config
from ..core.views import Insights
from ..models import Compliance, Evidence
from .deps import get_config, get_insights

log = logging.getLogger("shadowlens.reports")
router = APIRouter(prefix="/api")

EVIDENCE_FILE = "evidence.json"


def evidence_path(config: Config) -> Path:
    """Where ``python -m shadowlens.eval.run`` writes its result: next to the database (SOT 8.5)."""
    return config.db_path.parent / EVIDENCE_FILE


@router.get("/compliance", response_model=Compliance)
def get_compliance(insights: Insights = Depends(get_insights)) -> Compliance:
    return insights.compliance()


@router.get("/evidence", response_model=Evidence, response_model_by_alias=True)
def get_evidence(config: Config = Depends(get_config)) -> Evidence:
    """The measured results from the labeled fixtures. The metric values are never made up here: with no
    file, or one that does not match the contract, the answer is ``available: false``."""
    try:
        raw = json.loads(evidence_path(config).read_text(encoding="utf-8"))
        return Evidence.model_validate(raw)
    except FileNotFoundError:
        return Evidence(available=False)
    except (OSError, ValueError, ValidationError) as exc:
        log.warning("evidence file unusable (%s)", type(exc).__name__)
        return Evidence(available=False)

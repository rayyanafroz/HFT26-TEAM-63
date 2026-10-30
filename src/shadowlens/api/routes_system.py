"""Routes about the app itself (SOT 6.7): health."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from .. import __version__
from ..config import Config
from ..db import Database
from ..models import Health, HealthLlm, LlmMode
from .deps import get_config, get_db

router = APIRouter(prefix="/api")


@router.get("/health", response_model=Health)
def health(config: Config = Depends(get_config), db: Database = Depends(get_db)) -> Health:
    try:
        db.count_events()  # proves the database answers
    except Exception as exc:  # noqa: BLE001 - reported as a clean 503 below
        raise HTTPException(status_code=503, detail="database unavailable") from exc
    return Health(
        version=__version__,
        llm=HealthLlm(
            enabled=config.llm_enabled,
            key_present=config.key_present,
            model=config.featherless_model,
            mode=LlmMode(config.llm_mode),
        ),
    )

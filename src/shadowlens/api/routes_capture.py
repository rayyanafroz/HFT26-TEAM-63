"""Routes for what is being watched and for the demo (SOT 6.7):

``/api/scan/connections``, ``/api/capture/*``, ``/api/demo/*``, ``/api/analyze/*``.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from ..config import Config
from ..core.capture import CaptureManager
from ..core.preview import AnalysisUnavailable, build_preview, build_samples
from ..core.score_publisher import ScorePublisher
from ..ingest.scenarios import ScenarioError, ScenarioNotFound
from ..models import (
    AnalyzePreviewRequest,
    CaptureControlRequest,
    CaptureStatus,
    IngestSummary,
    LoadScenarioRequest,
    OkResponse,
    PlayScenarioRequest,
    PlayScenarioResponse,
    Preview,
    SamplesResponse,
)
from .deps import get_capture, get_config, get_publisher

router = APIRouter(prefix="/api")


# ---- the process scan and the on/off switches -------------------------------

@router.post("/scan/connections", response_model=IngestSummary)
def scan_connections(capture: CaptureManager = Depends(get_capture)) -> IngestSummary:
    return capture.scan_once()


@router.get("/capture/status", response_model=CaptureStatus)
def capture_status(capture: CaptureManager = Depends(get_capture)) -> CaptureStatus:
    return capture.status()


@router.post("/capture/start", response_model=CaptureStatus)
def capture_start(body: CaptureControlRequest | None = None,
                  capture: CaptureManager = Depends(get_capture)) -> CaptureStatus:
    body = body or CaptureControlRequest()
    return capture.start(scan=body.scan, tail=body.tail)


@router.post("/capture/stop", response_model=CaptureStatus)
def capture_stop(body: CaptureControlRequest | None = None,
                 capture: CaptureManager = Depends(get_capture)) -> CaptureStatus:
    body = body or CaptureControlRequest()
    return capture.stop(scan=body.scan, tail=body.tail)


# ---- demo scenarios ----------------------------------------------------------

def _scenario_error(exc: Exception) -> HTTPException:
    if isinstance(exc, ScenarioNotFound):
        return HTTPException(status_code=404, detail="scenario not found")
    return HTTPException(status_code=500, detail=str(exc))      # a broken template: our fault, message holds no content


@router.post("/demo/load-scenario", response_model=IngestSummary)
def load_scenario(body: LoadScenarioRequest, capture: CaptureManager = Depends(get_capture)) -> IngestSummary:
    try:
        return capture.player.load(body.name.value)
    except (ScenarioNotFound, ScenarioError) as exc:
        raise _scenario_error(exc) from exc


@router.post("/demo/play", response_model=PlayScenarioResponse)
def play_scenario(body: PlayScenarioRequest, capture: CaptureManager = Depends(get_capture)) -> PlayScenarioResponse:
    try:
        return capture.player.play(body.name.value, body.speed)
    except (ScenarioNotFound, ScenarioError) as exc:
        raise _scenario_error(exc) from exc


@router.post("/demo/stop", response_model=OkResponse)
def stop_scenario(capture: CaptureManager = Depends(get_capture)) -> OkResponse:
    capture.player.stop()
    return OkResponse()


@router.post("/demo/reset", response_model=OkResponse)
def reset_everything(capture: CaptureManager = Depends(get_capture),
                     publisher: ScorePublisher = Depends(get_publisher)) -> OkResponse:
    capture.reset()
    publisher.publish_now()                                      # the gauge goes back to zero everywhere
    return OkResponse()


# ---- Leak Lab ----------------------------------------------------------------

@router.post("/analyze/preview", response_model=Preview)
def analyze_preview(body: AnalyzePreviewRequest, config: Config = Depends(get_config)) -> Preview:
    try:
        return build_preview(body.text, body.mode, config)
    except AnalysisUnavailable as exc:
        raise HTTPException(status_code=501, detail=str(exc)) from exc


@router.get("/analyze/samples", response_model=SamplesResponse)
def analyze_samples() -> SamplesResponse:
    try:
        return build_samples()
    except AnalysisUnavailable as exc:
        raise HTTPException(status_code=501, detail=str(exc)) from exc

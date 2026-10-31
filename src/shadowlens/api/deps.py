"""Small helpers that give route functions access to the app's shared objects."""

from __future__ import annotations

from fastapi import Request

from ..config import Config
from ..core.capture import CaptureManager
from ..core.pipeline import Pipeline
from ..core.score_publisher import ScorePublisher
from ..core.views import Insights
from ..db import Database


def get_config(request: Request) -> Config:
    return request.app.state.config


def get_db(request: Request) -> Database:
    return request.app.state.db


def get_pipeline(request: Request) -> Pipeline:
    return request.app.state.pipeline


def get_insights(request: Request) -> Insights:
    return request.app.state.insights


def get_publisher(request: Request) -> ScorePublisher:
    return request.app.state.publisher


def get_capture(request: Request) -> CaptureManager:
    return request.app.state.capture


def get_triage(request: Request):
    return request.app.state.triage

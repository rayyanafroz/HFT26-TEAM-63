"""Small helpers that give route functions access to the app's shared objects."""

from __future__ import annotations

from fastapi import Request

from ..config import Config
from ..db import Database


def get_config(request: Request) -> Config:
    return request.app.state.config


def get_db(request: Request) -> Database:
    return request.app.state.db

"""Shared test setup."""

import pytest
from starlette import testclient


@pytest.fixture(autouse=True)
def _tests_talk_to_this_machine(monkeypatch):
    """The API only answers requests addressed to this machine (SOT AT-21), so test clients use 127.0.0.1
    instead of Starlette's default ``testserver``. A test that checks the refusal passes its own Host."""
    original = testclient.TestClient.__init__

    def init(self, *args, **kwargs):
        kwargs.setdefault("base_url", "http://127.0.0.1")
        original(self, *args, **kwargs)

    monkeypatch.setattr(testclient.TestClient, "__init__", init)

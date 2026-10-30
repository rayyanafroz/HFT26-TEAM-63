import re

import pytest
from fastapi.testclient import TestClient

from shadowlens import __version__
from shadowlens.api.app import PLACEHOLDER_HTML, create_app
from shadowlens.config import Config
from shadowlens.db import Database


def make_config(tmp_path, **env):
    return Config.load(env=env, base_dir=tmp_path, use_dotenv=False)


@pytest.fixture
def db(tmp_path):
    database = Database(tmp_path / "shadow.db")
    yield database
    database.close()


@pytest.fixture
def client(tmp_path, db):
    app = create_app(make_config(tmp_path), db=db, ui_dir=tmp_path / "no-ui")
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


# ---- health ------------------------------------------------------------------

def test_health_default_shape(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    assert r.json() == {
        "status": "ok", "version": __version__, "db": True,
        "llm": {"enabled": True, "key_present": False, "model": None, "mode": "template"}}


def test_health_reports_llm_mode_without_leaking_the_key(tmp_path, db):
    cfg = make_config(tmp_path, FEATHERLESS_API_KEY="do-not-leak-me", FEATHERLESS_MODEL="some-model")
    with TestClient(create_app(cfg, db=db, ui_dir=tmp_path)) as c:
        body = c.get("/api/health")
    assert body.json()["llm"] == {"enabled": True, "key_present": True, "model": "some-model", "mode": "llm"}
    assert "do-not-leak-me" not in body.text


def test_health_is_503_when_the_database_fails(tmp_path):
    class BrokenDb:
        def count_events(self):
            raise RuntimeError("disk on fire")

    app = create_app(make_config(tmp_path), db=BrokenDb(), ui_dir=tmp_path)
    with TestClient(app, raise_server_exceptions=False) as c:
        r = c.get("/api/health")
    assert r.status_code == 503
    assert r.json() == {"error": "database unavailable"}
    assert "fire" not in r.text                      # internal detail is not sent


# ---- errors are always {"error": "..."} --------------------------------------

def test_unknown_api_route_is_a_json_404(client):
    r = client.get("/api/nope")
    assert r.status_code == 404
    assert set(r.json()) == {"error"}


def test_wrong_method_is_a_json_405(client):
    r = client.post("/api/health")
    assert r.status_code == 405
    assert set(r.json()) == {"error"}


def test_validation_errors_are_json_422(tmp_path, db):
    app = create_app(make_config(tmp_path), db=db, ui_dir=tmp_path)

    @app.get("/api/_needs_int")
    def needs_int(n: int):  # noqa: ARG001
        return {}

    with TestClient(app) as c:
        r = c.get("/api/_needs_int", params={"n": "abc"})
    assert r.status_code == 422
    assert set(r.json()) == {"error"}
    assert r.json()["error"].startswith("invalid request: query.n:")      # names where the bad value was


def test_unexpected_errors_are_json_500_without_details(tmp_path, db):
    app = create_app(make_config(tmp_path), db=db, ui_dir=tmp_path)

    @app.get("/api/_boom")
    def boom():
        raise RuntimeError("secret internal detail /home/user/x")

    with TestClient(app, raise_server_exceptions=False) as c:
        r = c.get("/api/_boom")
    assert r.status_code == 500
    assert r.json() == {"error": "internal error"}
    assert "secret internal" not in r.text


# ---- the dashboard files -----------------------------------------------------

def test_placeholder_page_when_there_is_no_index_html(client):
    r = client.get("/")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
    assert "ShadowLens" in r.text


def test_placeholder_makes_no_external_requests():
    assert not re.search(r"https?://|//cdn|src=|<link|@import", PLACEHOLDER_HTML)


def test_serves_the_real_ui_when_index_html_exists(tmp_path, db):
    ui = tmp_path / "ui"
    (ui / "js").mkdir(parents=True)
    (ui / "index.html").write_text("<html><title>REAL UI</title></html>", encoding="utf-8")
    (ui / "js" / "main.js").write_text("export const x = 1;", encoding="utf-8")
    (ui / "mock").mkdir()
    (ui / "mock" / "stats_summary.json").write_text('{"ok": true}', encoding="utf-8")
    with TestClient(create_app(make_config(tmp_path), db=db, ui_dir=ui)) as c:
        assert "REAL UI" in c.get("/").text
        js = c.get("/js/main.js")
        assert js.status_code == 200 and "javascript" in js.headers["content-type"]
        assert c.get("/mock/stats_summary.json").json() == {"ok": True}


def test_api_still_wins_over_static_files(tmp_path, db):
    ui = tmp_path / "ui"
    ui.mkdir()
    (ui / "index.html").write_text("<html>UI</html>", encoding="utf-8")
    with TestClient(create_app(make_config(tmp_path), db=db, ui_dir=ui)) as c:
        assert c.get("/api/health").json()["status"] == "ok"
        missing = c.get("/api/nope")
        assert missing.status_code == 404 and set(missing.json()) == {"error"}   # JSON, not the UI page
        assert c.get("/does-not-exist.js").status_code == 404


def test_api_docs_pages_are_off(client):
    """Swagger/ReDoc load scripts from a CDN, which would break 'no external requests'."""
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404


# ---- database lifecycle ------------------------------------------------------

def test_app_opens_and_closes_its_own_database(tmp_path):
    cfg = make_config(tmp_path, SHADOWLENS_DB_PATH="store/own.db")
    app = create_app(cfg, ui_dir=tmp_path)
    assert app.state.db is None
    with TestClient(app) as c:
        assert c.get("/api/health").status_code == 200
        assert (tmp_path / "store" / "own.db").exists()
        assert app.state.db is not None
    assert app.state.db is None                       # closed and released on shutdown


def test_an_injected_database_is_left_open(tmp_path, db):
    with TestClient(create_app(make_config(tmp_path), db=db, ui_dir=tmp_path)):
        pass
    assert db.count_events() == 0                     # still usable: the app did not close it

import socket
import sys
import threading
import time
import types

import httpx
import pytest

from shadowlens import __main__ as entry
from shadowlens import desktop
from shadowlens.config import Config


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def make_config(tmp_path, port, **env):
    env = {"SHADOWLENS_PORT": str(port), "SHADOWLENS_DB_PATH": str(tmp_path / "shadow.db"),
           "SHADOWLENS_RESOLVE": "false", **env}          # tests never make DNS lookups
    return Config.load(env=env, base_dir=tmp_path, use_dotenv=False)


def health(port):
    return httpx.get(f"http://127.0.0.1:{port}/api/health", timeout=2)


def wait_until(predicate, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


def run_main_in_thread(argv, **kwargs):
    """Run main() in a thread; returns (thread, result_dict, stop_event)."""
    stop = threading.Event()
    result = {}
    t = threading.Thread(target=lambda: result.update(code=entry.main(argv, stop_event=stop, **kwargs)))
    t.start()
    return t, result, stop


# ---- helpers -----------------------------------------------------------------

def test_parse_args():
    assert entry.parse_args([]).browser is False
    assert entry.parse_args(["--browser"]).browser is True
    assert entry.parse_args(["--port", "9000"]).port == 9000


def test_port_in_use_detection():
    with socket.socket() as srv:
        srv.bind(("127.0.0.1", 0))
        srv.listen()
        port = srv.getsockname()[1]
        assert entry.port_in_use("127.0.0.1", port) is True
    assert entry.port_in_use("127.0.0.1", port) is False


def test_utf8_console_is_safe_without_reconfigure(monkeypatch):
    monkeypatch.setattr(sys, "stdout", types.SimpleNamespace(write=lambda s: None))   # no .reconfigure
    entry._utf8_console()                                                              # must not raise


# ---- main(): the three ways of running ---------------------------------------

def test_desktop_mode_opens_the_window_and_stops_the_server_when_it_closes(tmp_path):
    port = free_port()
    seen = {}

    def fake_window(url):
        seen["url"] = url
        seen["healthy_while_open"] = health(port).status_code == 200
        return True                                    # "the user closed the window"

    code = entry.main([], config=make_config(tmp_path, port), open_window=fake_window)
    assert code == 0
    assert seen == {"url": f"http://127.0.0.1:{port}", "healthy_while_open": True}
    assert entry.port_in_use("127.0.0.1", port) is False         # server was stopped


def test_browser_flag_opens_nothing_and_keeps_serving_until_stopped(tmp_path):
    port = free_port()
    calls = []
    t, result, stop = run_main_in_thread(
        ["--browser"], config=make_config(tmp_path, port),
        open_window=lambda url: calls.append("window"), open_browser=lambda url: calls.append("browser"))
    try:
        assert wait_until(lambda: entry.port_in_use("127.0.0.1", port))
        assert wait_until(lambda: health(port).status_code == 200)
        assert health(port).json()["status"] == "ok"
        assert calls == []
    finally:
        stop.set()
        t.join(timeout=15)
    assert result["code"] == 0 and calls == []
    assert entry.port_in_use("127.0.0.1", port) is False


def test_desktop_disabled_in_config_behaves_like_the_browser_flag(tmp_path):
    port = free_port()
    calls = []
    t, result, stop = run_main_in_thread(
        [], config=make_config(tmp_path, port, SHADOWLENS_DESKTOP="false"),
        open_window=lambda url: calls.append("window"), open_browser=lambda url: calls.append("browser"))
    try:
        assert wait_until(lambda: entry.port_in_use("127.0.0.1", port))
    finally:
        stop.set()
        t.join(timeout=15)
    assert calls == [] and result["code"] == 0


def test_falls_back_to_the_browser_when_the_window_fails(tmp_path, capsys):
    port = free_port()
    opened = []
    t, result, stop = run_main_in_thread(
        [], config=make_config(tmp_path, port), open_window=lambda url: False,
        open_browser=lambda url: opened.append(url))
    try:
        assert wait_until(lambda: opened)
        assert opened == [f"http://127.0.0.1:{port}"]
        assert health(port).status_code == 200          # keeps serving for the browser
    finally:
        stop.set()
        t.join(timeout=15)
    assert result["code"] == 0
    assert "opening your browser" in capsys.readouterr().out


def test_port_override_flag(tmp_path):
    other = free_port()
    seen = {}
    code = entry.main(["--port", str(other)], config=make_config(tmp_path, free_port()),
                      open_window=lambda url: seen.setdefault("url", url) and True)
    assert code == 0 and seen["url"] == f"http://127.0.0.1:{other}"


def test_refuses_to_start_when_the_port_is_taken(tmp_path, capsys):
    with socket.socket() as srv:
        srv.bind(("127.0.0.1", 0))
        srv.listen()
        port = srv.getsockname()[1]
        code = entry.main([], config=make_config(tmp_path, port), open_window=lambda url: True)
    assert code == 1
    assert "already in use" in capsys.readouterr().err


# ---- desktop.open_window never crashes ---------------------------------------

def fake_webview(start_error=None, create_error=None):
    calls = {}
    mod = types.ModuleType("webview")

    def create_window(*args, **kwargs):
        if create_error:
            raise create_error
        calls["create"] = (args, kwargs)

    def start(**kwargs):
        if start_error:
            raise start_error
        calls["start"] = kwargs

    mod.create_window, mod.start = create_window, start
    return mod, calls


def test_open_window_uses_the_sot_window_settings(monkeypatch):
    mod, calls = fake_webview()
    monkeypatch.setitem(sys.modules, "webview", mod)
    assert desktop.open_window("http://127.0.0.1:8787") is True
    args, kwargs = calls["create"]
    assert args == ("ShadowLens", "http://127.0.0.1:8787")
    assert (kwargs["width"], kwargs["height"], kwargs["min_size"]) == (1360, 860, (1100, 700))
    assert calls["start"] == {"debug": False}           # no devtools in production


def test_open_window_returns_false_when_pywebview_is_missing(monkeypatch):
    monkeypatch.setitem(sys.modules, "webview", None)   # makes `import webview` raise ImportError
    assert desktop.open_window("http://127.0.0.1:8787") is False


@pytest.mark.parametrize("kind", ["start", "create"])
def test_open_window_returns_false_when_the_backend_fails(monkeypatch, kind):
    error = RuntimeError("no WebView2 runtime")
    mod, _ = fake_webview(**{f"{kind}_error": error})
    monkeypatch.setitem(sys.modules, "webview", mod)
    assert desktop.open_window("http://127.0.0.1:8787") is False

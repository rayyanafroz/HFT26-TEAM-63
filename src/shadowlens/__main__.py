"""``python -m shadowlens``: start the server, then show the dashboard.

Default: a desktop window (closing it stops the server). With ``--browser`` (or
``SHADOWLENS_DESKTOP=false``) no window is opened; the URL is printed and the
server runs until Ctrl+C. If the window cannot open, the default browser is used.
"""

from __future__ import annotations

import argparse
import dataclasses
import socket
import sys
import threading
import time
import webbrowser
from typing import Callable, Sequence

import httpx
import uvicorn

from . import __version__, desktop
from .api.app import create_app
from .api.sse import EventBus
from .config import Config

STARTUP_TIMEOUT_S = 20.0


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="python -m shadowlens", description="ShadowLens local AI-usage auditor")
    parser.add_argument("--browser", action="store_true",
                        help="do not open a desktop window; print the URL and keep serving")
    parser.add_argument("--port", type=int, help="override SHADOWLENS_PORT")
    parser.add_argument("--version", action="version", version=f"ShadowLens {__version__}")
    return parser.parse_args(argv)


def _utf8_console() -> None:
    """The default Windows console codec can crash on non-ASCII text; make it forgiving."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="replace")


def port_in_use(host: str, port: int) -> bool:
    """True if something is already listening on host:port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.5)
        return probe.connect_ex((host, port)) == 0


def start_server(app, config: Config) -> tuple[uvicorn.Server, threading.Thread]:
    """Run uvicorn in a background thread (the main thread is kept for the window)."""
    # timeout_graceful_shutdown: an open dashboard tab holds a live-stream connection; without a
    # limit, stopping the server would wait for it forever.
    server = uvicorn.Server(uvicorn.Config(
        app, host=config.host, port=config.port, log_level="info", access_log=False,
        timeout_graceful_shutdown=2))
    thread = threading.Thread(target=server.run, name="shadowlens-server", daemon=True)
    thread.start()
    return server, thread


def wait_until_healthy(url: str, thread: threading.Thread, timeout: float = STARTUP_TIMEOUT_S) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and thread.is_alive():
        try:
            if httpx.get(f"{url}/api/health", timeout=1.0).status_code == 200:
                return True
        except httpx.HTTPError:
            pass
        time.sleep(0.1)
    return False


def stop_server(server: uvicorn.Server, thread: threading.Thread, bus: EventBus | None = None) -> None:
    """Stop the server. Ending the live streams first lets open dashboard tabs finish cleanly;
    otherwise uvicorn waits its grace period and then cancels them with a noisy error."""
    if bus is not None:
        bus.close()
    server.should_exit = True
    thread.join(timeout=10)


def main(
    argv: Sequence[str] | None = None,
    *,
    config: Config | None = None,
    open_window: Callable[[str], bool] | None = None,
    open_browser: Callable[[str], object] | None = None,
    stop_event: threading.Event | None = None,
) -> int:
    """Run ShadowLens. The keyword arguments exist so tests can replace the window,
    the browser and the "keep running" wait."""
    args = parse_args(argv)
    _utf8_console()
    config = config or Config.load()
    if args.port is not None:
        config = dataclasses.replace(config, port=args.port)
    url = config.server_url

    if port_in_use(config.host, config.port):
        print(f"Port {config.port} is already in use. Set SHADOWLENS_PORT (or use --port) to another port.",
              file=sys.stderr)
        return 1

    app = create_app(config)
    server, thread = start_server(app, config)
    try:
        if not wait_until_healthy(url, thread):
            print("ShadowLens did not start. Check the messages above.", file=sys.stderr)
            return 1
        print(f"ShadowLens {__version__} is running at {url}")

        if config.desktop and not args.browser:
            if (open_window or desktop.open_window)(url):
                return 0  # the window was closed: stop the server (finally below)
            print("The desktop window is not available here; opening your browser instead.")
            (open_browser or webbrowser.open)(url)

        stop_event = stop_event or threading.Event()
        try:
            while thread.is_alive() and not stop_event.is_set():
                stop_event.wait(0.5)
        except KeyboardInterrupt:
            print("Stopping.")
        return 0
    finally:
        stop_server(server, thread, app.state.bus)


if __name__ == "__main__":
    raise SystemExit(main())

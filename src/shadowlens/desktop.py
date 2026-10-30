"""The desktop window (SOT 5.5): a native window around the local dashboard.

pywebview uses WebView2 (Edge) on Windows. If the window cannot be created for
any reason, ``open_window`` returns False and the caller falls back to the
browser. Nothing here may crash the app.
"""

from __future__ import annotations

import logging

log = logging.getLogger("shadowlens.desktop")

TITLE = "ShadowLens"
WIDTH, HEIGHT = 1360, 860
MIN_SIZE = (1100, 700)


def open_window(url: str, title: str = TITLE) -> bool:
    """Open the dashboard in a native window and block until it is closed.

    Returns True if a window was shown (and has now been closed), False if no
    window could be created.
    """
    try:
        import webview  # pywebview; imported here so a missing install is not fatal
    except Exception as exc:  # noqa: BLE001 - ImportError, or a backend failing at import
        log.warning("pywebview is not usable (%s)", type(exc).__name__)
        return False

    try:
        webview.create_window(title, url, width=WIDTH, height=HEIGHT, min_size=MIN_SIZE)
        webview.start(debug=False)  # blocks until the window is closed
    except Exception as exc:  # noqa: BLE001 - e.g. no WebView2 / GTK / Qt backend
        log.warning("could not open the desktop window (%s)", type(exc).__name__)
        return False
    return True

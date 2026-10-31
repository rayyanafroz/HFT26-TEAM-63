"""Leak Lab for the terminal: type anything, see what ShadowLens finds (SOT 2.7 W1, 9.3.2).

    python -m scenarios.leak_lab [--server http://127.0.0.1:8787] [--agent] [--color auto|always|never]

Nothing here is scripted. Each line you type goes to the real analyzer, and you get back:

  * your text with every match highlighted (severity is a shape and a word, never color alone),
  * what was found, with the value masked,
  * the exact text an AI model would receive, with secrets replaced by placeholders,
  * whether the egress guard would block it, and the risk it would add,
  * how long the analysis took.

It asks the running ShadowLens server. If none is running it uses the same analyzer in this
process and says so. Nothing typed is stored, logged or sent anywhere: there is no history file.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable

from shadowlens.config import Config

REQUEST_TIMEOUT_S = 8.0
PROBE_TIMEOUT_S = 3.0
RULE_WIDTH = 78

# Never through a system or environment proxy: this talks to the same machine (SOT 2.5, principle 4).
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

# Severity: a shape and a word, plus color (SOT 9.2). ASCII shapes if the console cannot draw them.
_GLYPHS = {"critical": "◆", "high": "▲", "medium": "■", "low": "●", "info": "–"}
_GLYPHS_ASCII = {"critical": "*", "high": "^", "medium": "#", "low": "o", "info": "-"}
_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
# 256-color backgrounds: red, orange, yellow, blue, grey (the palette of SOT 9.2).
_PAINT = {"critical": "1;97;48;5;196", "high": "30;48;5;208", "medium": "30;48;5;220",
          "low": "97;48;5;33", "info": "97;48;5;60"}
_RESET = "\x1b[0m"

HELP = """\
Type or paste a line and press Enter. Try a fake key, a card number, an email, a password.
  :paste     several lines at once (finish with an empty line)
  :agent     analyse an agent request (JSON with tool calls) instead of plain text
  :text      back to plain text
  :samples   run the three ready-made examples
  :server    look for the ShadowLens server again
  :help      this message          :quit  (or q, or Ctrl+C) to leave
"""


class PreviewError(RuntimeError):
    """The analyzer answered, but with an error. The message is safe to show."""


class ServerUnavailable(RuntimeError):
    """Nobody is answering at the server address."""


@dataclass(frozen=True)
class Style:
    color: bool = False
    glyphs: bool = True

    def shape(self, severity: str) -> str:
        return (_GLYPHS if self.glyphs else _GLYPHS_ASCII).get(severity, "?")

    def rule(self, title: str) -> str:
        line = "─" if self.glyphs else "-"
        text = f" {title} "
        return self.bold(f"{line * 2}{text}{line * max(2, RULE_WIDTH - len(text) - 2)}")

    def bold(self, text: str) -> str:
        return f"\x1b[1m{text}{_RESET}" if self.color else text

    def dim(self, text: str) -> str:
        return f"\x1b[2m{text}{_RESET}" if self.color else text

    def green(self, text: str) -> str:
        return f"\x1b[32m{text}{_RESET}" if self.color else text

    def red(self, text: str) -> str:
        return f"\x1b[1;31m{text}{_RESET}" if self.color else text


def enable_ansi() -> bool:
    """Can this console show colors? On Windows the console has to be asked to."""
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return False
    if os.name != "nt":
        return True
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32                              # type: ignore[attr-defined]
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))   # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    except Exception:  # noqa: BLE001 - when unsure, no colors
        return False


def can_draw_glyphs() -> bool:
    try:
        "◆▲■●─".encode(sys.stdout.encoding or "ascii")
        return True
    except (UnicodeEncodeError, LookupError):
        return False


# ---- asking the analyzer -------------------------------------------------------------------

def _server_call(server: str, path: str, body: dict[str, Any] | None, timeout: float = REQUEST_TIMEOUT_S,
                 method: str | None = None) -> Any:
    request = urllib.request.Request(
        server.rstrip("/") + path, method=method or ("POST" if body is not None else "GET"),
        data=json.dumps(body).encode("utf-8") if body is not None else None,
        headers={"Content-Type": "application/json"})
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:                              # the server answered: with an error
        try:
            message = json.loads(exc.read().decode("utf-8")).get("error", "")
        except (ValueError, OSError):
            message = ""
        raise PreviewError(message or f"the server answered HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
        raise ServerUnavailable(server) from exc


class Analyzer:
    """Asks the running server, or the same analyzer in this process when there is none.

    On Windows a connection to a port nobody listens on takes about two seconds to fail, so the
    server is looked for once and the answer is remembered, not rediscovered for every line.
    """

    def __init__(self, server: str, config: Config):
        self.server = server
        self.config = config
        self.server_up: bool | None = None            # None = not looked yet

    def check(self) -> bool:
        try:
            _server_call(self.server, "/api/health", None, timeout=PROBE_TIMEOUT_S)
            self.server_up = True
        except (ServerUnavailable, PreviewError):
            self.server_up = False
        return self.server_up

    @property
    def where(self) -> str:
        return self.server if self.server_up else "this process (no server is running)"

    def _local(self, text: str, mode: str) -> dict[str, Any]:
        from shadowlens.core.preview import AnalysisUnavailable, build_preview
        from shadowlens.models import AnalyzeMode
        try:
            return build_preview(text, AnalyzeMode(mode), self.config).model_dump(mode="json")
        except AnalysisUnavailable as exc:
            raise PreviewError(str(exc)) from exc

    def preview(self, text: str, mode: str) -> tuple[dict[str, Any], str, float]:
        """``(answer, where it came from, milliseconds)``."""
        if self.server_up is None:
            self.check()
        started = time.perf_counter()
        answer = None
        if self.server_up:
            try:
                answer = _server_call(self.server, "/api/analyze/preview", {"text": text, "mode": mode})
            except ServerUnavailable:
                self.server_up = False                 # it went away while we were talking
        if answer is None:
            answer = self._local(text, mode)
        return answer, self.where, (time.perf_counter() - started) * 1000

    def samples(self) -> dict[str, str]:
        if self.server_up is None:
            self.check()
        if self.server_up:
            try:
                return _server_call(self.server, "/api/analyze/samples", None)
            except ServerUnavailable:
                self.server_up = False
        from shadowlens.fakes import samples as local_samples
        return local_samples()


# ---- showing the answer ------------------------------------------------------------------------

def highlight(text: str, findings: list[dict[str, Any]], style: Style) -> str:
    """The typed text with every match painted. Where matches overlap the smaller one wins."""
    spans = [(row["span"][0], row["span"][1], row["severity"]) for row in findings
             if len(row.get("span", ())) == 2 and 0 <= row["span"][0] < row["span"][1] <= len(text)]
    if not spans or not style.color:
        return text
    paint: list[str | None] = [None] * len(text)
    for start, end, severity in sorted(spans, key=lambda s: s[1] - s[0], reverse=True):
        for index in range(start, end):
            paint[index] = severity
    out: list[str] = []
    current: str | None = None
    for char, severity in zip(text, paint):
        if severity != current:
            if current is not None:
                out.append(_RESET)
            if severity is not None:
                out.append(f"\x1b[{_PAINT.get(severity, _PAINT['info'])}m")
            current = severity
        out.append(char)
    if current is not None:
        out.append(_RESET)
    return "".join(out)


def render(text: str, answer: dict[str, Any], *, ms: float, where: str, style: Style) -> str:
    findings = sorted(answer.get("findings", []), key=lambda r: (-_RANK.get(r["severity"], 0), r["span"][0]))
    lines = [style.rule("YOU TYPED"), highlight(text, findings, style), ""]

    # One line per distinct finding: the same value twice is still one problem.
    shown: dict[tuple[str, str], tuple[dict[str, Any], int]] = {}
    for row in findings:
        key = (row["rule_id"], row["masked_preview"])
        shown[key] = (row, shown[key][1] + 1) if key in shown else (row, 1)
    lines.append(style.rule(f"WHAT WAS FOUND ({len(shown)})"))
    if not shown:
        lines.append(style.green("  nothing sensitive found"))
    for row, count in shown.values():
        mark = f"{style.shape(row['severity'])} {row['severity']:<8}"
        times = f"  x{count}" if count > 1 else ""
        lines.append(f"  {mark} {row['title']:<58.58} {row['masked_preview']}{times}")
    lines.append("")

    lines += [style.rule("WHAT THE AI MODEL WOULD RECEIVE"), style.green(answer["redacted_text"]), ""]

    points = answer.get("points_preview", {})
    verdict = style.red("WOULD BE BLOCKED") if answer.get("would_block") else style.green("would not be blocked")
    lines.append(f"  egress guard: {verdict}      "
                 f"risk this adds: {style.bold(str(points.get('tool_score', 0)) + '/100')} "
                 f"(S = {points.get('S', 0)})")
    lines.append(style.dim(f"  analysed in {ms:.0f} ms by {where}. Nothing typed here is stored."))
    return "\n".join(lines)


# ---- the loop ----------------------------------------------------------------------------------------

def read_paste(read: Callable[[str], str]) -> str:
    lines: list[str] = []
    while True:
        line = read("  ... " if lines else "  paste, finish with an empty line > ")
        if not line.strip():
            return "\n".join(lines)
        lines.append(line)


def _announce(analyzer: Analyzer, style: Style) -> str:
    if analyzer.server_up:
        return style.dim(f"  connected to the ShadowLens server at {analyzer.server}")
    return style.dim("  no ShadowLens server found: using the same analyzer inside this program")


def run(analyzer: Analyzer, style: Style, mode: str = "text",
        read: Callable[[str], str] | None = None, write: Callable[[str], None] = print) -> int:
    read = read or input                               # looked up now, not when this file was loaded
    if analyzer.server_up is None:                     # look once; ":server" looks again
        analyzer.check()
    write(style.bold("ShadowLens Leak Lab") + style.dim("   type :help for commands, :quit to leave"))
    write(_announce(analyzer, style))
    while True:
        try:
            text = read(f"leak lab ({'agent json' if mode == 'agent_json' else 'text'}) > ")
        except (EOFError, KeyboardInterrupt):
            write("")
            return 0
        text = text.lstrip("﻿")                   # a byte-order mark that a paste from Notepad can carry
        command = text.strip().lower()
        if command in (":quit", ":q", "q", "quit", "exit"):
            return 0
        if command == ":help":
            write(HELP)
            continue
        if command == ":server":
            analyzer.check()
            write(_announce(analyzer, style))
            continue
        if command in (":agent", ":text"):
            mode = "agent_json" if command == ":agent" else "text"
            write(style.dim(f"  analysing {'agent requests' if mode == 'agent_json' else 'plain text'} now"))
            continue
        if command == ":samples":
            try:
                ready = analyzer.samples()
            except PreviewError as exc:
                write(style.red(f"  could not get the samples: {exc}"))
                continue
            for name, sample_mode in (("key", "text"), ("pii", "text"), ("agent", "agent_json")):
                if name in ready:
                    write(style.bold(f"\n● example: {name}"))
                    _show(ready[name], sample_mode, analyzer, style, write)
            continue
        if command == ":paste":
            text = read_paste(read)
        if not text.strip():
            continue
        _show(text, mode, analyzer, style, write)
        write("")


def _show(text: str, mode: str, analyzer: Analyzer, style: Style, write: Callable[[str], None]) -> None:
    try:
        answer, where, ms = analyzer.preview(text, mode)
    except PreviewError as exc:
        write(style.red(f"  could not analyse that: {exc}"))
        return
    except Exception as exc:  # noqa: BLE001 - one bad answer must not end the demo
        write(style.red(f"  something went wrong ({type(exc).__name__}); the server may need a restart"))
        return
    write(render(text, answer, ms=ms, where=where, style=style))


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stdin):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description="Type anything and see what ShadowLens finds.")
    config = Config.load()
    parser.add_argument("--server", default=config.server_url, help="the running ShadowLens server")
    parser.add_argument("--agent", action="store_true", help="start in agent-request mode")
    parser.add_argument("--color", choices=("auto", "always", "never"), default="auto")
    args = parser.parse_args(argv)
    color = {"always": True, "never": False}.get(args.color)
    style = Style(color=enable_ansi() if color is None else color, glyphs=can_draw_glyphs())
    return run(Analyzer(args.server, config), style, "agent_json" if args.agent else "text")


if __name__ == "__main__":
    raise SystemExit(main())

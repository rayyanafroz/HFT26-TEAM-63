"""A guided demo of ShadowLens in one terminal.

    python -m scenarios.demo [--server URL] [--replays] [--only laptop,lab] [--speed 1.0] [--auto]

It drives the RUNNING ShadowLens server through its real API and shows the live event feed inline,
so there is nothing to paste and no second terminal to watch. Start the server first:

    python -m shadowlens --browser

By default every step is live:

  laptop    what AI is on THIS machine (running, installed, extensions) and which of it is talking to
            its provider right now. Nothing here is scripted: it is read from the machine.
  sockets   a stand-in local model starts here and a program leaks a key to it over real connections.
  lab       the audience types anything and sees what ShadowLens finds.

``--replays`` adds three recorded scenarios (leak, organisation, agent) for when nothing live is
possible, or to show the 52-point headline. They are labelled [REPLAY]: the traffic was written ahead
of time (scenarios/generate.py); the detection, scoring and feed that process it are the real application.

The first step resets the data on the server, so you are asked before it starts (``--auto`` skips that).
"""

from __future__ import annotations

import argparse
import http.client
import json
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Callable

from scenarios import agent_sim
from scenarios.leak_lab import (
    _OPENER,
    Analyzer,
    PreviewError,
    ServerUnavailable,
    Style,
    _server_call,
    can_draw_glyphs,
    enable_ansi,
    run as run_leak_lab,
)
from scenarios.mock_ollama import MockOllamaServer
from shadowlens.config import Config
from shadowlens.fakes import fake
from shadowlens.ingest import inventory

# (key, title, tag, what to say before it starts), in the order they run
STEPS = (
    ("laptop", "YOUR LAPTOP: WHAT AI IS HERE", "LIVE",
     "ShadowLens looks at this machine: what is running, installed or left behind, and what is talking to its provider."),
    ("sockets", "A LEAK OVER REAL CONNECTIONS", "LIVE SOCKETS",
     "A stand-in local model starts on this machine and a program sends it a key over a real connection."),
    ("leak", "A LEAK, AS IT HAPPENS", "REPLAY",
     "A script sends 12 requests to OpenAI and one of them holds an AWS secret key."),
    ("org", "A WHOLE ORGANISATION", "REPLAY",
     "120 requests from 10 invented tools. Then a provider is approved and every score is recalculated."),
    ("agent", "A ROGUE AGENT", "REPLAY",
     "An autonomous agent starts with ordinary work, then reads password files and deletes things."),
    ("lab", "LEAK LAB: TYPE ANYTHING", "LIVE",
     "Type or paste anything. Nothing is scripted and nothing is stored."),
)
KEYS = tuple(key for key, *_ in STEPS)
RESETS = frozenset({"laptop", "sockets", "leak", "org", "agent"})        # the steps that clear the server's data
FEED_TIMEOUT_S = 30.0
SETTLE_S = 1.0
MODEL_PORTS = (11434, 11435)        # the ports the provider catalog knows as Ollama (SOT 12.2)


class StopDemo(Exception):
    """The presenter asked to stop."""


def plan(replays: bool) -> list[str]:
    """The steps a normal run takes: the live ones, or all of them (the lab always last)."""
    return [key for key, _, tag, _ in STEPS if replays or tag != "REPLAY"]


def post_file(server: str, path: str, name: str, data: bytes) -> Any:
    """Upload a file the way a browser form does (``multipart/form-data``)."""
    boundary = "shadowlens" + uuid.uuid4().hex
    body = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{name}"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n").encode() + data + f"\r\n--{boundary}--\r\n".encode()
    request = urllib.request.Request(server.rstrip("/") + path, data=body, method="POST",
                                     headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    try:
        with _OPENER.open(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise PreviewError(f"the server answered HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
        raise ServerUnavailable(server) from exc


class Feed:
    """The server's live event stream (``/api/stream``), printed as it arrives."""

    def __init__(self, server: str, show: Callable[[str, dict[str, Any]], None]):
        self.server = server
        self.show = show
        self._connection: http.client.HTTPConnection | None = None
        self._response: Any = None
        self._thread: threading.Thread | None = None

    def __enter__(self) -> "Feed":
        # http.client, not urllib: it keeps hold of the socket, and the socket is how we stop reading.
        # (Closing the response from another thread waits for the server's next 15 s heartbeat.)
        address = urllib.parse.urlsplit(self.server)
        self._connection = http.client.HTTPConnection(address.hostname, address.port, timeout=FEED_TIMEOUT_S)
        try:
            self._connection.request("GET", "/api/stream", headers={"Accept": "text/event-stream"})
            self._response = self._connection.getresponse()            # subscribed before anything starts
        except OSError as exc:
            self._connection.close()
            raise ServerUnavailable(self.server) from exc
        self._thread = threading.Thread(target=self._read, name="demo-feed", daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        time.sleep(SETTLE_S / 2)                  # let the last messages reach the screen
        sock = getattr(self._connection, "sock", None)
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)   # wakes the blocked reader at once
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=3)
        if self._connection is not None:
            self._connection.close()

    def _read(self) -> None:
        event: str | None = None
        data: list[str] = []
        try:
            for raw in iter(self._response.readline, b""):
                line = raw.decode("utf-8", "replace").rstrip("\r\n")
                if line.startswith(":"):
                    continue
                if line == "":
                    if event and data:
                        try:
                            self.show(event, json.loads("\n".join(data)))
                        except ValueError:
                            pass
                    event, data = None, []
                elif line.startswith("event:"):
                    event = line[6:].strip()
                elif line.startswith("data:"):
                    data.append(line[5:].lstrip())
        except (OSError, ValueError, AttributeError):
            return                                # closed by __exit__, or the server went away


class Demo:
    def __init__(self, server: str, config: Config, style: Style, *, speed: float = 1.0, auto: bool = False,
                 read: Callable[[str], str] | None = None, write: Callable[[str], None] = print,
                 model_ports: tuple[int, ...] = MODEL_PORTS, sim_count: int = 5, sim_interval: float = 3.0,
                 look_at_machine: Callable[[], inventory.InventoryResult] = inventory.scan):
        self.server, self.config, self.style = server, config, style
        self.speed, self.auto = speed, auto
        self.read, self.write = read, write
        self.model_ports, self.sim_count, self.sim_interval = model_ports, sim_count, sim_interval
        self.look_at_machine = look_at_machine
        self._lock = threading.Lock()
        self._last_risk: int | None = None
        self._focus_on: set[str] | None = None        # provider ids whose address-only events may be shown
        self._plan: list[str] = list(KEYS)

    # ---- small helpers --------------------------------------------------------------------

    def say(self, text: str = "") -> None:
        with self._lock:
            self.write(text)

    def api(self, path: str, body: dict[str, Any] | None = None, method: str | None = None) -> Any:
        return _server_call(self.server, path, body, timeout=30, method=method)

    def pause(self, message: str) -> None:
        if self.auto:
            return
        answer = (self.read or input)(self.style.dim(f"  {message} (Enter to continue, q to stop) ")).strip().lower()
        if answer in ("q", "quit", "stop", ":q"):
            raise StopDemo

    def reset(self) -> None:
        self.api("/api/demo/reset", {})
        self._last_risk = None

    def header(self, key: str) -> None:
        _, title, tag, blurb = next(step for step in STEPS if step[0] == key)
        position = self._plan.index(key) + 1 if key in self._plan else 1
        self.say()
        self.say(self.style.rule(f"{position} / {len(self._plan)}  {title}"))
        self.say(f"  {self.style.bold('[' + tag + ']')} {blurb}")
        self.say()

    def table(self, headers: list[str], rows: list[list[str]], widths: list[int]) -> None:
        def line(cells: list[str]) -> str:
            return "  " + "  ".join(f"{cell:<{width}.{width}}" for cell, width in zip(cells, widths))
        self.say(self.style.dim(line(headers)))
        for row in rows:
            self.say(line(row))

    # ---- the live feed ---------------------------------------------------------------------

    def _on_message(self, kind: str, data: dict[str, Any]) -> None:
        s = self.style
        if kind == "event.new":
            if (self._focus_on is not None and data.get("visibility") != "full"
                    and data.get("provider_id") not in self._focus_on):
                return              # a guess about some other program on this laptop: not part of this step
            where = data.get("host") or f"{data.get('dst_ip')}:{data.get('dst_port')}"
            seen = "content read" if data.get("visibility") == "full" else "address only"
            self.say(s.dim(f"    request   {data.get('tool_id', '?'):<24} {data.get('method') or ''} "
                           f"{where}{data.get('path') or ''}  ({seen})"))
        elif kind == "finding.new" and data.get("category") != "policy":
            line = f"    {s.shape(data['severity'])} FOUND   {data['rule_id']:<26} {data['masked_preview']}  in {data['tool_id']}"
            self.say(s.red(line) if data["severity"] in ("high", "critical") else line)
        elif kind == "alert.new":
            self.say(s.bold(f"    ALERT     {data['title']}"))
        elif kind == "score.update":
            risk = data.get("risk", {}).get("org_risk")
            if risk is not None and risk != self._last_risk:
                self._last_risk = risk
                self.say(s.bold(f"    RISK now  {risk}/100 ({data['risk'].get('band')})"))

    # ---- shared output ------------------------------------------------------------------------

    def _show_alerts(self) -> None:
        alerts = self.api("/api/alerts?limit=50")["items"]
        self.say(self.style.dim(f"  {len(alerts)} alert(s):"))
        for alert in alerts:
            masked = alert["finding"]["masked_preview"]
            self.say(f"    {self.style.shape(alert['severity'])} {alert['severity']:<9} {alert['title']:<58.58} "
                     f"{alert['tool_id']}  {masked}")

    def _tools_table(self, only_confirmed: bool = False) -> list[dict[str, Any]]:
        everything = sorted(self.api("/api/tools")["items"], key=lambda t: t["risk"], reverse=True)
        tools = [t for t in everything if not (only_confirmed and t.get("unconfirmed"))]
        self.table(["TOOL", "RISK", "BAND", "APPROVED", "MATCH", "READ"],
                   [[t["tool_id"], str(t["risk"]), t["risk_band"], "yes" if t["sanctioned"] else "no",
                     "unconfirmed" if t.get("unconfirmed") else "confirmed",
                     f"{t['visibility']['full']} full, {t['visibility']['metadata_only']} address"]
                    for t in tools], [30, 5, 9, 9, 12, 20])
        if len(everything) > len(tools):
            self.say(self.style.dim(f"  ({len(everything) - len(tools)} unconfirmed guess(es) about other programs "
                                    f"on this laptop are left out here)"))
        return tools

    # ---- the live steps -------------------------------------------------------------------------

    def step_laptop(self) -> None:
        self.header("laptop")
        s = self.style
        found = self.look_at_machine()
        self.say(s.dim("  Looked at: " + "; ".join(found.looked_at) + "."))
        for note in found.warnings + found.errors:
            self.say(s.red(f"  note: {note}"))
        self.say()
        if not found.tools:
            self.say("  No known AI tool was found on this machine.")
        for tool in found.tools:
            label = {"running": s.green("running  "), "installed": "installed", "traces": s.dim("traces   ")}[tool.status]
            self.say(f"  {label}  {s.bold(tool.name)}  {s.dim('(' + tool.kind + ')')}")
            for item in tool.evidence:
                self.say(s.dim(f"      {item.kind:<18} {item.detail}"))
            self._show_connections(tool)
        self.say()
        self.say(s.dim("  Not looked at: " + "; ".join(found.not_covered) + "."))

        records = inventory.connection_records(found)
        self.reset()
        if not records:
            self.say()
            self.say("  Nothing found is talking to its provider right now, so there is nothing to record.")
            return
        summary = post_file(self.server, "/api/ingest/log", "laptop.jsonl",
                            "\n".join(json.dumps(r) for r in records).encode("utf-8"))
        risk = self.api("/api/stats/summary")["risk"]
        self.say()
        self.say(f"  {len(records)} confirmed connection(s) were given to ShadowLens like any other traffic: "
                 f"{summary['accepted']} recorded, {summary['findings']} finding(s), {summary['alerts']} alert(s).")
        self.say(s.dim("  Each was recorded as a CONNECT: the connection was observed, no request was seen, nothing was read."))
        self.say()
        self._tools_table(only_confirmed=True)
        self._show_alerts()
        self.say(f"  AI risk for this laptop: {s.bold(str(risk['org_risk']) + '/100')} ({risk['band']}).")

    def _show_connections(self, tool: inventory.FoundTool) -> None:
        for conn in dict.fromkeys((c.host, c.ip, c.port) for c in tool.verified):
            host, ip, port = conn
            self.say(self.style.green(f"      network            connected to {host} ({ip}:{port}), confirmed"))
        others = len({(c.ip, c.port) for c in tool.connections if not c.host})
        if others:
            self.say(self.style.dim(f"      network            also connected to {others} other address(es), "
                                    f"not tied to its provider"))

    def _start_model(self, live_dir: Path) -> tuple[MockOllamaServer | None, int | None]:
        live_dir.mkdir(parents=True, exist_ok=True)
        for port in self.model_ports:
            try:
                server = MockOllamaServer(port, live_dir / "ollama.jsonl")
            except OSError:
                continue
            threading.Thread(target=server.serve_forever, name="demo-model", daemon=True).start()
            return server, port
        return None, None

    def step_live_sockets(self) -> None:
        self.header("sockets")
        self.reset()
        status = self.api("/api/capture/start", {"tail": True})
        live_dir = Path(status["live_tail"]["dir"])
        model, port = self._start_model(live_dir)
        if model is None:
            self.say("  Skipped: ports " + " and ".join(map(str, self.model_ports)) + " are in use "
                     "(a real Ollama?). Stop it for this step, or point the demo at another port.")
            return
        self._focus_on = {p["provider_id"] for p in self.api("/api/providers")["items"] if p["category"] == "local_llm"}
        try:
            self.say(f"  Stand-in model listening on 127.0.0.1:{port}. A program now sends it a prompt with a key:")
            with Feed(self.server, self._on_message):
                sim = threading.Thread(
                    target=agent_sim.run, args=(port, self.sim_count, self.sim_interval),
                    kwargs={"report": lambda line: self.say(self.style.dim(f"    client    {line}"))},
                    name="demo-client", daemon=True)
                sim.start()
                scanned = False
                while sim.is_alive():
                    time.sleep(min(1.0, max(self.sim_interval / 2, 0.2)))
                    result = self.api("/api/scan/connections", {})       # the real process scan
                    if result["accepted"] and not scanned:
                        scanned = True
                        self.say(self.style.bold("    SCAN      found a program connected to a local model server"))
                time.sleep(SETTLE_S * 2)                                   # the log tail polls twice a second
        finally:
            self._focus_on = None
            model.shutdown()
            model.server_close()
        self.say()
        self._tools_table(only_confirmed=True)
        self._show_alerts()

    def step_leak_lab(self) -> None:
        self.header("lab")
        self.say(self.style.dim("  Try: a fake API key, a card number such as 4111 1111 1111 1111, an email, "
                                "password=Hunter2024"))
        analyzer = Analyzer(self.server, self.config)
        run_leak_lab(analyzer, self.style, read=self.read, write=self.say)

    # ---- the recorded steps -------------------------------------------------------------------------

    def step_leak(self) -> None:
        self.header("leak")
        self.reset()
        with Feed(self.server, self._on_message):
            played = self.api("/api/demo/play", {"name": "quick_leak", "speed": self.speed})
            time.sleep(float(played["duration_s"]) + SETTLE_S)
        s = self.style
        summary = self.api("/api/stats/summary")
        self.say()
        self.say(f"  Result: AI risk {s.bold(str(summary['risk']['org_risk']) + '/100')} ({summary['risk']['band']})")
        self._show_alerts()
        explain = self.api("/api/score/explain")
        self.say(s.dim("  How the score was worked out:"))
        for item in explain["items"]:
            self.say(f"    {item['rule_id']:<26} {item['severity']:<9} {item['points']:>6.1f} points")
        self.say(f"    total S = {explain['S']}  ->  tool score {explain['score']}/100")
        secret = fake("aws_secret_key", 1)                            # the key this scenario leaks
        served = "".join(json.dumps(self.api(f"/api/{name}?limit=1000")) for name in ("events", "findings", "alerts"))
        verdict = s.green("not found") if secret not in served else s.red("FOUND, this is a bug")
        self.say(f"  Check: the real key in everything ShadowLens stores and serves: {verdict}")

    def step_org(self) -> None:
        self.header("org")
        self.reset()
        loaded = self.api("/api/demo/load-scenario", {"name": "full_demo"})
        summary = self.api("/api/stats/summary")
        self.say(f"  {loaded['accepted']} requests, {loaded['findings']} findings, {loaded['alerts']} alerts. "
                 f"AI risk {self.style.bold(str(summary['risk']['org_risk']) + '/100')} ({summary['risk']['band']})")
        self.say()
        tools = self._tools_table()
        candidates = [t for t in tools if not t["sanctioned"] and not t.get("unconfirmed")]
        if not candidates:
            return
        provider = candidates[0]["tool_id"].split("|")[1]
        before = summary["risk"]["org_risk"]
        approved = self.api(f"/api/providers/{provider}/sanction", {"sanctioned": True}, method="PUT")
        self.say()
        self.say(f"  Approve {self.style.bold(provider)} (the riskiest unapproved tool): "
                 f"AI risk {before} -> {self.style.bold(str(approved['risk']['org_risk']))}, recalculated for everything.")
        restored = self.api(f"/api/providers/{provider}/sanction", {"sanctioned": False}, method="PUT")
        self.say(self.style.dim(f"  Approval taken back again: AI risk {restored['risk']['org_risk']}."))

    def step_agent(self) -> None:
        self.header("agent")
        self.reset()
        loaded = self.api("/api/demo/load-scenario", {"name": "agent_attack"})
        agents = self.api("/api/agents")["items"]
        if not agents:
            self.say("  no agent activity was recorded")
            return
        row = agents[0]
        self.say(f"  {row['tool_id']}: {loaded['findings']} findings, risk {row['risk']}/100 ({row['risk_band']})")
        self.say(self.style.dim("  What it did, in order:"))
        steps: dict[tuple[str, str | None, str | None], list[str]] = {}
        risky: dict[tuple[str, str | None, str | None], bool] = {}
        for act in row["activity"]:
            if act["kind"] != "used":
                continue
            key = (act["name"], act.get("argument"), act.get("rule_id"))
            steps.setdefault(key, []).append(act["capability"])
            risky[key] = risky.get(key, False) or act["risky"]
        for key, capabilities in steps.items():
            name, argument, rule = key
            mark = self.style.shape("high") if risky[key] else " "
            text = f"    {mark} {name:<10} {(argument or '')[:52]:<52}  {', '.join(capabilities)}"
            self.say(self.style.red(text + f"  [{rule}]") if risky[key] else text)
        self.say()
        self.say(self.style.dim("  What it was allowed to do, and what it did:"))
        self.table(["PERMISSION", "DECLARED", "USED", "RISKY", ""],
                   [[name, "yes" if c["granted"] else "no", "yes" if c["used"] else "no",
                     "yes" if c["risky"] else "no",
                     "used without being declared" if c["used"] and not c["granted"] else ""]
                    for name, c in row["capabilities"].items()], [16, 9, 6, 6, 30])

    # ---- running them -----------------------------------------------------------------------

    def run(self, chosen: list[str]) -> int:
        s = self.style
        try:
            health = self.api("/api/health")
        except (ServerUnavailable, PreviewError):
            self.say(s.red(f"  No ShadowLens server answered at {self.server}."))
            self.say(f"  Start it in another terminal, then run this again:\n\n      {sys.executable} -m shadowlens --browser\n")
            return 2
        self._plan = chosen
        self.say(s.bold("ShadowLens demo") + s.dim(f"   server {self.server}   AI advice: {health['llm']['mode']} mode"))
        self.say(s.dim("  [LIVE] this laptop, now   [LIVE SOCKETS] real connections, stand-in model   "
                       "[REPLAY] recorded traffic, real analysis"))
        actions = {"laptop": self.step_laptop, "sockets": self.step_live_sockets, "leak": self.step_leak,
                   "org": self.step_org, "agent": self.step_agent, "lab": self.step_leak_lab}
        first_reset = next((key for key in chosen if key in RESETS), None)
        try:
            for key in chosen:
                title = next(step[1] for step in STEPS if step[0] == key)
                warning = " This clears the demo data on the server." if key == first_reset else ""
                self.pause(f"Next: {title.lower()}.{warning}")
                try:
                    actions[key]()
                except StopDemo:
                    raise
                except (PreviewError, ServerUnavailable) as exc:
                    self.say(s.red(f"  This step could not finish: {exc}"))
                except Exception as exc:  # noqa: BLE001 - one broken step must not end the demo
                    self.say(s.red(f"  This step failed ({type(exc).__name__}); carrying on."))
        except StopDemo:
            self.say(s.dim("\n  Stopped."))
            return 0
        self.say(s.dim("\n  Done. The data from the last step is still on the server."))
        return 0


def parse_steps(text: str) -> list[str]:
    chosen = []
    for part in text.split(","):
        part = part.strip().lower()
        if not part:
            continue
        if part not in KEYS:
            raise argparse.ArgumentTypeError(f"steps are {', '.join(KEYS)}; not {part!r}")
        chosen.append(part)
    return chosen


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stdin):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    config = Config.load()
    parser = argparse.ArgumentParser(description="A guided demo of ShadowLens.")
    parser.add_argument("--server", default=config.server_url)
    parser.add_argument("--replays", action="store_true", help="also run the three recorded scenarios")
    parser.add_argument("--only", type=parse_steps, help=f"comma list of steps to run: {', '.join(KEYS)}")
    parser.add_argument("--speed", type=float, default=1.0, help="how fast the recorded leak plays (1 = real time)")
    parser.add_argument("--auto", action="store_true", help="no pauses and no Leak Lab (for testing)")
    parser.add_argument("--color", choices=("auto", "always", "never"), default="auto")
    args = parser.parse_args(argv)
    if args.speed <= 0:
        parser.error("--speed must be above 0")
    color = {"always": True, "never": False}.get(args.color)
    style = Style(color=enable_ansi() if color is None else color, glyphs=can_draw_glyphs())
    chosen = args.only or plan(args.replays)
    if args.auto and args.only is None:
        chosen = [key for key in chosen if key != "lab"]          # the lab needs a keyboard
    return Demo(args.server, config, style, speed=args.speed, auto=args.auto).run(chosen)


if __name__ == "__main__":
    raise SystemExit(main())

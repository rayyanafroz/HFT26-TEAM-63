"""The guided demo, run against a real server on a real port, with nothing stubbed (SOT 12.1).

Where the demo reads this machine, the tests give it a pretend machine built from real files and the
real scanning code; one test reads the real machine.
"""

import json
import re
import socket
import threading
import time

import pytest
import uvicorn
import yaml

from scenarios import demo
from scenarios.demo import KEYS, STEPS, Demo, Feed, StopDemo, parse_steps, plan, post_file
from scenarios.leak_lab import Style
from shadowlens.api.app import create_app
from shadowlens.config import Config
from shadowlens.fakes import fake
from shadowlens.ingest import inventory
from shadowlens.ingest.inventory import RunningProgram, load_signatures
from shadowlens.providers.catalog import Catalog

PLAIN = Style(color=False, glyphs=True)


@pytest.fixture
def config(tmp_path):
    return Config.load(env={"SHADOWLENS_RESOLVE": "false", "SHADOWLENS_LIVE_DIR": str(tmp_path / "live")},
                       base_dir=tmp_path, use_dotenv=False)


@pytest.fixture
def server(config, tmp_path):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    instance = uvicorn.Server(uvicorn.Config(create_app(config, ui_dir=tmp_path / "none"), host="127.0.0.1",
                                             port=port, log_level="warning", lifespan="on"))
    thread = threading.Thread(target=instance.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 15
    while not instance.started and time.monotonic() < deadline:
        time.sleep(0.02)
    assert instance.started
    yield f"http://127.0.0.1:{port}"
    instance.should_exit = True
    thread.join(timeout=10)


@pytest.fixture
def make(server, config):
    def build(**kw):
        out = []
        kw.setdefault("speed", 50.0)
        kw.setdefault("auto", True)
        return Demo(server, config, PLAIN, write=out.append, **kw), out
    return build


def text(out):
    return "\n".join(out)


def api(server, path, body=None, method=None):
    return demo._server_call(server, path, body, method=method)


# ---- the laptop step ---------------------------------------------------------------------------------

CLAUDE = {"id": "claude_code", "name": "Claude Code", "kind": "coding agent", "provider": "anthropic",
          "processes": [{"name": "claude", "exe_contains": ["anthropic.claude-code"]}],
          "vscode_extensions": ["anthropic.claude-code"], "folders": ["~/.claude"]}
COPILOT = {"id": "github_copilot", "name": "GitHub Copilot", "kind": "coding assistant", "provider": "copilot",
           "processes": [{"name": "copilot-runtime"}]}
OLLAMA = {"id": "ollama", "name": "Ollama", "kind": "local model server", "provider": "ollama",
          "processes": [{"name": "ollama"}]}


@pytest.fixture
def pretend_machine(tmp_path):
    """A machine with Claude Code running and talking to Anthropic, Copilot idle, and a leftover folder."""
    home = tmp_path / "home"
    (home / ".vscode/extensions/anthropic.claude-code-2.1.314-win32-x64").mkdir(parents=True)
    (home / ".claude").mkdir()
    (home / ".leftover").mkdir()
    path = tmp_path / "ai_tools.yaml"
    left = {"id": "leftover_tool", "name": "Leftover Tool", "kind": "coding agent", "folders": ["~/.leftover"]}
    path.write_text(yaml.safe_dump({
        "tools": [CLAUDE, COPILOT, OLLAMA, left],
        "editors": [{"name": "VS Code", "extensions_dir": "~/.vscode/extensions"}]}), encoding="utf-8")

    def look(programs=None, connections=None):
        claude_exe = str(home / ".vscode/extensions/anthropic.claude-code-2.1.314-win32-x64/claude.exe")
        return inventory.scan(
            load_signatures(path), catalog=Catalog.load(), home=home, env={"PATH": ""},
            programs=lambda: programs if programs is not None else [
                RunningProgram(7, "claude", claude_exe), RunningProgram(8, "copilot-runtime", None),
                RunningProgram(9, "notepad", None)],
            apps=lambda: [], which=lambda c: None,
            connections=lambda: connections if connections is not None else [(7, "160.79.104.10", 443), (7, "9.9.9.9", 443)],
            resolve=lambda host: {"160.79.104.10"} if host == "api.anthropic.com" else set())
    return look


def test_the_laptop_step_lists_what_is_there_with_its_evidence(make, pretend_machine):
    d, out = make(look_at_machine=pretend_machine)
    d.step_laptop()
    shown = text(out)
    assert "1 / 6" in shown or "1 / " in shown
    assert re.search(r"running\s+Claude Code", shown) and re.search(r"running\s+GitHub Copilot", shown)
    assert re.search(r"traces\s+Leftover Tool", shown) and "last changed" in shown
    assert "VS Code extension anthropic.claude-code 2.1.314-win32-x64" in shown
    assert "Looked at: 3 running programs" in shown
    assert "Not looked at: Python and Node packages" in shown and "browser tab" in shown


def test_it_never_names_a_program_it_did_not_find(make, pretend_machine):
    d, out = make(look_at_machine=lambda: pretend_machine(programs=[RunningProgram(1, "notepad", None)], connections=[]))
    d.step_laptop()
    shown = text(out)
    assert not re.search(r"running\s+Claude Code", shown) and not re.search(r"running\s+Ollama", shown)
    assert "Nothing found is talking to its provider right now" in shown


def test_a_confirmed_connection_is_recorded_and_scored_through_the_real_pipeline(make, server, pretend_machine):
    d, out = make(look_at_machine=pretend_machine)
    d.step_laptop()
    shown = text(out)
    assert "connected to api.anthropic.com (160.79.104.10:443), confirmed" in shown
    assert "also connected to 1 other address(es), not tied to its provider" in shown
    assert re.search(r"claude\|anthropic\s+\d+\s+\w+\s+no\s+confirmed", shown)
    assert "Unapproved AI tool in use: Anthropic" in shown and "AI risk for this laptop: 5/100" in shown
    tools = api(server, "/api/tools")["items"]
    assert [t["tool_id"] for t in tools] == ["claude|anthropic"] and tools[0]["confidence"] == "high"
    assert tools[0]["visibility"] == {"full": 0, "metadata_only": 1}                # nothing was read


def test_several_connections_to_one_address_are_one_line(make, pretend_machine):
    d, out = make(look_at_machine=lambda: pretend_machine(connections=[(7, "160.79.104.10", 443)] * 3))
    d.step_laptop()
    assert text(out).count("connected to api.anthropic.com") == 1


def test_the_other_connection_is_not_given_to_shadowlens(make, server, pretend_machine):
    d, _ = make(look_at_machine=pretend_machine)
    d.step_laptop()
    events = api(server, "/api/events")["items"]
    assert [(e["dst_ip"], e["process"]) for e in events] == [("160.79.104.10", "claude")]


def test_a_local_model_server_is_recorded_by_its_port(make, server, pretend_machine):
    d, out = make(look_at_machine=lambda: pretend_machine(
        programs=[RunningProgram(3, "ollama", None)], connections=[(3, "127.0.0.1", 11434)]))
    d.step_laptop()
    assert "connected to localhost:11434 (127.0.0.1:11434), confirmed" in text(out)
    tool = api(server, "/api/tools")["items"][0]
    assert tool["tool_id"] == "ollama|ollama" and tool["category"] == "local_llm"


def test_the_step_clears_old_data_first(make, server, pretend_machine):
    api(server, "/api/demo/load-scenario", {"name": "agent_attack"})
    d, _ = make(look_at_machine=pretend_machine)
    d.step_laptop()
    assert {t["tool_id"] for t in api(server, "/api/tools")["items"]} == {"claude|anthropic"}


def test_the_laptop_step_on_this_real_machine_runs(make, server):
    d, out = make()
    d.step_laptop()
    shown = text(out)
    assert "Looked at:" in shown and "Not looked at:" in shown
    assert re.search(r"Looked at: \d+ running programs", shown)
    assert "carrying on" not in shown and "could not finish" not in shown


def test_post_file_uploads_a_log(server):
    line = {"ts": "2026-10-31T10:00:00Z", "host": "api.openai.com", "method": "POST", "path": "/v1"}
    summary = post_file(server, "/api/ingest/log", "x.jsonl", json.dumps(line).encode())
    assert summary["accepted"] == 1


# ---- the recorded steps ---------------------------------------------------------------------------------

def test_the_leak_ramps_to_the_score_the_sot_promises_and_the_feed_is_live(make, server):
    # Slow enough for the score publisher (it updates at most every 250 ms) to show the climb.
    d, out = make(speed=4.0)
    d.step_leak()
    shown = text(out)
    assert "RISK now  5/100" in shown and "RISK now  52/100 (high)" in shown       # AT-08
    assert shown.index("RISK now  5/100") < shown.index("FOUND") < shown.index("RISK now  52/100")
    assert "AWS secret access key sent to an AI tool" in shown and "TyRb... (len 40)" in shown
    assert "total S = 58.5  ->  tool score 52/100" in shown
    assert "not found" in shown.split("Check:")[1]


def test_the_real_key_is_nowhere_in_the_output_or_the_server(make, server):
    d, out = make()
    d.step_leak()
    secret = fake("aws_secret_key", 1)
    assert secret not in text(out)
    served = "".join(json.dumps(api(server, f"/api/{name}?limit=1000")) for name in ("events", "findings", "alerts"))
    assert secret not in served


def test_the_organisation_step_recalculates_and_then_restores(make, server):
    d, out = make()
    d.step_org()
    shown = text(out)
    assert "120 requests" in shown and "AI risk 77/100 (critical)" in shown
    assert re.search(r"Approve openai .*77 -> 68", shown) and "Approval taken back again: AI risk 77" in shown
    assert api(server, "/api/stats/summary")["risk"]["org_risk"] == 77            # the demo leaves no change behind


def test_the_agent_step_shows_the_attack_in_order(make):
    d, out = make()
    d.step_agent()
    shown = text(out)
    order = [shown.index(marker) for marker in ("src/main.py", "/etc/passwd", ".env", "printenv", "rm -rf ~")]
    assert order == sorted(order)
    assert "[AGENT_DANGEROUS_CMD]" in shown and "used without being declared" in shown
    assert re.search(r"network\s+no\s+yes\s+yes", shown) and re.search(r"shell\s+yes\s+yes\s+yes", shown)


# ---- real connections ---------------------------------------------------------------------------------------

@pytest.fixture
def model_ports_free():
    for port in (11434, 11435):
        with socket.socket() as probe:
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                pytest.skip(f"port {port} is in use (a real Ollama?)")


def test_live_sockets_catch_the_key_and_name_the_program(make, server, model_ports_free):
    d, out = make(sim_count=3, sim_interval=0.6)
    d.step_live_sockets()
    shown = text(out)
    assert "SEC_OPENAI_KEY" in shown and "sk-p... (len 51)" in shown
    assert re.search(r"python\|ollama\s+\d+\s+\w+\s+yes\s+confirmed", shown)
    assert "SCAN      found a program connected to a local model server" in shown
    assert fake("openai_key", 0) not in shown
    assert api(server, "/api/findings?rule_id=SEC_OPENAI_KEY")["total"] == 1


def test_the_stand_in_model_is_gone_afterwards(make, model_ports_free):
    d, _ = make(sim_count=2, sim_interval=0.3)
    d.step_live_sockets()
    with socket.socket() as probe:
        assert probe.connect_ex(("127.0.0.1", 11434)) != 0


def test_busy_ports_skip_the_step_with_a_reason(make):
    held = []
    for _ in range(2):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        sock.listen()
        held.append(sock)
    try:
        d, out = make(model_ports=tuple(s.getsockname()[1] for s in held))
        d.step_live_sockets()
        assert "Skipped" in text(out) and "in use" in text(out)
    finally:
        for sock in held:
            sock.close()


# ---- the feed ---------------------------------------------------------------------------------------------------

def test_the_feed_delivers_the_servers_events_in_order(server):
    got = []
    with Feed(server, lambda kind, data: got.append(kind)):
        api(server, "/api/demo/reset", {})
        api(server, "/api/demo/load-scenario", {"name": "quick_leak"})
        time.sleep(1.0)
    assert got.count("event.new") == 12 and got.count("alert.new") == 2 and "score.update" in got
    assert got.index("event.new") < got.index("finding.new")


def test_the_feed_stops_at_once_not_at_the_next_heartbeat(server):
    """Closing used to wait for the server's 15 s heartbeat, which stalled the demo twice."""
    feed = Feed(server, lambda kind, data: None)
    started = time.perf_counter()
    with feed:
        pass
    assert time.perf_counter() - started < 3
    assert not feed._thread.is_alive()


def test_a_feed_to_nowhere_is_reported():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        closed = f"http://127.0.0.1:{probe.getsockname()[1]}"
    with pytest.raises(demo.ServerUnavailable):
        with Feed(closed, lambda kind, data: None):
            pass


# ---- the plan and the whole run ---------------------------------------------------------------------------------------

def test_the_default_run_is_all_live_and_the_lab_comes_last():
    assert plan(replays=False) == ["laptop", "sockets", "lab"]
    assert plan(replays=True) == ["laptop", "sockets", "leak", "org", "agent", "lab"]
    assert {tag for key, _, tag, _ in STEPS if key in plan(False)} == {"LIVE", "LIVE SOCKETS"}
    assert {tag for key, _, tag, _ in STEPS if key not in plan(False)} == {"REPLAY"}


def test_steps_are_numbered_within_the_run_not_the_full_list(make, pretend_machine):
    d, out = make(look_at_machine=pretend_machine)
    d.run(["laptop", "lab"][:1])
    assert "1 / 1  YOUR LAPTOP" in text(out)


def test_each_replay_says_it_is_recorded(make):
    d, out = make()
    for key in ("leak", "org", "agent"):
        d.header(key)
    assert text(out).count("[REPLAY]") == 3 and "invented tools" in text(out)


def test_a_full_run_goes_through_every_step_and_carries_on_after_a_failure(make, pretend_machine, monkeypatch):
    d, out = make(look_at_machine=pretend_machine, sim_count=2, sim_interval=0.3)
    monkeypatch.setattr(Demo, "step_org", lambda self: (_ for _ in ()).throw(ValueError("SECRETMARKER")))
    assert d.run(["laptop", "org", "agent"]) == 0
    shown = text(out)
    assert "This step failed (ValueError); carrying on." in shown and "SECRETMARKER" not in shown
    assert "1 / 3" in shown and "3 / 3" in shown and "AGENT_DANGEROUS_CMD" in shown


def test_stopping_with_q_ends_politely(make):
    d, out = make(auto=False)
    d.read = lambda prompt: "q"
    assert d.run(["laptop", "leak"]) == 0 and "Stopped." in text(out) and "1 / 2" not in text(out)


def test_the_first_prompt_warns_that_data_is_cleared_but_the_lab_does_not(make):
    prompts = []
    d, _ = make(auto=False)

    def read(prompt):
        prompts.append(prompt)
        raise StopDemo
    d.read = read
    d.run(["laptop"])
    d.run(["lab"])
    assert "clears the demo data" in prompts[0] and "clears the demo data" not in prompts[1]


def test_leak_lab_uses_the_keyboard(make, server):
    d, out = make(auto=False)
    keys = iter([f"key {fake('stripe_key', 21)}", ":quit"])
    d.read = lambda prompt: next(keys)
    d.step_leak_lab()
    shown = text(out)
    assert "LEAK LAB" in shown and "Stripe API key" in shown and "connected to the ShadowLens server" in shown


def test_no_server_gives_instructions_not_a_crash(config):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        closed = f"http://127.0.0.1:{probe.getsockname()[1]}"
    out = []
    code = Demo(closed, config, PLAIN, auto=True, write=out.append).run(["laptop"])
    assert code == 2 and "-m shadowlens --browser" in text(out) and "No ShadowLens server answered" in text(out)


def test_step_names_are_checked():
    assert parse_steps("laptop, Lab") == ["laptop", "lab"]
    for bad in ("1", "everything", "laptop,nope"):
        with pytest.raises(Exception):
            parse_steps(bad)
    assert KEYS == tuple(step[0] for step in STEPS)


def test_main_runs_chosen_steps(server, capsys, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert demo.main(["--server", server, "--auto", "--only", "agent", "--color", "never"]) == 0
    out = capsys.readouterr().out
    assert "1 / 1  A ROGUE AGENT" in out and "YOUR LAPTOP" not in out


def test_replays_add_the_recorded_steps(server, capsys, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    demo.main(["--server", server, "--auto", "--replays", "--only", "leak,agent", "--speed", "50", "--color", "never"])
    assert "[REPLAY]" in capsys.readouterr().out


def test_auto_leaves_out_the_lab_unless_asked(server, capsys, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    demo.main(["--server", server, "--auto", "--only", "agent", "--color", "never"])
    assert "LEAK LAB" not in capsys.readouterr().out

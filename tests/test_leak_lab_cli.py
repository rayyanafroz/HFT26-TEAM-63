"""The terminal Leak Lab: real analyzer, real server, no stand-ins (SOT 9.3.2)."""

import re
import socket
import threading
import time

import pytest
import uvicorn

from scenarios import leak_lab
from scenarios.leak_lab import Analyzer, PreviewError, Style, highlight, render, run
from shadowlens.api.app import create_app
from shadowlens.config import Config
from shadowlens.fakes import fake

ANSI = re.compile(r"\x1b\[[0-9;]*m")
PLAIN = Style(color=False, glyphs=True)
COLOR = Style(color=True, glyphs=True)


@pytest.fixture
def config(tmp_path):
    return Config.load(env={"SHADOWLENS_RESOLVE": "false", "SHADOWLENS_LIVE_DIR": str(tmp_path / "live")},
                       base_dir=tmp_path, use_dotenv=False)


@pytest.fixture
def server(config, tmp_path):
    """The actual app on a real port, in a thread."""
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
    assert instance.started, "the test server did not start"
    yield f"http://127.0.0.1:{port}"
    instance.should_exit = True
    thread.join(timeout=10)


@pytest.fixture
def live(server, config):
    analyzer = Analyzer(server, config)
    assert analyzer.check()
    return analyzer


@pytest.fixture
def offline(config):
    """No server, and already known to be none (finding that out takes about 2 s on Windows)."""
    analyzer = Analyzer("http://127.0.0.1:9", config)
    analyzer.server_up = False
    return analyzer


def typed(*lines):
    """A fake keyboard: the lines in order, then Ctrl+D."""
    queue = list(lines)

    def read(prompt):
        if not queue:
            raise EOFError
        return queue.pop(0)
    return read


def session(analyzer, *lines, style=PLAIN, mode="text"):
    out = []
    code = run(analyzer, style, mode, read=typed(*lines), write=out.append)
    return code, "\n".join(out)


# ---- through the real server ----------------------------------------------------------------------

def test_a_typed_key_is_found_masked_and_redacted_by_the_real_server(live):
    key = fake("openai_key", 3)
    code, shown = session(live, f"why does {key} fail?")
    assert code == 0 and f"connected to the ShadowLens server at {live.server}" in shown
    assert "WHAT WAS FOUND (1)" in shown and "OpenAI-style API key" in shown and "sk-p... (len 51)" in shown
    receive = shown.split("WHAT THE AI MODEL WOULD RECEIVE")[1]
    assert "[REDACTED:SEC_OPENAI_KEY:" in receive and key not in receive
    assert "analysed in" in shown and live.server in shown and "Nothing typed here is stored" in shown


def test_clean_text_says_so_and_adds_no_risk(live):
    _, shown = session(live, "write me a poem about autumn")
    assert "nothing sensitive found" in shown and "WHAT WAS FOUND (0)" in shown and "0/100" in shown


def test_it_stores_nothing_and_publishes_nothing(live):
    session(live, f"key {fake('openai_key', 4)}", ":samples")
    assert leak_lab._server_call(live.server, "/api/events", None)["total"] == 0
    assert leak_lab._server_call(live.server, "/api/findings", None)["total"] == 0


def test_agent_mode_finds_a_dangerous_command(live):
    body = ('{"messages":[{"role":"assistant","tool_calls":[{"function":{"name":"bash",'
            '"arguments":"{\\"command\\": \\"rm -rf ~\\"}"}}]}]}')
    _, shown = session(live, ":agent", body)
    assert "Agent ran a dangerous command" in shown and "analysing agent requests now" in shown


def test_samples_run_all_three_examples(live):
    _, shown = session(live, ":samples")
    assert shown.count("● example:") == 3
    assert "Agent" in shown.split("example: agent")[1] and "sent to an AI tool" in shown.split("example: key")[1]


def test_paste_mode_takes_several_lines(live):
    key = fake("github_token", 5)
    _, shown = session(live, ":paste", "line one", f"line two {key}", "line three", "")
    assert "GitHub token" in shown and shown.count("YOU TYPED") == 1 and key not in shown.split("WOULD RECEIVE")[1]


def test_a_too_long_message_is_reported_not_fatal(live):
    _, shown = session(live, "x" * 20001, "still working")
    assert "could not analyse that" in shown and shown.count("YOU TYPED") == 1


def test_a_system_proxy_is_never_used(live, monkeypatch):
    """A proxy on a conference network must not sit between the demo and its own server."""
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:9")
    answer, where, _ = live.preview(f"key {fake('stripe_key', 12)}", "text")
    assert where == live.server and answer["findings"][0]["rule_id"] == "SEC_STRIPE_KEY"


# ---- when no server is running ---------------------------------------------------------------------------

def test_a_closed_port_is_detected_once_and_remembered(config):
    analyzer = Analyzer("http://127.0.0.1:9", config)
    assert analyzer.server_up is None
    assert analyzer.check() is False and analyzer.server_up is False
    started = time.perf_counter()
    for number in range(5):                                       # each would cost ~2 s on Windows if it looked again
        analyzer.preview(f"line {number} {fake('hf_token', number)}", "text")
    assert time.perf_counter() - started < 1.5


def test_it_falls_back_to_the_analyzer_in_this_process(offline):
    key = fake("stripe_key", 6)
    answer, where, ms = offline.preview(f"key {key}", "text")
    assert "no server is running" in where and ms >= 0
    assert [row["rule_id"] for row in answer["findings"]] == ["SEC_STRIPE_KEY"]
    assert key not in answer["redacted_text"]


def test_the_whole_session_works_without_a_server(offline):
    _, shown = session(offline, f"card {fake('card_visa', 7)}", ":samples")
    assert "no ShadowLens server found" in shown
    assert "Payment card number" in shown and "no server is running" in shown and shown.count("● example:") == 3


def test_both_routes_give_the_same_answer(live, offline):
    text = f"DB_PASSWORD={fake('password', 8)} and {fake('email', 8)}"
    assert live.preview(text, "text")[0] == offline.preview(text, "text")[0]


def test_the_server_going_away_mid_session_switches_to_this_process(config):
    analyzer = Analyzer("http://127.0.0.1:9", config)
    analyzer.server_up = True                                     # it was up a moment ago
    answer, where, _ = analyzer.preview(f"key {fake('hf_token', 9)}", "text")
    assert analyzer.server_up is False and "no server is running" in where
    assert answer["findings"][0]["rule_id"] == "SEC_HF_TOKEN"


def test_server_command_finds_a_server_that_started_later(server, config):
    analyzer = Analyzer(server, config)
    analyzer.server_up = False
    out = []
    run(analyzer, PLAIN, read=typed(":server"), write=out.append)
    assert analyzer.server_up is True
    assert any("connected to the ShadowLens server" in line for line in out[2:])   # after the start-up lines


# ---- showing the answer -----------------------------------------------------------------------------------

def answer_for(text, analyzer):
    return analyzer.preview(text, "text")[0]


def test_highlighting_paints_exactly_the_matches(offline):
    key = fake("openai_key", 9)
    text = f"before {key} after"
    answer = answer_for(text, offline)
    painted = highlight(text, answer["findings"], COLOR)
    assert ANSI.sub("", painted) == text                            # painting never changes the words
    start, end = answer["findings"][0]["span"]
    assert text[start:end] == key and painted.startswith("before ") and "\x1b[" in painted
    assert highlight(text, answer["findings"], PLAIN) == text       # no color, no escape codes


def test_color_is_never_the_only_signal():
    answer = {"findings": [{"rule_id": "PII_SSN", "severity": "high", "title": "t", "masked_preview": "****1",
                            "span": [0, 1]}], "redacted_text": "x", "would_block": False,
              "points_preview": {"S": 1, "tool_score": 1}}
    shown = render("x", answer, ms=1, where="w", style=PLAIN)
    assert "▲ high" in shown and not ANSI.search(shown)


@pytest.mark.parametrize("severity,shape", [("critical", "◆"), ("high", "▲"), ("medium", "■"), ("low", "●"), ("info", "–")])
def test_each_severity_has_its_own_shape_and_word(severity, shape):
    assert Style().shape(severity) == shape


def test_ascii_shapes_when_the_console_cannot_draw_them():
    style = Style(color=False, glyphs=False)
    assert {style.shape(s) for s in ("critical", "high", "medium", "low", "info")} == {"*", "^", "#", "o", "-"}
    assert "─" not in style.rule("T") and "-" in style.rule("T")


def test_overlapping_matches_do_not_break_the_text():
    rows = [{"severity": "low", "span": [0, 10]}, {"severity": "critical", "span": [3, 6]}]
    assert ANSI.sub("", highlight("0123456789 tail", rows, COLOR)) == "0123456789 tail"


@pytest.mark.parametrize("span", [[5, 2], [-1, 3], [0, 999], [3]])
def test_a_bad_span_from_the_server_is_ignored(span):
    assert ANSI.sub("", highlight("short", [{"severity": "high", "span": span}], COLOR)) == "short"


def test_the_same_value_twice_is_one_line_with_a_count(offline):
    key = fake("openai_key", 10)
    text = f"{key} {key}"
    shown = render(text, answer_for(text, offline), ms=1, where="w", style=PLAIN)
    assert "WHAT WAS FOUND (1)" in shown and "x2" in shown


def test_no_finding_title_is_cut_off():
    """The longest rule title once lost its last words, leaving 'sent to an' beside the value."""
    from shadowlens.core.rule_titles import RULE_TITLES
    longest = max(RULE_TITLES.values(), key=len)
    row = {"rule_id": "SEC_HIGH_ENTROPY", "severity": "low", "title": longest, "masked_preview": "ghp_... (len 39)", "span": [0, 1]}
    answer = {"findings": [row], "redacted_text": "x", "would_block": False, "points_preview": {"S": 1, "tool_score": 1}}
    assert longest in render("x", answer, ms=1, where="w", style=PLAIN)


def test_the_blocked_verdict_is_a_word_not_just_a_color():
    answer = {"findings": [], "redacted_text": "t", "would_block": True, "points_preview": {"S": 0, "tool_score": 0}}
    assert "WOULD BE BLOCKED" in render("t", answer, ms=1, where="w", style=PLAIN)


# ---- commands and failures ------------------------------------------------------------------------------------

def test_quit_commands_and_ctrl_d_end_the_session_cleanly(offline):
    for line in (":quit", ":q", "q", "exit"):
        assert session(offline, line)[0] == 0
    assert session(offline)[0] == 0                                  # Ctrl+D straight away


def test_a_byte_order_mark_from_a_paste_is_ignored(offline):
    _, shown = session(offline, "﻿:help", "﻿q")
    assert ":paste" in shown
    _, shown = session(offline, f"﻿key {fake('hf_token', 13)}")
    assert "﻿" not in shown and "Hugging Face token" in shown


def test_blank_lines_and_help_are_harmless(offline):
    _, shown = session(offline, "", "   ", ":help")
    assert "YOU TYPED" not in shown and ":paste" in shown and ":server" in shown


def test_ctrl_c_ends_the_session(offline):
    def interrupted(prompt):
        raise KeyboardInterrupt
    assert run(offline, PLAIN, read=interrupted, write=lambda s: None) == 0


def test_a_session_does_not_look_for_the_server_again_when_it_already_knows(offline, monkeypatch):
    monkeypatch.setattr(Analyzer, "check", lambda self: (_ for _ in ()).throw(AssertionError("looked again")))
    assert session(offline, "hello")[0] == 0


def test_an_error_from_the_server_is_shown_and_the_session_continues(offline, monkeypatch):
    def broken(self, text, mode):
        raise PreviewError("text analysis is not installed yet")
    monkeypatch.setattr(Analyzer, "preview", broken)
    _, shown = session(offline, "hello", "again")
    assert shown.count("could not analyse that: text analysis is not installed yet") == 2


def test_an_unexpected_failure_does_not_end_the_demo(offline, monkeypatch):
    def explode(self, text, mode):
        raise ValueError("SECRETMARKER")
    monkeypatch.setattr(Analyzer, "preview", explode)
    code, shown = session(offline, "hello", "again")
    assert code == 0 and shown.count("something went wrong (ValueError)") == 2 and "SECRETMARKER" not in shown


def test_ansi_is_off_when_the_output_is_not_a_terminal(monkeypatch):
    monkeypatch.setattr("sys.stdout.isatty", lambda: False, raising=False)
    assert leak_lab.enable_ansi() is False


def test_no_color_variable_is_respected(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    assert leak_lab.enable_ansi() is False


def test_main_runs_with_arguments(monkeypatch, server, capsys, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("builtins.input", typed(f"key {fake('hf_token', 11)}"))
    assert leak_lab.main(["--server", server, "--color", "never"]) == 0
    out = capsys.readouterr().out
    assert "Hugging Face token" in out and "connected to the ShadowLens server" in out and not ANSI.search(out)


def test_main_can_start_in_agent_mode(monkeypatch, capsys, tmp_path):
    monkeypatch.chdir(tmp_path)
    prompts = []

    def read(prompt):
        prompts.append(prompt)
        raise EOFError
    monkeypatch.setattr("builtins.input", read)
    leak_lab.main(["--server", "http://127.0.0.1:9", "--agent", "--color", "never"])
    assert "agent json" in prompts[0]

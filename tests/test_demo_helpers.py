"""The live demo helpers, over real sockets and real files (SOT 8.3).

``reader_body`` below is a small copy of the transcript reader rule in SOT 7.2.1, until the
real reader exists. Swap it for the real one then.
"""

import http.client
import json
import os
import socket
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

import pytest

from scenarios import agent_sim, transcript_sim
from scenarios.mock_ollama import MockOllamaServer, build_log_line, resolve_client
from shadowlens.analysis import AnalysisSettings, analyze
from shadowlens.analysis.secrets import find_named_secrets
from shadowlens.config import Config
from shadowlens.core.ctx import AgentSessionContext
from shadowlens.core.pipeline import Pipeline
from shadowlens.db import Database
from shadowlens.fakes import expand, fake
from shadowlens.models import NetEvent, utc_now_iso
from shadowlens.providers.catalog import Catalog

REPO_ROOT = Path(__file__).resolve().parents[1]
SETTINGS = AnalysisSettings(salt=b"s" * 32)
HOST = "127.0.0.1"


@pytest.fixture
def server(tmp_path):
    instance = MockOllamaServer(0, tmp_path / "ollama.jsonl")
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    yield instance
    instance.shutdown()
    instance.server_close()


@pytest.fixture
def silent_server():
    instance = MockOllamaServer(0, None)
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    yield instance
    instance.shutdown()
    instance.server_close()


def port_of(instance):
    return instance.server_address[1]


def post(port, path, payload):
    connection = http.client.HTTPConnection(HOST, port, timeout=10)
    connection.request("POST", path, body=json.dumps(payload), headers={"Content-Type": "application/json"})
    response = connection.getresponse()
    data = response.read()
    connection.close()
    return response, data


def log_lines(instance):
    return [json.loads(line) for line in instance.log_path.read_text(encoding="utf-8").splitlines()]


def event_from_log(line):
    return NetEvent(id=str(uuid.uuid4()), ts=line["ts"], source=line["source"], process=line["process_name"],
                    pid=line["pid"], dst_ip=line["dst_ip"], dst_port=line["dst_port"], host=line["host"],
                    host_basis="host_header", method=line["method"], path=line["path"],
                    headers=line["headers"], body_text=line["body"], bytes_out=line["bytes_out"])


# ---- mock_ollama: replies ----------------------------------------------------------

def test_chat_without_streaming(server):
    response, data = post(port_of(server), "/api/chat", {"model": "llama3", "stream": False, "messages": []})
    reply = json.loads(data)
    assert response.status == 200 and reply["done"] is True
    assert reply["model"] == "llama3" and reply["message"]["role"] == "assistant"


def test_generate_without_streaming(server):
    _, data = post(port_of(server), "/api/generate", {"model": "m", "stream": False, "prompt": "hi"})
    assert json.loads(data)["response"]


def test_streaming_is_the_default_and_arrives_as_json_lines(server):
    response, data = post(port_of(server), "/api/chat", {"model": "m", "messages": []})
    parts = [json.loads(line) for line in data.decode().splitlines()]
    assert response.getheader("Transfer-Encoding") == "chunked"
    assert len(parts) > 2 and parts[-1]["done"] is True and not any(p["done"] for p in parts[:-1])
    assert "".join(p["message"]["content"] for p in parts).startswith("This is a canned reply")


def test_tags_and_unknown_paths(server):
    connection = http.client.HTTPConnection(HOST, port_of(server), timeout=10)
    connection.request("GET", "/api/tags")
    response = connection.getresponse()
    assert response.status == 200 and json.loads(response.read())["models"]
    connection.request("GET", "/nope")
    response = connection.getresponse()
    response.read()
    assert response.status == 404
    connection.close()


def test_bad_bodies_do_not_break_the_server(server):
    connection = http.client.HTTPConnection(HOST, port_of(server), timeout=10)
    for body in (b"not json", b"[1, 2]", b"\xff\xfe"):
        connection.request("POST", "/api/chat", body=body)
        response = connection.getresponse()
        response.read()
        assert response.status == 200
    connection.close()


def test_oversized_body_is_refused():
    from scenarios import mock_ollama
    instance = MockOllamaServer(0, None)
    threading.Thread(target=instance.serve_forever, daemon=True).start()
    try:
        connection = http.client.HTTPConnection(HOST, port_of(instance), timeout=10)
        connection.putrequest("POST", "/api/chat")
        connection.putheader("Content-Length", str(mock_ollama.MAX_BODY_BYTES + 1))
        connection.endheaders()
        assert connection.getresponse().status == 413
        connection.close()
    finally:
        instance.shutdown()
        instance.server_close()


def test_second_server_on_the_same_port_is_refused(server):
    """SOT 1.2: on Windows, address reuse would quietly let two programs share the port."""
    with pytest.raises(OSError):
        MockOllamaServer(port_of(server), None)


def test_server_binds_to_loopback_only(server):
    assert server.server_address[0] == HOST


# ---- mock_ollama: the log ------------------------------------------------------------

def test_request_is_logged_in_the_http_log_format(server):
    post(port_of(server), "/api/chat?x=1", {"model": "m", "stream": False, "messages": []})
    line = log_lines(server)[0]
    assert {"ts", "host", "method", "path", "body"} <= set(line)
    assert line["source"] == "live_log" and line["tls"] is False
    assert (line["host"], line["dst_ip"], line["dst_port"]) == ("localhost", HOST, port_of(server))
    assert line["path"] == "/api/chat" and json.loads(line["body"])["model"] == "m"
    assert line["bytes_out"] == len(line["body"])
    NetEvent.model_validate({**event_from_log(line).model_dump(exclude={"visibility"})})


def test_client_process_is_found_from_its_source_port(server):
    post(port_of(server), "/api/chat", {"stream": False})
    line = log_lines(server)[0]
    assert line["process_name"].startswith(("python", "pytest")) and line["pid"] == os.getpid()


def test_header_is_the_fallback_when_the_port_is_not_found():
    with socket.socket() as probe:
        probe.bind((HOST, 0))
        unused_port = probe.getsockname()[1]
    # The socket is closed, so no connection has this port any more.
    assert resolve_client(unused_port, "Agent-Sim") == ("agent-sim", None)
    assert resolve_client(unused_port, None) == ("unknown", None)


def test_no_log_writes_nothing(silent_server, tmp_path):
    post(port_of(silent_server), "/api/chat", {"stream": False})
    assert list(tmp_path.iterdir()) == []


def test_many_clients_at_once_never_mix_up_log_lines(server):
    threads = [threading.Thread(target=post, args=(port_of(server), "/api/chat", {"stream": False, "n": n}))
               for n in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(json.loads(line["body"])["n"] for line in log_lines(server)) == list(range(12))


def test_only_kept_headers_reach_the_log():
    line = build_log_line("POST", "/api/chat", 1, "x", 1, {"cookie": "c", "user-agent": "u"}, "p", None)
    assert line["headers"] == {"user-agent": "u"}


# ---- agent_sim -----------------------------------------------------------------------

def test_agent_sim_keeps_one_connection(server):
    seen = []
    original = server.get_request

    def counting_get_request():
        accepted = original()
        seen.append(accepted[1])
        return accepted

    server.get_request = counting_get_request
    assert agent_sim.run(port_of(server), count=3, interval=0) == 3
    assert len(seen) == 1
    assert len(log_lines(server)) == 3


def test_agent_sim_payload_gives_one_finding_through_the_real_pipeline(server, tmp_path):
    agent_sim.run(port_of(server), count=3, interval=0)
    config = Config.load(env={"SHADOWLENS_RESOLVE": "false"}, base_dir=tmp_path, use_dotenv=False)
    database = Database(tmp_path / "shadow.db")
    try:
        # The port is what names Ollama, and this test server is on a random one.
        events = [event_from_log({**line, "dst_port": 11434}) for line in log_lines(server)]
        summary = Pipeline(config, database, Catalog.load(), analyze=analyze).ingest(events, source="live_log")
        assert summary.accepted == 3
        found = database.list_findings(rule_id="SEC_OPENAI_KEY").items
        assert len(found) == 1
        assert found[0].masked_preview == f"sk-p... (len {len(fake('openai_key'))})"
    finally:
        database.close()


def test_agent_sim_key_index_changes_the_key():
    assert agent_sim.build_body(0) != agent_sim.build_body(1)
    assert fake("openai_key", 1) in agent_sim.build_body(1)


def test_agent_sim_reports_a_closed_port(capsys):
    with socket.socket() as probe:
        probe.bind((HOST, 0))
        closed = probe.getsockname()[1]
    assert agent_sim.main(["--port", str(closed), "--count", "1"]) == 1
    assert "Nothing is answering" in capsys.readouterr().out


# ---- transcripts ---------------------------------------------------------------------

def reader_body(raw_line):
    """SOT 7.2.1: user text and tool results, assistant tool calls only; assistant prose is dropped."""
    data = json.loads(raw_line)
    message = data.get("message")
    if not isinstance(message, dict):
        return None
    role, content = message.get("role"), message.get("content")
    if isinstance(content, str):
        content = [{"type": "text", "text": content}]
    wanted = {"user": ("text", "tool_result"), "assistant": ("tool_use",)}.get(role, ())
    kept = [block for block in content if isinstance(block, dict) and block.get("type") in wanted]
    if not kept:
        return None
    return json.dumps({"model": message.get("model", "unknown"), "messages": [{"role": role, "content": kept}]})


def analyze_transcript(lines):
    ctx = AgentSessionContext(tool_id="claude-code|anthropic")
    findings, activity = [], []
    for raw in lines:
        body = reader_body(raw)
        if body is None:
            continue
        event = NetEvent(id=str(uuid.uuid4()), ts=utc_now_iso(), source="transcript", process="claude-code",
                         dst_ip="0.0.0.0", dst_port=443, host="api.anthropic.com", host_basis="transcript",
                         method="POST", path="/v1/messages", body_text=body)
        result = analyze(event, SETTINGS, ctx)
        findings += result.findings
        activity += result.agent_activity
    return findings, activity


def test_sim_writes_real_lines_with_a_delay_and_a_new_file_each_run(tmp_path, capsys):
    first = transcript_sim.run(tmp_path, interval=0)
    second = transcript_sim.run(tmp_path, interval=0)
    assert first != second and first.parent == tmp_path
    lines = first.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3
    parents = [json.loads(line)["parentUuid"] for line in lines]
    assert parents[0] is None and parents[1] == json.loads(lines[0])["uuid"]


def test_sim_lines_appear_one_at_a_time(tmp_path):
    thread = threading.Thread(target=transcript_sim.run, args=(tmp_path, 0.4))
    thread.start()
    deadline = time.monotonic() + 5
    while not list(tmp_path.glob("*.jsonl")) and time.monotonic() < deadline:
        time.sleep(0.01)
    path = next(tmp_path.glob("*.jsonl"))
    early = len(path.read_text(encoding="utf-8").splitlines())
    thread.join()
    assert early < 3 and len(path.read_text(encoding="utf-8").splitlines()) == 3


def test_sim_output_gives_the_three_w5_findings(tmp_path):
    path = transcript_sim.run(tmp_path, interval=0)
    findings, activity = analyze_transcript(path.read_text(encoding="utf-8").splitlines())
    rules = {finding.rule_id for finding in findings}
    assert {"SEC_OPENAI_KEY", "AGENT_SENSITIVE_FILE_READ", "AGENT_SHELL_EXEC", "AGENT_DANGEROUS_CMD"} <= rules
    assert {row.capability.value for row in activity} >= {"shell", "fs_read", "sensitive_file", "network"}


def test_sim_key_index_gives_a_new_finding_without_reset(tmp_path):
    first = transcript_sim.run(tmp_path, interval=0, key_index=1).read_text(encoding="utf-8")
    second = transcript_sim.run(tmp_path, interval=0, key_index=2).read_text(encoding="utf-8")
    assert fake("openai_key", 1) in first and fake("openai_key", 2) in second


def test_sim_main_uses_its_arguments(tmp_path, capsys):
    target = tmp_path / "new" / "folder"
    assert transcript_sim.main(["--dir", str(target), "--interval", "0"]) == 0
    assert len(list(target.glob("*.jsonl"))) == 1


# ---- AT-28: the sample transcript --------------------------------------------------------

SAMPLE = REPO_ROOT / "fixtures" / "sample_claude_transcript.jsonl"


def sample_lines():
    return expand(SAMPLE.read_text(encoding="utf-8")).splitlines()


def test_at28_planted_key_shell_and_sensitive_read():
    findings, _ = analyze_transcript(sample_lines())
    rules = [finding.rule_id for finding in findings]
    for rule_id in ("SEC_OPENAI_KEY", "AGENT_SHELL_EXEC", "AGENT_SENSITIVE_FILE_READ", "AGENT_DANGEROUS_CMD"):
        assert rule_id in rules


def test_at28_tool_result_is_inspected():
    findings, _ = analyze_transcript(sample_lines())
    match = next(finding for finding in findings if finding.rule_id == "SEC_AWS_ACCESS_KEY")
    assert match.location.field.value == "tool_result"


def test_at28_assistant_prose_and_thinking_create_no_finding():
    rules = {finding.rule_id for finding in analyze_transcript(sample_lines())[0]}
    # Both sit in assistant text and thinking blocks in the sample.
    assert "SEC_ANTHROPIC_KEY" not in rules and "SEC_GITHUB_TOKEN" not in rules


def test_sample_file_holds_only_placeholders():
    """AT-26."""
    assert find_named_secrets(SAMPLE.read_text(encoding="utf-8")) == []
    assert "{{fake:openai_key#61}}" in SAMPLE.read_text(encoding="utf-8")


def test_lines_without_a_message_produce_no_event():
    assert reader_body(sample_lines()[0]) is None


# ---- the real commands, as separate programs -----------------------------------------------

def _free_port():
    with socket.socket() as probe:
        probe.bind((HOST, 0))
        return probe.getsockname()[1]


def _wait_for_port(port, seconds=15):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        with socket.socket() as probe:
            probe.settimeout(0.2)
            if probe.connect_ex((HOST, port)) == 0:
                return True
        time.sleep(0.05)
    return False


def test_the_commands_work_together_end_to_end(tmp_path):
    """python -m scenarios.mock_ollama + agent_sim: two programs, a real socket, a real log file."""
    port = _free_port()
    env = {**os.environ, "SHADOWLENS_LIVE_DIR": str(tmp_path / "live")}
    server_process = subprocess.Popen(
        [sys.executable, "-m", "scenarios.mock_ollama", "--port", str(port)],
        cwd=REPO_ROOT, env=env, stdout=subprocess.DEVNULL,
    )
    try:
        assert _wait_for_port(port), "mock_ollama did not start"
        done = subprocess.run(
            [sys.executable, "-m", "scenarios.agent_sim", "--port", str(port), "--count", "2", "--interval", "0"],
            cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=30,
        )
        assert done.returncode == 0, done.stdout + done.stderr
    finally:
        server_process.terminate()
        server_process.wait(timeout=10)
    lines = [json.loads(line) for line in (tmp_path / "live" / "ollama.jsonl").read_text(encoding="utf-8").splitlines()]
    assert len(lines) == 2
    assert lines[0]["process_name"].startswith("python")
    # One connection means one client program, so both lines name the same pid.
    assert lines[0]["pid"] == lines[1]["pid"] and lines[0]["pid"] is not None

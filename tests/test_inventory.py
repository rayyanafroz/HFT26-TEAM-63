"""The machine inventory: real files and folders, injected only where a real machine is not wanted (SOT 4.5)."""

import json
import os
import socket
import sys
import time
from pathlib import Path

import pytest
import yaml

from shadowlens.ingest import inventory
from shadowlens.ingest.inventory import (
    Connection,
    InstalledApp,
    RunningProgram,
    connection_records,
    expand_path,
    load_signatures,
    scan,
)
from shadowlens.providers.catalog import Catalog

REPO_ROOT = Path(__file__).resolve().parents[1]
CATALOG = Catalog.load()


def write_signatures(tmp_path, tools=None, **extra):
    data = {"tools": tools if tools is not None else [], **extra}
    path = tmp_path / "ai_tools.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


CLAUDE = {"id": "claude_code", "name": "Claude Code", "kind": "coding agent", "provider": "anthropic",
          "processes": [{"name": "claude", "exe_contains": ["anthropic.claude-code"]}],
          "vscode_extensions": ["anthropic.claude-code"], "folders": ["~/.claude"], "commands": ["claude"]}


def look(tmp_path, tools, *, programs=(), apps=(), connections=(), resolve=None, which=None, **extra):
    """A scan of a pretend home folder. Everything not injected is a real look at tmp_path."""
    signatures = load_signatures(write_signatures(tmp_path, tools, **extra))
    return scan(signatures, catalog=CATALOG, home=tmp_path / "home", env={"PATH": ""},
                programs=lambda: programs, apps=lambda: apps, connections=lambda: connections,
                resolve=resolve or (lambda host: set()), which=which or (lambda command: None))


@pytest.fixture
def home(tmp_path):
    (tmp_path / "home").mkdir()
    return tmp_path / "home"


# ---- the signature file ----------------------------------------------------------------------

def test_the_shipped_signatures_load_clean():
    signatures = load_signatures()
    assert signatures.warnings == () and len(signatures.tools) >= 10
    assert {t.id for t in signatures.tools} >= {"claude_code", "github_copilot", "ollama", "cursor"}
    assert signatures.editors and signatures.browsers and signatures.browser_name_patterns


def test_every_provider_a_signature_names_exists_in_the_catalog():
    for tool in load_signatures().tools:
        assert tool.provider is None or CATALOG.get(tool.provider) is not None, tool.id


def test_a_missing_file_is_a_warning_not_a_crash(tmp_path):
    signatures = load_signatures(tmp_path / "nope.yaml")
    assert signatures.tools == () and "not found" in signatures.warnings[0]
    result = scan(signatures, catalog=CATALOG, home=tmp_path, env={}, programs=lambda: [], apps=lambda: [],
                  connections=lambda: [], which=lambda c: None)
    assert result.tools == [] and "no tool signatures are loaded" in result.warnings


@pytest.mark.parametrize("content", ["{{{ not yaml", "- a list", "just text", ""])
def test_a_damaged_file_is_a_warning(tmp_path, content):
    path = tmp_path / "ai_tools.yaml"
    path.write_text(content, encoding="utf-8")
    assert load_signatures(path).warnings and load_signatures(path).tools == ()


def test_one_bad_entry_is_skipped_and_the_rest_still_load(tmp_path):
    good = {"id": "ollama", "name": "Ollama", "kind": "local model server", "commands": ["ollama"]}
    bad = [{"id": "Bad Id", "name": "x", "kind": "y", "commands": ["x"]},
           {"id": "empty", "name": "x", "kind": "y"},
           {"id": "typo", "name": "x", "kind": "y", "comands": ["x"]},
           {**good}, {**good}]
    signatures = load_signatures(write_signatures(tmp_path, bad))
    assert [t.id for t in signatures.tools] == ["ollama"]
    text = " ".join(signatures.warnings)
    assert "Bad Id" in text and "empty" in text and "typo" in text and "duplicate id" in text


def test_a_bad_pattern_is_skipped(tmp_path):
    signatures = load_signatures(write_signatures(tmp_path, [], browser_extension_name_patterns=["(", "ChatGPT"]))
    assert len(signatures.browser_name_patterns) == 1 and signatures.warnings


# ---- running programs -------------------------------------------------------------------------------

def test_a_program_is_matched_by_name_and_where_it_runs_from(tmp_path, home):
    result = look(tmp_path, [CLAUDE], programs=[
        RunningProgram(10, "claude", str(home / ".vscode/extensions/anthropic.claude-code-2.1.314/resources/claude.exe")),
        RunningProgram(11, "claude", "C:/Somewhere/Else/claude.exe"),           # same name, other program
        RunningProgram(12, "notepad", None)])
    tool = result.tools[0]
    assert tool.status == "running" and tool.pids == [10]
    assert "~" in tool.evidence[0].detail and "pid 10" in tool.evidence[0].detail
    assert "386" not in result.looked_at[0] and result.looked_at[0] == "3 running programs"


def test_windows_path_style_and_case_do_not_matter(tmp_path):
    result = look(tmp_path, [CLAUDE], programs=[
        RunningProgram(1, "claude", r"C:\Users\Dev\.VSCODE\Extensions\Anthropic.Claude-Code-2.1\claude.exe")])
    assert result.tools[0].pids == [1]


def test_a_program_without_a_readable_location_matches_only_name_only_rules(tmp_path):
    tools = [CLAUDE, {"id": "ollama", "name": "Ollama", "kind": "local model server", "processes": [{"name": "ollama"}]}]
    result = look(tmp_path, tools, programs=[RunningProgram(1, "claude", None), RunningProgram(2, "ollama", None)])
    assert [t.id for t in result.tools] == ["ollama"]
    assert "an unreadable location" in result.tools[0].evidence[0].detail


def test_the_first_matching_rule_owns_a_program(tmp_path):
    tools = [{"id": "a", "name": "A", "kind": "k", "processes": [{"name": "tool"}]},
             {"id": "b", "name": "B", "kind": "k", "processes": [{"name": "tool"}]}]
    assert [t.id for t in look(tmp_path, tools, programs=[RunningProgram(1, "tool", None)]).tools] == ["a"]


def test_loose_names_never_match(tmp_path):
    """The keyword trap: 'assistant' finds X-Rite Color Assistant."""
    tools = [{"id": "copilot", "name": "Copilot", "kind": "k", "processes": [{"name": "copilot-runtime"}],
              "apps": [{"name": "Copilot", "publisher": "Microsoft"}]}]
    result = look(tmp_path, tools,
                  programs=[RunningProgram(1, "xritecolorassistant", None), RunningProgram(2, "copilot", None)],
                  apps=[InstalledApp("X-Rite Color Assistant 2.67.0", "X-Rite, Inc"), InstalledApp("Copilot Tools", "Acme")])
    assert result.tools == []


# ---- installed apps ------------------------------------------------------------------------------------

def test_an_app_needs_its_exact_name_and_the_right_publisher(tmp_path):
    tools = [{"id": "mc", "name": "Microsoft Copilot", "kind": "assistant app", "apps": [{"name": "Copilot", "publisher": "Microsoft"}]}]
    result = look(tmp_path, tools, apps=[InstalledApp("copilot", "Microsoft Corporation", "156.0"),
                                         InstalledApp("Copilot", "Some Other Vendor")])
    assert len(result.tools) == 1 and result.tools[0].status == "installed"
    assert "156.0" in result.tools[0].evidence[0].detail and "Microsoft Corporation" in result.tools[0].evidence[0].detail
    assert result.looked_at[0] == "0 running programs" and result.looked_at[1] == "2 installed apps"


# ---- editor extensions ---------------------------------------------------------------------------------

def make_extension(home, folder, name):
    (home / folder / "extensions" / name).mkdir(parents=True)


EDITORS = {"editors": [{"name": "VS Code", "extensions_dir": "~/.vscode/extensions"}]}


def test_editor_extensions_are_found_by_their_id_with_the_version(tmp_path, home):
    make_extension(home, ".vscode", "anthropic.claude-code-2.1.314-win32-x64")
    make_extension(home, ".vscode", "ms-python.python-2026.1.0")
    result = look(tmp_path, [CLAUDE], **EDITORS)
    assert result.tools[0].evidence[0].detail == "VS Code extension anthropic.claude-code 2.1.314-win32-x64"
    assert "2 editor extensions" in result.looked_at


def test_an_uninstalled_extension_still_on_disk_is_ignored(tmp_path, home):
    make_extension(home, ".vscode", "anthropic.claude-code-2.1.314-win32-x64")
    (home / ".vscode/extensions/.obsolete").write_text(json.dumps({"anthropic.claude-code-2.1.314-win32-x64": True}))
    assert look(tmp_path, [CLAUDE], **EDITORS).tools == []


def test_a_similar_extension_id_does_not_match(tmp_path, home):
    make_extension(home, ".vscode", "someone.claude-code-helper-1.0.0")
    assert look(tmp_path, [CLAUDE], **EDITORS).tools == []


def test_a_missing_editor_folder_is_fine(tmp_path, home):
    assert look(tmp_path, [CLAUDE], **EDITORS).tools == []


# ---- browser extensions ----------------------------------------------------------------------------------

def make_browser_extension(home, ext_id, manifest, locales=None, profile="Default", version="1.0_0"):
    folder = home / "Chrome" / profile / "Extensions" / ext_id / version
    folder.mkdir(parents=True)
    (folder / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    for locale, messages in (locales or {}).items():
        (folder / "_locales" / locale).mkdir(parents=True)
        (folder / "_locales" / locale / "messages.json").write_text(json.dumps(messages), encoding="utf-8")


BROWSERS = {"browsers": [{"name": "Chrome", "user_data": ["~/Chrome"]}],
            "browser_extension_name_patterns": [r"\bAI\b", "ChatGPT"]}


def test_a_browser_extension_is_found_by_its_name(tmp_path, home):
    make_browser_extension(home, "a" * 32, {"name": "Summarize with ChatGPT", "version": "2.0"})
    make_browser_extension(home, "b" * 32, {"name": "MetaMask", "version": "1.0"})
    result = look(tmp_path, [], **BROWSERS)
    assert len(result.tools) == 1 and result.tools[0].name == "Summarize with ChatGPT"
    assert result.tools[0].matched_by_name and "matched by its name" in result.tools[0].evidence[0].detail
    assert "2 browser extensions" in result.looked_at


def test_a_localised_extension_name_is_resolved(tmp_path, home):
    make_browser_extension(home, "c" * 32, {"name": "__MSG_appName__", "version": "3", "default_locale": "en"},
                           locales={"en": {"appName": {"message": "Visual AI Tutor"}}})
    assert look(tmp_path, [], **BROWSERS).tools[0].name == "Visual AI Tutor"


def test_a_name_that_cannot_be_resolved_is_not_guessed(tmp_path, home):
    make_browser_extension(home, "d" * 32, {"name": "__MSG_appName__", "version": "3"})
    assert look(tmp_path, [], **BROWSERS).tools == []


@pytest.mark.parametrize("name", ["Training", "Maintain", "Said", "AIRPLANE mode", "Mail"])
def test_the_word_ai_must_stand_alone(tmp_path, home, name):
    make_browser_extension(home, "e" * 32, {"name": name, "version": "1"})
    assert look(tmp_path, [], **BROWSERS).tools == []


def test_the_same_extension_in_two_profiles_is_one_entry(tmp_path, home):
    for profile in ("Default", "Profile 1"):
        make_browser_extension(home, "f" * 32, {"name": "Ask ChatGPT", "version": "1"}, profile=profile)
    result = look(tmp_path, [], **BROWSERS)
    assert len(result.tools) == 1 and len(result.tools[0].evidence) == 2


def test_a_broken_manifest_is_skipped(tmp_path, home):
    folder = home / "Chrome/Default/Extensions" / ("g" * 32) / "1.0"
    folder.mkdir(parents=True)
    (folder / "manifest.json").write_text("{ not json", encoding="utf-8")
    make_browser_extension(home, "h" * 32, {"name": "Ask ChatGPT", "version": "1"})
    result = look(tmp_path, [], **BROWSERS)
    assert [t.name for t in result.tools] == ["Ask ChatGPT"] and result.errors == []


def test_only_profile_folders_are_read(tmp_path, home):
    make_browser_extension(home, "i" * 32, {"name": "Ask ChatGPT", "version": "1"}, profile="Crashpad")
    assert look(tmp_path, [], **BROWSERS).tools == []


# ---- folders and commands -----------------------------------------------------------------------------------

def test_a_folder_alone_is_only_traces_and_says_when_it_last_changed(tmp_path, home):
    (home / ".claude").mkdir()
    result = look(tmp_path, [CLAUDE])
    assert result.tools[0].status == "traces" and "last changed 20" in result.tools[0].evidence[0].detail


def test_a_command_on_the_path_means_installed(tmp_path, home):
    result = look(tmp_path, [CLAUDE], which=lambda command: str(home / "bin" / "claude") if command == "claude" else None)
    assert result.tools[0].status == "installed" and "command claude" in result.tools[0].evidence[0].detail


def test_environment_variables_in_folders(tmp_path, home):
    (tmp_path / "appdata" / "Tool").mkdir(parents=True)
    tools = [{"id": "t", "name": "T", "kind": "k", "folders": ["%APPDATA%/Tool", "$MISSING/Tool"]}]
    signatures = load_signatures(write_signatures(tmp_path, tools))
    result = scan(signatures, catalog=CATALOG, home=home, env={"APPDATA": str(tmp_path / "appdata")},
                  programs=lambda: [], apps=lambda: [], connections=lambda: [], which=lambda c: None)
    assert len(result.tools) == 1


def test_expand_path_rules(tmp_path):
    assert expand_path("~/x", tmp_path, {}) == tmp_path / "x"
    assert expand_path("%A%/y", tmp_path, {"A": "/root"}) == Path("/root/y")
    assert expand_path("${A}/y", tmp_path, {"A": "/root"}) == Path("/root/y")
    assert expand_path("%NOPE%/y", tmp_path, {}) is None


def test_evidence_from_several_places_joins_one_tool(tmp_path, home):
    make_extension(home, ".vscode", "anthropic.claude-code-2.1.314")
    (home / ".claude").mkdir()
    result = look(tmp_path, [CLAUDE], programs=[RunningProgram(5, "claude", str(home / ".vscode/extensions/anthropic.claude-code-2.1/c.exe"))],
                  **EDITORS)
    assert len(result.tools) == 1
    assert {e.kind for e in result.tools[0].evidence} == {"running", "extension", "folder"}


def test_tools_are_listed_running_first_then_installed_then_traces(tmp_path, home):
    tools = [{"id": "z_run", "name": "Zed Running", "kind": "k", "processes": [{"name": "zed"}]},
             {"id": "a_trace", "name": "Alpha Traces", "kind": "k", "folders": ["~/.alpha"]},
             {"id": "m_inst", "name": "Mid Installed", "kind": "k", "apps": [{"name": "Mid"}]}]
    (home / ".alpha").mkdir()
    result = look(tmp_path, tools, programs=[RunningProgram(1, "zed", None)], apps=[InstalledApp("Mid")])
    assert [t.status for t in result.tools] == ["running", "installed", "traces"]


# ---- connections ---------------------------------------------------------------------------------------------------

def running_claude(home):
    return [RunningProgram(7, "claude", str(home / ".vscode/extensions/anthropic.claude-code-2.1/claude.exe"))]


def test_a_connection_to_the_providers_own_address_is_confirmed(tmp_path, home):
    result = look(tmp_path, [CLAUDE], programs=running_claude(home),
                  connections=[(7, "160.79.104.10", 443), (99, "1.2.3.4", 443)],
                  resolve=lambda host: {"160.79.104.10"} if host == "api.anthropic.com" else set())
    conn = result.tools[0].connections
    assert conn == [Connection("160.79.104.10", 443, 7, "api.anthropic.com")] and result.errors == []


def test_a_connection_elsewhere_is_listed_but_not_confirmed(tmp_path, home):
    result = look(tmp_path, [CLAUDE], programs=running_claude(home), connections=[(7, "8.8.8.8", 443)],
                  resolve=lambda host: {"160.79.104.10"})
    assert result.tools[0].connections == [Connection("8.8.8.8", 443, 7, None)] and not result.tools[0].verified


def test_a_failed_lookup_leaves_connections_unconfirmed_and_says_so(tmp_path, home):
    def refuse(host):
        raise socket.gaierror("no network")
    result = look(tmp_path, [CLAUDE], programs=running_claude(home), connections=[(7, "160.79.104.10", 443)], resolve=refuse)
    assert result.tools[0].connections[0].host is None
    assert any("could not look up api.anthropic.com" in e for e in result.errors)


def test_a_hung_lookup_is_cut_off_at_the_timeout_not_waited_for(tmp_path, home, monkeypatch):
    """A stuck DNS server can take 30 s; the scan must not."""
    monkeypatch.setattr(inventory, "LOOKUP_TIMEOUT_S", 0.3)
    started = time.perf_counter()
    result = look(tmp_path, [CLAUDE], programs=running_claude(home), connections=[(7, "160.79.104.10", 443)],
                  resolve=lambda host: time.sleep(6) or {"160.79.104.10"})
    assert time.perf_counter() - started < 1.5
    assert any("could not look up api.anthropic.com" in e for e in result.errors)
    assert result.tools[0].connections[0].host is None


def test_lookup_all_reports_which_hosts_failed_and_keeps_the_rest():
    def resolve(host):
        if host == "bad.example":
            raise OSError("no")
        return {"1.1.1.1"} if host == "a.example" else {"1.1.1.1", "2.2.2.2"}
    mapped, failed = inventory.lookup_all(["a.example", "bad.example", "b.example"], resolve, 2.0)
    assert failed == ["bad.example"] and mapped == {"1.1.1.1": "a.example", "2.2.2.2": "b.example"}


def test_lookup_all_with_no_hosts_is_empty():
    assert inventory.lookup_all([], lambda host: {"1.1.1.1"}, 1.0) == ({}, [])


def test_a_tool_talking_to_itself_is_not_a_provider_connection(tmp_path, home):
    result = look(tmp_path, [CLAUDE], programs=running_claude(home), connections=[(7, "127.0.0.1", 5000)])
    assert result.tools[0].connections == []


def test_a_local_model_server_is_confirmed_by_its_port(tmp_path):
    ollama = {"id": "ollama", "name": "Ollama", "kind": "local model server", "provider": "ollama",
              "processes": [{"name": "ollama"}]}
    result = look(tmp_path, [ollama], programs=[RunningProgram(3, "ollama", None)],
                  connections=[(3, "127.0.0.1", 11434), (3, "127.0.0.1", 9999)])
    hosts = {(c.port, c.host) for c in result.tools[0].connections}
    assert hosts == {(11434, "localhost:11434"), (9999, None)}


def test_one_provider_is_looked_up_once_however_many_programs(tmp_path, home):
    calls = []
    tools = [{**CLAUDE, "processes": [{"name": "claude"}]}]
    look(tmp_path, tools, programs=[RunningProgram(1, "claude", None), RunningProgram(2, "claude", None)],
         connections=[(1, "1.1.1.1", 443), (2, "1.1.1.1", 443), (2, "2.2.2.2", 443)],
         resolve=lambda host: calls.append(host) or set())
    assert calls == ["api.anthropic.com"]


# ---- what ShadowLens is given ------------------------------------------------------------------------------------------

def test_only_confirmed_connections_become_log_lines(tmp_path, home):
    result = look(tmp_path, [CLAUDE], programs=running_claude(home),
                  connections=[(7, "160.79.104.10", 443), (7, "8.8.8.8", 443)],
                  resolve=lambda host: {"160.79.104.10"})
    [record] = connection_records(result, now="2026-10-31T10:00:00.000Z")
    assert record == {"ts": "2026-10-31T10:00:00.000Z", "host": "api.anthropic.com", "method": "CONNECT", "path": "/",
                      "body": None, "dst_ip": "160.79.104.10", "dst_port": 443, "tls": True, "source": "conn_scan",
                      "process_name": "claude", "pid": 7}


def test_a_local_server_line_uses_the_local_shape(tmp_path):
    ollama = {"id": "ollama", "name": "Ollama", "kind": "local model server", "provider": "ollama", "processes": [{"name": "ollama"}]}
    result = look(tmp_path, [ollama], programs=[RunningProgram(3, "ollama", None)], connections=[(3, "127.0.0.1", 11434)])
    [record] = connection_records(result)
    assert record["host"] == "localhost:11434" and record["tls"] is False and record["dst_ip"] == "127.0.0.1"


def test_the_lines_pass_through_the_real_parser_and_classifier(tmp_path, home):
    from shadowlens.ingest.http_log import parse_log
    from shadowlens.providers.classify import classify
    result = look(tmp_path, [CLAUDE], programs=running_claude(home), connections=[(7, "160.79.104.10", 443)],
                  resolve=lambda host: {"160.79.104.10"})
    parsed = parse_log("\n".join(json.dumps(r) for r in connection_records(result)))
    assert parsed.skipped == 0 and len(parsed.events) == 1
    event = parsed.events[0]
    match = classify(event, CATALOG)
    assert event.visibility.value == "metadata_only" and event.process == "claude"
    assert match.tool_id == "claude|anthropic" and match.confidence.value == "high"


# ---- failures stay local ---------------------------------------------------------------------------------------------------

def test_one_failing_look_up_costs_only_itself(tmp_path, home):
    def boom():
        raise PermissionError("denied")
    (home / ".claude").mkdir()
    signatures = load_signatures(write_signatures(tmp_path, [CLAUDE]))
    result = scan(signatures, catalog=CATALOG, home=home, env={}, programs=boom, apps=boom, connections=boom,
                  which=lambda c: None)
    assert result.tools[0].status == "traces"
    assert sorted(result.errors) == ["could not look at installed apps (PermissionError)",
                                     "could not look at network connections (PermissionError)",
                                     "could not look at running programs (PermissionError)"]
    assert "PermissionError" in " ".join(result.errors) and "denied" not in " ".join(result.errors)


def test_without_the_provider_catalog_connections_are_listed_unconfirmed(tmp_path, home, monkeypatch):
    monkeypatch.setattr(Catalog, "load", classmethod(lambda cls, path=None: (_ for _ in ()).throw(OSError("gone"))))
    signatures = load_signatures(write_signatures(tmp_path, [CLAUDE]))
    result = scan(signatures, home=home, env={}, programs=lambda: running_claude(home), apps=lambda: [],
                  connections=lambda: [(7, "160.79.104.10", 443)], which=lambda c: None)
    assert result.tools[0].connections == [Connection("160.79.104.10", 443, 7, None)]


def test_what_it_cannot_see_is_always_stated(tmp_path):
    assert any("Python" in item for item in look(tmp_path, []).not_covered)
    assert any("browser tab" in item for item in look(tmp_path, []).not_covered)


# ---- the real machine -----------------------------------------------------------------------------------------------------------

def test_a_scan_of_this_machine_works_and_is_quick():
    started = time.perf_counter()
    result = scan()
    assert time.perf_counter() - started < 20
    assert result.looked_at and result.warnings == []
    assert int(result.looked_at[0].split()[0]) > 5                     # there are programs running
    for tool in result.tools:
        assert tool.evidence and tool.status in ("running", "installed", "traces")
        assert all(c.host is None or tool.provider_id for c in tool.connections)


def test_the_real_scan_never_confirms_a_connection_to_the_wrong_provider():
    for tool in scan().tools:
        provider = CATALOG.get(tool.provider_id) if tool.provider_id else None
        for conn in tool.verified:
            assert provider is not None and (conn.host in provider.hosts or conn.host.startswith("localhost:"))

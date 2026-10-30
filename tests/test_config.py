from pathlib import Path

import pytest

from shadowlens.config import LOOPBACK_HOST, Config, parse_dotenv

REPO_ROOT = Path(__file__).resolve().parents[1]


def load(env=None, tmp=None, **kwargs):
    """Load a Config from a dict only (no real environment, no .env file)."""
    return Config.load(env=env or {}, base_dir=tmp or Path("/proj"), use_dotenv=False, **kwargs)


# ---- defaults ----------------------------------------------------------------

def test_defaults_match_the_sot():
    c = load()
    assert (c.host, c.port, c.desktop) == ("127.0.0.1", 8787, True)
    assert c.db_path == Path("/proj/data/shadow.db")
    assert c.salt_path == Path("/proj/data/salt")
    assert c.max_body_bytes == 65536
    assert c.workspace_roots == ("~/projects", "~/source", "/workspace")
    assert c.internal_markers == ()
    assert c.sanctioned == ("ollama",)
    assert c.scan_interval_s == 0
    assert c.resolve is True
    assert c.live_dir == Path("/proj/data/live")
    assert c.transcripts_enabled is False and c.transcript_dirs == ()
    assert c.proxy_enabled is False
    assert (c.proxy_port, c.proxy_upstream) == (11436, "127.0.0.1:11434")
    assert c.llm_enabled is True and c.llm_timeout_s == 15
    assert c.llm_send_context is True and c.llm_max_auto == 12
    assert c.featherless_api_key is None and c.featherless_model is None
    assert c.featherless_base_url == "https://api.featherless.ai/v1"
    assert c.warnings == ()


def test_env_example_equals_defaults():
    """.env.example must stay identical to the built-in defaults."""
    example = Config.load(
        env={}, env_file=REPO_ROOT / ".env.example", base_dir=Path("/proj"), use_dotenv=True
    )
    assert example == load()


# ---- overrides and parsing ---------------------------------------------------

def test_overrides():
    c = load({"SHADOWLENS_PORT": "9000", "SHADOWLENS_DESKTOP": "false",
              "SHADOWLENS_MAX_BODY_BYTES": "1024", "SHADOWLENS_SCAN_INTERVAL_S": "2.5"})
    assert (c.port, c.desktop, c.max_body_bytes, c.scan_interval_s) == (9000, False, 1024, 2.5)
    assert c.server_url == "http://127.0.0.1:9000"


@pytest.mark.parametrize("text,expected", [
    ("true", True), ("TRUE", True), ("1", True), ("yes", True), ("on", True),
    ("false", False), ("False", False), ("0", False), ("no", False), ("off", False),
])
def test_boolean_values(text, expected):
    assert load({"SHADOWLENS_RESOLVE": text}).resolve is expected


def test_bad_boolean_falls_back_with_warning():
    c = load({"SHADOWLENS_RESOLVE": "maybe"})
    assert c.resolve is True
    assert any("SHADOWLENS_RESOLVE" in w for w in c.warnings)


@pytest.mark.parametrize("name,value", [
    ("SHADOWLENS_PORT", "abc"),
    ("SHADOWLENS_PORT", "0"),
    ("SHADOWLENS_PORT", "70000"),
    ("SHADOWLENS_MAX_BODY_BYTES", "-5"),
    ("SHADOWLENS_LLM_MAX_AUTO", "-1"),
    ("SHADOWLENS_SCAN_INTERVAL_S", "-1"),
    ("SHADOWLENS_LLM_TIMEOUT_S", "0"),
    ("SHADOWLENS_LLM_TIMEOUT_S", "soon"),
])
def test_bad_numbers_fall_back_with_warning(name, value):
    default = load()
    c = load({name: value})
    assert c == _same_except_warnings(default, c)
    assert any(name in w for w in c.warnings)


def _same_except_warnings(a, b):
    from dataclasses import replace
    return replace(a, warnings=b.warnings)


def test_warning_never_contains_the_value():
    c = load({"SHADOWLENS_PORT": "super-secret-value"})
    assert all("super-secret-value" not in w for w in c.warnings)


def test_empty_value_means_default():
    assert load({"SHADOWLENS_PORT": "  "}).port == 8787


# ---- host is locked to loopback ----------------------------------------------

@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.5", "localhost", "example.com"])
def test_host_is_forced_to_loopback(host):
    c = load({"SHADOWLENS_HOST": host})
    assert c.host == LOOPBACK_HOST
    assert any("SHADOWLENS_HOST" in w for w in c.warnings)


# ---- lists -------------------------------------------------------------------

def test_comma_lists_are_trimmed_and_empties_dropped():
    c = load({"SHADOWLENS_INTERNAL_MARKERS": " Project X , ,Acme Corp,", "SHADOWLENS_SANCTIONED": " Ollama, OpenAI "})
    assert c.internal_markers == ("Project X", "Acme Corp")
    assert c.sanctioned == ("ollama", "openai")  # provider ids are lowercased


def test_workspace_roots_are_kept_as_strings():
    # They are matched like payload paths (SOT 7.4), so they must not be expanded.
    c = load({"SHADOWLENS_WORKSPACE_ROOTS": "~/work, C:\\Users\\dev\\proj"})
    assert c.workspace_roots == ("~/work", "C:\\Users\\dev\\proj")


# ---- paths -------------------------------------------------------------------

def test_relative_paths_resolve_against_base_dir(tmp_path):
    c = load({"SHADOWLENS_DB_PATH": "store/x.db"}, tmp=tmp_path)
    assert c.db_path == tmp_path / "store" / "x.db"


def test_absolute_paths_are_kept(tmp_path):
    target = tmp_path / "elsewhere" / "x.db"
    assert load({"SHADOWLENS_DB_PATH": str(target)}).db_path == target


def test_tilde_expands_to_home():
    c = load({"SHADOWLENS_LIVE_DIR": "~/live"})
    assert c.live_dir == Path.home() / "live"


def test_transcript_dirs_expand_and_resolve(tmp_path):
    c = load({"SHADOWLENS_TRANSCRIPT_DIRS": "~/.claude/projects/demo, rel/dir"}, tmp=tmp_path)
    assert c.transcript_dirs == (Path.home() / ".claude/projects/demo", tmp_path / "rel/dir")


def test_ensure_dirs_creates_folders_and_is_idempotent(tmp_path):
    c = load(tmp=tmp_path)
    c.ensure_dirs()
    c.ensure_dirs()
    assert (tmp_path / "data").is_dir() and (tmp_path / "data" / "live").is_dir()


# ---- proxy upstream ----------------------------------------------------------

@pytest.mark.parametrize("bad", ["localhost", "127.0.0.1:", ":11434", "127.0.0.1:99999", "127.0.0.1:abc"])
def test_bad_proxy_upstream_falls_back(bad):
    c = load({"SHADOWLENS_PROXY_UPSTREAM": bad})
    assert c.proxy_upstream == "127.0.0.1:11434"
    assert any("SHADOWLENS_PROXY_UPSTREAM" in w for w in c.warnings)


def test_good_proxy_upstream_is_kept():
    assert load({"SHADOWLENS_PROXY_UPSTREAM": "localhost:11500"}).proxy_upstream == "localhost:11500"


# ---- AI triage mode ----------------------------------------------------------

@pytest.mark.parametrize("env,mode", [
    ({}, "template"),
    ({"FEATHERLESS_API_KEY": "k"}, "template"),                                  # no model
    ({"FEATHERLESS_MODEL": "m"}, "template"),                                    # no key
    ({"FEATHERLESS_API_KEY": "k", "FEATHERLESS_MODEL": "m"}, "llm"),
    ({"FEATHERLESS_API_KEY": "k", "FEATHERLESS_MODEL": "m", "SHADOWLENS_LLM_ENABLED": "false"}, "template"),
])
def test_llm_mode(env, mode):
    assert load(env).llm_mode == mode


def test_key_is_never_printed():
    c = load({"FEATHERLESS_API_KEY": "do-not-print-me"})
    assert c.key_present is True
    assert "do-not-print-me" not in repr(c)
    assert "do-not-print-me" not in str(c)


# ---- .env file ---------------------------------------------------------------

def test_parse_dotenv_handles_comments_quotes_bom_and_crlf():
    text = "\ufeff# comment\r\nA=1\r\n\r\nB = \"two words\"\r\nC='x'\r\nD=a#b\r\nnoequals\r\n=nokey\r\n"
    assert parse_dotenv(text) == {"A": "1", "B": "two words", "C": "x", "D": "a#b"}


def test_dotenv_file_is_read_and_real_environment_wins(tmp_path):
    (tmp_path / ".env").write_text("SHADOWLENS_PORT=9100\nSHADOWLENS_DESKTOP=false\n", encoding="utf-8")
    from_file = Config.load(env={}, base_dir=tmp_path)
    assert (from_file.port, from_file.desktop) == (9100, False)
    overridden = Config.load(env={"SHADOWLENS_PORT": "9200"}, base_dir=tmp_path)
    assert (overridden.port, overridden.desktop) == (9200, False)


def test_missing_dotenv_is_fine(tmp_path):
    assert Config.load(env={}, base_dir=tmp_path).port == 8787


def test_config_is_immutable():
    c = load()
    with pytest.raises(Exception):
        c.port = 1  # type: ignore[misc]

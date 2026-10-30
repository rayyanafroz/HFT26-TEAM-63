import copy

import pytest

from shadowlens.config import Config
from shadowlens.models import Category, MatchBasis, MatchConfidence, NetEvent, new_id
from shadowlens.providers.catalog import Catalog, CatalogError
from shadowlens.providers.classify import classify, hostname_of, is_local_destination

CATALOG = Catalog.load()


def ev(host=None, dst_ip="203.0.113.7", dst_port=443, path=None, process="python3"):
    return NetEvent(id=new_id(), ts="2026-10-31T10:00:00.000Z", source="http_log", process=process,
                    dst_ip=dst_ip, dst_port=dst_port, host=host, host_basis="host_header", path=path)


# ---- the catalog equals the SOT table ----------------------------------------

# (id, category, hosts, native key rules): transcribed from SOT 7.1 independently of the YAML.
SOT_TABLE = [
    ("openai", "cloud_llm", ["api.openai.com"], ["SEC_OPENAI_KEY"]),
    ("anthropic", "cloud_llm", ["api.anthropic.com"], ["SEC_ANTHROPIC_KEY"]),
    ("google_gemini", "cloud_llm", ["generativelanguage.googleapis.com"], ["SEC_GOOGLE_API_KEY"]),
    ("mistral", "cloud_llm", ["api.mistral.ai"], []),
    ("cohere", "cloud_llm", ["api.cohere.com", "api.cohere.ai"], []),
    ("groq", "cloud_llm", ["api.groq.com"], []),
    ("together", "cloud_llm", ["api.together.xyz", "api.together.ai"], []),
    ("fireworks", "cloud_llm", ["api.fireworks.ai"], []),
    ("featherless", "cloud_llm", ["api.featherless.ai"], []),
    ("perplexity", "cloud_llm", ["api.perplexity.ai"], []),
    ("deepseek", "cloud_llm", ["api.deepseek.com"], []),
    ("xai", "cloud_llm", ["api.x.ai"], []),
    ("openrouter", "cloud_llm", ["openrouter.ai"], []),
    ("replicate", "cloud_llm", ["api.replicate.com"], []),
    ("azure_openai", "cloud_llm", [], []),
    ("aws_bedrock", "cloud_llm", [], []),
    ("huggingface", "model_hub", ["huggingface.co", "api-inference.huggingface.co", "router.huggingface.co"],
     ["SEC_HF_TOKEN"]),
    ("chatgpt_web", "ai_app", ["chatgpt.com", "chat.openai.com"], []),
    ("claude_web", "ai_app", ["claude.ai"], []),
    ("gemini_web", "ai_app", ["gemini.google.com"], []),
    ("copilot", "ai_app", ["copilot.microsoft.com", "api.githubcopilot.com"], []),
    ("cursor", "ai_app", ["cursor.sh"], []),
    ("poe", "ai_app", ["poe.com"], []),
    ("character_ai", "ai_app", ["character.ai"], []),
    ("ollama", "local_llm", [], []),
    ("lmstudio", "local_llm", [], []),
    ("local_openai_compatible", "local_llm", [], []),
]


def test_catalog_has_every_row_of_the_sot_table_in_order():
    assert len(CATALOG.providers) == len(SOT_TABLE) == 27
    for provider, (pid, category, hosts, native) in zip(CATALOG.providers, SOT_TABLE):
        assert (provider.id, provider.category.value, provider.hosts, provider.native_key_rules) == \
               (pid, category, hosts, native), pid


def test_regex_and_port_providers():
    assert CATALOG.get("azure_openai").host_regex == r".*\.openai\.azure\.com"
    assert CATALOG.get("aws_bedrock").host_regex == r"bedrock-runtime\.[a-z0-9-]+\.amazonaws\.com"
    assert CATALOG.get("ollama").ports == [11434]
    assert CATALOG.get("lmstudio").ports == [1234]
    amb = CATALOG.get("local_openai_compatible")
    assert amb.ports == [8000, 8080, 5000] and amb.ports_need_path_hint is True
    assert amb.path_hints == ["/v1/chat/completions", "/completion", "/v1/completions", "/api/v1/generate"]


def test_unverified_hosts_are_flagged():
    assert {p.id for p in CATALOG.providers if p.unverified} == {"cursor", "poe", "character_ai"}


def test_category_exposure_multipliers():
    assert {c.value: CATALOG.exposure(c) for c in Category} == {
        "cloud_llm": 1.0, "ai_app": 1.0, "model_hub": 1.1, "local_llm": 0.4}


def test_catalog_agrees_with_the_config_default_for_sanctioned_providers():
    config = Config.load(env={}, use_dotenv=False)
    assert CATALOG.sanctioned_by_default() == frozenset(config.sanctioned) == {"ollama"}


# ---- step 1: host ------------------------------------------------------------

@pytest.mark.parametrize("host,provider", [
    ("api.openai.com", "openai"), ("API.OpenAI.COM", "openai"), ("api.openai.com:443", "openai"),
    ("api.openai.com.", "openai"), ("eu.api.openai.com", "openai"),
    ("api.anthropic.com", "anthropic"), ("generativelanguage.googleapis.com", "google_gemini"),
    ("api.cohere.ai", "cohere"), ("api.together.ai", "together"), ("api.x.ai", "xai"),
    ("openrouter.ai", "openrouter"), ("api.featherless.ai", "featherless"),
    ("myteam.openai.azure.com", "azure_openai"),
    ("bedrock-runtime.us-east-1.amazonaws.com", "aws_bedrock"),
    ("huggingface.co", "huggingface"), ("cdn-lfs.huggingface.co", "huggingface"),
    ("router.huggingface.co", "huggingface"),
    ("chatgpt.com", "chatgpt_web"), ("chat.openai.com", "chatgpt_web"),   # not "openai": it is the web app
    ("claude.ai", "claude_web"), ("www.claude.ai", "claude_web"), ("gemini.google.com", "gemini_web"),
    ("copilot.microsoft.com", "copilot"), ("api.githubcopilot.com", "copilot"),
    ("api2.cursor.sh", "cursor"), ("poe.com", "poe"), ("beta.character.ai", "character_ai"),
])
def test_known_hosts(host, provider):
    m = classify(ev(host=host), CATALOG)
    assert m is not None, host
    assert (m.provider_id, m.confidence, m.match_basis) == (provider, MatchConfidence.HIGH, MatchBasis.HOST)


@pytest.mark.parametrize("host", [
    "github.com", "www.google.com", "google.com", "example.com", "api.openai.com.evil.net",
    "xapi.openai.com", "notopenrouter.ai", "evilclaude.ai", "bedrock.us-east-1.amazonaws.com",
    "openai.azure.com.attacker.io", "huggingface.co.evil.net", "", None,
])
def test_non_ai_and_lookalike_hosts_do_not_match(host):
    assert classify(ev(host=host), CATALOG) is None


def test_the_longest_matching_host_wins():
    cat = Catalog.from_dict({
        "category_exposure": {c.value: 1.0 for c in Category},
        "providers": [
            {"id": "wide", "display_name": "Wide", "category": "cloud_llm", "hosts": ["example.com"]},
            {"id": "narrow", "display_name": "Narrow", "category": "cloud_llm", "hosts": ["api.example.com"]},
        ]})
    assert classify(ev(host="api.example.com"), cat).provider_id == "narrow"
    assert classify(ev(host="www.example.com"), cat).provider_id == "wide"
    assert classify(ev(host="eu.api.example.com"), cat).provider_id == "narrow"


def test_match_carries_display_details_and_tool_id():
    m = classify(ev(host="api.openai.com", process="Python3"), CATALOG)
    assert (m.display_name, m.category, m.tool_id) == ("OpenAI", Category.CLOUD_LLM, "python3|openai")
    assert classify(ev(host="api.openai.com", process=None), CATALOG).tool_id == "unknown|openai"
    assert classify(ev(host="chatgpt.com", process="browser"), CATALOG).tool_id == "browser|chatgpt_web"


# ---- step 2: local ports -----------------------------------------------------

@pytest.mark.parametrize("kwargs,provider", [
    (dict(dst_ip="127.0.0.1", dst_port=11434), "ollama"),
    (dict(dst_ip="127.0.0.1", dst_port=11434, path="/api/chat"), "ollama"),
    (dict(dst_ip="::1", dst_port=11434), "ollama"),
    (dict(dst_ip="192.168.1.50", dst_port=11434), "ollama"),
    (dict(dst_ip="10.0.0.8", dst_port=11434), "ollama"),
    (dict(dst_ip="0.0.0.0", dst_port=11434, host="localhost:11434"), "ollama"),
    (dict(dst_ip="0.0.0.0", dst_port=11434, host="127.0.0.1"), "ollama"),
    (dict(dst_ip="127.0.0.1", dst_port=1234), "lmstudio"),
])
def test_dedicated_local_ports_are_high_confidence(kwargs, provider):
    m = classify(ev(**kwargs), CATALOG)
    assert m is not None
    assert (m.provider_id, m.confidence, m.match_basis) == (provider, MatchConfidence.HIGH, MatchBasis.PORT)


@pytest.mark.parametrize("port,path", [
    (8080, "/v1/chat/completions"), (8000, "/v1/completions"), (5000, "/api/v1/generate"),
    (8080, "/completion"), (8080, "/V1/Chat/Completions"), (8000, "/completions"),
])
def test_ambiguous_ports_need_an_llm_looking_path(port, path):
    m = classify(ev(dst_ip="127.0.0.1", dst_port=port, path=path), CATALOG)
    assert m is not None
    assert (m.provider_id, m.confidence, m.match_basis) == (
        "local_openai_compatible", MatchConfidence.MEDIUM, MatchBasis.PORT)


@pytest.mark.parametrize("port,path", [
    (8080, None), (8080, "/"), (8080, "/index.html"), (8000, "/api/users"), (5000, "/health"),
    (3000, "/v1/chat/completions"), (443, "/v1/chat/completions"),
])
def test_ambiguous_or_unknown_local_ports_without_a_hint_do_not_match(port, path):
    assert classify(ev(dst_ip="127.0.0.1", dst_port=port, path=path), CATALOG) is None


def test_local_ports_are_ignored_for_public_destinations():
    assert classify(ev(dst_ip="8.8.8.8", dst_port=11434), CATALOG) is None
    assert classify(ev(dst_ip="8.8.8.8", dst_port=8080, path="/v1/chat/completions"), CATALOG) is None


def test_unknown_destination_address_is_not_treated_as_local():
    # 0.0.0.0 means "we did not know the address" in our logs: a real cloud host must not look local.
    assert classify(ev(host="api.example.com", dst_ip="0.0.0.0", dst_port=8080,
                       path="/v1/chat/completions"), CATALOG) is None


def test_host_beats_port():
    m = classify(ev(host="api.openai.com", dst_ip="127.0.0.1", dst_port=11434), CATALOG)
    assert (m.provider_id, m.match_basis) == ("openai", MatchBasis.HOST)


@pytest.mark.parametrize("host,expected", [
    ("localhost", "localhost"), ("LOCALHOST:8080", "localhost"), ("api.example.com:443", "api.example.com"),
    ("[::1]:11434", "::1"), ("::1", "::1"), ("example.com.", "example.com"), ("", None), (None, None),
])
def test_hostname_of(host, expected):
    assert hostname_of(host) == expected


@pytest.mark.parametrize("ip,local", [
    ("127.0.0.1", True), ("127.5.5.5", True), ("::1", True),
    ("10.0.0.1", True), ("172.16.0.1", True), ("172.31.255.255", True), ("192.168.1.1", True),
    ("169.254.10.10", True), ("fc00::1", True), ("fd12:3456::1", True), ("fe80::1", True),
    ("172.15.255.255", False), ("172.32.0.1", False), ("100.64.0.1", False),       # just outside RFC 1918
    ("8.8.8.8", False), ("1.1.1.1", False), ("2001:4860:4860::8888", False),
    ("203.0.113.7", False), ("192.0.2.1", False), ("198.51.100.9", False),         # documentation ranges
    ("0.0.0.0", False), ("::", False),
])
def test_local_address_definition(ip, local):
    assert is_local_destination(ev(dst_ip=ip), None) is local


def test_fake_public_fixture_addresses_never_look_local():
    # Fixtures use documentation addresses as 'public' servers; a local-port rule must not fire for them.
    for ip in ("203.0.113.7", "192.0.2.10", "198.51.100.20"):
        assert classify(ev(dst_ip=ip, dst_port=11434), CATALOG) is None
        assert classify(ev(dst_ip=ip, dst_port=8080, path="/v1/chat/completions"), CATALOG) is None


def test_is_local_destination():
    assert is_local_destination(ev(dst_ip="127.0.0.1"), None)
    assert is_local_destination(ev(dst_ip="203.0.113.7"), "localhost")
    assert not is_local_destination(ev(dst_ip="203.0.113.7"), "api.example.com")
    assert not is_local_destination(ev(dst_ip="0.0.0.0"), None)


# ---- step 3: resolver map ----------------------------------------------------

def test_resolved_ip_is_a_low_confidence_match():
    m = classify(ev(dst_ip="203.0.113.50", dst_port=443), CATALOG, {"203.0.113.50": "anthropic"})
    assert (m.provider_id, m.confidence, m.match_basis) == ("anthropic", MatchConfidence.LOW, MatchBasis.RESOLVED_IP)
    assert m.tool_id == "python3|anthropic"


def test_resolver_misses_and_bad_entries():
    assert classify(ev(dst_ip="203.0.113.50"), CATALOG, {"198.51.100.1": "openai"}) is None
    assert classify(ev(dst_ip="203.0.113.50"), CATALOG, {}) is None
    assert classify(ev(dst_ip="203.0.113.50"), CATALOG, None) is None
    assert classify(ev(dst_ip="203.0.113.50"), CATALOG, {"203.0.113.50": "not_a_provider"}) is None


def test_host_and_port_both_beat_the_resolver():
    ips = {"203.0.113.50": "anthropic", "127.0.0.1": "anthropic"}
    assert classify(ev(host="api.openai.com", dst_ip="203.0.113.50"), CATALOG, ips).match_basis is MatchBasis.HOST
    assert classify(ev(dst_ip="127.0.0.1", dst_port=11434), CATALOG, ips).match_basis is MatchBasis.PORT


def test_a_live_scan_event_for_a_local_model_server_matches_by_port():
    """conn_scan has no host and no path: only the address and port (AT-01)."""
    e = NetEvent(id=new_id(), ts="2026-10-31T10:00:00.000Z", source="conn_scan", process="python3", pid=4123,
                 dst_ip="127.0.0.1", dst_port=11434, host_basis="port_only")
    m = classify(e, CATALOG)
    assert (m.provider_id, m.tool_id) == ("ollama", "python3|ollama")


# ---- provider-native keys and resolvable hosts -------------------------------

@pytest.mark.parametrize("provider,rule,expected", [
    ("openai", "SEC_OPENAI_KEY", True), ("openai", "SEC_ANTHROPIC_KEY", False),
    ("anthropic", "SEC_ANTHROPIC_KEY", True), ("google_gemini", "SEC_GOOGLE_API_KEY", True),
    ("huggingface", "SEC_HF_TOKEN", True), ("mistral", "SEC_JWT", False),
    ("mistral", "SEC_OPENAI_KEY", False), ("nobody", "SEC_OPENAI_KEY", False),
])
def test_native_key_ok(provider, rule, expected):
    assert CATALOG.native_key_ok(provider, rule) is expected


def test_resolvable_hosts_are_the_cloud_literal_hosts():
    hosts = CATALOG.resolvable_hosts()
    assert hosts["api.openai.com"] == "openai" and hosts["claude.ai"] == "claude_web"
    assert hosts["api-inference.huggingface.co"] == "huggingface"
    assert all(CATALOG.get(pid) and not CATALOG.get(pid).is_local for pid in hosts.values())
    assert not {"localhost", "127.0.0.1"} & set(hosts)
    assert len(hosts) == sum(len(p.hosts) for p in CATALOG.providers)       # regex/local providers add none


# ---- the loader rejects bad catalogs -----------------------------------------

def good():
    return {"category_exposure": {c.value: 1.0 for c in Category},
            "providers": [{"id": "a", "display_name": "A", "category": "cloud_llm", "hosts": ["a.example.com"]}]}


def change(mutator):
    data = copy.deepcopy(good())
    mutator(data)
    return data


@pytest.mark.parametrize("mutator,fragment", [
    (lambda d: d["providers"].append(dict(d["providers"][0])), "duplicate"),
    (lambda d: d["providers"][0].update(category="space_lasers"), "category"),
    (lambda d: d["providers"][0].update(host_regex="("), "host_regex"),
    (lambda d: d["providers"][0].update(native_key_rules=["SEC_MADE_UP"]), "unknown rule"),
    (lambda d: d["providers"][0].update(hosts=[], ), "needs hosts"),
    (lambda d: d["providers"][0].update(hosts=["http://bad/path"]), "host names"),
    (lambda d: d["providers"][0].update(bogus_key=1), "bogus_key"),
    (lambda d: d["providers"][0].update(id="Bad Id"), "id"),
    (lambda d: d["providers"][0].update(ports=[70000]), "ports"),
    (lambda d: d["providers"][0].update(ports_need_path_hint=True), "path_hints"),
    (lambda d: d["providers"][0].update(path_hints=["no-slash"]), "start with"),
    (lambda d: d.update(extra_top_level=1), "top-level"),
    (lambda d: d.pop("category_exposure"), "category_exposure"),
    (lambda d: d["category_exposure"].pop("model_hub"), "category_exposure"),
    (lambda d: d["category_exposure"].update(model_hub=0), "category_exposure"),
    (lambda d: d.update(providers="nope"), "providers"),
])
def test_bad_catalogs_are_rejected_with_a_useful_message(mutator, fragment):
    with pytest.raises(CatalogError) as err:
        Catalog.from_dict(change(mutator))
    assert fragment.lower() in str(err.value).lower()


def test_error_names_the_provider():
    with pytest.raises(CatalogError, match="provider a:"):
        Catalog.from_dict(change(lambda d: d["providers"][0].update(category="nope")))


def test_missing_and_malformed_files(tmp_path):
    with pytest.raises(CatalogError, match="not found"):
        Catalog.load(tmp_path / "missing.yaml")
    broken = tmp_path / "broken.yaml"
    broken.write_text("providers: [unclosed", encoding="utf-8")
    with pytest.raises(CatalogError, match="cannot read"):
        Catalog.load(broken)
    with pytest.raises(CatalogError, match="mapping"):
        Catalog.from_dict(None)

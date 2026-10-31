"""Agent behavior: what a tool was given, what it did, and which of that is risky (SOT 7.4).

Paths inside payloads are only ever strings. They are normalized here and never
touch the filesystem.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterator

from shadowlens.analysis.masking import hash12
from shadowlens.analysis.normalize import deobfuscate_command
from shadowlens.analysis.settings import AgentRules, AnalysisSettings
from shadowlens.core.ctx import AgentSessionContext
from shadowlens.models import CapabilityName, Severity

_SHELL_KEYS = ("command", "cmd", "script", "code", "input")
_COMMAND_KEYS = ("command", "cmd")  # for tools not known to be shells
_FILE_KEYS = ("path", "file_path", "filepath", "filename", "file_name", "file", "directory", "dir", "target",
              "target_file", "absolute_path", "relative_workspace_path", "notebook_path", "source", "src", "dest",
              "destination", "uri", "url", "location")
# Fields that hold what is WRITTEN or said about a call, not what it acts on. A note that mentions ".env" or
# "rm -rf /" in one of these is not an action.
_CONTENT_KEYS = frozenset({"content", "contents", "new_string", "old_string", "new_str", "old_str", "text", "data",
                           "body", "diff", "patch", "file_text", "insert_text", "replacement"})
_NOTE_KEYS = frozenset({"description", "summary", "title", "explanation", "reason", "note", "notes", "comment",
                        "label", "name", "message", "prompt", "thought", "rationale"})
_FILE_CAPABILITIES = frozenset({"fs_read", "fs_write"})
_GRANTABLE = frozenset({"shell", "fs_read", "fs_write", "network", "mcp"})
_EXCESSIVE_AT = 3
_RISKY_SEVERITIES = frozenset({"high", "critical"})

_COMMAND_SPLIT_RE = re.compile(r"&&|\|\||;|\||\n")
_WRITES_OR_SUBSTITUTES_RE = re.compile(r">|\$\(|`")
_FIND_ACTIONS_RE = re.compile(r"\s-(?:exec|execdir|delete|ok)\b")

_HOME_PREFIX_RE = re.compile(
    r"^(?:/home/[^/]+|/users/[^/]+|[a-z]:/users/[^/]+|%userprofile%|\$env:userprofile|\$home|~)(?:/|$)"
)
_DRIVE_RE = re.compile(r"^[a-z]:(?:/|$)")


# ---- parsing: one shape for OpenAI, Anthropic, Ollama and MCP -------------------

@dataclass(frozen=True)
class ToolCall:
    name: str
    args: dict[str, Any]


@dataclass
class ParsedBody:
    declared: list[tuple[str, str]] = field(default_factory=list)  # (name, description)
    calls: list[ToolCall] = field(default_factory=list)
    mcp_calls: list[ToolCall] = field(default_factory=list)
    results: list[str] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not (self.declared or self.calls or self.mcp_calls or self.results)


def _as_args(raw: Any) -> dict[str, Any]:
    """Tool arguments as a dict. A string that is not JSON is treated as the command."""
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            decoded = json.loads(raw)
        except (ValueError, RecursionError):
            return {"command": raw}
        return decoded if isinstance(decoded, dict) else {"command": raw}
    return {}


def _block_text(content: Any) -> str:
    """A tool result's content: a string, or a list of ``{text}`` blocks."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = [_block_text(item.get("text") or item.get("content")) if isinstance(item, dict) else _block_text(item)
                 for item in content]
        return "\n".join(part for part in parts if part)
    return ""


def _declared_tools(tools: Any) -> Iterator[tuple[str, str]]:
    for tool in tools if isinstance(tools, list) else []:
        if not isinstance(tool, dict):
            continue
        function = tool.get("function") if isinstance(tool.get("function"), dict) else tool
        name = function.get("name")
        if isinstance(name, str) and name:
            description = function.get("description")
            yield name, description if isinstance(description, str) else ""


def _parse_message(message: dict[str, Any], parsed: ParsedBody) -> None:
    for call in message.get("tool_calls") if isinstance(message.get("tool_calls"), list) else []:
        function = call.get("function") if isinstance(call, dict) else None
        if isinstance(function, dict) and isinstance(function.get("name"), str):
            parsed.calls.append(ToolCall(function["name"], _as_args(function.get("arguments"))))

    content = message.get("content")
    if message.get("role") == "tool":
        text = _block_text(content)
        if text:
            parsed.results.append(text)
    for block in content if isinstance(content, list) else []:
        if not isinstance(block, dict):
            continue
        if block.get("type") == "tool_use" and isinstance(block.get("name"), str):
            parsed.calls.append(ToolCall(block["name"], _as_args(block.get("input"))))
        elif block.get("type") == "tool_result":
            text = _block_text(block.get("content"))
            if text:
                parsed.results.append(text)


def _parse_responses_items(items: Any, parsed: ParsedBody) -> None:
    """OpenAI Responses API: ``input`` is a list of items such as ``function_call`` and ``local_shell_call``."""
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        kind = item.get("type")
        if kind in ("function_call", "tool_call", "custom_tool_call") and isinstance(item.get("name"), str):
            parsed.calls.append(ToolCall(item["name"], _as_args(item.get("arguments", item.get("input")))))
        elif kind == "local_shell_call" and isinstance(item.get("action"), dict):
            parsed.calls.append(ToolCall("local_shell", {"command": item["action"].get("command")}))
        elif kind in ("function_call_output", "local_shell_call_output"):
            text = _block_text(item.get("output"))
            if text:
                parsed.results.append(text)
        elif isinstance(item.get("content"), (list, str)):          # an ordinary message item
            _parse_message(item, parsed)


def _parse_gemini_contents(contents: Any, parsed: ParsedBody) -> None:
    """Gemini: ``contents[].parts[]`` hold ``functionCall`` and ``functionResponse``."""
    for content in contents if isinstance(contents, list) else []:
        for part in content.get("parts", []) if isinstance(content, dict) and isinstance(content.get("parts"), list) else []:
            if not isinstance(part, dict):
                continue
            call = part.get("functionCall")
            if isinstance(call, dict) and isinstance(call.get("name"), str):
                parsed.calls.append(ToolCall(call["name"], _as_args(call.get("args"))))
            response = part.get("functionResponse")
            if isinstance(response, dict):
                text = _block_text(response.get("response"))
                if text:
                    parsed.results.append(text)


def parse_agent_body(body_text: str | None) -> ParsedBody | None:
    """Tool declarations, calls and results in a request body, or ``None`` if there are none."""
    if not body_text:
        return None
    try:
        body = json.loads(body_text)
    except (ValueError, RecursionError):
        return None
    if not isinstance(body, dict):
        return None

    parsed = ParsedBody(declared=list(_declared_tools(body.get("tools"))))
    if body.get("method") == "tools/call" and isinstance(body.get("params"), dict):
        name = body["params"].get("name")
        if isinstance(name, str) and name:
            parsed.mcp_calls.append(ToolCall(name, _as_args(body["params"].get("arguments"))))
    for message in body.get("messages") if isinstance(body.get("messages"), list) else []:
        if isinstance(message, dict):
            _parse_message(message, parsed)
    _parse_responses_items(body.get("input"), parsed)
    _parse_gemini_contents(body.get("contents"), parsed)
    return None if parsed.empty else parsed


# ---- helpers on names, commands and paths ---------------------------------------

def tool_capabilities(name: str, rules: AgentRules) -> set[str]:
    """What a tool name stands for. ``runShellCommand`` is read as ``run_shell_command``."""
    words = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
    return {capability for capability, pattern in rules.capabilities.items()
            if pattern.fullmatch(name) or pattern.fullmatch(words)}


def _string_values(args: dict[str, Any], keys: tuple[str, ...]) -> list[str]:
    values: list[str] = []
    for key in keys:
        value = args.get(key)
        if isinstance(value, str) and value:
            values.append(value)
    return values


def _as_command(value: Any) -> str | None:
    """A string, or a list of words (``["rm", "-rf", "/"]``) as the one command it stands for."""
    if isinstance(value, str):
        return value or None
    if isinstance(value, list) and value and all(isinstance(item, str) for item in value):
        return " ".join(value)
    return None


def _acted_on_strings(value: Any, skip: frozenset[str], depth: int = 0) -> Iterator[str]:
    """Every string in the arguments except the ones under a content or note field."""
    if depth > 6:
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() not in skip:
                yield from _acted_on_strings(item, skip, depth + 1)
    elif isinstance(value, list):
        joined = _as_command(value)
        if joined is not None:
            yield joined
        else:
            for item in value:
                yield from _acted_on_strings(item, skip, depth + 1)
    elif isinstance(value, str) and value:
        yield value


def extract_commands(args: dict[str, Any], capabilities: set[str]) -> list[str]:
    commands = _string_values(args, _SHELL_KEYS if "shell" in capabilities else _COMMAND_KEYS)
    listed = args.get("commands")
    if isinstance(listed, list):
        commands.extend(item for item in listed if isinstance(item, str) and item)
    for key in ("argv", "args", "arguments", "cmd", "command"):         # a command given as a list of words
        joined = _as_command(args.get(key))
        if joined is not None and joined not in commands and isinstance(args.get(key), list):
            commands.append(joined)
    if "shell" in capabilities and not commands:
        # A shell tool whose command sits under a key we do not know: everything but notes about the call counts.
        commands.extend(_acted_on_strings(args, _NOTE_KEYS))
    return commands


def extract_paths(args: dict[str, Any]) -> list[str]:
    paths = _string_values(args, _FILE_KEYS)
    listed = args.get("paths")
    if isinstance(listed, list):
        paths.extend(item for item in listed if isinstance(item, str) and item)
    return paths


def all_strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from all_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from all_strings(item)


def is_read_only(commands: list[str], rules: AgentRules) -> bool:
    """True when the first word of every command only looks at things."""
    pieces = [piece.strip() for command in commands for piece in _COMMAND_SPLIT_RE.split(command)]
    pieces = [piece for piece in pieces if piece]
    if not pieces:
        return False
    if any(_WRITES_OR_SUBSTITUTES_RE.search(command) for command in commands):
        return False
    for piece in pieces:
        words = piece.split()
        first = words[0].lower()
        if first == "git":
            if len(words) < 2 or words[1].lower() not in rules.read_only_git:
                return False
        elif first not in rules.read_only_commands:
            return False
        elif first == "find" and _FIND_ACTIONS_RE.search(piece):
            return False
    return True


def normalize_path(path: str) -> str:
    """One lowercase form for Windows and POSIX path strings; every home folder becomes ``~/``."""
    text = path.strip().strip("\"'").replace("\\", "/").lower()
    match = _HOME_PREFIX_RE.match(text)
    if match:
        return "~/" + text[match.end():]
    return text


def is_outside_workspace(path: str, roots: tuple[str, ...]) -> bool:
    normalized = normalize_path(path)
    if ".." in normalized.split("/"):
        return True
    if not normalized.startswith(("/", "~/")) and not _DRIVE_RE.match(normalized):
        return False  # a plain relative path stays where the agent is working
    for root in roots:
        base = normalize_path(root).rstrip("/")
        if normalized == base or normalized.startswith(base + "/"):
            return False
    return True


def matches_any(patterns: tuple[re.Pattern[str], ...], text: str) -> bool:
    return any(pattern.search(text) for pattern in patterns)


def matches_any_view(patterns: tuple[re.Pattern[str], ...], text: str) -> bool:
    """``matches_any`` on the command as written and as the shell will read it (``r''m``, ``\\rm``, ``${IFS}``)."""
    if matches_any(patterns, text):
        return True
    plain = deobfuscate_command(text)
    return plain != text and matches_any(patterns, plain)


# ---- rules --------------------------------------------------------------------

@dataclass(frozen=True)
class AgentHit:
    """A rule that fired. ``argument`` is still raw; the caller redacts it before it goes anywhere."""

    rule_id: str
    severity: str
    hash12: str
    tool_name: str
    argument: str | None
    field: str  # "tool_call" or "tool_declaration"


@dataclass
class CallOutcome:
    call: ToolCall
    hits: list[AgentHit]
    capabilities: set[str]
    argument: str | None

    @property
    def risky_hit(self) -> AgentHit | None:
        """The worst hit, so a dangerous shell command is shown as dangerous, not just as a shell call."""
        risky = [hit for hit in self.hits if hit.severity in _RISKY_SEVERITIES]
        return max(risky, key=lambda hit: Severity(hit.severity).rank, default=None)


def _call_hash(call: ToolCall, salt: bytes) -> str:
    return hash12(call.name + json.dumps(call.args, sort_keys=True, default=str), salt)


def _evaluate_call(call: ToolCall, is_mcp: bool, digest: str, settings: AnalysisSettings) -> CallOutcome:
    rules = settings.agent_rules
    capabilities = tool_capabilities(call.name, rules)
    commands = extract_commands(call.args, capabilities)
    paths = extract_paths(call.args)
    command_text = "\n".join(commands)
    argument = command_text or (paths[0] if paths else None)
    hits: list[AgentHit] = []

    def hit(rule_id: str, severity: str) -> None:
        hits.append(AgentHit(rule_id, severity, digest, call.name, argument, "tool_call"))

    if "shell" in capabilities:
        hit("AGENT_SHELL_EXEC", "medium" if is_read_only(commands, rules) else "high")
    if command_text and matches_any_view(rules.dangerous_commands, command_text):
        hit("AGENT_DANGEROUS_CMD", "critical")
    if command_text and matches_any_view(rules.egress_commands, command_text):
        hit("AGENT_EGRESS_COMMAND", "high")
    if command_text and matches_any_view(rules.network_commands, command_text):
        capabilities.add("network")

    # File tools are judged on their path, so editing a file that merely mentions ".env" stays quiet.
    is_file_tool = bool(capabilities & _FILE_CAPABILITIES)
    if is_file_tool:
        # Paths can sit under any key (target_file, uri, location...): check everything except file content.
        checked = paths + commands + [x for x in _acted_on_strings(call.args, _CONTENT_KEYS | _NOTE_KEYS) if x not in paths]
    elif "shell" in capabilities:
        checked = paths + commands
    else:
        checked = list(all_strings(call.args))
    sensitive = [text for text in checked if matches_any_view(rules.sensitive_paths, text)]
    if sensitive:
        hit("AGENT_SENSITIVE_FILE_READ", "high")
        capabilities.add("sensitive_file")
    elif is_file_tool and any(is_outside_workspace(path, settings.workspace_roots) for path in paths):
        hit("AGENT_FS_READ_OUTSIDE_WORKSPACE", "medium")

    if is_mcp:
        high = bool(capabilities & ({"shell"} | _FILE_CAPABILITIES))
        hit("AGENT_MCP_TOOL_CALL", "high" if high else "medium")
        capabilities.add("mcp")

    if tool_capabilities(call.name, rules) & {"network"}:
        # Hashed on the name alone: having and using one network tool is a single finding.
        hits.append(AgentHit("AGENT_NETWORK_TOOL", "low", hash12(call.name, settings.salt),
                             call.name, argument, "tool_call"))
    return CallOutcome(call, hits, capabilities, argument)


def evaluate_calls(parsed: ParsedBody, session: AgentSessionContext, settings: AnalysisSettings) -> list[CallOutcome]:
    """Rules for calls this session has not seen yet."""
    outcomes: list[CallOutcome] = []
    for calls, is_mcp in ((parsed.calls, False), (parsed.mcp_calls, True)):
        for call in calls:
            digest = _call_hash(call, settings.salt)
            if digest in session.seen_calls:
                continue
            session.seen_calls.add(digest)
            outcomes.append(_evaluate_call(call, is_mcp, digest, settings))
    return outcomes


def evaluate_declarations(
    parsed: ParsedBody, session: AgentSessionContext, settings: AnalysisSettings
) -> tuple[list[AgentHit], list[tuple[str, str]]]:
    """Rules on declared tools, and the capabilities newly granted as (capability, tool name)."""
    rules = settings.agent_rules
    new_grants: list[tuple[str, str]] = []
    shell_tool: str | None = None
    network_tools: list[str] = []
    for name, _ in parsed.declared:
        capabilities = tool_capabilities(name, rules)
        for capability in sorted(capabilities):
            if CapabilityName(capability) not in session.granted:
                session.granted.add(CapabilityName(capability))
                new_grants.append((capability, name))
        if "shell" in capabilities and shell_tool is None:
            shell_tool = name
        if "network" in capabilities:
            network_tools.append(name)

    hits: list[AgentHit] = []
    salt = settings.salt
    granted = {capability.value for capability in session.granted} & _GRANTABLE
    if len(granted) >= _EXCESSIVE_AT:
        listed = ", ".join(sorted(granted))
        hits.append(AgentHit("AGENT_EXCESSIVE_AGENCY", "medium", hash12("excessive", salt),
                             "(declared tools)", listed, "tool_declaration"))
    elif shell_tool is not None:
        hits.append(AgentHit("AGENT_SHELL_TOOL_DECLARED", "medium", hash12(shell_tool, salt),
                             shell_tool, None, "tool_declaration"))
    for name in network_tools:
        hits.append(AgentHit("AGENT_NETWORK_TOOL", "low", hash12(name, salt), name, None, "tool_declaration"))
    return hits, new_grants

"""Shadow Lens for coding agents: stops secrets before a prompt or a tool call reaches the model.

Claude Code runs this program at four points and acts on what it prints:

* ``UserPromptSubmit``: a prompt that holds a key, a password or personal data is blocked, and the person
  is shown what was found and a safe version to send instead;
* ``PreToolUse``: a tool call whose input holds a secret is denied; one that reads a credential file or
  sends local data out is put to the person first; a dangerous shell command is denied;
* ``PostToolUse``: when what a tool printed holds a secret (``cat .env``), the model is told not to repeat it.

    python -m shadowlens.hook install [--scope user|project|local]    add the hooks to Claude Code
    python -m shadowlens.hook uninstall [--scope ...]
    python -m shadowlens.hook status
    python -m shadowlens.hook scan [FILE...]      the same check for the shell; exit 1 when something is found
    python -m shadowlens.hook scan --redact FILE  print the text with values replaced
    python -m shadowlens.hook precommit           scan what is staged in git (add to .git/hooks/pre-commit)

Settings (environment, or the dashboard's .env): ``SHADOWLENS_HOOK_MODE`` = ``block`` (default), ``warn``
(report, never block) or ``off``; ``SHADOWLENS_HOOK_FILES`` = ``ask`` (default), ``deny`` or ``allow`` for
credential files; ``SHADOWLENS_HOOK_FAIL`` = ``open`` (default: if the check itself breaks, do not get in the
way) or ``closed``. Every decision is recorded for the dashboard's Guard screen as masks only.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

from . import __version__, guard
from .analysis.pathmatch import matches_any_view, normalize_path
from .analysis.settings import AnalysisSettings, load_agent_rules, settings_for
from .analysis.text import analyze_text
from .config import Config
from .core.rule_titles import title_for

ROOT = Path(__file__).resolve().parents[2]
MARKER = "shadowlens-hook"                 # tags our entries in Claude Code's settings so they can be found again
SEVERITY_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
BLOCK_AT = "high"                          # severity that stops a prompt or a tool call
ASK_AT = "medium"                          # severity that asks first (tool calls) or warns (prompts)
MAX_TEXT = 2_000_000                       # characters examined per input
FILE_TOOLS = {"Read": ("file_path",), "Edit": ("file_path",), "Write": ("file_path",), "MultiEdit": ("file_path",),
              "NotebookEdit": ("notebook_path",), "NotebookRead": ("notebook_path",), "Glob": ("path", "pattern"),
              "Grep": ("path", "glob")}
MATCHER = "Bash|Read|Edit|Write|MultiEdit|NotebookEdit|Glob|Grep|WebFetch|WebSearch|mcp__.*"
MAX_PEEK_BYTES = 2_000_000                 # files larger than this are not opened before a Read

# The same placeholder names as the browser extension (extension/src/shared/rules.js).
PLACEHOLDERS = {
    "SEC_PRIVATE_KEY": "PRIVATE_KEY", "SEC_AWS_SECRET_KEY": "AWS_SECRET_ACCESS_KEY", "SEC_GITHUB_TOKEN": "GITHUB_TOKEN",
    "SEC_STRIPE_KEY": "STRIPE_KEY", "SEC_DB_URL": "DATABASE_URL", "SEC_AWS_ACCESS_KEY": "AWS_ACCESS_KEY_ID",
    "SEC_OPENAI_KEY": "OPENAI_API_KEY", "SEC_ANTHROPIC_KEY": "ANTHROPIC_API_KEY", "SEC_SLACK_TOKEN": "SLACK_TOKEN",
    "SEC_GOOGLE_API_KEY": "GOOGLE_API_KEY", "SEC_HF_TOKEN": "HF_TOKEN", "SEC_JWT": "JWT", "SEC_GENERIC_ASSIGNMENT": "SECRET",
    "SEC_HIGH_ENTROPY": "TOKEN", "PII_CREDIT_CARD": "CARD_NUMBER", "PII_AADHAAR": "AADHAAR", "PII_IBAN": "IBAN", "PII_SSN": "SSN",
    "PII_BULK": "PERSONAL_DATA", "PII_PAN": "PAN", "PII_EMAIL": "EMAIL", "PII_PHONE": "PHONE", "PII_INTERNAL_HOST": "INTERNAL_HOST",
}

# Commands that only read and print. Their output can be put through the redactor without changing what
# they do. "find" is read-only unless it executes or deletes; git only for the subcommands listed.
READ_ONLY = {"cat", "grep", "egrep", "fgrep", "rg", "head", "tail", "ls", "echo", "wc", "env", "printenv", "jq", "sort", "uniq",
             "cut", "tr", "nl", "column", "less", "more", "file", "stat", "du", "df", "tree", "find", "git", "printf", "strings", "od", "xxd"}
READ_ONLY_GIT = {"diff", "show", "log", "status", "grep", "blame", "cat-file"}
_NOT_SIMPLE = re.compile(r"[<>`]|\$\(|&(?!&)|\n|<<")


# ---- settings ---------------------------------------------------------------------------------------

class Options:
    def __init__(self, env: dict[str, str] | None = None) -> None:
        env = os.environ if env is None else env
        self.mode = env.get("SHADOWLENS_HOOK_MODE", "block").lower()
        self.files = env.get("SHADOWLENS_HOOK_FILES", "ask").lower()
        self.fail = env.get("SHADOWLENS_HOOK_FAIL", "open").lower()
        if self.mode not in {"block", "warn", "off"}:
            self.mode = "block"
        if self.files not in {"ask", "deny", "allow"}:
            self.files = "ask"
        if self.fail not in {"open", "closed"}:
            self.fail = "open"


def load_config() -> Config:
    return Config.load(base_dir=ROOT)


# ---- looking at text ---------------------------------------------------------------------------------

def _severity(finding: Any) -> str:
    return finding.severity


def worst(findings: list[Any]) -> str:
    return max((_severity(f) for f in findings), key=lambda s: SEVERITY_ORDER.get(s, 0), default="none")


def describe(findings: list[Any]) -> list[str]:
    """One line per finding: what it is, how serious, and a mask. Never the value."""
    lines = []
    for f in findings:
        title = title_for(f.rule_id).removesuffix(" sent to an AI tool")
        lines.append(f"- {title} ({f.severity}): {f.masked_preview}" + (f" ×{f.count}" if getattr(f, "count", None) and f.count > 1 else ""))
    return lines


def analyze(text: str, settings: AnalysisSettings):
    # No cap on entropy findings: every one is listed, so every one can be replaced.
    settings = dataclasses.replace(settings, max_entropy_findings_per_event=100_000)
    return analyze_text(text[:MAX_TEXT], settings)


def friendly_redact(text: str, findings: list[Any]) -> str:
    """The text with each value replaced by a numbered placeholder such as [OPENAI_API_KEY_1], as in the browser."""
    names: dict[tuple[str, str], str] = {}
    counters: dict[str, int] = {}
    edits = []
    for f in findings:
        name = PLACEHOLDERS.get(f.rule_id)
        if not name:
            continue                                          # code findings and the like are not values
        key = (f.rule_id, f.hash12)
        if key not in names:
            counters[name] = counters.get(name, 0) + 1
            names[key] = f"[{name}_{counters[name]}]"
        edits.extend((a, b, names[key]) for a, b in f.spans)
    out, cursor = [], 0
    for a, b, placeholder in sorted(edits, key=lambda e: (e[0], -e[1])):
        if a < cursor:
            continue
        out.append(text[cursor:a])
        out.append(placeholder)
        cursor = b
    out.append(text[cursor:])
    return "".join(out)


def is_read_only(command: str) -> bool:
    """A command whose every step only reads and prints, with no redirection or substitution."""
    if not command.strip() or _NOT_SIMPLE.search(command):
        return False
    for part in re.split(r"\|\||&&|;|\|", command):
        try:
            words = shlex.split(part)
        except ValueError:
            return False
        if not words:
            continue
        while words and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", words[0]):
            words = words[1:]                                 # FOO=bar cat x
        if not words or os.path.basename(words[0]) not in READ_ONLY:
            return False
        name = os.path.basename(words[0])
        if name == "find" and any(w in {"-exec", "-execdir", "-delete", "-ok", "-fprint"} for w in words):
            return False
        if name == "git" and not (len(words) > 1 and words[1] in READ_ONLY_GIT):
            return False
    return True


def redacting(command: str) -> str:
    """The command with its output (stdout and stderr) put through the redactor; its exit status is kept."""
    return f'set -o pipefail; {{ {command} ; }} 2>&1 | "{launcher_path()}" redact-stream'


def peek(path: str, cwd: str | None) -> str | None:
    """A small text file's content, read before the agent reads it; None if it cannot be read as text."""
    try:
        p = Path(path).expanduser()
        if not p.is_absolute() and cwd:
            p = Path(cwd) / p
        if not p.is_file() or p.stat().st_size > MAX_PEEK_BYTES:
            return None
        data = p.read_bytes()
        if b"\0" in data[:8192]:
            return None
        return data.decode("utf-8", errors="replace")
    except OSError:
        return None


def tool_text(tool: str, tool_input: Any) -> str:
    """The text of a tool call that could hold a secret: every string in its input."""
    parts: list[str] = []

    def walk(value: Any, depth: int = 0) -> None:
        if depth > 8:
            return
        if isinstance(value, str):
            parts.append(value)
        elif isinstance(value, dict):
            for v in value.values():
                walk(v, depth + 1)
        elif isinstance(value, list):
            for v in value:
                walk(v, depth + 1)

    walk(tool_input)
    return "\n".join(parts)


def touched_paths(tool: str, tool_input: Any) -> list[str]:
    if not isinstance(tool_input, dict):
        return []
    keys = FILE_TOOLS.get(tool, ())
    return [str(tool_input[k]) for k in keys if tool_input.get(k)]


# ---- decisions ---------------------------------------------------------------------------------------

def decide_prompt(prompt: str, settings: AnalysisSettings, options: Options) -> dict[str, Any]:
    """``{"action": allow|warn|block, "findings", "message", "redacted"}`` for a prompt."""
    result = analyze(prompt, settings)
    top = worst(result.findings)
    rank = SEVERITY_ORDER[top]
    if result.failed and not result.findings:
        return {"action": "allow", "findings": [], "message": "", "redacted": None, "failed": result.failed}
    if rank >= SEVERITY_ORDER[BLOCK_AT]:
        action = "block"
    elif rank >= SEVERITY_ORDER[ASK_AT]:
        action = "warn"
    else:
        action = "allow" if not result.findings else "note"
    if options.mode == "warn" and action == "block":
        action = "warn"
    if options.mode == "off":
        action = "allow"
    message = ""
    if result.findings and action != "allow":
        lines = describe(result.findings)
        if action == "block":
            message = ("Shadow Lens stopped this prompt. It contains:\n" + "\n".join(lines)
                       + "\n\nNothing was sent to the model. A safe version you can send instead:\n\n" + friendly_redact(prompt, result.findings))
        else:
            message = "Shadow Lens noticed:\n" + "\n".join(lines) + "\nThe prompt was sent."
    return {"action": action, "findings": result.findings, "message": message, "redacted": friendly_redact(prompt, result.findings), "failed": result.failed}


def decide_tool(tool: str, tool_input: Any, settings: AnalysisSettings, options: Options, cwd: str | None = None) -> dict[str, Any]:
    """``{"action": allow|ask|deny, "reason", "findings", "updated_input"}`` for one tool call."""
    rules = settings.agent_rules
    text = tool_text(tool, tool_input)
    result = analyze(text, settings) if text else None
    findings = result.findings if result else []
    # Credential and key files hold secrets by definition, so only values count in file *content* checks.
    reasons: list[str] = []
    action = "allow"

    def raise_to(level: str) -> None:
        nonlocal action
        if ["allow", "ask", "deny"].index(level) > ["allow", "ask", "deny"].index(action):
            action = level

    top = worst(findings)
    if findings and SEVERITY_ORDER[top] >= SEVERITY_ORDER[BLOCK_AT]:
        raise_to("deny")
        reasons.append("The input contains a secret:\n" + "\n".join(describe(findings)))
    elif findings and SEVERITY_ORDER[top] >= SEVERITY_ORDER[ASK_AT]:
        raise_to("ask")
        reasons.append("The input may contain a secret:\n" + "\n".join(describe(findings)))

    paths = touched_paths(tool, tool_input)
    command = tool_input.get("command") if isinstance(tool_input, dict) and tool == "Bash" else None
    sensitive = [p for p in paths if matches_any_view(rules.sensitive_paths, normalize_path(p))]
    if isinstance(command, str) and matches_any_view(rules.sensitive_paths, command):
        sensitive.append("a credential file named in the command")
    if sensitive and options.files != "allow":
        raise_to("deny" if options.files == "deny" else "ask")
        reasons.append("It reads a credential file: " + ", ".join(sorted(set(sensitive))[:3]))
    if isinstance(command, str):
        if matches_any_view(rules.dangerous_commands, command):
            raise_to("deny")
            reasons.append("It runs a dangerous command.")
        elif matches_any_view(rules.egress_commands, command):
            raise_to("ask")
            reasons.append("It sends local data to another machine.")

    # Reading an ordinary file that holds a secret sends the secret to the model: look first.
    if tool in {"Read", "NotebookRead"} and not sensitive and options.files != "allow" and isinstance(tool_input, dict):
        content = peek(str(tool_input.get("file_path") or tool_input.get("notebook_path") or ""), cwd)
        if content:
            inside = [f for f in analyze(content, settings).findings if SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[BLOCK_AT]]
            if inside:
                raise_to("deny" if options.files == "deny" else "ask")
                findings = findings + inside
                reasons.append("The file holds a secret, and reading it sends the secret to the model:\n" + "\n".join(describe(inside)))

    # A read-only command's output reaches the model as it is: put it through the redactor.
    updated = None
    if isinstance(command, str) and action == "allow" and options.mode == "block" and is_read_only(command):
        updated = {**tool_input, "command": redacting(command)}
    if options.mode == "off":
        action, reasons, updated = "allow", [], None
    elif options.mode == "warn" and action == "deny":
        action = "ask"
    return {"action": action, "reason": "Shadow Lens: " + " ".join(reasons) if reasons else "", "findings": findings, "updated_input": updated}


def decide_output(output: str, settings: AnalysisSettings, options: Options) -> dict[str, Any]:
    """After a tool ran: did what it printed hold a secret? (The model has it already; it is told not to repeat it.)"""
    result = analyze(output, settings) if output else None
    findings = [f for f in (result.findings if result else []) if SEVERITY_ORDER[_severity(f)] >= SEVERITY_ORDER[ASK_AT]]
    if not findings or options.mode == "off":
        return {"findings": [], "note": ""}
    note = ("Shadow Lens: the output above contained sensitive values (" + "; ".join(sorted({title_for(f.rule_id).removesuffix(' sent to an AI tool') for f in findings}))
            + "). Do not repeat them in your answer, in code, in a command or in a file; refer to them by name, for example as environment variables.")
    return {"findings": findings, "note": note}


# ---- Claude Code's side of the protocol ------------------------------------------------------------------

def tool_response_text(response: Any) -> str:
    if isinstance(response, str):
        return response
    parts: list[str] = []

    def walk(value: Any, depth: int = 0) -> None:
        if depth > 6:
            return
        if isinstance(value, str):
            parts.append(value)
        elif isinstance(value, dict):
            for v in value.values():
                walk(v, depth + 1)
        elif isinstance(value, list):
            for v in value:
                walk(v, depth + 1)

    walk(response)
    return "\n".join(parts)


def event_for(site: str, kind: str, action: str, findings: list[Any], reason: str | None = None) -> dict[str, Any]:
    return {
        "site": site, "kind": kind, "action": action, "severity": worst(findings), "reason": reason,
        "findings": [{"rule_id": f.rule_id, "hash12": f.hash12, "masked_preview": f.masked_preview, "severity": f.severity} for f in findings],
    }


def remember(config: Config, event: dict[str, Any]) -> None:
    """Record for the dashboard. A broken or locked database must never break the hook."""
    try:
        from .db import open_database  # noqa: PLC0415 - only when something happened

        db = open_database(config)
        try:
            guard.record(db, event, "claude_code")
        finally:
            db.close()
    except Exception:  # noqa: BLE001
        pass


def handle(payload: dict[str, Any], config: Config, options: Options, record: bool = True) -> tuple[dict[str, Any] | None, str | None]:
    """The reply for one hook call: (JSON for stdout or None, text for stderr or None)."""
    settings = settings_for(config)
    event = payload.get("hook_event_name")
    project = Path(str(payload.get("cwd") or ".")).name[:40] or "project"
    if event == "UserPromptSubmit":
        d = decide_prompt(str(payload.get("prompt") or ""), settings, options)
        if d["action"] in {"block", "warn", "note"} and record:
            remember(config, event_for(project, "prompt", {"block": "blocked", "warn": "warned", "note": "noted"}[d["action"]], d["findings"]))
        if d["action"] == "block":
            return {"decision": "block", "reason": d["message"]}, None
        if d["action"] == "warn":
            return {"systemMessage": d["message"]}, None
        return None, None
    if event == "PreToolUse":
        tool = str(payload.get("tool_name") or "")
        d = decide_tool(tool, payload.get("tool_input"), settings, options, cwd=payload.get("cwd"))
        if d["action"] == "allow":
            if d["updated_input"]:
                return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow",
                                               "permissionDecisionReason": "Shadow Lens: output redacted",
                                               "updatedInput": d["updated_input"]}}, None
            return None, None
        if record:
            remember(config, event_for(project, "tool", "blocked" if d["action"] == "deny" else "warned", d["findings"], reason=tool))
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": d["action"], "permissionDecisionReason": d["reason"]}}, None
    if event == "PostToolUse":
        d = decide_output(tool_response_text(payload.get("tool_response")), settings, options)
        if not d["findings"]:
            return None, None
        if record:
            remember(config, event_for(project, "output", "warned", d["findings"], reason=str(payload.get("tool_name") or "")))
        return {"hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext": d["note"]}}, None
    return None, None


def run_hook(stdin: Any = None, stdout: Any = None, stderr: Any = None, config: Config | None = None, env: dict[str, str] | None = None) -> int:
    stdin, stdout, stderr = stdin or sys.stdin, stdout or sys.stdout, stderr or sys.stderr
    options = Options(env)
    try:
        payload = json.loads(stdin.read() or "{}")
        if not isinstance(payload, dict):
            return 0
        if options.mode == "off":
            return 0
        reply, note = handle(payload, config or load_config(), options)
    except Exception as exc:  # noqa: BLE001 - see SHADOWLENS_HOOK_FAIL
        stderr.write(f"Shadow Lens could not check this ({type(exc).__name__}).\n")
        return 2 if options.fail == "closed" else 0
    if reply is not None:
        stdout.write(json.dumps(reply, ensure_ascii=False) + "\n")
    if note:
        stderr.write(note + "\n")
    return 0


# ---- installing ---------------------------------------------------------------------------------------

def launcher_path(root: Path = ROOT, platform: str = sys.platform) -> Path:
    return root / "data" / ("shadowlens-hook.bat" if platform == "win32" else "shadowlens-hook")


def write_launcher(python: str = sys.executable, root: Path = ROOT, platform: str = sys.platform) -> Path:
    path = launcher_path(root, platform)
    path.parent.mkdir(parents=True, exist_ok=True)
    if platform == "win32":
        path.write_text(f'@echo off\r\n"{python}" -m shadowlens.hook %*\r\n', encoding="utf-8")
    else:
        # PYTHONPATH makes this work from any folder, whether or not the package is installed.
        path.write_text(f'#!/bin/sh\nPYTHONPATH="{root / "src"}${{PYTHONPATH:+:$PYTHONPATH}}" exec "{python}" -m shadowlens.hook "$@"\n', encoding="utf-8")
        path.chmod(0o755)
    return path


def settings_path(scope: str, home: Path, project: Path) -> Path:
    return {"user": home / ".claude" / "settings.json", "project": project / ".claude" / "settings.json",
            "local": project / ".claude" / "settings.local.json"}[scope]


def _is_ours(entry: Any) -> bool:
    return isinstance(entry, dict) and any(MARKER in str(h.get("command", "")) for h in entry.get("hooks", []) if isinstance(h, dict))


def hook_entries(command: str) -> dict[str, list[dict[str, Any]]]:
    def entry(matcher: str | None = None) -> dict[str, Any]:
        out: dict[str, Any] = {"hooks": [{"type": "command", "command": command, "timeout": 20}]}
        if matcher:
            out["matcher"] = matcher
        return out

    return {"UserPromptSubmit": [entry()], "PreToolUse": [entry(MATCHER)], "PostToolUse": [entry(MATCHER)]}


def install(scope: str, home: Path, project: Path, python: str = sys.executable, root: Path = ROOT, platform: str = sys.platform) -> Path:
    launcher = write_launcher(python, root, platform)
    path = settings_path(scope, home, project)
    settings: dict[str, Any] = {}
    if path.exists():
        try:
            settings = json.loads(path.read_text(encoding="utf-8") or "{}")
        except json.JSONDecodeError as exc:
            raise SystemExit(f"{path} is not valid JSON ({exc}); fix or remove it, then run install again.") from exc
        if not isinstance(settings, dict):
            raise SystemExit(f"{path} does not hold a JSON object.")
    hooks = settings.setdefault("hooks", {})
    marked = f'"{launcher}" {MARKER}'              # quoted for paths with spaces; the trailing word tags the entry
    for event, entries in hook_entries(marked).items():
        kept = [e for e in hooks.get(event, []) if not _is_ours(e)]
        hooks[event] = kept + entries
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
    return path


def uninstall(scope: str, home: Path, project: Path) -> bool:
    path = settings_path(scope, home, project)
    if not path.exists():
        return False
    settings = json.loads(path.read_text(encoding="utf-8") or "{}")
    hooks = settings.get("hooks", {})
    changed = False
    for event in list(hooks):
        kept = [e for e in hooks[event] if not _is_ours(e)]
        changed |= len(kept) != len(hooks[event])
        if kept:
            hooks[event] = kept
        else:
            del hooks[event]
    if not hooks:
        settings.pop("hooks", None)
    path.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
    return changed


def installed(scope: str, home: Path, project: Path) -> bool:
    path = settings_path(scope, home, project)
    try:
        hooks = json.loads(path.read_text(encoding="utf-8")).get("hooks", {})
    except (OSError, json.JSONDecodeError):
        return False
    return any(_is_ours(e) for entries in hooks.values() for e in entries)


# ---- scanning from the shell ---------------------------------------------------------------------------

def scan_text(text: str, name: str, settings: AnalysisSettings, redact: bool) -> tuple[list[str], str]:
    result = analyze(text, settings)
    lines = [f"{name}: {line[2:]}" for line in describe(result.findings)]
    return lines, result.redacted_text if redact else text


def staged_additions() -> list[tuple[str, str]]:
    """(file, added text) for what is staged in git: only added lines, so old problems do not block new work."""
    out = subprocess.run(["git", "diff", "--cached", "--no-color", "-U0", "--diff-filter=ACMR"], capture_output=True, text=True, encoding="utf-8", errors="replace")
    if out.returncode != 0:
        raise SystemExit("not a git repository (or git failed)")
    files: dict[str, list[str]] = {}
    current = None
    for line in out.stdout.splitlines():
        if line.startswith("+++ b/"):
            current = line[6:]
            files.setdefault(current, [])
        elif line.startswith("+") and not line.startswith("+++") and current:
            files[current].append(line[1:])
    return [(f, "\n".join(lines)) for f, lines in files.items() if lines]


def cli(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="python -m shadowlens.hook", description="Shadow Lens for coding agents and the shell.")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("install", "uninstall"):
        p = sub.add_parser(name, help=f"{name} the Claude Code hooks")
        p.add_argument("--scope", choices=["user", "project", "local"], default="user", help="user: all projects (default); project: this project, shared; local: this project, just you")
    sub.add_parser("status", help="where the hooks are installed")
    scan = sub.add_parser("scan", help="check files or standard input for secrets and personal data")
    scan.add_argument("files", nargs="*")
    scan.add_argument("--redact", action="store_true", help="print the text with values replaced by placeholders")
    sub.add_parser("precommit", help="check what is staged in git")
    sub.add_parser("redact-stream", help="copy standard input to standard output with values replaced (used by the hooks)")
    sub.add_parser("version")
    args = parser.parse_args(argv)
    home, project = Path.home(), Path.cwd()
    if args.command == "install":
        path = install(args.scope, home, project)
        print(f"Installed in {path}\nRestart Claude Code (or run /hooks) to load it. Try: type a prompt containing a fake key.")
        return 0
    if args.command == "uninstall":
        print("Removed." if uninstall(args.scope, home, project) else "Nothing to remove.")
        return 0
    if args.command == "status":
        for scope in ("user", "project", "local"):
            print(f"{scope:8} {'installed' if installed(scope, home, project) else 'not installed'}  ({settings_path(scope, home, project)})")
        return 0
    if args.command == "version":
        print(__version__)
        return 0
    settings = settings_for(load_config())
    if args.command == "redact-stream":
        text = sys.stdin.buffer.read().decode("utf-8", errors="replace")
        try:
            out = friendly_redact(text, analyze(text, settings).findings)
        except Exception:  # noqa: BLE001 - never pass unchecked output through as if it were checked
            out = "[Shadow Lens could not check this output, so it was withheld.]\n"
        sys.stdout.write(out)
        sys.stdout.flush()
        return 0
    if args.command == "precommit":
        found = 0
        for name, text in staged_additions():
            lines, _ = scan_text(text, name, settings, False)
            found += len(lines)
            print("\n".join(lines))
        if found:
            print(f"\nShadow Lens: {found} sensitive value(s) in what you are about to commit. Remove them, or commit with --no-verify.", file=sys.stderr)
        return 1 if found else 0
    sources = [(f, Path(f).read_text(encoding="utf-8", errors="replace")) for f in args.files] or [("stdin", sys.stdin.read())]
    status = 0
    for name, text in sources:
        lines, shown = scan_text(text, name, settings, args.redact)
        if args.redact:
            sys.stdout.write(shown)
        elif lines:
            print("\n".join(lines))
        status |= bool(lines)
    return 1 if status else 0


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    # Claude Code runs the launcher with no arguments (or only our marker) and JSON on stdin.
    if not argv or argv == [MARKER]:
        return run_hook()
    return cli(argv)


if __name__ == "__main__":
    sys.exit(main())

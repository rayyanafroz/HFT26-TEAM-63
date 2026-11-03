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
import json
import os
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
    result = analyze_text(text[:MAX_TEXT], settings)
    return result


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
                       + "\n\nNothing was sent to the model. A safe version you can send instead:\n\n" + result.redacted_text)
        else:
            message = "Shadow Lens noticed:\n" + "\n".join(lines) + "\nThe prompt was sent."
    return {"action": action, "findings": result.findings, "message": message, "redacted": result.redacted_text, "failed": result.failed}


def decide_tool(tool: str, tool_input: Any, settings: AnalysisSettings, options: Options) -> dict[str, Any]:
    """``{"action": allow|ask|deny, "reason", "findings"}`` for one tool call."""
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
    if options.mode == "off":
        action, reasons = "allow", []
    elif options.mode == "warn" and action == "deny":
        action = "ask"
    return {"action": action, "reason": "Shadow Lens: " + " ".join(reasons) if reasons else "", "findings": findings}


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
        d = decide_tool(tool, payload.get("tool_input"), settings, options)
        if d["action"] == "allow":
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

"""What AI is on this machine: running, installed or left behind (SOT 1, 4.5, 7.2.1).

The live scan only sees programs that are talking right now, and can only guess who they talk to.
This looks at the machine itself: running programs, installed apps, editor and browser extensions,
the folders AI tools keep, and commands on the PATH. A running tool's connections are then checked
against the addresses of its own provider, which confirms "this program really is talking to
api.anthropic.com" even when that address is shared with another service.

Everything is read-only and local. What is looked for is data (``config/ai_tools.yaml``), matched by
exact identifiers. Each look-up runs on its own, so one that fails costs only itself and is reported
in ``InventoryResult.errors``.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import shutil
import socket
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any, Callable, Iterable, Mapping

import yaml
from pydantic import Field, StringConstraints, ValidationError, model_validator

from ..models import ShadowModel, utc_now_iso
from ..providers.catalog import Catalog

log = logging.getLogger("shadowlens.inventory")

DEFAULT_SIGNATURES_PATH = Path(__file__).resolve().parents[3] / "config" / "ai_tools.yaml"
LOOKUP_TIMEOUT_S = 3.0
MAX_BROWSER_EXTENSIONS = 2000

# What this cannot see, said on screen so the list is never mistaken for "everything".
NOT_COVERED = (
    "Python and Node packages (openai, langchain...)",
    "Microsoft Store apps",
    "AI websites used in a browser tab (nothing is installed for those)",
    "other people's accounts on this machine",
)


# ---- what to look for (config/ai_tools.yaml) -----------------------------------------------------

class ProcessRule(ShadowModel):
    name: str = Field(min_length=1)
    exe_contains: list[str] = Field(default_factory=list)     # where the program runs from; empty = anywhere


class AppRule(ShadowModel):
    name: str = Field(min_length=1)
    publisher: str | None = None                              # a part of the publisher's name


class ToolSignature(ShadowModel):
    id: Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]*$")]
    name: str = Field(min_length=1)
    kind: str = Field(min_length=1)
    provider: str | None = None
    processes: list[ProcessRule] = Field(default_factory=list)
    apps: list[AppRule] = Field(default_factory=list)
    vscode_extensions: list[str] = Field(default_factory=list)
    folders: list[str] = Field(default_factory=list)
    commands: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _has_something_to_look_for(self) -> "ToolSignature":
        if not (self.processes or self.apps or self.vscode_extensions or self.folders or self.commands):
            raise ValueError("needs at least one of processes, apps, vscode_extensions, folders, commands")
        return self


class Editor(ShadowModel):
    name: str = Field(min_length=1)
    extensions_dir: str = Field(min_length=1)


class Browser(ShadowModel):
    name: str = Field(min_length=1)
    user_data: list[str] = Field(min_length=1)


@dataclass(frozen=True)
class Signatures:
    tools: tuple[ToolSignature, ...] = ()
    editors: tuple[Editor, ...] = ()
    browsers: tuple[Browser, ...] = ()
    browser_name_patterns: tuple[re.Pattern[str], ...] = ()
    warnings: tuple[str, ...] = ()


def _first_error(exc: ValidationError) -> str:
    first = exc.errors()[0]
    return f"{'.'.join(str(p) for p in first['loc'])}: {first['msg']}" if first["loc"] else first["msg"]


def _valid_entries(raw: Any, model: type[ShadowModel], section: str, warnings: list[str]) -> list[Any]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        warnings.append(f"{section} is not a list; ignored")
        return []
    kept = []
    for index, entry in enumerate(raw):
        try:
            kept.append(model.model_validate(entry))
        except ValidationError as exc:
            label = entry.get("id", f"#{index + 1}") if isinstance(entry, dict) else f"#{index + 1}"
            warnings.append(f"{section} entry {label} skipped: {_first_error(exc)}")
    return kept


def load_signatures(path: Path | str | None = None) -> Signatures:
    """Read the signature file. Never raises: a missing or damaged file gives an empty list and a warning."""
    file = Path(path) if path is not None else DEFAULT_SIGNATURES_PATH
    warnings: list[str] = []
    try:
        raw = yaml.safe_load(file.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return Signatures(warnings=(f"{file.name} not found: no AI tool can be identified",))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        return Signatures(warnings=(f"could not read {file.name} ({type(exc).__name__}): no AI tool can be identified",))
    if not isinstance(raw, dict):
        return Signatures(warnings=(f"{file.name} is not a mapping: no AI tool can be identified",))

    tools = _valid_entries(raw.get("tools"), ToolSignature, "tools", warnings)
    seen: set[str] = set()
    unique = []
    for tool in tools:
        if tool.id in seen:
            warnings.append(f"tools entry {tool.id} skipped: duplicate id")
            continue
        seen.add(tool.id)
        unique.append(tool)

    patterns = []
    for text in raw.get("browser_extension_name_patterns") or []:
        try:
            patterns.append(re.compile(str(text), re.IGNORECASE))
        except re.error:
            warnings.append("a browser_extension_name_patterns entry is not a valid pattern; skipped")
    return Signatures(
        tools=tuple(unique),
        editors=tuple(_valid_entries(raw.get("editors"), Editor, "editors", warnings)),
        browsers=tuple(_valid_entries(raw.get("browsers"), Browser, "browsers", warnings)),
        browser_name_patterns=tuple(patterns),
        warnings=tuple(warnings),
    )


# ---- what was found ---------------------------------------------------------------------------------

@dataclass(frozen=True)
class Evidence:
    kind: str       # running | app | extension | browser extension | folder | command
    detail: str


@dataclass(frozen=True)
class Connection:
    ip: str
    port: int
    pid: int
    host: str | None = None     # the provider host this address belongs to, when that was confirmed


@dataclass
class FoundTool:
    id: str
    name: str
    kind: str
    provider_id: str | None = None
    evidence: list[Evidence] = field(default_factory=list)
    pids: list[int] = field(default_factory=list)
    connections: list[Connection] = field(default_factory=list)
    matched_by_name: bool = False        # a browser extension recognised only by its name

    @property
    def status(self) -> str:
        kinds = {e.kind for e in self.evidence}
        if "running" in kinds:
            return "running"
        return "installed" if kinds - {"folder"} else "traces"

    @property
    def verified(self) -> list[Connection]:
        return [c for c in self.connections if c.host]

    def add(self, kind: str, detail: str) -> None:
        item = Evidence(kind, detail)
        if item not in self.evidence:
            self.evidence.append(item)


@dataclass
class InventoryResult:
    tools: list[FoundTool] = field(default_factory=list)
    looked_at: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def not_covered(self) -> tuple[str, ...]:
        return NOT_COVERED


@dataclass(frozen=True)
class RunningProgram:
    pid: int
    name: str            # lower case, without ".exe"
    exe: str | None


@dataclass(frozen=True)
class InstalledApp:
    name: str
    publisher: str | None = None
    version: str | None = None


# ---- the real sources (each can be replaced in tests) -------------------------------------------------

def running_programs() -> list[RunningProgram]:
    import psutil
    found = []
    for proc in psutil.process_iter(["pid", "name", "exe"]):
        try:
            name = (proc.info["name"] or "").lower().removesuffix(".exe")
            if name:
                found.append(RunningProgram(proc.info["pid"], name, proc.info.get("exe")))
        except (psutil.Error, OSError):
            continue
    return found


def installed_apps() -> list[InstalledApp]:
    if sys.platform.startswith("win"):
        return _windows_apps()
    if sys.platform == "darwin":
        folder = Path("/Applications")
        return [InstalledApp(p.stem) for p in sorted(folder.glob("*.app"))] if folder.is_dir() else []
    return []


def _windows_apps() -> list[InstalledApp]:
    import winreg
    uninstall = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    places = [(winreg.HKEY_LOCAL_MACHINE, uninstall),
              (winreg.HKEY_LOCAL_MACHINE, uninstall.replace("SOFTWARE\\", "SOFTWARE\\WOW6432Node\\")),
              (winreg.HKEY_CURRENT_USER, uninstall)]
    apps: list[InstalledApp] = []
    for root, sub in places:
        try:
            parent = winreg.OpenKey(root, sub)
        except OSError:
            continue
        with parent:
            for index in range(winreg.QueryInfoKey(parent)[0]):
                try:
                    with winreg.OpenKey(parent, winreg.EnumKey(parent, index)) as key:
                        values = {}
                        for field_name in ("DisplayName", "Publisher", "DisplayVersion"):
                            try:
                                values[field_name] = str(winreg.QueryValueEx(key, field_name)[0])
                            except OSError:
                                values[field_name] = None
                    if values["DisplayName"]:
                        apps.append(InstalledApp(values["DisplayName"], values["Publisher"], values["DisplayVersion"]))
                except OSError:
                    continue
    return apps


def open_connections() -> list[tuple[int, str, int]]:
    """``(pid, remote ip, remote port)`` of every established connection."""
    import psutil
    return [(c.pid, str(c.raddr.ip), int(c.raddr.port)) for c in psutil.net_connections(kind="inet")
            if c.pid and c.raddr and c.status == psutil.CONN_ESTABLISHED]


def resolve_addresses(host: str) -> set[str]:
    return {info[4][0] for info in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)}


def lookup_all(hosts: Iterable[str], resolve: Callable[[str], set[str]], timeout: float) -> tuple[dict[str, str], list[str]]:
    """``({ip: host}, hosts that failed or timed out)``, all looked up at the same time.

    The wait is cut off at ``timeout`` however long a lookup hangs: each runs in a daemon thread that
    is simply abandoned. (A thread pool would wait for it when closing, and a stuck DNS server can take
    30 seconds or more.)
    """
    outcome: dict[str, set[str] | None] = {}

    def work(host: str) -> None:
        try:
            outcome[host] = resolve(host)
        except Exception:  # noqa: BLE001 - reported as a failed lookup
            outcome[host] = None

    hosts = list(hosts)
    threads = [threading.Thread(target=work, args=(host,), name="inventory-lookup", daemon=True) for host in hosts]
    for thread in threads:
        thread.start()
    deadline = time.monotonic() + timeout
    for thread in threads:
        thread.join(max(0.0, deadline - time.monotonic()))
    mapped: dict[str, str] = {}
    failed = []
    for host in hosts:
        addresses = outcome.get(host)
        if addresses is None:
            failed.append(host)
            continue
        for ip in addresses:
            mapped.setdefault(ip, host)
    return mapped, failed


# ---- helpers ------------------------------------------------------------------------------------------------

_VARIABLE = re.compile(r"%([^%]+)%|\$\{([^}]+)\}|\$([A-Za-z_][A-Za-z0-9_]*)")


def expand_path(template: str, home: Path, env: Mapping[str, str]) -> Path | None:
    """``~`` and ``%VAR%`` / ``$VAR`` in a configured path. ``None`` if a variable is not set here."""
    missing = False

    def substitute(match: re.Match[str]) -> str:
        nonlocal missing
        name = next(g for g in match.groups() if g)
        value = env.get(name) or env.get(name.upper())
        if value is None:
            missing = True
            return ""
        return value

    text = str(home) + template[1:] if template.startswith("~") else template
    text = _VARIABLE.sub(substitute, text)
    return None if missing else Path(text)


def _shown(path: Path | str, home: Path) -> str:
    text = str(path)
    prefix = str(home)
    return "~" + text[len(prefix):] if text.lower().startswith(prefix.lower()) else text


def _normal(path: str) -> str:
    return path.replace("\\", "/").lower()


_EXTENSION_DIR = re.compile(r"^(?P<id>.+?)-(?P<version>\d+\.\d+\.\d+.*)$")


# ---- the scan --------------------------------------------------------------------------------------------------

class _Scan:
    """One look at the machine. Holds the tools found so far, keyed by id."""

    def __init__(self, signatures: Signatures, catalog: Catalog | None, home: Path, env: Mapping[str, str]):
        self.signatures, self.catalog, self.home, self.env = signatures, catalog, home, env
        self.found: dict[str, FoundTool] = {}
        self.result = InventoryResult(warnings=list(signatures.warnings))
        self.by_id = {t.id: t for t in signatures.tools}

    def tool(self, signature: ToolSignature) -> FoundTool:
        if signature.id not in self.found:
            self.found[signature.id] = FoundTool(signature.id, signature.name, signature.kind, signature.provider)
        return self.found[signature.id]

    def guarded(self, what: str, run: Callable[[], Any]) -> Any:
        try:
            return run()
        except Exception as exc:  # noqa: BLE001 - one look-up failing must not hide the others
            log.warning("inventory: could not look at %s (%s)", what, type(exc).__name__)
            self.result.errors.append(f"could not look at {what} ({type(exc).__name__})")
            return None

    # -- running programs

    def programs(self, programs: Iterable[RunningProgram]) -> None:
        count = 0
        rules = [(tool, rule) for tool in self.signatures.tools for rule in tool.processes]
        for program in programs:
            count += 1
            exe = _normal(program.exe) if program.exe else ""
            for tool, rule in rules:
                if program.name != rule.name.lower():
                    continue
                if rule.exe_contains and not any(_normal(part) in exe for part in rule.exe_contains):
                    continue
                found = self.tool(tool)
                found.add("running", f"{program.name} (pid {program.pid}) from "
                                     f"{_shown(program.exe, self.home) if program.exe else 'an unreadable location'}")
                if program.pid not in found.pids:
                    found.pids.append(program.pid)
                break                                   # the first matching rule owns this program
        self.result.looked_at.append(f"{count} running programs")

    # -- installed apps

    def apps(self, apps: Iterable[InstalledApp]) -> None:
        listed = list(apps)
        for tool in self.signatures.tools:
            for rule in tool.apps:
                for app in listed:
                    if app.name.strip().lower() != rule.name.lower():
                        continue
                    if rule.publisher and rule.publisher.lower() not in (app.publisher or "").lower():
                        continue
                    version = f" {app.version}" if app.version else ""
                    self.tool(tool).add("app", f"installed app {app.name}{version} ({app.publisher or 'unknown publisher'})")
        self.result.looked_at.append(f"{len(listed)} installed apps")

    # -- editor extensions

    def editor_extensions(self) -> None:
        wanted: dict[str, ToolSignature] = {e.lower(): t for t in self.signatures.tools for e in t.vscode_extensions}
        total = 0
        for editor in self.signatures.editors:
            folder = expand_path(editor.extensions_dir, self.home, self.env)
            if folder is None or not folder.is_dir():
                continue
            removed = self._removed_extensions(folder)
            for entry in sorted(folder.iterdir()):
                if not entry.is_dir() or entry.name in removed or entry.name.startswith("."):
                    continue
                total += 1
                match = _EXTENSION_DIR.match(entry.name)
                if match and match["id"].lower() in wanted:
                    self.tool(wanted[match["id"].lower()]).add(
                        "extension", f"{editor.name} extension {match['id']} {match['version']}")
        self.result.looked_at.append(f"{total} editor extensions")

    @staticmethod
    def _removed_extensions(folder: Path) -> set[str]:
        """Editors leave an uninstalled extension on disk and list it here until the next restart."""
        try:
            data = json.loads((folder / ".obsolete").read_text(encoding="utf-8"))
            return set(data) if isinstance(data, dict) else set()
        except (OSError, ValueError):
            return set()

    # -- browser extensions

    def browser_extensions(self) -> None:
        total = 0
        for browser in self.signatures.browsers:
            roots = [p for p in (expand_path(t, self.home, self.env) for t in browser.user_data) if p and p.is_dir()]
            for root in roots[:1]:
                for profile in sorted(p for p in root.iterdir() if p.is_dir() and (p.name == "Default" or p.name.startswith("Profile "))):
                    folder = profile / "Extensions"
                    if not folder.is_dir():
                        continue
                    for extension in sorted(p for p in folder.iterdir() if p.is_dir()):
                        total += 1
                        if total > MAX_BROWSER_EXTENSIONS:
                            self.result.errors.append("too many browser extensions; the rest were not read")
                            return
                        name, version = self._extension_name(extension)
                        if name and any(p.search(name) for p in self.signatures.browser_name_patterns):
                            found = self.found.setdefault(
                                f"browser_extension_{browser.name.lower()}_{extension.name}",
                                FoundTool(f"browser_extension_{browser.name.lower()}_{extension.name}",
                                          f"{name}", "browser extension", None, matched_by_name=True))
                            found.add("browser extension",
                                      f"{browser.name} extension \"{name}\" {version or ''} (profile {profile.name}, "
                                      f"matched by its name)".replace("  ", " "))
        self.result.looked_at.append(f"{total} browser extensions")

    @staticmethod
    def _extension_name(extension: Path) -> tuple[str | None, str | None]:
        versions = sorted((p for p in extension.iterdir() if p.is_dir()), key=lambda p: p.name, reverse=True)
        if not versions:
            return None, None
        try:
            manifest = json.loads((versions[0] / "manifest.json").read_text(encoding="utf-8-sig"))
        except (OSError, ValueError):
            return None, None
        if not isinstance(manifest, dict):
            return None, None
        name = str(manifest.get("name") or "")
        if name.startswith("__MSG_") and name.endswith("__"):
            key = name[6:-2].lower()
            for locale in dict.fromkeys([str(manifest.get("default_locale") or ""), "en", "en_US", "en_GB"]):
                try:
                    messages = json.loads((versions[0] / "_locales" / locale / "messages.json").read_text(encoding="utf-8-sig"))
                except (OSError, ValueError):
                    continue
                if isinstance(messages, dict):
                    for message_key, value in messages.items():
                        if message_key.lower() == key and isinstance(value, dict) and value.get("message"):
                            return str(value["message"]), str(manifest.get("version") or "")
            return None, None
        return name or None, str(manifest.get("version") or "")

    # -- folders and commands

    def folders_and_commands(self, which: Callable[[str], str | None]) -> None:
        folders = commands = 0
        for tool in self.signatures.tools:
            for template in tool.folders:
                folders += 1
                path = expand_path(template, self.home, self.env)
                if path is not None and path.exists():
                    try:                      # when it was last touched tells "in use" from "left behind"
                        changed = f" (last changed {datetime.fromtimestamp(path.stat().st_mtime):%Y-%m-%d})"
                    except OSError:
                        changed = ""
                    self.tool(tool).add("folder", f"folder {_shown(path, self.home)}{changed}")
            for command in tool.commands:
                commands += 1
                located = which(command)
                if located:
                    self.tool(tool).add("command", f"command {command} at {_shown(located, self.home)}")
        self.result.looked_at.append(f"{folders} AI tool folders and {commands} commands")

    # -- connections

    def connections(self, connections: Iterable[tuple[int, str, int]], resolve: Callable[[str], set[str]]) -> None:
        by_pid = {pid: tool for tool in self.found.values() for pid in tool.pids}
        if not by_pid:
            return
        mine = [(pid, ip, port) for pid, ip, port in connections if pid in by_pid]
        cache: dict[str, dict[str, str]] = {}

        def addresses_of(provider_id: str) -> dict[str, str]:
            """``{ip: host}`` for the provider's literal host names."""
            provider = self.catalog.get(provider_id) if self.catalog else None
            if provider is None or provider.is_local:
                return {}
            if provider_id not in cache:
                mapped, failed = lookup_all(provider.hosts, resolve, LOOKUP_TIMEOUT_S)
                for host in failed:
                    self.result.errors.append(f"could not look up {host}, so its connections are unconfirmed")
                cache[provider_id] = mapped
            return cache[provider_id]

        for pid, ip, port in dict.fromkeys(mine):
            tool = by_pid[pid]
            provider = self.catalog.get(tool.provider_id) if self.catalog and tool.provider_id else None
            try:
                address = ipaddress.ip_address(ip)
            except ValueError:
                continue
            host = None
            if provider is not None and provider.is_local:
                if address.is_loopback and port in provider.ports:
                    host = f"localhost:{port}"
            elif address.is_loopback:
                continue                                # a tool talking to its own helpers, not to a provider
            elif provider is not None:
                host = addresses_of(provider.id).get(ip)
            tool.connections.append(Connection(ip, port, pid, host))


def scan(
    signatures: Signatures | None = None,
    *,
    catalog: Catalog | None = None,
    home: Path | None = None,
    env: Mapping[str, str] | None = None,
    programs: Callable[[], Iterable[RunningProgram]] = running_programs,
    apps: Callable[[], Iterable[InstalledApp]] = installed_apps,
    connections: Callable[[], Iterable[tuple[int, str, int]]] = open_connections,
    resolve: Callable[[str], set[str]] = resolve_addresses,
    which: Callable[[str], str | None] | None = None,
) -> InventoryResult:
    """Look at this machine. Never raises; what could not be read is in ``errors``."""
    signatures = signatures if signatures is not None else load_signatures()
    home = home if home is not None else Path.home()
    env = env if env is not None else os.environ
    if catalog is None:
        try:
            catalog = Catalog.load()
        except Exception as exc:  # noqa: BLE001 - without it connections are listed, just not confirmed
            log.warning("inventory: provider catalog unavailable (%s)", type(exc).__name__)
    state = _Scan(signatures, catalog, home, env)
    if not signatures.tools:
        state.result.warnings.append("no tool signatures are loaded")

    find = which or (lambda command: shutil.which(command, path=env.get("PATH")))
    state.guarded("running programs", lambda: state.programs(programs()))
    state.guarded("installed apps", lambda: state.apps(apps()))
    state.guarded("editor extensions", state.editor_extensions)
    state.guarded("browser extensions", state.browser_extensions)
    state.guarded("AI tool folders", lambda: state.folders_and_commands(find))
    state.guarded("network connections", lambda: state.connections(connections(), resolve))

    order = {"running": 0, "installed": 1, "traces": 2}
    state.result.tools = sorted(state.found.values(), key=lambda t: (order[t.status], t.name.lower()))
    return state.result


def connection_records(result: InventoryResult, now: str | None = None) -> list[dict[str, Any]]:
    """Confirmed connections as HTTP-log lines (SOT 6.3), ready to upload to ``/api/ingest/log``.

    Each is a connection that was actually observed, recorded as a CONNECT because no request was seen
    (``body`` is null, so ShadowLens treats it as "address only" and reads nothing).
    """
    stamp = now or utc_now_iso()
    records, seen = [], set()
    for tool in result.tools:
        for conn in tool.verified:
            local = conn.host.startswith("localhost:")
            key = (tool.id, conn.host, conn.ip, conn.port, conn.pid)
            if key in seen:
                continue
            seen.add(key)
            process = next((e.detail.split(" ")[0] for e in tool.evidence if e.kind == "running"), "unknown")
            records.append({
                "ts": stamp, "host": conn.host, "method": "CONNECT", "path": "/", "body": None,
                "dst_ip": conn.ip, "dst_port": conn.port, "tls": not local, "source": "conn_scan",
                "process_name": process, "pid": conn.pid,
            })
    return records

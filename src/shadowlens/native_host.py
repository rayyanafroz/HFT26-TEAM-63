"""The Native Messaging host: how the Shadow Lens browser extension reaches the dashboard on this computer.

Chrome (or Edge, Brave, Chromium) starts this program when the extension connects, and they exchange
JSON messages over stdin and stdout, each prefixed by its length (4 bytes, native byte order). Guard
events from the extension are cleaned (``guard.clean_event``) and stored in the dashboard's database.

    python -m shadowlens.native_host install      register it with the browsers on this computer
    python -m shadowlens.native_host uninstall
    python -m shadowlens.native_host status

Nothing but protocol messages may go to stdout: Chrome would read anything else as a broken message.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import struct
import sys
from pathlib import Path
from typing import Any, BinaryIO

from . import __version__, guard
from .config import Config
from .db import open_database

HOST_NAME = "com.shadowlens.companion"
MAX_MESSAGE = 8 * 1024 * 1024       # what we accept from the browser (it may send up to 4 GB)
ROOT = Path(__file__).resolve().parents[2]
KEY_FILE = ROOT / "extension" / "static" / "extension-key.json"

log = logging.getLogger("shadowlens.native_host")


# ---- the protocol -----------------------------------------------------------------------------

def read_message(stream: BinaryIO) -> Any | None:
    """The next message, or None at the end of the stream."""
    header = stream.read(4)
    if len(header) < 4:
        return None
    (length,) = struct.unpack("=I", header)
    if length > MAX_MESSAGE:
        raise ValueError(f"message of {length} bytes is too large")
    body = stream.read(length)
    if len(body) < length:
        return None
    return json.loads(body.decode("utf-8"))


def write_message(stream: BinaryIO, message: Any) -> None:
    body = json.dumps(message, separators=(",", ":")).encode("utf-8")
    stream.write(struct.pack("=I", len(body)) + body)
    stream.flush()


def handle(message: Any, db: Any, config: Config) -> Any | None:
    """The reply to one message (None when there is nothing to say)."""
    if not isinstance(message, dict):
        return {"type": "error", "error": "a message must be an object"}
    kind = message.get("type")
    if kind == "hello":
        return {"type": "hello", "version": __version__, "dashboard": f"http://127.0.0.1:{config.port}/#/guard"}
    if kind == "guard_event":
        stored = guard.record(db, message.get("event"), "browser")
        return {"type": "ack", "stored": stored is not None}
    return {"type": "error", "error": f"unknown message type {kind!r}"}


def serve(stdin: BinaryIO, stdout: BinaryIO, config: Config | None = None) -> int:
    # The launcher starts us in the project folder: its .env and data/ are the dashboard's.
    config = config or Config.load(base_dir=Path.cwd())
    config.ensure_dirs()
    db = open_database(config)
    try:
        while True:
            try:
                message = read_message(stdin)
            except (ValueError, UnicodeDecodeError) as exc:
                log.warning("bad message: %s", exc)
                return 1
            if message is None:
                return 0
            reply = handle(message, db, config)
            if reply is not None:
                write_message(stdout, reply)
    finally:
        db.close()


# ---- installing -------------------------------------------------------------------------------

def extension_id() -> str:
    return json.loads(KEY_FILE.read_text(encoding="utf-8"))["id"]


def browser_dirs(home: Path, platform: str) -> dict[str, Path]:
    """Where each browser looks for host manifests (Linux and macOS: folders; Windows: see registry_keys)."""
    if platform == "darwin":
        support = home / "Library" / "Application Support"
        return {
            "Chrome": support / "Google" / "Chrome", "Chromium": support / "Chromium",
            "Edge": support / "Microsoft Edge", "Brave": support / "BraveSoftware" / "Brave-Browser",
        }
    config = home / ".config"
    return {
        "Chrome": config / "google-chrome", "Chromium": config / "chromium", "Edge": config / "microsoft-edge",
        "Brave": config / "BraveSoftware" / "Brave-Browser", "Vivaldi": config / "vivaldi",
    }


REGISTRY_KEYS = {
    "Chrome": r"Software\Google\Chrome\NativeMessagingHosts",
    "Chromium": r"Software\Chromium\NativeMessagingHosts",
    "Edge": r"Software\Microsoft\Edge\NativeMessagingHosts",
    "Brave": r"Software\BraveSoftware\Brave-Browser\NativeMessagingHosts",
}


def launcher_text(platform: str, python: str, root: Path) -> str:
    """A small program that starts the host from the project folder (so .env and data/ are the dashboard's)."""
    if platform == "win32":
        return f'@echo off\r\ncd /d "{root}"\r\n"{python}" -m shadowlens.native_host %*\r\n'
    return f'#!/bin/sh\ncd "{root}" || exit 1\nexec "{python}" -m shadowlens.native_host "$@"\n'


def manifest(launcher: Path, ext_id: str) -> dict[str, Any]:
    return {
        "name": HOST_NAME,
        "description": "Shadow Lens companion: records what the browser guard stopped, on this computer",
        "path": str(launcher),
        "type": "stdio",
        "allowed_origins": [f"chrome-extension://{ext_id}/"],
    }


def install(home: Path, platform: str = sys.platform, ext_id: str | None = None, python: str = sys.executable,
            root: Path = ROOT, all_browsers: bool = False) -> list[str]:
    """Register the host; returns what was done, one line per place."""
    ext_id = ext_id or extension_id()
    done = []
    if platform == "win32":
        folder = Path(os.environ.get("LOCALAPPDATA", home / "AppData" / "Local")) / "ShadowLens"
        folder.mkdir(parents=True, exist_ok=True)
        launcher = folder / "shadowlens-host.bat"
        launcher.write_text(launcher_text(platform, python, root), encoding="utf-8")
        path = folder / f"{HOST_NAME}.json"
        path.write_text(json.dumps(manifest(launcher, ext_id), indent=2), encoding="utf-8")
        import winreg  # noqa: PLC0415 - Windows only

        for browser, key in REGISTRY_KEYS.items():
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, f"{key}\\{HOST_NAME}") as handle_:
                winreg.SetValueEx(handle_, "", 0, winreg.REG_SZ, str(path))
            done.append(f"{browser}: HKCU\\{key}\\{HOST_NAME}")
        return done
    launcher = root / "data" / "shadowlens-host"
    launcher.parent.mkdir(parents=True, exist_ok=True)
    launcher.write_text(launcher_text(platform, python, root), encoding="utf-8")
    launcher.chmod(0o755)
    for browser, base in browser_dirs(home, platform).items():
        if not base.exists() and not all_browsers:
            continue
        target = base / "NativeMessagingHosts" / f"{HOST_NAME}.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(manifest(launcher, ext_id), indent=2) + "\n", encoding="utf-8")
        done.append(f"{browser}: {target}")
    return done


def uninstall(home: Path, platform: str = sys.platform) -> list[str]:
    done = []
    if platform == "win32":
        import winreg  # noqa: PLC0415

        for browser, key in REGISTRY_KEYS.items():
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, f"{key}\\{HOST_NAME}")
                done.append(f"{browser}: removed")
            except FileNotFoundError:
                pass
        return done
    for browser, base in browser_dirs(home, platform).items():
        target = base / "NativeMessagingHosts" / f"{HOST_NAME}.json"
        if target.exists():
            target.unlink()
            done.append(f"{browser}: removed {target}")
    return done


def status(home: Path, platform: str = sys.platform) -> list[str]:
    if platform == "win32":
        return [f"{b}: HKCU\\{k}\\{HOST_NAME}" for b, k in REGISTRY_KEYS.items()]
    return [f"{b}: {'installed' if (base / 'NativeMessagingHosts' / f'{HOST_NAME}.json').exists() else 'not installed'}"
            for b, base in browser_dirs(home, platform).items() if base.exists()]


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    # Chrome starts the host with the extension's origin (and on Windows a window handle) as arguments.
    if not argv or argv[0].startswith("chrome-extension://") or argv[0].startswith("--parent-window"):
        logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
        return serve(sys.stdin.buffer, sys.stdout.buffer)
    parser = argparse.ArgumentParser(prog="python -m shadowlens.native_host", description="Connect the Shadow Lens browser extension to this computer.")
    sub = parser.add_subparsers(dest="command", required=True)
    install_cmd = sub.add_parser("install", help="register the host with the browsers on this computer")
    install_cmd.add_argument("--extension-id", help="the extension's id (default: the id of extension/static/extension-key.json)")
    install_cmd.add_argument("--all-browsers", action="store_true", help="also for browsers that are not installed yet")
    sub.add_parser("uninstall", help="remove the registration")
    sub.add_parser("status", help="where the host is registered")
    args = parser.parse_args(argv)
    home = Path.home()
    if args.command == "install":
        lines = install(home, ext_id=args.extension_id, all_browsers=args.all_browsers)
        print("\n".join(lines) if lines else "No Chromium-based browser found. Use --all-browsers to register anyway.")
        print("Restart the browser, then the extension's popup shows “Open the dashboard”.")
    elif args.command == "uninstall":
        print("\n".join(uninstall(home)) or "Nothing was registered.")
    else:
        print("\n".join(status(home)) or "No Chromium-based browser found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

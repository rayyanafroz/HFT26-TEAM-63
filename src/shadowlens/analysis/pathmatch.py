"""Small helpers for matching agent rules against paths and commands. No heavy imports: the coding-agent
hook runs on every prompt and tool call and has to start fast."""

from __future__ import annotations

import re

from shadowlens.analysis.normalize import deobfuscate_command

_HOME_PREFIX_RE = re.compile(
    r"^(?:/home/[^/]+|/users/[^/]+|[a-z]:/users/[^/]+|%userprofile%|\$env:userprofile|\$home|~)(?:/|$)"
)


def normalize_path(path: str) -> str:
    """One lowercase form for Windows and POSIX path strings; every home folder becomes ``~/``."""
    text = path.strip().strip("\"'").replace("\\", "/").lower()
    match = _HOME_PREFIX_RE.match(text)
    if match:
        return "~/" + text[match.end():]
    return text


def matches_any(patterns: tuple[re.Pattern[str], ...], text: str) -> bool:
    return any(pattern.search(text) for pattern in patterns)


def matches_any_view(patterns: tuple[re.Pattern[str], ...], text: str) -> bool:
    """``matches_any`` on the command as written and as the shell will read it (``r''m``, ``\\rm``, ``${IFS}``)."""
    if matches_any(patterns, text):
        return True
    plain = deobfuscate_command(text)
    return plain != text and matches_any(patterns, plain)

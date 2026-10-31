"""Masks, hashes and placeholders: how a match may appear anywhere (SOT 6.10).

No more than 4 characters of a secret may ever leave this module (AT-12).
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from pathlib import Path

SALT_BYTES = 32

# Text that has already been redacted; the egress guard skips it (SOT 7.3).
PLACEHOLDER_RE = re.compile(r"\[(?:REDACTED:[A-Z_]+:[0-9a-f]{12}|PII:[A-Z_]+)\]")

# Rules masked as digits/IDs: "****" plus the last 4 characters (SOT 6.10).
_LAST4_RULES = frozenset({"PII_CREDIT_CARD", "PII_AADHAAR", "PII_SSN", "PII_PHONE", "PII_PAN", "PII_IBAN"})


def load_or_create_salt(path: Path) -> bytes:
    """Read the HMAC salt, creating it on first use (or if the file is damaged)."""
    path = Path(path)
    try:
        salt = path.read_bytes()
        if len(salt) == SALT_BYTES:
            return salt
    except FileNotFoundError:
        pass
    salt = secrets.token_bytes(SALT_BYTES)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(salt)
    return salt


def hash12(value: str, salt: bytes) -> str:
    """First 12 hex characters of ``HMAC-SHA256(salt, value)``."""
    return hmac.new(salt, value.encode("utf-8", "surrogatepass"), hashlib.sha256).hexdigest()[:12]


# ---- display masks (masked_preview) -------------------------------------------

def mask_secret(value: str) -> str:
    if len(value) >= 20:
        return f"{value[:4]}... (len {len(value)})"
    return f"... (len {len(value)})"


def mask_email(value: str) -> str:
    local, sep, domain = value.partition("@")
    if not sep or not local or not domain:
        return mask_secret(value)
    return f"{local[0]}***@{domain}"


def mask_last4(value: str) -> str:
    """Spaces and dashes are removed first; 4 characters or fewer show nothing."""
    compact = re.sub(r"[\s\-]", "", value)
    return "****" + (compact[-4:] if len(compact) > 4 else "")


def mask_for(rule_id: str, value: str) -> str:
    """The display mask for a match of ``rule_id``."""
    if rule_id == "PII_EMAIL":
        return mask_email(value)
    if rule_id in _LAST4_RULES:
        return mask_last4(value)
    return mask_secret(value)


# ---- placeholders (context, argument and all LLM text) ------------------------

def placeholder_for(rule_id: str, hash_value: str) -> str:
    """``[PII:<TYPE>]`` for personal data, ``[REDACTED:<rule_id>:<hash12>]`` otherwise."""
    if rule_id.startswith("PII_"):
        return f"[PII:{rule_id[len('PII_'):]}]"
    return f"[REDACTED:{rule_id}:{hash_value}]"

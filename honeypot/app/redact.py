"""Credential and secret redaction.

A honeypot that logs plaintext passwords is a liability, not an asset: the
operator ends up holding a credential dump harvested from third parties. This
module guarantees that anything resembling a secret is reduced to a salted
digest before it ever reaches storage.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any
from urllib.parse import parse_qs

# Field names treated as secret-bearing, matched case-insensitively as a
# substring so `user_password`, `passwd` and `apiKey` are all covered.
SECRET_FIELD_PATTERNS = (
    "pass",
    "pwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "auth",
    "credential",
    "session",
    "cookie",
)

_JSON_SECRET_RE = re.compile(
    r'("(?:[^"]*(?:%s)[^"]*)"\s*:\s*)"(?:[^"\\]|\\.)*"' % "|".join(SECRET_FIELD_PATTERNS),
    re.IGNORECASE,
)


def is_secret_field(name: str) -> bool:
    """True when a form/JSON field name looks like it carries a secret."""
    lowered = name.lower()
    return any(pattern in lowered for pattern in SECRET_FIELD_PATTERNS)


def digest(value: str, salt: str) -> str:
    """Salted SHA-256, truncated to 16 hex chars.

    Short enough to eyeball in a report, long enough that correlating repeat
    attempts stays reliable, and one-way so the plaintext is unrecoverable.
    """
    return hashlib.sha256(f"{salt}:{value}".encode("utf-8")).hexdigest()[:16]


def redact_form_body(body: str, salt: str) -> str:
    """Redact secret values in an urlencoded form body, preserving structure."""
    if not body:
        return body
    try:
        parsed = parse_qs(body, keep_blank_values=True)
    except ValueError:
        return "<unparseable>"

    parts: list[str] = []
    for key, values in parsed.items():
        for value in values:
            if is_secret_field(key):
                parts.append(f"{key}=sha256:{digest(value, salt)}")
            else:
                parts.append(f"{key}={value}")
    return "&".join(parts)


def redact_json_body(body: str, salt: str) -> str:
    """Redact secret values in a JSON body without needing it to be valid JSON."""

    def _replace(match: re.Match[str]) -> str:
        raw = match.group(0)
        value_start = raw.index(":", raw.index('"', 1)) + 1
        value = raw[value_start:].strip().strip('"')
        return f'{match.group(1)}"sha256:{digest(value, salt)}"'

    return _JSON_SECRET_RE.sub(_replace, body)


def redact_body(body: str, content_type: str, salt: str) -> str:
    """Dispatch redaction based on the declared content type."""
    ctype = (content_type or "").lower()
    if "json" in ctype:
        return redact_json_body(body, salt)
    if "x-www-form-urlencoded" in ctype:
        return redact_form_body(body, salt)
    # Unknown content type: keep it, but strip anything that looks like a
    # `key=value` secret pair inline.
    return re.sub(
        r"(?i)\b((?:%s)\w*)=([^&\s]+)" % "|".join(SECRET_FIELD_PATTERNS),
        lambda m: f"{m.group(1)}=sha256:{digest(m.group(2), salt)}",
        body,
    )


def redact_headers(headers: dict[str, str], salt: str) -> dict[str, str]:
    """Redact header values that carry session material."""
    cleaned: dict[str, Any] = {}
    for name, value in headers.items():
        if is_secret_field(name):
            cleaned[name] = f"sha256:{digest(value, salt)}"
        else:
            cleaned[name] = value
    return cleaned

"""Hashes anything that looks like a secret before it hits storage.

Storing plaintext passwords collected from attackers would mean holding a
credential dump from third parties. Everything here is one-way.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any
from urllib.parse import parse_qs

# matched as substrings, case insensitive, so passwd / user_password / apiKey all hit
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
    lowered = name.lower()
    return any(pattern in lowered for pattern in SECRET_FIELD_PATTERNS)


def digest(value: str, salt: str) -> str:
    """Salted sha256, truncated to 16 chars.

    Short enough to read in a report, long enough to correlate repeat attempts.
    """
    return hashlib.sha256(f"{salt}:{value}".encode("utf-8")).hexdigest()[:16]


def redact_form_body(body: str, salt: str) -> str:
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
    # regex instead of json.loads because attacker payloads are often malformed
    def _replace(match: re.Match[str]) -> str:
        raw = match.group(0)
        value_start = raw.index(":", raw.index('"', 1)) + 1
        value = raw[value_start:].strip().strip('"')
        return f'{match.group(1)}"sha256:{digest(value, salt)}"'

    return _JSON_SECRET_RE.sub(_replace, body)


def redact_body(body: str, content_type: str, salt: str) -> str:
    ctype = (content_type or "").lower()
    if "json" in ctype:
        return redact_json_body(body, salt)
    if "x-www-form-urlencoded" in ctype:
        return redact_form_body(body, salt)

    # unknown type: still catch inline key=value secrets
    return re.sub(
        r"(?i)\b((?:%s)\w*)=([^&\s]+)" % "|".join(SECRET_FIELD_PATTERNS),
        lambda m: f"{m.group(1)}=sha256:{digest(m.group(2), salt)}",
        body,
    )


def redact_headers(headers: dict[str, str], salt: str) -> dict[str, str]:
    cleaned: dict[str, Any] = {}
    for name, value in headers.items():
        if is_secret_field(name):
            cleaned[name] = f"sha256:{digest(value, salt)}"
        else:
            cleaned[name] = value
    return cleaned

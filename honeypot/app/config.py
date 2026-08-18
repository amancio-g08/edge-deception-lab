"""Settings loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    # storage
    db_path: Path = field(
        default_factory=lambda: Path(os.getenv("EDL_DB_PATH", "/data/events.db"))
    )

    # capture
    max_body_bytes: int = field(default_factory=lambda: _env_int("EDL_MAX_BODY_BYTES", 8192))
    trusted_edge_header: str = field(
        default_factory=lambda: os.getenv("EDL_EDGE_IP_HEADER", "X-Edge-Client-IP")
    )

    # privacy. passwords are hashed, never stored raw
    credential_salt: str = field(
        default_factory=lambda: os.getenv("EDL_CREDENTIAL_SALT", "edge-deception-lab")
    )
    store_ip_raw: bool = field(default_factory=lambda: _env_bool("EDL_STORE_IP_RAW", True))

    # classification
    velocity_window_seconds: int = field(
        default_factory=lambda: _env_int("EDL_VELOCITY_WINDOW", 300)
    )
    verify_bot_rdns: bool = field(default_factory=lambda: _env_bool("EDL_VERIFY_BOT_RDNS", True))

    # dashboard
    dashboard_enabled: bool = field(
        default_factory=lambda: _env_bool("EDL_DASHBOARD_ENABLED", True)
    )


settings = Settings()

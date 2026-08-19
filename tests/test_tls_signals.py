"""TLS fingerprint signals.

The case that matters: a client with a perfect set of browser headers whose
handshake came out of OpenSSL. Headers alone cannot catch it. That is the whole
reason JA4 is in the project.
"""

from __future__ import annotations

from honeypot.app.classifier import Verdict, VelocityContext, classify
from honeypot.app.fingerprint import build_fingerprint, tls_family

CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

# A full, correct browser header set. Anyone scraping seriously sends this.
PERFECT_BROWSER_HEADERS = {
    "host": "portal.example",
    "user-agent": CHROME_UA,
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "accept-language": "pt-BR,pt;q=0.9,en;q=0.8",
    "accept-encoding": "gzip, deflate, br",
    "sec-fetch-site": "same-origin",
    "sec-fetch-mode": "navigate",
    "sec-fetch-dest": "document",
    "sec-fetch-user": "?1",
    "sec-ch-ua": '"Chromium";v="126"',
    "referer": "https://portal.example/",
}

# Captured from real clients, see tlsfront/testdata/clienthellos.txt
JA4_CHROMIUM = "t13i1515h2_8daaf6152771_d8a2da3f94cd"
JA4_OPENSSL = "t13i3111h2_e8f1e7e78f70_b26ce05bbdd6"
JA4_PYTHON = "t13d181100_85036bcba153_d41ae481755e"


def fp(headers, ja4=""):
    return build_fingerprint(headers, list(headers.keys()), None, ja4)


def test_cipher_hash_identifies_the_tls_stack():
    assert tls_family(JA4_CHROMIUM) == "chromium"
    assert tls_family(JA4_OPENSSL) == "openssl"
    assert tls_family(JA4_PYTHON) == "python-ssl"
    assert tls_family("") is None
    assert tls_family("garbage") is None
    assert tls_family("t13i1515h2_deadbeefcafe_d8a2da3f94cd") is None


def test_perfect_browser_headers_over_an_openssl_handshake_is_caught():
    """The reason this phase exists.

    Header-based detection sees a flawless Chrome. The handshake says the
    request came out of OpenSSL, and no browser ships that ClientHello.
    """
    result = classify(
        method="GET",
        path="/api/v1/products",
        query="",
        fingerprint=fp(PERFECT_BROWSER_HEADERS, JA4_OPENSSL),
        velocity=VelocityContext(requests=3, distinct_paths=2),
    )
    assert result.verdict != Verdict.LIKELY_HUMAN
    assert any(s.name == "tls_contradicts_user_agent" for s in result.signals)


def test_the_same_client_without_tls_data_still_passes():
    """Same headers, no JA4. Over plain HTTP there is nothing to contradict, and
    the classifier must not invent evidence it does not have."""
    result = classify(
        method="GET",
        path="/api/v1/products",
        query="",
        fingerprint=fp(PERFECT_BROWSER_HEADERS),
        velocity=VelocityContext(requests=3, distinct_paths=2),
    )
    assert result.verdict == Verdict.LIKELY_HUMAN
    assert not any(s.name.startswith("tls_") for s in result.signals)


def test_forged_header_evidence_is_discarded_not_outweighed():
    """A contradicted claim is worth nothing, not merely less.

    Scoring the forged headers as human evidence and hoping the TLS weight wins
    would make the outcome depend on how many headers the attacker bothered to
    copy.
    """
    result = classify(
        method="GET",
        path="/",
        query="",
        fingerprint=fp(PERFECT_BROWSER_HEADERS, JA4_OPENSSL),
        velocity=VelocityContext(requests=2, distinct_paths=1),
    )
    assert result.human_score == 0.0
    assert not any(s.verdict == Verdict.LIKELY_HUMAN for s in result.signals)


def test_real_browser_over_a_chromium_handshake_is_corroborated():
    with_tls = classify(
        method="GET",
        path="/",
        query="",
        fingerprint=fp(PERFECT_BROWSER_HEADERS, JA4_CHROMIUM),
        velocity=VelocityContext(requests=2, distinct_paths=1),
    )
    without_tls = classify(
        method="GET",
        path="/",
        query="",
        fingerprint=fp(PERFECT_BROWSER_HEADERS),
        velocity=VelocityContext(requests=2, distinct_paths=1),
    )
    assert with_tls.verdict == Verdict.LIKELY_HUMAN
    assert with_tls.human_score > without_tls.human_score
    assert any(s.name == "browser_tls_stack" for s in with_tls.signals)


def test_honest_and_lying_scripts_are_told_apart_by_signal_not_by_score():
    """Both are automation. What differs is the evidence recorded.

    The honest client scores *higher*, because admitting to being
    python-requests also means failing several header checks. That is not a
    defect: an analyst triaging these acts on which signals fired, not on which
    total is larger. A bigger automation score means more corroboration, never
    more malice.
    """
    honest = classify(
        method="GET",
        path="/status",
        query="",
        fingerprint=fp({"host": "h", "user-agent": "python-requests/2.32.0"}, JA4_PYTHON),
        velocity=VelocityContext(requests=4, distinct_paths=1),
    )
    liar = classify(
        method="GET",
        path="/status",
        query="",
        fingerprint=fp(PERFECT_BROWSER_HEADERS, JA4_PYTHON),
        velocity=VelocityContext(requests=4, distinct_paths=1),
    )

    assert honest.verdict == Verdict.UNCLASSIFIED_AUTOMATION
    assert liar.verdict == Verdict.UNCLASSIFIED_AUTOMATION

    honest_names = {s.name for s in honest.signals}
    liar_names = {s.name for s in liar.signals}

    assert "scripted_tls_stack" in honest_names
    assert "tls_contradicts_user_agent" in liar_names
    assert "tls_contradicts_user_agent" not in honest_names

    # The liar passes every header check, so TLS is the only thing that caught
    # it. Remove that signal and the classifier has nothing left.
    header_evidence = liar_names - {"tls_contradicts_user_agent"}
    assert not header_evidence, f"expected TLS to be the sole evidence, also got {header_evidence}"


def test_unknown_tls_stack_produces_no_signal_either_way():
    """An unrecognised fingerprint is missing knowledge, not evidence. Treating
    it as suspicious would flag every client the table has not met yet."""
    result = classify(
        method="GET",
        path="/",
        query="",
        fingerprint=fp(PERFECT_BROWSER_HEADERS, "t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb"),
        velocity=VelocityContext(requests=2, distinct_paths=1),
    )
    assert not any(s.name.startswith("tls_") or s.name == "scripted_tls_stack"
                   for s in result.signals)
    assert result.verdict == Verdict.LIKELY_HUMAN


def test_tls_evidence_does_not_override_intent():
    """A scanner is a scanner regardless of what its handshake looks like."""
    result = classify(
        method="GET",
        path="/.env",
        query="",
        fingerprint=fp({"host": "h", "user-agent": "curl/8.4.0"}, JA4_OPENSSL),
        velocity=VelocityContext(requests=10, distinct_paths=9, not_found_ratio=0.9),
        status_code=404,
    )
    assert result.verdict == Verdict.VULN_SCANNER

"""Behavioural classification of captured requests.

The design goal is the one that matters in real bot management: **every verdict
must be explainable**. A score with no signal list behind it cannot be defended
to a customer when it produces a false positive, so the classifier returns the
individual signals that fired, their weights, and the resulting margin.

Categories are deliberately behavioural rather than identity-based. "This client
enumerated 40 distinct paths in 60 seconds" survives a spoofed User-Agent;
"this client said it was curl" does not.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

from .fingerprint import Fingerprint


class Verdict(str, Enum):
    VERIFIED_CRAWLER = "verified_crawler"
    VULN_SCANNER = "vuln_scanner"
    CREDENTIAL_ATTACK = "credential_attack"
    CONTENT_SCRAPER = "content_scraper"
    RECON_PROBE = "recon_probe"
    UNCLASSIFIED_AUTOMATION = "unclassified_automation"
    LIKELY_HUMAN = "likely_human"


# Paths that exist only to be found by someone looking for them. A request for
# `/.env` is not a mistake a browser makes.
SENSITIVE_ARTIFACT_PATHS = (
    "/.env",
    "/.git",
    "/.aws",
    "/.ssh",
    "/config.json",
    "/credentials",
    "/backup",
    "/dump.sql",
    "/db.sql",
    "/wp-config.php",
    "/phpinfo.php",
    "/server-status",
    "/actuator",
    "/.well-known/security.txt",
    "/telescope",
    "/debug",
)

ADMIN_SURFACE_PATHS = (
    "/admin",
    "/wp-admin",
    "/wp-login.php",
    "/administrator",
    "/phpmyadmin",
    "/pma",
    "/manager/html",
    "/cgi-bin",
    "/solr",
    "/jenkins",
    "/console",
)

# Exploit-shaped payloads. Matched against the raw path + query only; the point
# is detecting *probing*, not blocking, since nothing here is a real app.
EXPLOIT_PATTERNS = (
    (re.compile(r"\.\./|\.\.%2f", re.IGNORECASE), "path-traversal"),
    (re.compile(r"union[\s+]+select|sleep\(\d|benchmark\(", re.IGNORECASE), "sqli-probe"),
    (re.compile(r"<script|javascript:|onerror\s*=", re.IGNORECASE), "xss-probe"),
    (re.compile(r"\$\{jndi:", re.IGNORECASE), "log4shell-probe"),
    (re.compile(r"/bin/(sh|bash)|;\s*cat\s|%0a", re.IGNORECASE), "command-injection-probe"),
    (re.compile(r"\{\{.*\}\}|\$\{.*\}", re.IGNORECASE), "template-injection-probe"),
)

LOGIN_PATHS = ("/login", "/signin", "/auth", "/wp-login.php", "/api/v1/auth", "/session")

# Cheap, high-volume content endpoints a scraper would iterate.
CONTENT_PATHS = ("/api/v1/products", "/api/v1/customers", "/catalog", "/search")


@dataclass
class Signal:
    """One piece of evidence, with the category it argues for."""

    name: str
    weight: float
    verdict: Verdict
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "weight": self.weight,
            "verdict": self.verdict.value,
            "detail": self.detail,
        }


@dataclass
class VelocityContext:
    """Aggregates for the source IP over the configured sliding window."""

    requests: int = 1
    distinct_paths: int = 1
    distinct_usernames: int = 0
    distinct_user_agents: int = 1
    not_found_ratio: float = 0.0


# Verdicts that describe *what the client is trying to do*. These are ranked
# against each other. `UNCLASSIFIED_AUTOMATION` is deliberately excluded: it is a
# fallback bucket, not a competitor — see `classify()`.
INTENT_VERDICTS = (
    Verdict.VULN_SCANNER,
    Verdict.CREDENTIAL_ATTACK,
    Verdict.CONTENT_SCRAPER,
    Verdict.RECON_PROBE,
)


@dataclass
class Classification:
    verdict: Verdict
    confidence: float
    signals: list[Signal] = field(default_factory=list)
    scores: dict[str, float] = field(default_factory=dict)
    automation_score: float = 0.0
    human_score: float = 0.0

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "confidence": round(self.confidence, 3),
            "automation_score": round(self.automation_score, 2),
            "human_score": round(self.human_score, 2),
            "signals": [s.to_dict() for s in self.signals],
            "scores": {k: round(v, 2) for k, v in self.scores.items()},
        }


def _path_signals(path: str, query: str, method: str) -> list[Signal]:
    signals: list[Signal] = []
    target = f"{path}?{query}" if query else path
    lowered = path.lower()

    for artifact in SENSITIVE_ARTIFACT_PATHS:
        if lowered.startswith(artifact):
            signals.append(
                Signal("sensitive_artifact_request", 4.0, Verdict.VULN_SCANNER, artifact)
            )
            break

    for admin in ADMIN_SURFACE_PATHS:
        if lowered.startswith(admin):
            signals.append(Signal("admin_surface_request", 2.5, Verdict.RECON_PROBE, admin))
            break

    for pattern, label in EXPLOIT_PATTERNS:
        if pattern.search(target):
            signals.append(Signal("exploit_pattern", 5.0, Verdict.VULN_SCANNER, label))

    if method == "POST" and any(lowered.startswith(p) for p in LOGIN_PATHS):
        signals.append(Signal("login_post", 3.0, Verdict.CREDENTIAL_ATTACK, lowered))

    if method == "GET" and any(lowered.startswith(p) for p in CONTENT_PATHS):
        signals.append(Signal("content_endpoint", 1.5, Verdict.CONTENT_SCRAPER, lowered))

    return signals


def _fingerprint_signals(fp: Fingerprint) -> list[Signal]:
    signals: list[Signal] = []

    if fp.tool_signature:
        signals.append(
            Signal("automation_user_agent", 3.5, Verdict.UNCLASSIFIED_AUTOMATION, fp.tool_signature)
        )

    if fp.declared_crawler and fp.crawler_verified:
        signals.append(
            Signal("crawler_rdns_verified", 8.0, Verdict.VERIFIED_CRAWLER, fp.declared_crawler)
        )
    elif fp.declared_crawler and not fp.crawler_verified:
        # Impersonating a search engine is one of the most reliable malicious
        # indicators there is: legitimate crawlers always pass rDNS.
        signals.append(
            Signal("crawler_impersonation", 5.0, Verdict.CONTENT_SCRAPER, fp.declared_crawler)
        )

    if not fp.ua_raw:
        signals.append(Signal("no_user_agent", 2.5, Verdict.UNCLASSIFIED_AUTOMATION))

    if fp.claims_browser and not fp.has_sec_fetch:
        # A UA claiming a modern browser with no Fetch Metadata is a
        # contradiction: the headers are emitted by the browser itself.
        signals.append(
            Signal("browser_ua_without_sec_fetch", 3.0, Verdict.UNCLASSIFIED_AUTOMATION)
        )

    if fp.missing_baseline_headers:
        signals.append(
            Signal(
                "missing_baseline_headers",
                1.0 * len(fp.missing_baseline_headers),
                Verdict.UNCLASSIFIED_AUTOMATION,
                ",".join(fp.missing_baseline_headers),
            )
        )

    if fp.accept_is_wildcard and fp.claims_browser:
        signals.append(Signal("wildcard_accept_with_browser_ua", 1.5, Verdict.UNCLASSIFIED_AUTOMATION))

    if fp.header_count <= 4:
        signals.append(
            Signal("minimal_header_set", 1.5, Verdict.UNCLASSIFIED_AUTOMATION, str(fp.header_count))
        )

    return signals


def _velocity_signals(ctx: VelocityContext, is_login_attempt: bool) -> list[Signal]:
    signals: list[Signal] = []

    if ctx.distinct_paths >= 20:
        signals.append(
            Signal("path_enumeration", 4.0, Verdict.VULN_SCANNER, f"{ctx.distinct_paths} paths")
        )
    elif ctx.distinct_paths >= 8:
        signals.append(
            Signal("path_sweep", 2.0, Verdict.RECON_PROBE, f"{ctx.distinct_paths} paths")
        )

    if ctx.not_found_ratio >= 0.6 and ctx.requests >= 5:
        signals.append(
            Signal("high_404_ratio", 2.5, Verdict.VULN_SCANNER, f"{ctx.not_found_ratio:.0%}")
        )

    # Username-rotation signals apply only to a request that is itself an
    # authentication attempt. Without this gate, one credential-stuffing run
    # behind a NAT or corporate proxy would recolour every unrelated request
    # from the same address — the shared-IP false positive that makes customers
    # stop trusting a bot policy.
    if is_login_attempt:
        if ctx.distinct_usernames >= 5:
            signals.append(
                Signal(
                    "username_rotation",
                    5.0,
                    Verdict.CREDENTIAL_ATTACK,
                    f"{ctx.distinct_usernames} usernames",
                )
            )
        elif ctx.distinct_usernames >= 2:
            signals.append(
                Signal(
                    "multiple_usernames",
                    2.0,
                    Verdict.CREDENTIAL_ATTACK,
                    f"{ctx.distinct_usernames} usernames",
                )
            )

    if ctx.distinct_user_agents >= 3:
        signals.append(
            Signal(
                "user_agent_rotation",
                3.0,
                Verdict.UNCLASSIFIED_AUTOMATION,
                f"{ctx.distinct_user_agents} UAs",
            )
        )

    if ctx.requests >= 60:
        signals.append(
            Signal("high_request_volume", 2.0, Verdict.CONTENT_SCRAPER, f"{ctx.requests} req")
        )

    return signals


def _human_signals(fp: Fingerprint, ctx: VelocityContext) -> list[Signal]:
    """Evidence *against* automation. Without these, everything looks like a bot."""
    signals: list[Signal] = []

    if fp.has_sec_fetch and fp.claims_browser and not fp.tool_signature:
        signals.append(Signal("sec_fetch_present", 3.0, Verdict.LIKELY_HUMAN))
    if fp.has_client_hints:
        signals.append(Signal("client_hints_present", 1.5, Verdict.LIKELY_HUMAN))
    if fp.has_referer:
        signals.append(Signal("referer_present", 1.0, Verdict.LIKELY_HUMAN))
    if not fp.missing_baseline_headers and fp.header_count >= 8:
        signals.append(Signal("complete_header_set", 2.0, Verdict.LIKELY_HUMAN))
    if ctx.requests <= 5 and ctx.distinct_paths <= 3:
        signals.append(Signal("low_velocity", 1.0, Verdict.LIKELY_HUMAN))

    return signals


def classify(
    *,
    method: str,
    path: str,
    query: str,
    fingerprint: Fingerprint,
    velocity: VelocityContext | None = None,
    status_code: int = 200,
) -> Classification:
    """Score a single request and return an explainable verdict."""
    ctx = velocity or VelocityContext()

    normalized_method = method.upper()
    is_login_attempt = normalized_method == "POST" and any(
        path.lower().startswith(p) for p in LOGIN_PATHS
    )

    signals: list[Signal] = []
    signals += _path_signals(path, query, normalized_method)
    signals += _fingerprint_signals(fingerprint)
    signals += _velocity_signals(ctx, is_login_attempt)
    signals += _human_signals(fingerprint, ctx)

    if status_code == 404:
        signals.append(Signal("not_found_response", 0.5, Verdict.RECON_PROBE))

    scores: dict[str, float] = {v.value: 0.0 for v in Verdict}
    for signal in signals:
        scores[signal.verdict.value] += signal.weight

    # A verified crawler short-circuits everything else. This mirrors the
    # allowlist behaviour of a production bot manager: once identity is proven
    # by forward-confirmed rDNS, behavioural heuristics must not override it.
    if scores[Verdict.VERIFIED_CRAWLER.value] > 0:
        return Classification(
            verdict=Verdict.VERIFIED_CRAWLER,
            confidence=0.99,
            signals=signals,
            scores=scores,
            automation_score=scores[Verdict.UNCLASSIFIED_AUTOMATION.value],
            human_score=scores[Verdict.LIKELY_HUMAN.value],
        )

    automation_score = scores[Verdict.UNCLASSIFIED_AUTOMATION.value]
    human_score = scores[Verdict.LIKELY_HUMAN.value]

    # Two questions, answered separately — the same split a production bot
    # manager makes. "Is this automated?" is a property of the client stack.
    # "What is it trying to do?" is a property of the behaviour. Collapsing them
    # into one ranking lets a noisy client fingerprint outvote an unambiguous
    # attack pattern, which is exactly the false-negative that matters.
    intent_ranked = sorted(
        ((v, scores[v.value]) for v in INTENT_VERDICTS),
        key=lambda kv: kv[1],
        reverse=True,
    )
    top_intent, top_score = intent_ranked[0]
    runner_up = intent_ranked[1][1] if len(intent_ranked) > 1 else 0.0

    def _finish(verdict: Verdict, confidence: float) -> Classification:
        return Classification(
            verdict=verdict,
            confidence=round(min(confidence, 0.99), 3),
            signals=signals,
            scores=scores,
            automation_score=automation_score,
            human_score=human_score,
        )

    if top_score > 0 and top_score >= human_score:
        # Margin over the runner-up intent, plus absolute evidence, plus a small
        # corroboration bonus when the client also *looks* automated.
        margin = (top_score - runner_up) / top_score
        magnitude = min(top_score / 8.0, 1.0)
        corroboration = 0.15 * min(automation_score / 8.0, 1.0)
        return _finish(top_intent, 0.35 + 0.5 * (0.5 * margin + 0.5 * magnitude) + corroboration)

    if automation_score > human_score:
        # Automated, but the intent is not yet legible. In production this is the
        # bucket that goes to alert-only until a pattern emerges — never straight
        # to block.
        return _finish(
            Verdict.UNCLASSIFIED_AUTOMATION, 0.35 + 0.5 * min(automation_score / 8.0, 1.0)
        )

    if human_score == 0.0:
        return _finish(Verdict.LIKELY_HUMAN, 0.3)

    return _finish(Verdict.LIKELY_HUMAN, 0.35 + 0.5 * min(human_score / 8.0, 1.0))

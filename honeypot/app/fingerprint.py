"""Request fingerprinting.

The premise: a real browser is a very constrained thing. It sends a stable set
of headers, in a stable order, with a stable set of `Sec-Fetch-*` metadata. HTTP
clients used for automation — curl, python-requests, Go's net/http, sqlmap,
headless drivers — deviate in ways that survive a spoofed User-Agent.

This module extracts those deviations as structured signals. It never decides
anything on its own; `classifier.py` consumes what it produces.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field

# Headers a mainstream browser emits on a top-level navigation. Absence is a
# much stronger signal than presence, since presence is trivially spoofed.
BROWSER_BASELINE_HEADERS = (
    "accept",
    "accept-encoding",
    "accept-language",
    "user-agent",
)

# Fetch Metadata headers. Shipped by every current Chromium/Firefox build and
# almost never reproduced by scripted clients.
SEC_FETCH_HEADERS = (
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-dest",
    "sec-fetch-user",
)

# Client Hints, Chromium-only. Their presence alongside a Firefox/Safari UA is a
# contradiction worth flagging.
CLIENT_HINT_HEADERS = ("sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform")

# User-Agent substrings that self-identify automation. Attackers who bother to
# spoof will not appear here; the ones who do not bother are the majority.
TOOL_UA_SIGNATURES = {
    "sqlmap": "sqlmap",
    "nikto": "nikto",
    "nmap": "nmap",
    "masscan": "masscan",
    "zgrab": "zgrab",
    "nuclei": "nuclei",
    "wpscan": "wpscan",
    "dirbuster": "dirbuster",
    "gobuster": "gobuster",
    "feroxbuster": "feroxbuster",
    "hydra": "hydra",
    "havij": "havij",
    "acunetix": "acunetix",
    "netsparker": "netsparker",
    "curl": "curl",
    "wget": "wget",
    "python-requests": "python-requests",
    "python-urllib": "python-urllib",
    "go-http-client": "go-http-client",
    "java/": "java-http",
    "okhttp": "okhttp",
    "libwww-perl": "libwww-perl",
    "axios": "axios",
    "node-fetch": "node-fetch",
    "scrapy": "scrapy",
    "httpx": "httpx",
    "postmanruntime": "postman",
    "insomnia": "insomnia",
    "headlesschrome": "headless-chrome",
    "phantomjs": "phantomjs",
    "puppeteer": "puppeteer",
    "playwright": "playwright",
    "selenium": "selenium",
}

# Declared crawlers, with the reverse-DNS suffixes that make the claim
# verifiable. This mirrors how a real bot-management product separates a
# "verified" Googlebot from anything that merely says it is one.
DECLARED_CRAWLERS = {
    "googlebot": (".googlebot.com", ".google.com"),
    "bingbot": (".search.msn.com",),
    "duckduckbot": (".duckduckgo.com",),
    "yandexbot": (".yandex.ru", ".yandex.net", ".yandex.com"),
    "baiduspider": (".baidu.com", ".baidu.jp"),
    "applebot": (".applebot.apple.com",),
    "facebookexternalhit": (".fbsv.net", ".facebook.com"),
    "twitterbot": (".twttr.com",),
    "ahrefsbot": (".ahrefs.com",),
    "semrushbot": (".semrush.com",),
    "gptbot": (".openai.com",),
    "claudebot": (".anthropic.com",),
}

_BROWSER_UA_RE = re.compile(r"mozilla/5\.0", re.IGNORECASE)
_CHROMIUM_UA_RE = re.compile(r"\b(chrome|chromium|edg)/", re.IGNORECASE)


@dataclass
class Fingerprint:
    """Structured view of what the client looked like on the wire."""

    ua_raw: str = ""
    ua_family: str = "unknown"
    header_count: int = 0
    header_order_hash: str = ""
    missing_baseline_headers: list[str] = field(default_factory=list)
    has_sec_fetch: bool = False
    has_client_hints: bool = False
    claims_browser: bool = False
    tool_signature: str | None = None
    declared_crawler: str | None = None
    crawler_verified: bool = False
    accept_is_wildcard: bool = False
    has_referer: bool = False
    connection_close: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


def header_order_hash(header_names: list[str]) -> str:
    """Stable digest of header ordering.

    Header order is a property of the HTTP client implementation, not of the
    request content. Two requests with the same order hash very likely came out
    of the same stack, even across different User-Agent strings.
    """
    normalized = ",".join(name.lower() for name in header_names)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]


def detect_tool(user_agent: str) -> str | None:
    """Return a normalized tool name when the UA self-identifies automation."""
    ua = (user_agent or "").lower()
    for needle, label in TOOL_UA_SIGNATURES.items():
        if needle in ua:
            return label
    return None


def detect_declared_crawler(user_agent: str) -> str | None:
    """Return the crawler a UA claims to be, without validating the claim."""
    ua = (user_agent or "").lower()
    for name in DECLARED_CRAWLERS:
        if name in ua:
            return name
    return None


def verify_crawler(name: str, hostname: str | None) -> bool:
    """Validate a crawler claim against its published reverse-DNS suffixes.

    `hostname` is expected to come from a forward-confirmed reverse DNS lookup
    (PTR, then A/AAAA back to the same address). Passing an unconfirmed PTR here
    would make the check spoofable.
    """
    if not hostname:
        return False
    suffixes = DECLARED_CRAWLERS.get(name, ())
    host = hostname.lower().rstrip(".")
    return any(host.endswith(suffix) for suffix in suffixes)


def classify_ua_family(user_agent: str) -> str:
    """Coarse UA bucket, used for reporting rather than for decisions."""
    ua = (user_agent or "").lower()
    if not ua:
        return "absent"
    if detect_tool(ua):
        return "tool"
    if detect_declared_crawler(ua):
        return "declared-crawler"
    if _CHROMIUM_UA_RE.search(ua):
        return "chromium"
    if "firefox/" in ua:
        return "firefox"
    if "safari/" in ua and "chrome" not in ua:
        return "safari"
    if _BROWSER_UA_RE.search(ua):
        return "browser-like"
    return "unknown"


def build_fingerprint(
    headers: dict[str, str],
    header_order: list[str],
    rdns_hostname: str | None = None,
) -> Fingerprint:
    """Assemble a `Fingerprint` from a captured request.

    `headers` should be lowercase-keyed. `header_order` preserves the order the
    headers arrived in, which is lost once they are put in a dict.
    """
    lowered = {k.lower(): v for k, v in headers.items()}
    ua = lowered.get("user-agent", "")

    declared = detect_declared_crawler(ua)
    fp = Fingerprint(
        ua_raw=ua,
        ua_family=classify_ua_family(ua),
        header_count=len(header_order),
        header_order_hash=header_order_hash(header_order),
        missing_baseline_headers=[h for h in BROWSER_BASELINE_HEADERS if h not in lowered],
        has_sec_fetch=any(h in lowered for h in SEC_FETCH_HEADERS),
        has_client_hints=any(h in lowered for h in CLIENT_HINT_HEADERS),
        claims_browser=bool(_BROWSER_UA_RE.search(ua)),
        tool_signature=detect_tool(ua),
        declared_crawler=declared,
        crawler_verified=verify_crawler(declared, rdns_hostname) if declared else False,
        accept_is_wildcard=lowered.get("accept", "").strip() == "*/*",
        has_referer="referer" in lowered,
        connection_close=lowered.get("connection", "").lower() == "close",
    )
    return fp

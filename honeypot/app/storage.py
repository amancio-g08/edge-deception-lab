"""SQLite storage.

One file, no external service, so the whole lab clones and runs with one
command. WAL keeps the dashboard reads from blocking capture writes.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    ts                  TEXT    NOT NULL,
    src_ip              TEXT,
    src_ip_hash         TEXT    NOT NULL,
    edge_ip             TEXT,
    method              TEXT    NOT NULL,
    path                TEXT    NOT NULL,
    query               TEXT    NOT NULL DEFAULT '',
    status              INTEGER NOT NULL,
    decoy               TEXT,
    content_type        TEXT,
    body_size           INTEGER NOT NULL DEFAULT 0,
    body_redacted       TEXT,
    headers_json        TEXT    NOT NULL DEFAULT '{}',
    header_order_hash   TEXT,
    ua_raw              TEXT,
    ua_family           TEXT,
    tool_signature      TEXT,
    declared_crawler    TEXT,
    crawler_verified    INTEGER NOT NULL DEFAULT 0,
    username_hash       TEXT,
    verdict             TEXT    NOT NULL,
    confidence          REAL    NOT NULL,
    signals_json        TEXT    NOT NULL DEFAULT '[]',
    fingerprint_json    TEXT    NOT NULL DEFAULT '{}',
    ja4                 TEXT,
    ja4_raw             TEXT,
    tls_family          TEXT,
    client_id           TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_ts       ON events (ts);
CREATE INDEX IF NOT EXISTS idx_events_ip       ON events (src_ip_hash, ts);
CREATE INDEX IF NOT EXISTS idx_events_verdict  ON events (verdict);
CREATE INDEX IF NOT EXISTS idx_events_path     ON events (path);
CREATE INDEX IF NOT EXISTS idx_events_ja4      ON events (ja4);
CREATE INDEX IF NOT EXISTS idx_events_client   ON events (client_id, src_ip_hash, ts);
"""

# Columns added after the first release. A lab that has been collecting for a
# week should not have to throw the data away to pick up a new field.
MIGRATIONS = (
    ("ja4", "ALTER TABLE events ADD COLUMN ja4 TEXT"),
    ("ja4_raw", "ALTER TABLE events ADD COLUMN ja4_raw TEXT"),
    ("tls_family", "ALTER TABLE events ADD COLUMN tls_family TEXT"),
    ("client_id", "ALTER TABLE events ADD COLUMN client_id TEXT"),
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


class EventStore:
    """Thread-safe store for captured events."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(
            str(self.db_path), check_same_thread=False, isolation_level=None
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(SCHEMA)
        self._migrate()

    def _migrate(self) -> None:
        existing = {row["name"] for row in self._conn.execute("PRAGMA table_info(events)")}
        for column, statement in MIGRATIONS:
            if column not in existing:
                self._conn.execute(statement)

    @contextmanager
    def _cursor(self) -> Iterator[sqlite3.Cursor]:
        with self._lock:
            cur = self._conn.cursor()
            try:
                yield cur
            finally:
                cur.close()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def record(self, event: dict[str, Any]) -> int:
        """Insert one event, return the row id."""
        columns = (
            "ts", "src_ip", "src_ip_hash", "edge_ip", "method", "path", "query",
            "status", "decoy", "content_type", "body_size", "body_redacted",
            "headers_json", "header_order_hash", "ua_raw", "ua_family",
            "tool_signature", "declared_crawler", "crawler_verified",
            "username_hash", "verdict", "confidence", "signals_json",
            "fingerprint_json", "ja4", "ja4_raw", "tls_family", "client_id",
        )
        placeholders = ",".join("?" for _ in columns)
        values = [event.get(col) for col in columns]
        with self._cursor() as cur:
            cur.execute(
                f"INSERT INTO events ({','.join(columns)}) VALUES ({placeholders})", values
            )
            return int(cur.lastrowid or 0)

    def velocity_for(
        self, src_ip_hash: str, window_seconds: int, client_id: str | None = None
    ) -> dict[str, Any]:
        """Sliding-window aggregates for the classifier.

        Keyed on the client identity when there is one, falling back to the
        source IP. Keying on identity is the whole point of this: two clients
        behind one shared address get independent velocity, so one attacker
        stops tainting everyone who shares his egress.

        The IP still narrows the window (same client from a new address is a new
        context) so a rotating botnet does not collapse into one profile either.
        """
        since = iso(utc_now() - timedelta(seconds=window_seconds))
        if client_id:
            where = "client_id = ? AND src_ip_hash = ? AND ts >= ?"
            params = (client_id, src_ip_hash, since)
        else:
            where = "src_ip_hash = ? AND ts >= ?"
            params = (src_ip_hash, since)

        with self._cursor() as cur:
            row = cur.execute(
                f"""
                SELECT
                    COUNT(*)                                   AS requests,
                    COUNT(DISTINCT path)                       AS distinct_paths,
                    COUNT(DISTINCT username_hash)              AS distinct_usernames,
                    COUNT(DISTINCT ua_raw)                     AS distinct_user_agents,
                    AVG(CASE WHEN status = 404 THEN 1.0 ELSE 0.0 END) AS not_found_ratio
                FROM events
                WHERE {where}
                """,
                params,
            ).fetchone()

        return {
            "requests": (row["requests"] or 0) + 1,  # count the request being handled
            "distinct_paths": max(row["distinct_paths"] or 0, 1),
            "distinct_usernames": row["distinct_usernames"] or 0,
            "distinct_user_agents": max(row["distinct_user_agents"] or 0, 1),
            "not_found_ratio": float(row["not_found_ratio"] or 0.0),
        }

    def summary(self, hours: int = 24) -> dict[str, Any]:
        since = iso(utc_now() - timedelta(hours=hours))
        with self._cursor() as cur:
            totals = cur.execute(
                """
                SELECT
                    COUNT(*)                        AS events,
                    COUNT(DISTINCT src_ip_hash)     AS unique_sources,
                    COUNT(DISTINCT COALESCE(client_id, header_order_hash)) AS unique_clients,
                    SUM(CASE WHEN username_hash IS NOT NULL THEN 1 ELSE 0 END) AS credential_attempts
                FROM events WHERE ts >= ?
                """,
                (since,),
            ).fetchone()

            automated = cur.execute(
                """
                SELECT COUNT(*) AS n FROM events
                WHERE ts >= ? AND verdict NOT IN ('likely_human', 'verified_crawler')
                """,
                (since,),
            ).fetchone()

        total_events = totals["events"] or 0
        return {
            "window_hours": hours,
            "events": total_events,
            "unique_sources": totals["unique_sources"] or 0,
            "unique_client_stacks": totals["unique_clients"] or 0,
            "credential_attempts": totals["credential_attempts"] or 0,
            "automated_share": round((automated["n"] or 0) / total_events, 4)
            if total_events
            else 0.0,
        }

    def verdict_breakdown(self, hours: int = 24) -> list[dict[str, Any]]:
        since = iso(utc_now() - timedelta(hours=hours))
        with self._cursor() as cur:
            rows = cur.execute(
                """
                SELECT verdict, COUNT(*) AS n, AVG(confidence) AS avg_confidence
                FROM events WHERE ts >= ?
                GROUP BY verdict ORDER BY n DESC
                """,
                (since,),
            ).fetchall()
        return [
            {
                "verdict": r["verdict"],
                "count": r["n"],
                "avg_confidence": round(r["avg_confidence"] or 0.0, 3),
            }
            for r in rows
        ]

    def top_paths(self, hours: int = 24, limit: int = 10) -> list[dict[str, Any]]:
        since = iso(utc_now() - timedelta(hours=hours))
        with self._cursor() as cur:
            rows = cur.execute(
                """
                SELECT path, COUNT(*) AS n, COUNT(DISTINCT src_ip_hash) AS sources
                FROM events WHERE ts >= ?
                GROUP BY path ORDER BY n DESC LIMIT ?
                """,
                (since, limit),
            ).fetchall()
        return [{"path": r["path"], "count": r["n"], "sources": r["sources"]} for r in rows]

    def top_tools(self, hours: int = 24, limit: int = 10) -> list[dict[str, Any]]:
        since = iso(utc_now() - timedelta(hours=hours))
        with self._cursor() as cur:
            rows = cur.execute(
                """
                SELECT COALESCE(tool_signature, ua_family) AS client, COUNT(*) AS n
                FROM events WHERE ts >= ?
                GROUP BY client ORDER BY n DESC LIMIT ?
                """,
                (since, limit),
            ).fetchall()
        return [{"client": r["client"] or "unknown", "count": r["n"]} for r in rows]

    def timeline(self, hours: int = 24) -> list[dict[str, Any]]:
        """Automated vs legitimate over time."""
        since = iso(utc_now() - timedelta(hours=hours))

        # coarsest first, then fall through to finer buckets. a fresh sensor has
        # minutes of data inside a 24h window and one bucket isn't a chart
        if hours <= 2:
            candidates = [(16, "")]
        elif hours <= 48:
            candidates = [(13, ":00"), (16, "")]
        else:
            candidates = [(10, ""), (13, ":00"), (16, "")]

        rows: list[sqlite3.Row] = []
        prefix, suffix = candidates[-1]
        for candidate_prefix, candidate_suffix in candidates:
            with self._cursor() as cur:
                rows = cur.execute(
                    f"""
                    SELECT
                        substr(ts, 1, {candidate_prefix}) AS bucket,
                        SUM(CASE WHEN verdict NOT IN ('likely_human','verified_crawler')
                                 THEN 1 ELSE 0 END) AS automated,
                        SUM(CASE WHEN verdict IN ('likely_human','verified_crawler')
                                 THEN 1 ELSE 0 END) AS legitimate
                    FROM events WHERE ts >= ?
                    GROUP BY bucket ORDER BY bucket
                    """,
                    (since,),
                ).fetchall()
            prefix, suffix = candidate_prefix, candidate_suffix
            if len(rows) >= 3:
                break

        out = []
        for r in rows:
            bucket = f"{r['bucket']}{suffix}"
            label = bucket[11:16] if len(bucket) > 10 else bucket[5:10]
            out.append(
                {
                    "bucket": bucket,
                    "label": label,
                    "automated": r["automated"] or 0,
                    "legitimate": r["legitimate"] or 0,
                }
            )
        return out

    def top_sources(self, hours: int = 24, limit: int = 10) -> list[dict[str, Any]]:
        since = iso(utc_now() - timedelta(hours=hours))
        with self._cursor() as cur:
            rows = cur.execute(
                """
                SELECT
                    src_ip_hash,
                    MAX(src_ip)          AS src_ip,
                    COUNT(*)             AS n,
                    COUNT(DISTINCT path) AS paths,
                    MAX(confidence)      AS confidence,
                    (SELECT verdict FROM events e2
                      WHERE e2.src_ip_hash = e1.src_ip_hash AND e2.ts >= ?
                      GROUP BY verdict ORDER BY COUNT(*) DESC LIMIT 1) AS verdict
                FROM events e1 WHERE ts >= ?
                GROUP BY src_ip_hash ORDER BY n DESC LIMIT ?
                """,
                (since, since, limit),
            ).fetchall()
        return [
            {
                "source": r["src_ip"] or r["src_ip_hash"],
                "requests": r["n"],
                "distinct_paths": r["paths"],
                "verdict": r["verdict"],
                "confidence": round(r["confidence"] or 0.0, 2),
            }
            for r in rows
        ]

    def top_tls_stacks(self, hours: int = 24, limit: int = 10) -> list[dict[str, Any]]:
        """Client TLS stacks seen, with how many claim to be a browser.

        The gap between the two columns is the interesting part.
        """
        since = iso(utc_now() - timedelta(hours=hours))
        with self._cursor() as cur:
            rows = cur.execute(
                """
                SELECT
                    COALESCE(tls_family, 'unknown') AS family,
                    COUNT(*)                        AS n,
                    COUNT(DISTINCT ja4)             AS fingerprints,
                    SUM(CASE WHEN ua_raw LIKE 'Mozilla/5.0%' THEN 1 ELSE 0 END) AS claims_browser
                FROM events
                WHERE ts >= ? AND ja4 IS NOT NULL AND ja4 != ''
                GROUP BY family ORDER BY n DESC LIMIT ?
                """,
                (since, limit),
            ).fetchall()
        return [
            {
                "family": r["family"],
                "count": r["n"],
                "fingerprints": r["fingerprints"],
                "claims_browser": r["claims_browser"] or 0,
            }
            for r in rows
        ]

    def recent(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._cursor() as cur:
            rows = cur.execute(
                """
                SELECT ts, src_ip, method, path, query, status, verdict, confidence,
                       ua_raw, tool_signature, signals_json, ja4, tls_family, client_id
                FROM events ORDER BY id DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        out = []
        for r in rows:
            out.append(
                {
                    "ts": r["ts"],
                    "source": r["src_ip"],
                    "method": r["method"],
                    "path": r["path"] + (f"?{r['query']}" if r["query"] else ""),
                    "status": r["status"],
                    "verdict": r["verdict"],
                    "confidence": round(r["confidence"], 2),
                    "client": r["tool_signature"] or (r["ua_raw"] or "")[:60],
                    "ja4": r["ja4"] or "",
                    "tls_family": r["tls_family"] or "",
                    "client_id": r["client_id"] or "",
                    "signals": [s["name"] for s in json.loads(r["signals_json"])],
                }
            )
        return out

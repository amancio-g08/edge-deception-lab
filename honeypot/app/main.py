"""Capture service.

Serves the decoy surface, captures the full request, fingerprints the client,
classifies it and stores the verdict with its signals.

Analysis API lives under /_edl/*. nginx returns 404 for that prefix on the
public listener, so the dashboard never shares a door with the internet.
"""

from __future__ import annotations

import json
import time
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import parse_qs

from fastapi import FastAPI, Request, Response
from fastapi.responses import FileResponse, JSONResponse

from . import decoys, redact
from .classifier import VelocityContext, classify
from .config import settings
from .enrich import forward_confirmed_rdns
from .fingerprint import build_fingerprint
from .storage import EventStore, iso, utc_now

STATIC_DIR = Path(__file__).parent / "static"

USERNAME_FIELDS = ("username", "user", "email", "login", "usr", "log")


def _client_ip(request: Request) -> str:
    """Real client IP.

    Only the edge header is trusted, and only because nginx overwrites it on
    every request. Trusting X-Forwarded-For off the wire would put
    attacker-controlled data straight into the velocity aggregates.
    """
    edge_value = request.headers.get(settings.trusted_edge_header)
    if edge_value:
        return edge_value.split(",")[0].strip()
    return request.client.host if request.client else "0.0.0.0"


def _extract_username(body: str, content_type: str) -> str | None:
    if "x-www-form-urlencoded" in (content_type or "").lower():
        try:
            parsed = parse_qs(body, keep_blank_values=True)
        except ValueError:
            return None
        for field in USERNAME_FIELDS:
            if field in parsed and parsed[field]:
                return parsed[field][0]
        return None

    if "json" in (content_type or "").lower():
        try:
            payload = json.loads(body)
        except (json.JSONDecodeError, TypeError):
            return None
        if isinstance(payload, dict):
            for field in USERNAME_FIELDS:
                value = payload.get(field)
                if isinstance(value, str):
                    return value
    return None


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.store = EventStore(settings.db_path)
    try:
        yield
    finally:
        app.state.store.close()


app = FastAPI(
    title="Edge Deception Lab",
    description="Honeypot sensor with behavioural bot classification.",
    version="1.0.0",
    lifespan=lifespan,
    docs_url=None,       # a decoy that advertises FastAPI isn't imitating anything
    redoc_url=None,
    openapi_url=None,
)


@app.get("/_edl/api/health")
async def health() -> JSONResponse:
    return JSONResponse({"status": "ok", "ts": iso(utc_now())})


@app.get("/_edl/api/summary")
async def api_summary(request: Request, hours: int = 24) -> JSONResponse:
    store: EventStore = request.app.state.store
    return JSONResponse(
        {
            "summary": store.summary(hours),
            "verdicts": store.verdict_breakdown(hours),
            "top_paths": store.top_paths(hours),
            "top_clients": store.top_tools(hours),
            "timeline": store.timeline(hours),
            "top_sources": store.top_sources(hours),
        }
    )


@app.get("/_edl/api/events")
async def api_events(request: Request, limit: int = 50) -> JSONResponse:
    store: EventStore = request.app.state.store
    return JSONResponse({"events": store.recent(min(limit, 500))})


@app.get("/_edl/dashboard")
async def dashboard() -> Response:
    if not settings.dashboard_enabled:
        return JSONResponse({"error": "dashboard disabled"}, status_code=404)
    return FileResponse(STATIC_DIR / "dashboard.html")


@app.api_route(
    "/{full_path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
)
async def capture(request: Request, full_path: str) -> Response:
    started = time.perf_counter()
    store: EventStore = request.app.state.store

    path = "/" + full_path if not full_path.startswith("/") else full_path
    query = request.url.query or ""
    method = request.method

    raw_body = await request.body()
    truncated = raw_body[: settings.max_body_bytes]
    content_type = request.headers.get("content-type", "")
    body_text = truncated.decode("utf-8", errors="replace")

    header_order = [name.decode("latin-1") for name, _ in request.headers.raw]
    headers = {k.lower(): v for k, v in request.headers.items()}

    src_ip = _client_ip(request)
    rdns = (
        forward_confirmed_rdns(src_ip)
        if settings.verify_bot_rdns
        else None
    )

    fingerprint = build_fingerprint(headers, header_order, rdns)
    decoy = decoys.resolve(method, path)

    src_ip_hash = redact.digest(src_ip, settings.credential_salt)
    velocity_raw = store.velocity_for(src_ip_hash, settings.velocity_window_seconds)
    velocity = VelocityContext(**velocity_raw)

    classification = classify(
        method=method,
        path=path,
        query=query,
        fingerprint=fingerprint,
        velocity=velocity,
        status_code=decoy.status,
    )

    username = _extract_username(body_text, content_type)

    store.record(
        {
            "ts": iso(utc_now()),
            "src_ip": src_ip if settings.store_ip_raw else None,
            "src_ip_hash": src_ip_hash,
            "edge_ip": request.client.host if request.client else None,
            "method": method,
            "path": path,
            "query": query,
            "status": decoy.status,
            "decoy": decoy.name,
            "content_type": content_type,
            "body_size": len(raw_body),
            "body_redacted": redact.redact_body(
                body_text, content_type, settings.credential_salt
            ),
            "headers_json": json.dumps(
                redact.redact_headers(headers, settings.credential_salt)
            ),
            "header_order_hash": fingerprint.header_order_hash,
            "ua_raw": fingerprint.ua_raw,
            "ua_family": fingerprint.ua_family,
            "tool_signature": fingerprint.tool_signature,
            "declared_crawler": fingerprint.declared_crawler,
            "crawler_verified": int(fingerprint.crawler_verified),
            "username_hash": redact.digest(username, settings.credential_salt)
            if username
            else None,
            "verdict": classification.verdict.value,
            "confidence": classification.confidence,
            "signals_json": json.dumps([s.to_dict() for s in classification.signals]),
            "fingerprint_json": json.dumps(fingerprint.to_dict()),
        }
    )

    elapsed_ms = (time.perf_counter() - started) * 1000
    response_headers = dict(decoy.headers or {})
    response_headers["Server"] = decoys.SERVER_BANNER
    # no verdict in the response. a client that notices it's being profiled
    # changes behaviour and the sensor stops measuring anything
    response_headers["X-Response-Time"] = f"{elapsed_ms:.1f}ms"

    if method == "HEAD":
        return Response(status_code=decoy.status, headers=response_headers)

    return Response(
        content=decoy.body,
        status_code=decoy.status,
        media_type=decoy.content_type,
        headers=response_headers,
    )

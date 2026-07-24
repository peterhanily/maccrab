#!/usr/bin/env python3
"""
MacCrab Fleet Collector Server

PROTOTYPE — NOT production-grade. One shared bearer key, self-reported
pseudonymous hostIds (no per-device identity), no tenant isolation, no
RBAC. Binds loopback by default; put TLS (reverse proxy) in front for
anything non-local. See fleet/README.md for the security model.
As of MacCrab v1.21.5, endpoints are outbound-only: they push telemetry
here but never consume anything this server returns.

Receives telemetry from MacCrab instances and aggregates IOC sightings
for operator visibility.

Usage:
    pip install fastapi uvicorn
    python server.py [--port 8443] [--db fleet.db]

    Or: uvicorn server:app --host 127.0.0.1 --port 8443
"""

import argparse
import hmac
import json
import os
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from contextlib import contextmanager

from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import Optional

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

API_KEY = os.environ.get("MACCRAB_FLEET_KEY", "")
DB_PATH = os.environ.get("MACCRAB_FLEET_DB", "fleet.db")
ALLOW_ANONYMOUS = os.environ.get("MACCRAB_FLEET_ALLOW_ANONYMOUS", "") == "1"

# Refuse to start without a configured API key. Pre-fix, an empty
# API_KEY caused verify_auth() to fail-open (return without checking
# Authorization), so a deploy that forgot to set MACCRAB_FLEET_KEY
# accepted any caller. Now we require an explicit
# MACCRAB_FLEET_ALLOW_ANONYMOUS=1 opt-in for unauthenticated mode (dev
# loopback only) and fail-loud otherwise.
if not API_KEY and not ALLOW_ANONYMOUS:
    raise SystemExit(
        "fleet/server.py: MACCRAB_FLEET_KEY is unset. "
        "Set the env var to a strong random key, OR set "
        "MACCRAB_FLEET_ALLOW_ANONYMOUS=1 to explicitly accept "
        "unauthenticated traffic (development / single-host loopback only)."
    )

app = FastAPI(title="MacCrab Fleet Collector", version="0.4.0")

# Request size limit middleware.
# audit #18: the old Content-Length-only check was bypassable with chunked
# transfer-encoding (no Content-Length → check skipped → unbounded buffering).
# This ASGI middleware ALSO counts the streamed body bytes and rejects once the
# cumulative size crosses the cap — bounding resident memory to MAX_SIZE
# regardless of how the body is framed.
from starlette.responses import Response

class MaxBodySizeMiddleware:
    MAX_SIZE = 10 * 1024 * 1024  # 10 MB

    def __init__(self, app):
        self.app = app

    async def _too_large(self, scope, receive, send):
        await Response("Request too large", status_code=413)(scope, receive, send)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        # Fast path: an honest oversized Content-Length is rejected before any body.
        headers = dict(scope.get("headers") or [])
        cl = headers.get(b"content-length")
        if cl is not None:
            try:
                if int(cl) > self.MAX_SIZE:
                    await self._too_large(scope, receive, send)
                    return
            except ValueError:
                pass
        # Buffer up to the cap; the moment the STREAMED total exceeds it (chunked /
        # no Content-Length included), reject and stop reading — no unbounded buffer.
        body = bytearray()
        got_disconnect = False
        while True:
            message = await receive()
            mtype = message["type"]
            if mtype == "http.disconnect":
                got_disconnect = True
                break
            if mtype != "http.request":
                continue
            body.extend(message.get("body", b""))
            if len(body) > self.MAX_SIZE:
                await self._too_large(scope, receive, send)
                return
            if not message.get("more_body", False):
                break
        # Replay the (bounded) buffered body to the downstream app.
        replayed = False
        async def replay_receive():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            if got_disconnect:
                return {"type": "http.disconnect"}
            return await receive()
        await self.app(scope, replay_receive, send)

app.add_middleware(MaxBodySizeMiddleware)

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def init_db(path: str):
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS hosts (
            host_id TEXT PRIMARY KEY,
            last_seen REAL NOT NULL,
            version TEXT,
            alert_count INTEGER DEFAULT 0,
            ioc_count INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            rule_title TEXT NOT NULL,
            severity TEXT NOT NULL,
            process_path TEXT,
            mitre_techniques TEXT,
            timestamp REAL NOT NULL,
            received_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(timestamp);
        CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule_id);

        CREATE TABLE IF NOT EXISTS ioc_sightings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id TEXT NOT NULL,
            ioc_type TEXT NOT NULL,
            ioc_value TEXT NOT NULL,
            context TEXT,
            timestamp REAL NOT NULL,
            received_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_iocs_value ON ioc_sightings(ioc_value);
        CREATE INDEX IF NOT EXISTS idx_iocs_time ON ioc_sightings(timestamp);

        CREATE TABLE IF NOT EXISTS behavior_scores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id TEXT NOT NULL,
            process_path TEXT NOT NULL,
            score REAL NOT NULL,
            top_indicators TEXT,
            timestamp REAL NOT NULL
        );
    """)
    conn.close()


@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def verify_auth(authorization: Optional[str]):
    if not API_KEY:
        # Refuse-start guard at module init keeps this branch
        # reachable only when ALLOW_ANONYMOUS=1 is explicit.
        return
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing API key")
    # audit #18: constant-time compare so a network attacker can't recover the
    # key byte-by-byte from response-timing differences.
    if not hmac.compare_digest(authorization[7:], API_KEY):
        raise HTTPException(status_code=403, detail="Invalid API key")


# ---------------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------------

class TelemetryPayload(BaseModel):
    hostId: str
    timestamp: str
    version: str = ""
    alerts: list = []
    iocSightings: list = []
    behaviorScores: list = []


@app.post("/api/telemetry")
async def receive_telemetry(
    payload: TelemetryPayload,
    authorization: Optional[str] = Header(None)
):
    verify_auth(authorization)
    now = time.time()

    with get_db() as db:
        # Upsert host
        db.execute(
            "INSERT INTO hosts (host_id, last_seen, version, alert_count, ioc_count) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(host_id) DO UPDATE SET last_seen=?, version=?, "
            "alert_count=alert_count+?, ioc_count=ioc_count+?",
            (payload.hostId, now, payload.version, len(payload.alerts),
             len(payload.iocSightings), now, payload.version,
             len(payload.alerts), len(payload.iocSightings))
        )

        # Insert alerts
        for alert in payload.alerts:
            db.execute(
                "INSERT INTO alerts (host_id, rule_id, rule_title, severity, "
                "process_path, mitre_techniques, timestamp, received_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (payload.hostId, alert.get("ruleId", ""), alert.get("ruleTitle", ""),
                 alert.get("severity", ""), alert.get("processPath", ""),
                 alert.get("mitreTechniques", ""), now, now)
            )

        # Insert IOC sightings
        for ioc in payload.iocSightings:
            db.execute(
                "INSERT INTO ioc_sightings (host_id, ioc_type, ioc_value, "
                "context, timestamp, received_at) VALUES (?, ?, ?, ?, ?, ?)",
                (payload.hostId, ioc.get("type", ""), ioc.get("value", ""),
                 ioc.get("context", ""), now, now)
            )

        # Insert behavior scores
        for score in payload.behaviorScores:
            db.execute(
                "INSERT INTO behavior_scores (host_id, process_path, score, "
                "top_indicators, timestamp) VALUES (?, ?, ?, ?, ?)",
                (payload.hostId, score.get("processPath", ""),
                 score.get("score", 0), json.dumps(score.get("topIndicators", [])), now)
            )

    return {"status": "ok", "received": {
        "alerts": len(payload.alerts),
        "iocs": len(payload.iocSightings),
        "scores": len(payload.behaviorScores)
    }}


@app.get("/api/iocs")
async def get_ioc_aggregation(authorization: Optional[str] = Header(None)):
    verify_auth(authorization)
    cutoff = time.time() - 86400  # Last 24 hours

    with get_db() as db:
        # Aggregate IOCs by value
        iocs = db.execute("""
            SELECT ioc_type, ioc_value,
                   COUNT(*) as sighting_count,
                   COUNT(DISTINCT host_id) as host_count,
                   MIN(timestamp) as first_seen,
                   MAX(timestamp) as last_seen
            FROM ioc_sightings
            WHERE timestamp > ?
            GROUP BY ioc_type, ioc_value
            ORDER BY host_count DESC, sighting_count DESC
            LIMIT 500
        """, (cutoff,)).fetchall()

        # Hot processes (high behavioral scores across fleet)
        hot_processes = db.execute("""
            SELECT process_path,
                   AVG(score) as avg_score,
                   COUNT(DISTINCT host_id) as host_count
            FROM behavior_scores
            WHERE timestamp > ?
            GROUP BY process_path
            HAVING avg_score > 5.0
            ORDER BY avg_score DESC
            LIMIT 50
        """, (cutoff,)).fetchall()

        # Fleet size
        fleet_size = db.execute(
            "SELECT COUNT(*) FROM hosts WHERE last_seen > ?",
            (cutoff,)
        ).fetchone()[0]

    return {
        "iocs": [dict(r) for r in iocs],
        "hotProcesses": [dict(r) for r in hot_processes],
        "fleetSize": fleet_size,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.get("/api/incidents")
async def get_fleet_incidents(authorization: Optional[str] = Header(None)):
    verify_auth(authorization)
    cutoff = time.time() - 86400

    with get_db() as db:
        alerts = db.execute("""
            SELECT rule_title, severity,
                   COUNT(*) as count,
                   COUNT(DISTINCT host_id) as host_count,
                   GROUP_CONCAT(DISTINCT process_path) as processes
            FROM alerts
            WHERE timestamp > ?
            GROUP BY rule_id
            ORDER BY host_count DESC, count DESC
            LIMIT 50
        """, (cutoff,)).fetchall()

    return {"incidents": [dict(r) for r in alerts]}


@app.get("/api/fleet-campaigns")
async def get_fleet_campaigns(authorization: Optional[str] = Header(None)):
    """Detect cross-endpoint attack campaigns: same rule firing on 3+ hosts within 1 hour."""
    verify_auth(authorization)
    cutoff = time.time() - 3600  # Last hour

    with get_db() as db:
        campaigns = db.execute("""
            SELECT rule_id, rule_title, severity,
                   COUNT(*) as alert_count,
                   COUNT(DISTINCT host_id) as host_count,
                   GROUP_CONCAT(DISTINCT process_path) as processes,
                   GROUP_CONCAT(DISTINCT mitre_techniques) as techniques,
                   MIN(timestamp) as first_seen,
                   MAX(timestamp) as last_seen
            FROM alerts
            WHERE timestamp > ?
            GROUP BY rule_id
            HAVING host_count >= 3
            ORDER BY host_count DESC, alert_count DESC
            LIMIT 20
        """, (cutoff,)).fetchall()

    return {"campaigns": [dict(r) for r in campaigns], "window_seconds": 3600}


@app.get("/api/dashboard")
async def dashboard(authorization: Optional[str] = Header(None)):
    # v1.21.5: was the only unauthenticated data endpoint — fleet size,
    # alert counts, and top rules leaked to any caller.
    verify_auth(authorization)
    cutoff = time.time() - 86400

    with get_db() as db:
        fleet_size = db.execute(
            "SELECT COUNT(*) FROM hosts WHERE last_seen > ?", (cutoff,)
        ).fetchone()[0]
        total_alerts = db.execute(
            "SELECT COUNT(*) FROM alerts WHERE timestamp > ?", (cutoff,)
        ).fetchone()[0]
        total_iocs = db.execute(
            "SELECT COUNT(DISTINCT ioc_value) FROM ioc_sightings WHERE timestamp > ?", (cutoff,)
        ).fetchone()[0]
        top_rules = db.execute("""
            SELECT rule_title, severity, COUNT(*) as count
            FROM alerts WHERE timestamp > ?
            GROUP BY rule_id ORDER BY count DESC LIMIT 10
        """, (cutoff,)).fetchall()

    return {
        "fleetSize": fleet_size,
        "totalAlerts24h": total_alerts,
        "uniqueIOCs24h": total_iocs,
        "topRules": [dict(r) for r in top_rules]
    }


@app.get("/", response_class=HTMLResponse)
async def index():
    return """
    <html><head><title>MacCrab Fleet</title>
    <style>body{font-family:system-ui;max-width:800px;margin:40px auto;padding:0 20px}
    h1{color:#333}table{width:100%;border-collapse:collapse}td,th{padding:8px;border:1px solid #ddd;text-align:left}
    th{background:#f5f5f5}</style></head>
    <body>
    <h1>MacCrab Fleet Collector</h1>
    <p>API Endpoints:</p>
    <ul>
        <li><code>POST /api/telemetry</code> — Push telemetry from MacCrab instances</li>
        <li><code>GET /api/iocs</code> — Aggregated IOC sightings (operator view; not consumed by endpoints)</li>
        <li><code>GET /api/fleet-campaigns</code> — Cross-host campaign summary (operator view; not consumed by endpoints)</li>
        <li><code>GET /api/incidents</code> — Fleet-wide incident summary</li>
        <li><code>GET /api/dashboard</code> — Fleet overview stats</li>
    </ul>
    <p>Configure MacCrab instances with:</p>
    <pre>export MACCRAB_FLEET_URL=https://this-server:8443
export MACCRAB_FLEET_KEY=your-api-key
make dev</pre>
    <p>Terminate TLS in a reverse proxy (nginx/Caddy) in front of this
    server — endpoints refuse plaintext http to non-loopback hosts.</p>
    </body></html>
    """


# ---------------------------------------------------------------------------
# Maintenance
# ---------------------------------------------------------------------------

@app.on_event("startup")
async def startup():
    init_db(DB_PATH)
    print(f"MacCrab Fleet Collector started (db: {DB_PATH})")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    parser = argparse.ArgumentParser(description="MacCrab Fleet Collector")
    parser.add_argument("--port", type=int, default=8443)
    # v1.21.5: default loopback — binding 0.0.0.0 must be an explicit choice.
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--db", default="fleet.db")
    args = parser.parse_args()

    DB_PATH = args.db
    init_db(DB_PATH)
    uvicorn.run(app, host=args.host, port=args.port)

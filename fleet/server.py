#!/usr/bin/env python3
"""
MacCrab Fleet Collector Server

Receives telemetry from MacCrab instances, aggregates IOC sightings,
and provides fleet-wide threat intelligence back to endpoints.

Usage:
    pip install fastapi uvicorn
    python server.py [--port 8443] [--db fleet.db]

    Or: uvicorn server:app --host 0.0.0.0 --port 8443
"""

import argparse
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

app = FastAPI(title="MacCrab Fleet Collector", version="0.4.0")

# Request size limit middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

class MaxBodySizeMiddleware(BaseHTTPMiddleware):
    MAX_SIZE = 10 * 1024 * 1024  # 10 MB

    async def dispatch(self, request, call_next):
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > self.MAX_SIZE:
            return Response("Request too large", status_code=413)
        return await call_next(request)

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
        return  # No auth configured
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing API key")
    if authorization[7:] != API_KEY:
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


@app.get("/api/dashboard")
async def dashboard():
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
        <li><code>GET /api/iocs</code> — Pull aggregated IOC intelligence</li>
        <li><code>GET /api/incidents</code> — Fleet-wide incident summary</li>
        <li><code>GET /api/dashboard</code> — Fleet overview stats</li>
    </ul>
    <p>Configure MacCrab instances with:</p>
    <pre>export MACCRAB_FLEET_URL=http://this-server:8443
export MACCRAB_FLEET_KEY=your-api-key
make dev</pre>
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
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--db", default="fleet.db")
    args = parser.parse_args()

    DB_PATH = args.db
    init_db(DB_PATH)
    uvicorn.run(app, host=args.host, port=args.port)

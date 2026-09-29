"""
backend/database.py - SQLite Persistence Layer for Phantom Recon v2.1
=====================================================================
Uses aiosqlite with WAL mode for fast concurrent async operations.
Persists scan records, live streaming logs, rate limit timestamps, and
expiring share tokens for capstone review.
"""

import os
import json
import secrets
import aiosqlite
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any

from contextlib import asynccontextmanager

DB_PATH = os.getenv("PHANTOM_DB_PATH", os.path.join(os.path.dirname(__file__), "phantom.db"))

@asynccontextmanager
async def get_db():
    """Context manager for SQLite connections with WAL mode and row factory."""
    os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        await db.execute("PRAGMA journal_mode = WAL;")
        await db.execute("PRAGMA foreign_keys = ON;")
        yield db

async def init_db():
    """Initializes tables and indexes."""
    async with get_db() as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                consent_given INTEGER NOT NULL,
                passive_only INTEGER NOT NULL DEFAULT 0,
                demo_mode INTEGER NOT NULL DEFAULT 0,
                modules TEXT NOT NULL,
                risk_score INTEGER DEFAULT 0,
                risk_level TEXT DEFAULT 'UNKNOWN',
                summary TEXT,
                results TEXT,
                error_message TEXT,
                created_at TEXT NOT NULL,
                completed_at TEXT
            )
        """)

        await db.execute("""
            CREATE TABLE IF NOT EXISTS scan_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                level TEXT NOT NULL,
                message TEXT NOT NULL,
                phase TEXT,
                progress INTEGER DEFAULT 0,
                FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
        """)

        await db.execute("""
            CREATE TABLE IF NOT EXISTS shared_links (
                id TEXT PRIMARY KEY,
                token TEXT UNIQUE NOT NULL,
                scan_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                views_count INTEGER DEFAULT 0,
                FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
        """)

        await db.execute("""
            CREATE TABLE IF NOT EXISTS rate_limits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                timestamp REAL NOT NULL
            )
        """)

        # Indexes for fast querying
        await db.execute("CREATE INDEX IF NOT EXISTS idx_scan_logs_scan_id ON scan_logs(scan_id)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_shared_links_token ON shared_links(token)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_rate_limits_ip ON rate_limits(ip, timestamp)")
        await db.commit()

async def create_scan(scan_id: str, target: str, consent_given: bool, passive_only: bool, demo_mode: bool, modules: List[str]) -> Dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    modules_json = json.dumps(modules)
    async with get_db() as db:
        await db.execute("""
            INSERT INTO scans (id, target, status, consent_given, passive_only, demo_mode, modules, created_at)
            VALUES (?, ?, 'queued', ?, ?, ?, ?, ?)
        """, (scan_id, target, 1 if consent_given else 0, 1 if passive_only else 0, 1 if demo_mode else 0, modules_json, now))
        await db.commit()
    return {
        "id": scan_id,
        "target": target,
        "status": "queued",
        "consent_given": consent_given,
        "passive_only": passive_only,
        "demo_mode": demo_mode,
        "modules": modules,
        "created_at": now
    }

async def update_scan_status(scan_id: str, status: str, error_message: Optional[str] = None):
    now = datetime.now(timezone.utc).isoformat()
    completed_at = now if status in ("completed", "failed") else None
    async with get_db() as db:
        if completed_at:
            await db.execute("""
                UPDATE scans
                SET status = ?, error_message = ?, completed_at = ?
                WHERE id = ?
            """, (status, error_message, completed_at, scan_id))
        else:
            await db.execute("""
                UPDATE scans
                SET status = ?, error_message = ?
                WHERE id = ?
            """, (status, error_message, scan_id))
        await db.commit()

async def save_scan_results(scan_id: str, results: Dict[str, Any], risk_score: int, risk_level: str, summary: Dict[str, Any]):
    now = datetime.now(timezone.utc).isoformat()
    async with get_db() as db:
        await db.execute("""
            UPDATE scans
            SET status = 'completed',
                risk_score = ?,
                risk_level = ?,
                summary = ?,
                results = ?,
                completed_at = ?
            WHERE id = ?
        """, (risk_score, risk_level, json.dumps(summary, default=str), json.dumps(results, default=str), now, scan_id))
        await db.commit()

async def add_scan_log(scan_id: str, level: str, message: str, phase: Optional[str] = None, progress: int = 0):
    now = datetime.now(timezone.utc).isoformat()
    async with get_db() as db:
        await db.execute("""
            INSERT INTO scan_logs (scan_id, timestamp, level, message, phase, progress)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (scan_id, now, level, message, phase, progress))
        await db.commit()

async def get_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    async with get_db() as db:
        cursor = await db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = await cursor.fetchone()
        if not row:
            return None
        data = dict(row)
        data["modules"] = json.loads(data["modules"]) if data.get("modules") else []
        data["summary"] = json.loads(data["summary"]) if data.get("summary") else {}
        data["results"] = json.loads(data["results"]) if data.get("results") else {}
        data["consent_given"] = bool(data.get("consent_given"))
        data["passive_only"] = bool(data.get("passive_only"))
        data["demo_mode"] = bool(data.get("demo_mode"))
        return data

async def get_scan_logs(scan_id: str) -> List[Dict[str, Any]]:
    async with get_db() as db:
        cursor = await db.execute("""
            SELECT timestamp, level, message, phase, progress
            FROM scan_logs
            WHERE scan_id = ?
            ORDER BY id ASC
        """, (scan_id,))
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]

async def list_scans(limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
    async with get_db() as db:
        cursor = await db.execute("""
            SELECT id, target, status, consent_given, passive_only, demo_mode, modules,
                   risk_score, risk_level, summary, created_at, completed_at, error_message
            FROM scans
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
        """, (limit, offset))
        rows = await cursor.fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["modules"] = json.loads(d["modules"]) if d.get("modules") else []
            d["summary"] = json.loads(d["summary"]) if d.get("summary") else {}
            d["consent_given"] = bool(d.get("consent_given"))
            d["passive_only"] = bool(d.get("passive_only"))
            d["demo_mode"] = bool(d.get("demo_mode"))
            result.append(d)
        return result

async def delete_scan(scan_id: str) -> bool:
    async with get_db() as db:
        cursor = await db.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        await db.commit()
        return cursor.rowcount > 0

async def create_share_link(scan_id: str, expires_in_hours: int = 24) -> Optional[Dict[str, Any]]:
    """Creates a secure, time-limited share token for capstone review."""
    scan = await get_scan(scan_id)
    if not scan:
        return None
    token = secrets.token_urlsafe(24)
    link_id = secrets.token_hex(8)
    now = datetime.now(timezone.utc)
    expires_at = (now + timedelta(hours=expires_in_hours)).isoformat()
    now_str = now.isoformat()

    async with get_db() as db:
        await db.execute("""
            INSERT INTO shared_links (id, token, scan_id, created_at, expires_at, views_count)
            VALUES (?, ?, ?, ?, ?, 0)
        """, (link_id, token, scan_id, now_str, expires_at))
        await db.commit()

    return {
        "id": link_id,
        "token": token,
        "scan_id": scan_id,
        "created_at": now_str,
        "expires_at": expires_at,
        "expires_in_hours": expires_in_hours,
        "target": scan["target"]
    }

async def get_shared_scan(token: str) -> Optional[Dict[str, Any]]:
    """Fetches a scan by share token if not expired, and increments views_count."""
    now = datetime.now(timezone.utc).isoformat()
    async with get_db() as db:
        cursor = await db.execute("""
            SELECT id, scan_id, expires_at, views_count
            FROM shared_links
            WHERE token = ?
        """, (token,))
        link = await cursor.fetchone()
        if not link:
            return None
        
        link_dict = dict(link)
        if link_dict["expires_at"] < now:
            return {"expired": True, "expires_at": link_dict["expires_at"]}

        # Increment view count
        await db.execute("""
            UPDATE shared_links
            SET views_count = views_count + 1
            WHERE id = ?
        """, (link_dict["id"],))
        await db.commit()

        # Get the actual scan data
        scan = await get_scan(link_dict["scan_id"])
        if not scan:
            return None

        # Return sanitized read-only payload
        return {
            "expired": False,
            "token": token,
            "expires_at": link_dict["expires_at"],
            "views_count": link_dict["views_count"] + 1,
            "scan": {
                "id": scan["id"],
                "target": scan["target"],
                "status": scan["status"],
                "created_at": scan["created_at"],
                "completed_at": scan["completed_at"],
                "risk_score": scan["risk_score"],
                "risk_level": scan["risk_level"],
                "modules": scan["modules"],
                "summary": scan["summary"],
                "results": scan["results"]
            }
        }

async def check_rate_limit(ip: str, max_requests: int = 15, window_seconds: int = 3600) -> bool:
    """Sliding-window rate limiter per client IP. Returns True if allowed, False if exceeded."""
    import time
    now = time.time()
    cutoff = now - window_seconds

    async with get_db() as db:
        # Purge old records
        await db.execute("DELETE FROM rate_limits WHERE timestamp < ?", (cutoff,))
        # Count requests in window
        cursor = await db.execute("SELECT COUNT(*) as cnt FROM rate_limits WHERE ip = ? AND timestamp >= ?", (ip, cutoff))
        row = await cursor.fetchone()
        count = row["cnt"] if row else 0

        if count >= max_requests:
            return False

        # Record this request
        await db.execute("INSERT INTO rate_limits (ip, timestamp) VALUES (?, ?)", (ip, now))
        await db.commit()
        return True

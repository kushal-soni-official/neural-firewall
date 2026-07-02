"""
Neural Firewall — Session Store (SQLite-backed)
Persistent storage for HITL requests and pipeline audit logs.
Uses aiosqlite for async-safe database access with FastAPI.
"""

import os
import json
import asyncio
import aiosqlite
from pathlib import Path
from datetime import datetime, timezone
from dotenv import load_dotenv

_ENV_PATH = Path(__file__).parent.parent / ".env"
load_dotenv(dotenv_path=_ENV_PATH)

# ── Database path ──────────────────────────────────────────────────────────────
DB_PATH = Path(__file__).parent / "firewall.db"


async def init_db() -> None:
    """Create tables if they don't exist. Call once on app startup."""
    async with aiosqlite.connect(DB_PATH) as db:
        # HITL requests table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS hitl_requests (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                threat_score REAL,
                category TEXT,
                original_input_snippet TEXT,
                full_data TEXT,
                decided_at TEXT,
                decision TEXT
            )
        """)

        # Pipeline audit log table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS pipeline_logs (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                threat_score REAL,
                category TEXT,
                final_decision TEXT,
                processing_time_ms INTEGER,
                pipeline_log TEXT,
                had_hitl INTEGER DEFAULT 0
            )
        """)

        await db.commit()
    print(f"[OK] Database initialized at {DB_PATH}")


async def save_pipeline_result(result_dict: dict) -> None:
    """
    Save a completed pipeline result to the audit log.
    Only logs metadata — NOT raw user input (security rule 5 from NEURAL_FIREWALL_PROJECT.md).
    """
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            INSERT OR REPLACE INTO pipeline_logs
            (id, created_at, threat_score, category, final_decision, processing_time_ms, pipeline_log, had_hitl)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result_dict.get("request_id", ""),
                datetime.now(timezone.utc).isoformat(),
                result_dict.get("threat_score", 0.0),
                result_dict.get("category", "unknown"),
                result_dict.get("final_decision", "block"),
                result_dict.get("processing_time_ms", 0),
                json.dumps(result_dict.get("pipeline_log", [])),
                1 if result_dict.get("hitl_triggered") else 0,
            ),
        )
        await db.commit()


async def get_recent_logs(limit: int = 20) -> list[dict]:
    """Return the most recent pipeline audit log entries."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM pipeline_logs ORDER BY created_at DESC LIMIT ?", (limit,)
        ) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]


async def get_stats() -> dict:
    """Return aggregate statistics for the dashboard."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        async with db.execute("SELECT COUNT(*) as total FROM pipeline_logs") as cur:
            total = (await cur.fetchone())["total"]

        async with db.execute(
            "SELECT COUNT(*) as blocked FROM pipeline_logs WHERE final_decision != 'allow'"
        ) as cur:
            blocked = (await cur.fetchone())["blocked"]

        async with db.execute(
            "SELECT COUNT(*) as hitl_count FROM pipeline_logs WHERE had_hitl = 1"
        ) as cur:
            hitl_count = (await cur.fetchone())["hitl_count"]

        async with db.execute(
            "SELECT AVG(threat_score) as avg_score FROM pipeline_logs"
        ) as cur:
            avg_score = (await cur.fetchone())["avg_score"] or 0.0

        return {
            "total_analyzed": total,
            "total_blocked": blocked,
            "total_allowed": total - blocked,
            "hitl_triggered": hitl_count,
            "avg_threat_score": round(float(avg_score), 3),
            "block_rate": round(blocked / total, 3) if total > 0 else 0.0,
        }


# ── Standalone test ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    async def _test():
        print("[INFO] Session store tests...")
        await init_db()

        # Test save
        mock_result = {
            "request_id": "test-session-001",
            "threat_score": 0.92,
            "category": "direct_injection",
            "final_decision": "block",
            "processing_time_ms": 3200,
            "pipeline_log": [{"stage": "intake"}, {"stage": "inspection"}],
            "hitl_triggered": False,
        }
        await save_pipeline_result(mock_result)
        print("[OK] save_pipeline_result works")

        # Test get recent
        logs = await get_recent_logs(limit=5)
        print(f"[OK] get_recent_logs: {len(logs)} entries")

        # Test stats
        stats = await get_stats()
        print(f"[OK] get_stats: {stats}")

        # Cleanup test db
        import os
        if DB_PATH.exists():
            os.remove(DB_PATH)
            print("[OK] Test DB cleaned up")

        print("\n[PASS] Session store verified")

    asyncio.run(_test())

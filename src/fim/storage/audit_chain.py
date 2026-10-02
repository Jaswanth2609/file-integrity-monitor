"""
Cryptographically Hash-Chained Audit Log for FIM v2.0.
Ensures append-only tamper evidence: each log record embeds the SHA-256 hash of the preceding record.
"""

import hashlib
import json
import sqlite3
import time
from typing import Any, Dict, List, Optional, Tuple

class AuditChain:
    """Manages an append-only, tamper-evident hash-chained audit log in SQLite."""

    GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self._init_table()

    def _init_table(self) -> None:
        with self.conn:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL NOT NULL,
                    event TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL
                )
            """)
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts)")

    @staticmethod
    def calculate_entry_hash(ts: float, event: str, details_json: str, prev_hash: str) -> str:
        """Calculates deterministic SHA-256 hash for an audit entry."""
        payload = f"{ts:.6f}|{event}|{details_json}|{prev_hash}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def get_latest_hash(self) -> str:
        cursor = self.conn.cursor()
        cursor.execute("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        return row[0] if row else self.GENESIS_HASH

    def append_event(self, event: str, details: Dict[str, Any]) -> int:
        """Appends a new event to the tamper-evident audit log."""
        ts = time.time()
        details_json = json.dumps(details, sort_keys=True)
        prev_hash = self.get_latest_hash()
        entry_hash = self.calculate_entry_hash(ts, event, details_json, prev_hash)

        with self.conn:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO audit_log (ts, event, details_json, prev_hash, entry_hash)
                VALUES (?, ?, ?, ?, ?)
            """, (ts, event, details_json, prev_hash, entry_hash))
            return cursor.lastrowid

    def verify_integrity(self) -> Tuple[bool, Optional[str], int]:
        """
        Verifies the full cryptographic hash chain of the audit log.
        Returns (is_valid, error_message, total_records_checked).
        """
        cursor = self.conn.cursor()
        cursor.execute("SELECT id, ts, event, details_json, prev_hash, entry_hash FROM audit_log ORDER BY id ASC")
        rows = cursor.fetchall()

        if not rows:
            return True, None, 0

        expected_prev = self.GENESIS_HASH
        for row in rows:
            entry_id, ts, event, details_json, prev_hash, entry_hash = row
            if prev_hash != expected_prev:
                return False, f"Audit chain break at record ID {entry_id}: expected prev_hash {expected_prev}, found {prev_hash}", len(rows)

            recomputed = self.calculate_entry_hash(ts, event, details_json, prev_hash)
            if recomputed != entry_hash:
                return False, f"Audit record tampering detected at ID {entry_id}: payload modified!", len(rows)

            expected_prev = entry_hash

        return True, None, len(rows)

    def get_recent_records(self, limit: int = 50) -> List[Dict[str, Any]]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT id, ts, event, details_json, entry_hash FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))
        results = []
        for r in cursor.fetchall():
            results.append({
                "id": r[0],
                "timestamp": r[1],
                "event": r[2],
                "details": json.loads(r[3]),
                "entry_hash": r[4]
            })
        return results

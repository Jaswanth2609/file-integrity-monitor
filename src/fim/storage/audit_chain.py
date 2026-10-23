"""
Cryptographically Hash-Chained Audit Log for FIM v2.3.
Ensures append-only tamper evidence: each log record embeds the SHA-256 hash of the preceding record.
Stores audit events in a dedicated audit database, continuously updates external chain anchors,
and maintains a flat JSONL audit stream for SIEM ingestion.
"""

import hashlib
import json
import logging
import os
import stat
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

try:
    import fcntl
except ImportError:
    fcntl = None

logger = logging.getLogger("fim.audit")


class AuditChain:
    """Manages an append-only, tamper-evident hash-chained audit log with multi-layer verification."""

    GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

    def __init__(
        self,
        conn_or_path: Optional[Union[sqlite3.Connection, str, Path]] = None,
        anchor_path: Optional[Union[str, Path]] = None,
        jsonl_path: Optional[Union[str, Path]] = None,
        external_anchor_path: Optional[Union[str, Path]] = None,
    ):
        self._owned_conn = False
        self._lock_file = None
        self._lock = threading.Lock()

        if isinstance(conn_or_path, sqlite3.Connection):
            self.conn = conn_or_path
            self.db_path = None
        else:
            self.db_path = Path(conn_or_path or "~/.fim/audit.db").expanduser().resolve()
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self.conn = sqlite3.connect(str(self.db_path), timeout=30.0, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
            self._owned_conn = True
            self._setup_connection()

        self.anchor_path = Path(
            anchor_path
            or (self.db_path.parent if self.db_path else Path("~/.fim").expanduser())
            / "chain_anchor"
        ).resolve()
        self.jsonl_path = Path(
            jsonl_path
            or (self.db_path.parent if self.db_path else Path("~/.fim").expanduser())
            / "audit.jsonl"
        ).resolve()

        ext_env = os.environ.get("FIM_EXTERNAL_ANCHOR_PATH")
        ext_target = external_anchor_path or (ext_env if ext_env else None)
        self.external_anchor_path = Path(ext_target).resolve() if ext_target else None

        self._init_table()
        self._set_secure_permissions()

    def _setup_connection(self) -> None:
        try:
            self.conn.isolation_level = None
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA synchronous=NORMAL")
            self.conn.execute("PRAGMA foreign_keys=ON")
            self.conn.execute("PRAGMA busy_timeout=5000")
        except Exception:
            pass

    def _set_secure_permissions(self) -> None:
        try:
            if os.name != "nt" and self.db_path and self.db_path.exists():
                os.chmod(self.db_path, stat.S_IRUSR | stat.S_IWUSR)
        except Exception:
            pass

    def _init_table(self) -> None:
        with self._lock:
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

    def get_total_count(self) -> int:
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(id) FROM audit_log")
        row = cursor.fetchone()
        return row[0] if row else 0

    def append_event(self, event: str, details: Dict[str, Any]) -> int:
        """
        Appends a new event to the tamper-evident audit log, updates anchor, and appends to JSONL.
        Reads latest hash, computes entry hash, and inserts within a single BEGIN IMMEDIATE transaction
        to eliminate race conditions and fork risks between concurrent writers.
        """
        ts = time.time()
        details_json = json.dumps(details, sort_keys=True)

        with self._lock:
            if self.conn.isolation_level is not None:
                self.conn.isolation_level = None

            cursor = self.conn.cursor()
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                cursor.execute("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1")
                row = cursor.fetchone()
                prev_hash = row[0] if row else self.GENESIS_HASH

                entry_hash = self.calculate_entry_hash(ts, event, details_json, prev_hash)

                cursor.execute(
                    """
                    INSERT INTO audit_log (ts, event, details_json, prev_hash, entry_hash)
                    VALUES (?, ?, ?, ?, ?)
                """,
                    (ts, event, details_json, prev_hash, entry_hash),
                )
                entry_id = cursor.lastrowid

                cursor.execute("SELECT COUNT(id) FROM audit_log")
                count_row = cursor.fetchone()
                total_count = count_row[0] if count_row else 0

                self.conn.execute("COMMIT")
            except Exception:
                try:
                    self.conn.execute("ROLLBACK")
                except Exception:
                    pass
                raise

            # Update chain anchor file (owner read-only) with exact committed count and hash
            self._write_chain_anchor(entry_hash, total_count, ts)

            # Append to flat JSONL audit stream for SIEM forwarding
            self._append_jsonl(entry_id, ts, event, details, entry_hash, prev_hash)

            return entry_id

    def _write_anchor_file(self, target_path: Path, payload_bytes: bytes) -> None:
        try:
            target_path.parent.mkdir(parents=True, exist_ok=True)
            if os.name != "nt" and target_path.exists():
                try:
                    os.chmod(target_path, stat.S_IRUSR | stat.S_IWUSR)
                except Exception:
                    pass
            tmp_path = target_path.with_suffix(".tmp")
            with open(tmp_path, "wb") as f:
                f.write(payload_bytes)
                f.flush()
                os.fsync(f.fileno())
            tmp_path.replace(target_path)
            if os.name != "nt":
                os.chmod(target_path, stat.S_IRUSR)  # chmod 0400 read-only
        except Exception as e:
            logger.debug(f"Could not write chain anchor to {target_path}: {e}")

    def _write_chain_anchor(self, head_hash: str, total_count: int, ts: float) -> None:
        anchor_payload = {"head": head_hash, "count": total_count, "ts": ts}
        payload_bytes = json.dumps(anchor_payload, indent=2).encode("utf-8")
        self._write_anchor_file(self.anchor_path, payload_bytes)
        if self.external_anchor_path:
            self._write_anchor_file(self.external_anchor_path, payload_bytes)

    def export_chain_anchor(self, destination: Union[str, Path]) -> Path:
        """Exports the latest audit chain anchor to external/WORM media destination."""
        dest_path = Path(destination).resolve()
        latest_hash = self.get_latest_hash()
        total_count = self.get_total_count()
        payload = {"head": latest_hash, "count": total_count, "ts": time.time()}
        payload_bytes = json.dumps(payload, indent=2).encode("utf-8")
        self._write_anchor_file(dest_path, payload_bytes)
        return dest_path

    def _append_jsonl(
        self,
        entry_id: int,
        ts: float,
        event: str,
        details: Dict[str, Any],
        entry_hash: str,
        prev_hash: str,
    ) -> None:
        try:
            self.jsonl_path.parent.mkdir(parents=True, exist_ok=True)
            record = {
                "id": entry_id,
                "ts": ts,
                "event": event,
                "details": details,
                "entry_hash": entry_hash,
                "prev_hash": prev_hash,
            }
            with open(self.jsonl_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
            if os.name != "nt":
                os.chmod(self.jsonl_path, stat.S_IRUSR | stat.S_IWUSR)
        except Exception as e:
            logger.debug(f"Could not append to JSONL audit stream: {e}")

    def verify_integrity(
        self, external_anchor_path: Optional[Union[str, Path]] = None
    ) -> Tuple[bool, Optional[str], int]:
        """
        Verifies the full cryptographic hash chain of the audit log and validates against anchors.
        Checks the record at the exact anchored index so forged records appended after anchor fail.
        Returns (is_valid, error_message, total_records_checked).
        """
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT id, ts, event, details_json, prev_hash, entry_hash FROM audit_log ORDER BY id ASC"
        )
        rows = cursor.fetchall()

        if not rows:
            return True, None, 0

        expected_prev = self.GENESIS_HASH
        for row in rows:
            entry_id, ts, event, details_json, prev_hash, entry_hash = row
            if prev_hash != expected_prev:
                return (
                    False,
                    f"Audit chain break at record ID {entry_id}: expected prev_hash {expected_prev}, found {prev_hash}",
                    len(rows),
                )

            recomputed = self.calculate_entry_hash(ts, event, details_json, prev_hash)
            if recomputed != entry_hash:
                return (
                    False,
                    f"Audit record tampering detected at ID {entry_id}: payload modified!",
                    len(rows),
                )

            expected_prev = entry_hash

        # Verify against anchors (both external and local if present)
        anchors_to_check = []
        if external_anchor_path:
            anchors_to_check.append(("External anchor", Path(external_anchor_path).resolve()))
        elif self.external_anchor_path and self.external_anchor_path.exists():
            anchors_to_check.append(("External anchor", self.external_anchor_path))

        if self.anchor_path.exists():
            anchors_to_check.append(("Local anchor", self.anchor_path))

        for label, a_path in anchors_to_check:
            try:
                anchor_data = json.loads(a_path.read_text(encoding="utf-8"))
                anchored_count = anchor_data.get("count", 0)
                anchored_head = anchor_data.get("head", "")

                if anchored_count > 0:
                    if len(rows) < anchored_count:
                        return (
                            False,
                            f"{label} recorded {anchored_count} entries, but audit log has {len(rows)} — possible truncation or record deletion!",
                            len(rows),
                        )

                    anchored_row = rows[anchored_count - 1]
                    anchored_entry_hash = (
                        anchored_row["entry_hash"]
                        if isinstance(anchored_row, sqlite3.Row)
                        else anchored_row[5]
                    )
                    if anchored_head and anchored_entry_hash != anchored_head:
                        return (
                            False,
                            f"AUDIT INTEGRITY VIOLATION: Record at anchored index {anchored_count} ({anchored_entry_hash[:16]}...) does not match {label.lower()} head ({anchored_head[:16]}...)!",
                            len(rows),
                        )
            except Exception as e:
                logger.debug(f"Could not verify against {label} at {a_path}: {e}")

        return True, None, len(rows)

    def get_recent_records(self, limit: int = 50) -> List[Dict[str, Any]]:
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT id, ts, event, details_json, entry_hash FROM audit_log ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        results = []
        for r in cursor.fetchall():
            results.append(
                {
                    "id": r[0],
                    "timestamp": r[1],
                    "event": r[2],
                    "details": json.loads(r[3]),
                    "entry_hash": r[4],
                }
            )
        return results

    def get_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Alias for get_recent_records."""
        return self.get_recent_records(limit=limit)

    def close(self) -> None:
        if self._owned_conn and self.conn:
            try:
                self.conn.close()
            except Exception:
                pass

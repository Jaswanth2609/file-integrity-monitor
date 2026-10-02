"""
Database Manager for File Integrity Monitor.
Manages SQLite database storage for scan history, VirusTotal cache, and local hash database.
"""

import json
import os
import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

class DatabaseManager:
    """Handles SQLite operations for scan history, VT cache, and known hashes."""

    def __init__(self, db_path: str = "~/.fim/fim_database.db"):
        self.db_path = str(Path(db_path).expanduser().resolve())
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=20.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Initializes tables and indexes according to SRS Section 6.1."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # 1. scan_history table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT NOT NULL,
                    file_name TEXT NOT NULL,
                    file_size INTEGER,
                    md5_hash TEXT,
                    sha256_hash TEXT,
                    scan_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    scan_type TEXT,
                    vt_malicious INTEGER DEFAULT 0,
                    vt_suspicious INTEGER DEFAULT 0,
                    vt_undetected INTEGER DEFAULT 0,
                    vt_total INTEGER DEFAULT 0,
                    threat_level TEXT,
                    user_action TEXT DEFAULT 'none'
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_file_path ON scan_history(file_path)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_md5 ON scan_history(md5_hash)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON scan_history(scan_timestamp)")

            # 2. vt_cache table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vt_cache (
                    hash TEXT PRIMARY KEY,
                    malicious INTEGER DEFAULT 0,
                    suspicious INTEGER DEFAULT 0,
                    undetected INTEGER DEFAULT 0,
                    total_engines INTEGER DEFAULT 0,
                    detections TEXT,
                    cached_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_timestamp TIMESTAMP
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_expires ON vt_cache(expires_timestamp)")

            # 3. hash_database table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS hash_database (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hash_value TEXT NOT NULL UNIQUE,
                    hash_type TEXT,
                    source TEXT,
                    description TEXT,
                    added_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_hash ON hash_database(hash_value)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_type ON hash_database(hash_type)")

            conn.commit()

    # -------------------------------------------------------------
    # VirusTotal Cache Operations
    # -------------------------------------------------------------
    def get_cached_vt(self, hash_value: str) -> Optional[Dict[str, Any]]:
        """Retrieves non-expired cached VirusTotal result."""
        clean_hash = hash_value.strip().lower()
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM vt_cache WHERE hash = ? AND (expires_timestamp IS NULL OR expires_timestamp > ?)",
                (clean_hash, now_iso),
            )
            row = cursor.fetchone()
            if row:
                detections = []
                if row["detections"]:
                    try:
                        detections = json.loads(row["detections"])
                    except Exception:
                        detections = []
                return {
                    "hash": row["hash"],
                    "malicious": row["malicious"],
                    "suspicious": row["suspicious"],
                    "undetected": row["undetected"],
                    "total_engines": row["total_engines"],
                    "detections": detections,
                    "cached_timestamp": row["cached_timestamp"],
                    "expires_timestamp": row["expires_timestamp"],
                    "from_cache": True,
                }
        return None

    def save_cached_vt(
        self,
        hash_value: str,
        malicious: int,
        suspicious: int,
        undetected: int,
        total_engines: int,
        detections: List[Dict[str, Any]],
        ttl_hours: int = 24,
    ) -> None:
        """Saves VirusTotal result into cache with TTL."""
        clean_hash = hash_value.strip().lower()
        now = datetime.now(timezone.utc)
        expires = (now + timedelta(hours=ttl_hours)).isoformat()
        detections_json = json.dumps(detections)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO vt_cache (hash, malicious, suspicious, undetected, total_engines, detections, cached_timestamp, expires_timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(hash) DO UPDATE SET
                    malicious=excluded.malicious,
                    suspicious=excluded.suspicious,
                    undetected=excluded.undetected,
                    total_engines=excluded.total_engines,
                    detections=excluded.detections,
                    cached_timestamp=excluded.cached_timestamp,
                    expires_timestamp=excluded.expires_timestamp
                """,
                (clean_hash, malicious, suspicious, undetected, total_engines, detections_json, now.isoformat(), expires),
            )
            conn.commit()

    def cleanup_expired_cache(self) -> int:
        """Removes expired entries from cache."""
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM vt_cache WHERE expires_timestamp <= ?", (now_iso,))
            deleted = cursor.rowcount
            conn.commit()
            return deleted

    # -------------------------------------------------------------
    # Scan History Operations
    # -------------------------------------------------------------
    def add_scan_history(
        self,
        file_path: str,
        file_name: str,
        file_size: int,
        md5_hash: Optional[str],
        sha256_hash: Optional[str],
        scan_type: str = "single",
        vt_malicious: int = 0,
        vt_suspicious: int = 0,
        vt_undetected: int = 0,
        vt_total: int = 0,
        threat_level: str = "SAFE",
        user_action: str = "none",
    ) -> int:
        """Records a scan event in the database history."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO scan_history (
                    file_path, file_name, file_size, md5_hash, sha256_hash,
                    scan_type, vt_malicious, vt_suspicious, vt_undetected,
                    vt_total, threat_level, user_action
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    file_path, file_name, file_size, md5_hash, sha256_hash,
                    scan_type, vt_malicious, vt_suspicious, vt_undetected,
                    vt_total, threat_level, user_action,
                ),
            )
            scan_id = cursor.lastrowid
            conn.commit()
            return scan_id

    def get_recent_scans(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Returns the most recent scan records."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM scan_history ORDER BY id DESC LIMIT ?",
                (limit,),
            )
            return [dict(row) for row in cursor.fetchall()]

    def search_history(self, query: str) -> List[Dict[str, Any]]:
        """Searches scan history by file name, file path, or hash."""
        pattern = f"%{query.strip()}%"
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM scan_history
                WHERE file_name LIKE ? OR file_path LIKE ? OR md5_hash LIKE ? OR sha256_hash LIKE ?
                ORDER BY id DESC LIMIT 100
                """,
                (pattern, pattern, pattern, pattern),
            )
            return [dict(row) for row in cursor.fetchall()]

    def clear_history(self) -> int:
        """Clears all scan history records."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM scan_history")
            count = cursor.rowcount
            conn.commit()
            return count

    def get_history_count(self) -> int:
        """Returns total number of scan history records."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM scan_history")
            return cursor.fetchone()[0]

    # -------------------------------------------------------------
    # Known Hash Database Operations
    # -------------------------------------------------------------
    def add_hash(
        self,
        hash_value: str,
        hash_type: str = "md5",
        source: str = "manual",
        description: str = "Known Hash",
    ) -> bool:
        """Adds a single hash to the database."""
        clean_hash = hash_value.strip().lower()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    """
                    INSERT INTO hash_database (hash_value, hash_type, source, description)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(hash_value) DO UPDATE SET
                        hash_type=excluded.hash_type,
                        source=excluded.source,
                        description=excluded.description
                    """,
                    (clean_hash, hash_type.lower(), source, description),
                )
                conn.commit()
                return True
            except Exception:
                return False

    def check_hash_in_db(self, hash_value: str) -> Optional[Dict[str, Any]]:
        """Checks if hash is present in the known hash database."""
        clean_hash = hash_value.strip().lower()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM hash_database WHERE hash_value = ?",
                (clean_hash,),
            )
            row = cursor.fetchone()
            if row:
                return dict(row)
        return None

    def import_hash_file(self, file_path: str, source: Optional[str] = None) -> Tuple[int, int]:
        """
        Imports hashes from a text file (one hash per line or hash:description).
        Returns (imported_count, skipped_count).
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Hash file not found: {file_path}")

        source_name = source or Path(file_path).name
        imported = 0
        skipped = 0

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for line in lines:
                raw = line.strip()
                if not raw or raw.startswith("#"):
                    continue
                parts = raw.split(None, 1)
                hash_val = parts[0].strip().lower()
                desc = parts[1].strip() if len(parts) > 1 else f"Imported from {source_name}"
                
                # Determine type
                length = len(hash_val)
                if length == 32:
                    htype = "md5"
                elif length == 64:
                    htype = "sha256"
                elif length == 40:
                    htype = "sha1"
                else:
                    skipped += 1
                    continue

                try:
                    cursor.execute(
                        """
                        INSERT INTO hash_database (hash_value, hash_type, source, description)
                        VALUES (?, ?, ?, ?)
                        ON CONFLICT(hash_value) DO NOTHING
                        """,
                        (hash_val, htype, source_name, desc),
                    )
                    if cursor.rowcount > 0:
                        imported += 1
                    else:
                        skipped += 1
                except Exception:
                    skipped += 1
            conn.commit()

        return imported, skipped

    def get_all_hashes(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """Lists known hashes with pagination."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM hash_database ORDER BY id DESC LIMIT ? OFFSET ?",
                (limit, offset),
            )
            return [dict(row) for row in cursor.fetchall()]

    def get_hash_db_count(self) -> int:
        """Returns count of known hashes in database."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM hash_database")
            return cursor.fetchone()[0]

    def clear_hash_db(self) -> int:
        """Clears all records in hash database."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM hash_database")
            count = cursor.rowcount
            conn.commit()
            return count

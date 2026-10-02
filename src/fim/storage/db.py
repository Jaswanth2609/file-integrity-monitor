"""
Database persistence engine for FIM v2.0 using SQLite.
Includes parameterized queries, schema migrations, and indexing.
"""

import contextlib
import json
import os
import stat
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Tuple, Union

from .audit_chain import AuditChain
from ..errors import DatabaseError

SCHEMA_VERSION = 2

class DatabaseManager:
    """Central database management for FIM baselines, findings, runs, and intel cache."""

    def __init__(self, db_path: Optional[Union[str, Path]] = None):
        if db_path:
            self.db_path = Path(db_path).expanduser().resolve()
        else:
            self.db_path = Path("~/.fim/fim_database.db").expanduser().resolve()

        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        self._set_secure_permissions()

    @contextlib.contextmanager
    def get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _set_secure_permissions(self) -> None:
        try:
            if os.name != "nt" and self.db_path.exists():
                os.chmod(self.db_path, stat.S_IRUSR | stat.S_IWUSR)
        except Exception:
            pass

    def _init_db(self) -> None:
        with self.get_connection() as conn:
            # Metadata table for schema versioning
            conn.execute("""
                CREATE TABLE IF NOT EXISTS schema_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            """)

            # Baselines table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS baselines (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    created_at REAL NOT NULL,
                    root_paths TEXT NOT NULL,
                    algo TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    version INTEGER DEFAULT 1
                )
            """)

            # Baseline files table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS baseline_files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    baseline_id INTEGER NOT NULL,
                    path TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    hash TEXT NOT NULL,
                    mode INTEGER DEFAULT 0,
                    uid INTEGER DEFAULT 0,
                    gid INTEGER DEFAULT 0,
                    mtime REAL DEFAULT 0.0,
                    ctime REAL DEFAULT 0.0,
                    inode INTEGER DEFAULT 0,
                    symlink_target TEXT DEFAULT '',
                    FOREIGN KEY (baseline_id) REFERENCES baselines(id) ON DELETE CASCADE
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_bf_base_path ON baseline_files(baseline_id, path)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_bf_hash ON baseline_files(hash)")

            # Scan runs table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    started_at REAL NOT NULL,
                    finished_at REAL DEFAULT 0.0,
                    profile TEXT NOT NULL,
                    status TEXT NOT NULL,
                    files_checked INTEGER DEFAULT 0,
                    changes_found INTEGER DEFAULT 0,
                    exit_code INTEGER DEFAULT 0,
                    host TEXT DEFAULT ''
                )
            """)

            # Findings table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id INTEGER NOT NULL,
                    path TEXT NOT NULL,
                    change_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    old_hash TEXT,
                    new_hash TEXT,
                    attack_id TEXT,
                    accepted_by TEXT,
                    accepted_at REAL,
                    FOREIGN KEY (run_id) REFERENCES scan_runs(id) ON DELETE CASCADE
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id)")

            # Intel cache table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS intel_cache (
                    hash TEXT PRIMARY KEY,
                    provider TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    detections INTEGER DEFAULT 0,
                    total_engines INTEGER DEFAULT 0,
                    fetched_at REAL NOT NULL,
                    ttl_seconds INTEGER DEFAULT 86400,
                    raw_json TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_intel_fetched ON intel_cache(fetched_at)")

            # Alerts log table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    finding_id INTEGER,
                    channel TEXT NOT NULL,
                    sent_at REAL NOT NULL,
                    status TEXT NOT NULL,
                    details TEXT
                )
            """)

            # Legacy known hashes table for backward compatibility (v1)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS known_hashes (
                    hash TEXT PRIMARY KEY,
                    file_name TEXT,
                    threat_type TEXT DEFAULT 'MALICIOUS',
                    source TEXT,
                    added_at REAL NOT NULL
                )
            """)

            # Set schema version
            conn.execute("""
                INSERT OR REPLACE INTO schema_meta (key, value)
                VALUES ('schema_version', ?)
            """, (str(SCHEMA_VERSION),))

    @property
    def audit(self) -> AuditChain:
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        return AuditChain(conn)

    # ------------------ Baseline Storage Operations ------------------

    def save_baseline(
        self,
        name: str,
        root_paths: List[str],
        algo: str,
        signature: str,
        files_data: List[Dict[str, Any]],
        version: int = 1
    ) -> int:
        """Stores a named baseline and all its file metadata transactionally."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM baselines WHERE name = ?", (name,))
            existing = cursor.fetchone()
            if existing:
                cursor.execute("DELETE FROM baseline_files WHERE baseline_id = ?", (existing[0],))
                cursor.execute("DELETE FROM baselines WHERE id = ?", (existing[0],))

            created_at = time.time()
            cursor.execute("""
                INSERT INTO baselines (name, created_at, root_paths, algo, signature, version)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (name, created_at, json.dumps(root_paths), algo, signature, version))
            baseline_id = cursor.lastrowid

            records = [
                (
                    baseline_id,
                    f["path"],
                    f.get("size", 0),
                    f.get("hash", ""),
                    f.get("mode", 0),
                    f.get("uid", 0),
                    f.get("gid", 0),
                    f.get("mtime", 0.0),
                    f.get("ctime", 0.0),
                    f.get("inode", 0),
                    str(f.get("symlink_target") or "")
                )
                for f in files_data
            ]
            cursor.executemany("""
                INSERT INTO baseline_files (
                    baseline_id, path, size, hash, mode, uid, gid, mtime, ctime, inode, symlink_target
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, records)

            chain = AuditChain(conn)
            chain.append_event("BASELINE_CREATED", {
                "name": name,
                "file_count": len(files_data),
                "algo": algo,
                "signature": signature
            })

            return baseline_id

    def get_baseline(self, name: str) -> Optional[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM baselines WHERE name = ?", (name,))
            row = cursor.fetchone()
            if not row:
                return None
            
            b_id = row["id"]
            cursor.execute("SELECT * FROM baseline_files WHERE baseline_id = ?", (b_id,))
            files = [dict(f) for f in cursor.fetchall()]

            return {
                "id": b_id,
                "name": row["name"],
                "created_at": row["created_at"],
                "root_paths": json.loads(row["root_paths"]),
                "algo": row["algo"],
                "signature": row["signature"],
                "version": row["version"],
                "files": files
            }

    def list_baselines(self) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT b.id, b.name, b.created_at, b.root_paths, b.algo, b.version,
                       COUNT(f.id) as file_count
                FROM baselines b
                LEFT JOIN baseline_files f ON b.id = f.baseline_id
                GROUP BY b.id
                ORDER BY b.created_at DESC
            """)
            results = []
            for r in cursor.fetchall():
                results.append({
                    "id": r["id"],
                    "name": r["name"],
                    "created_at": r["created_at"],
                    "root_paths": json.loads(r["root_paths"]),
                    "algo": r["algo"],
                    "version": r["version"],
                    "file_count": r["file_count"]
                })
            return results

    def delete_baseline(self, name: str) -> bool:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM baselines WHERE name = ?", (name,))
            row = cursor.fetchone()
            if not row:
                return False
            b_id = row[0]
            cursor.execute("DELETE FROM baseline_files WHERE baseline_id = ?", (b_id,))
            cursor.execute("DELETE FROM baselines WHERE id = ?", (b_id,))

            chain = AuditChain(conn)
            chain.append_event("BASELINE_DELETED", {"name": name, "id": b_id})
            return True

    # ------------------ Scan Runs and Findings ------------------

    def start_scan_run(self, profile: str, host: str = "") -> int:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO scan_runs (started_at, profile, status, host)
                VALUES (?, ?, 'RUNNING', ?)
            """, (time.time(), profile, host))
            return cursor.lastrowid

    def finish_scan_run(
        self,
        run_id: int,
        files_checked: int,
        changes_found: int,
        exit_code: int,
        findings_data: List[Dict[str, Any]]
    ) -> None:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE scan_runs
                SET finished_at = ?, status = 'COMPLETED', files_checked = ?,
                    changes_found = ?, exit_code = ?
                WHERE id = ?
            """, (time.time(), files_checked, changes_found, exit_code, run_id))

            for f in findings_data:
                cursor.execute("""
                    INSERT INTO findings (
                        run_id, path, change_type, severity, old_hash, new_hash, attack_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    run_id,
                    f["path"],
                    f["change_type"],
                    f["severity"],
                    f.get("old_hash"),
                    f.get("new_hash"),
                    f.get("attack_id")
                ))

            chain = AuditChain(conn)
            chain.append_event("SCAN_COMPLETED", {
                "run_id": run_id,
                "files_checked": files_checked,
                "changes_found": changes_found,
                "exit_code": exit_code
            })

    def get_findings_for_run(self, run_id: int) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM findings WHERE run_id = ?", (run_id,))
            return [dict(r) for r in cursor.fetchall()]

    def accept_finding(self, finding_id: int, user: str = "admin") -> bool:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE findings
                SET accepted_by = ?, accepted_at = ?
                WHERE id = ?
            """, (user, time.time(), finding_id))
            return cursor.rowcount > 0

    # ------------------ Intel Cache Operations ------------------

    def get_cached_intel(self, hash_val: str, max_age_seconds: int = 86400) -> Optional[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM intel_cache WHERE hash = ?", (hash_val.lower(),))
            row = cursor.fetchone()
            if not row:
                return None
            
            if time.time() - row["fetched_at"] > max_age_seconds:
                return None
            
            return {
                "hash": row["hash"],
                "provider": row["provider"],
                "verdict": row["verdict"],
                "detections": row["detections"],
                "total_engines": row["total_engines"],
                "fetched_at": row["fetched_at"],
                "raw_json": json.loads(row["raw_json"]) if row["raw_json"] else {}
            }

    def cache_intel(
        self,
        hash_val: str,
        provider: str,
        verdict: str,
        detections: int,
        total_engines: int,
        raw_json: Optional[Dict[str, Any]] = None,
        ttl_seconds: int = 86400
    ) -> None:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO intel_cache (
                    hash, provider, verdict, detections, total_engines, fetched_at, ttl_seconds, raw_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                hash_val.lower(),
                provider,
                verdict,
                detections,
                total_engines,
                time.time(),
                ttl_seconds,
                json.dumps(raw_json or {})
            ))

    # ------------------ Legacy Known Hashes Support (v1) ------------------

    def import_hash_file(self, file_path: Union[str, Path], source: str = "import") -> Tuple[int, int]:
        p = Path(file_path)
        if not p.exists():
            return 0, 0
        
        lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
        imported = 0
        skipped = 0

        with self.get_connection() as conn:
            cursor = conn.cursor()
            for line in lines:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                h = parts[0].strip().lower()
                fname = parts[1].strip() if len(parts) > 1 else ""
                
                try:
                    cursor.execute("""
                        INSERT INTO known_hashes (hash, file_name, threat_type, source, added_at)
                        VALUES (?, ?, 'MALICIOUS', ?, ?)
                    """, (h, fname, source, time.time()))
                    imported += 1
                except sqlite3.IntegrityError:
                    skipped += 1

        return imported, skipped

    def check_known_hash(self, hash_val: str) -> Optional[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM known_hashes WHERE hash = ?", (hash_val.lower(),))
            row = cursor.fetchone()
            return dict(row) if row else None

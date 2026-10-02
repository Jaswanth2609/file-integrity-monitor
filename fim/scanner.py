"""
File Scanner Engine for File Integrity Monitor.
Orchestrates hash computation, local database lookups, VirusTotal reputation checks, and history recording.
"""

import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import psutil

from fim.config import ConfigManager
from fim.database import DatabaseManager
from fim.hasher import HashEngine
from fim.virustotal import VirusTotalClient, VTResult

@dataclass
class ScanResult:
    file_path: str
    file_name: str
    file_size: int
    md5: Optional[str] = None
    sha256: Optional[str] = None
    known_db_match: Optional[Dict[str, Any]] = None
    vt_result: Optional[VTResult] = None
    threat_level: str = "UNKNOWN"
    recommendation: Optional[str] = None
    error: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if self.vt_result:
            d["vt_result"] = self.vt_result.to_dict()
        return d

@dataclass
class DirectoryScanSummary:
    directory_path: str
    total_files: int = 0
    safe_files: int = 0
    suspicious_files: int = 0
    malicious_files: int = 0
    unknown_files: int = 0
    error_files: int = 0
    duration_seconds: float = 0.0
    results: List[ScanResult] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "directory_path": self.directory_path,
            "total_files": self.total_files,
            "safe_files": self.safe_files,
            "suspicious_files": self.suspicious_files,
            "malicious_files": self.malicious_files,
            "unknown_files": self.unknown_files,
            "error_files": self.error_files,
            "duration_seconds": self.duration_seconds,
            "results": [r.to_dict() for r in self.results],
        }

class FileScanner:
    """Orchestrator for file and directory integrity checks and malware reputation analysis."""

    def __init__(
        self,
        config: Optional[ConfigManager] = None,
        db_manager: Optional[DatabaseManager] = None,
        vt_client: Optional[VirusTotalClient] = None,
        hasher: Optional[HashEngine] = None,
    ):
        self.config = config or ConfigManager()
        self.db = db_manager or DatabaseManager(self.config.database_path)
        self.hasher = hasher or HashEngine(chunk_size=self.config.chunk_size)
        self.vt = vt_client or VirusTotalClient(
            api_key=self.config.vt_api_key,
            db_manager=self.db,
            rate_limit_rpm=self.config.rate_limit_rpm,
            cache_ttl_hours=self.config.cache_ttl_hours,
        )
        self.process = psutil.Process(os.getpid())

    def get_memory_usage_mb(self) -> float:
        """Returns current memory consumption in megabytes."""
        try:
            return self.process.memory_info().rss / (1024 * 1024)
        except Exception:
            return 0.0

    def scan_file(
        self,
        file_path: str,
        check_vt: bool = True,
        check_db: bool = True,
        record_history: bool = True,
        scan_type: str = "single",
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> ScanResult:
        """Performs comprehensive integrity check on a single file."""
        path_obj = Path(file_path).expanduser().resolve()
        file_name = path_obj.name
        file_path_str = str(path_obj)

        if not path_obj.exists():
            return ScanResult(
                file_path=file_path_str,
                file_name=file_name,
                file_size=0,
                threat_level="ERROR",
                error="E001: File not found. Please verify the file path.",
            )

        if not path_obj.is_file():
            return ScanResult(
                file_path=file_path_str,
                file_name=file_name,
                file_size=0,
                threat_level="ERROR",
                error="E001: Path is not a standard file.",
            )

        # 1. Calculate hashes
        if progress_callback:
            progress_callback(f"Calculating hashes for {file_name}...")
        
        hash_data = self.hasher.calculate_hashes(file_path_str)
        if hash_data.get("error"):
            return ScanResult(
                file_path=file_path_str,
                file_name=file_name,
                file_size=hash_data.get("size", 0),
                threat_level="ERROR",
                error=hash_data["error"],
            )

        md5_val = hash_data["md5"]
        sha256_val = hash_data["sha256"]
        file_size = hash_data.get("size", 0)

        # 2. Check local known hash database
        known_match = None
        if check_db and self.db:
            if progress_callback:
                progress_callback("Checking local hash database...")
            known_match = self.db.check_hash_in_db(sha256_val) or self.db.check_hash_in_db(md5_val)

        # 3. Check VirusTotal
        vt_res: Optional[VTResult] = None
        threat_level = "UNKNOWN"
        recommendation = None

        if check_vt:
            if progress_callback:
                progress_callback("Checking VirusTotal database...")
            # Prefer querying by SHA256, fallback to MD5
            vt_res = self.vt.query_hash(sha256_val or md5_val, progress_callback=progress_callback)
            
            if vt_res.status == "SUCCESS":
                threat_level = vt_res.threat_level
                recommendation = vt_res.recommendation
            elif vt_res.status == "NOT_FOUND":
                threat_level = "UNKNOWN"
                recommendation = vt_res.recommendation
            elif vt_res.status == "INVALID_KEY":
                threat_level = "UNKNOWN"
                recommendation = vt_res.recommendation
            else:
                threat_level = "UNKNOWN"
                recommendation = vt_res.error_message
        else:
            threat_level = "SAFE" if not known_match else "MALICIOUS"

        if known_match:
            # If found in known database, prioritize match description
            threat_level = "MALICIOUS" if "malware" in known_match.get("description", "").lower() or "suspicious" in known_match.get("description", "").lower() else threat_level
            recommendation = f"Matched local hash DB: {known_match.get('source')} - {known_match.get('description')}"

        scan_result = ScanResult(
            file_path=file_path_str,
            file_name=file_name,
            file_size=file_size,
            md5=md5_val,
            sha256=sha256_val,
            known_db_match=known_match,
            vt_result=vt_res,
            threat_level=threat_level,
            recommendation=recommendation,
        )

        # 4. Save to scan history
        if record_history and self.db:
            vt_mal = vt_res.malicious if vt_res else 0
            vt_susp = vt_res.suspicious if vt_res else 0
            vt_und = vt_res.undetected if vt_res else 0
            vt_tot = vt_res.total_engines if vt_res else 0
            self.db.add_scan_history(
                file_path=file_path_str,
                file_name=file_name,
                file_size=file_size,
                md5_hash=md5_val,
                sha256_hash=sha256_val,
                scan_type=scan_type,
                vt_malicious=vt_mal,
                vt_suspicious=vt_susp,
                vt_undetected=vt_und,
                vt_total=vt_tot,
                threat_level=threat_level,
                user_action="none",
            )

        return scan_result

    def scan_directory(
        self,
        directory_path: str,
        check_vt: bool = True,
        check_db: bool = True,
        recursive: bool = True,
        progress_callback: Optional[Callable[[int, int, str, ScanResult], None]] = None,
    ) -> DirectoryScanSummary:
        """Performs batch scan of all files in a directory."""
        import time
        start_time = time.time()
        dir_obj = Path(directory_path).expanduser().resolve()
        
        summary = DirectoryScanSummary(directory_path=str(dir_obj))
        if not dir_obj.exists() or not dir_obj.is_dir():
            summary.error_files = 1
            return summary

        # Gather target files
        all_files: List[Path] = []
        if recursive:
            for root, _, files in os.walk(dir_obj):
                for f in sorted(files):
                    all_files.append(Path(root) / f)
        else:
            for p in sorted(dir_obj.iterdir()):
                if p.is_file():
                    all_files.append(p)

        summary.total_files = len(all_files)
        mem_limit_mb = self.config.get("scanner.memory_threshold_mb", 300)

        for idx, file_item in enumerate(all_files, start=1):
            curr_mem = self.get_memory_usage_mb()
            if curr_mem > mem_limit_mb:
                pass  # High memory warning handled if needed

            res = self.scan_file(
                file_path=str(file_item),
                check_vt=check_vt,
                check_db=check_db,
                record_history=True,
                scan_type="directory",
            )
            summary.results.append(res)

            if res.error:
                summary.error_files += 1
            elif res.threat_level == "MALICIOUS":
                summary.malicious_files += 1
            elif res.threat_level == "SUSPICIOUS":
                summary.suspicious_files += 1
            elif res.threat_level == "SAFE":
                summary.safe_files += 1
            else:
                summary.unknown_files += 1

            if progress_callback:
                progress_callback(idx, summary.total_files, str(file_item), res)

        summary.duration_seconds = time.time() - start_time
        return summary

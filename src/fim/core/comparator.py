"""
Change Detection Engine for FIM v2.0.
Compares current filesystem state against trusted baseline snapshots.
Detects ADDED, MODIFIED, DELETED, PERMISSION_CHANGED, OWNER_CHANGED, and RENAMED events.
"""

import os
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .baseline import BaselineManager, BaselineManifest
from .hasher import HashEngine
from .rules import ChangeType, RuleEngine, Severity
from ..config import ConfigManager
from ..storage.db import DatabaseManager

@dataclass
class Finding:
    path: str
    change_type: ChangeType
    severity: Severity
    description: str
    old_hash: Optional[str] = None
    new_hash: Optional[str] = None
    attack_id: Optional[str] = None
    old_mode: Optional[int] = None
    new_mode: Optional[int] = None
    details: Dict[str, Any] = field(default_factory=dict)
    id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "path": self.path,
            "change_type": self.change_type.value,
            "severity": self.severity.value,
            "description": self.description,
            "old_hash": self.old_hash,
            "new_hash": self.new_hash,
            "attack_id": self.attack_id,
            "details": self.details
        }

@dataclass
class VerificationSummary:
    profile: str
    started_at: float
    finished_at: float
    total_baseline_files: int
    current_files_scanned: int
    findings: List[Finding]
    exit_code: int = 0
    run_id: Optional[int] = None

    @property
    def has_changes(self) -> bool:
        return len(self.findings) > 0

    @property
    def added_count(self) -> int:
        return sum(1 for f in self.findings if f.change_type == ChangeType.ADDED)

    @property
    def modified_count(self) -> int:
        return sum(1 for f in self.findings if f.change_type == ChangeType.MODIFIED)

    @property
    def deleted_count(self) -> int:
        return sum(1 for f in self.findings if f.change_type == ChangeType.DELETED)

    @property
    def renamed_count(self) -> int:
        return sum(1 for f in self.findings if f.change_type == ChangeType.RENAMED)

    @property
    def permission_count(self) -> int:
        return sum(1 for f in self.findings if f.change_type in [ChangeType.PERMISSION_CHANGED, ChangeType.OWNER_CHANGED])

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "profile": self.profile,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": self.finished_at - self.started_at,
            "total_baseline_files": self.total_baseline_files,
            "current_files_scanned": self.current_files_scanned,
            "changes_found": len(self.findings),
            "exit_code": self.exit_code,
            "findings": [f.to_dict() for f in self.findings]
        }

class IntegrityComparator:
    """Orchestrates comparison of current live files against signed baseline."""

    def __init__(self, config: Optional[ConfigManager] = None, db: Optional[DatabaseManager] = None):
        self.config = config or ConfigManager()
        self.db = db or DatabaseManager(self.config.db_path)
        self.baseline_mgr = BaselineManager(self.config, self.db)
        self.hasher = HashEngine(
            chunk_size=self.config.chunk_size_bytes,
            default_algo=self.config.get("hashing.default_algorithm", "sha256"),
            max_workers=int(self.config.get("hashing.max_workers", 4))
        )

    def check_baseline(
        self,
        profile_name: str = "default",
        progress_callback: Optional[Any] = None
    ) -> VerificationSummary:
        """
        Executes a full verification check against the named baseline.
        Returns a VerificationSummary with exit code 0 (clean) or 1 (changes found).
        """
        started_at = time.time()
        run_id = self.db.start_scan_run(profile=profile_name)

        # 1. Load and cryptographically verify baseline signature (tamper check)
        baseline = self.baseline_mgr.load_baseline(profile_name, verify=True)
        baseline_files = baseline.files

        # 2. Collect current live files from baseline root paths
        current_files_list = self.baseline_mgr.collect_files(baseline.root_paths)
        current_files_map: Dict[str, Path] = {str(fp): fp for fp in current_files_list}

        findings: List[Finding] = []
        current_hashes: Dict[str, str] = {}
        hash_to_curr_paths: Dict[str, List[str]] = {}

        # 3. Hash current files and inspect for modifications / permission changes
        total_live = len(current_files_list)
        for idx, (path_str, fp) in enumerate(current_files_map.items(), 1):
            if progress_callback:
                progress_callback(idx, total_live, path_str)

            try:
                st = fp.stat()
                # Detect symlink anomalies if symlink following is disabled
                if fp.is_symlink() and not self.config.get("hashing.follow_symlinks", False):
                    # Check symlink target
                    pass

                h_dict = self.hasher.calculate_hashes(fp, algorithms=[baseline.algo])
                curr_hash = h_dict.get(baseline.algo, "")
                current_hashes[path_str] = curr_hash
                hash_to_curr_paths.setdefault(curr_hash, []).append(path_str)

                # Check if present in baseline
                if path_str in baseline_files:
                    b_entry = baseline_files[path_str]
                    
                    # Content check
                    if curr_hash != b_entry.hash:
                        sev, attack_id, desc = RuleEngine.classify_change(
                            path_str, ChangeType.MODIFIED, is_executable=bool(st.st_mode & 0o111)
                        )
                        findings.append(Finding(
                            path=path_str,
                            change_type=ChangeType.MODIFIED,
                            severity=sev,
                            description=desc,
                            old_hash=b_entry.hash,
                            new_hash=curr_hash,
                            attack_id=attack_id,
                            old_mode=b_entry.mode,
                            new_mode=st.st_mode
                        ))
                    
                    # Permission / Mode check
                    elif (st.st_mode & 0o777) != (b_entry.mode & 0o777):
                        mode_diff = f"{oct(b_entry.mode & 0o777)} -> {oct(st.st_mode & 0o777)}"
                        sev, attack_id, desc = RuleEngine.classify_change(
                            path_str, ChangeType.PERMISSION_CHANGED, mode_diff=mode_diff
                        )
                        findings.append(Finding(
                            path=path_str,
                            change_type=ChangeType.PERMISSION_CHANGED,
                            severity=sev,
                            description=desc,
                            old_hash=b_entry.hash,
                            new_hash=curr_hash,
                            attack_id=attack_id,
                            old_mode=b_entry.mode,
                            new_mode=st.st_mode,
                            details={"mode_diff": mode_diff}
                        ))

                    # Owner / Group check
                    elif hasattr(st, "st_uid") and (st.st_uid != b_entry.uid or st.st_gid != b_entry.gid):
                        diff_str = f"uid:{b_entry.uid}->{st.st_uid}, gid:{b_entry.gid}->{st.st_gid}"
                        sev, attack_id, desc = RuleEngine.classify_change(
                            path_str, ChangeType.OWNER_CHANGED, mode_diff=diff_str
                        )
                        findings.append(Finding(
                            path=path_str,
                            change_type=ChangeType.OWNER_CHANGED,
                            severity=sev,
                            description=desc,
                            old_hash=b_entry.hash,
                            new_hash=curr_hash,
                            attack_id=attack_id,
                            details={"owner_diff": diff_str}
                        ))

            except Exception as e:
                findings.append(Finding(
                    path=path_str,
                    change_type=ChangeType.MODIFIED,
                    severity=Severity.HIGH,
                    description=f"Error accessing file during check: {e}"
                ))

        # 4. Check for DELETED or RENAMED files
        deleted_candidates: List[str] = []
        for b_path, b_entry in baseline_files.items():
            if b_path not in current_files_map:
                deleted_candidates.append(b_path)

        # Detect RENAMED/MOVED files: hash matches a new un-baselined file
        unbaselined_paths = [p for p in current_files_map if p not in baseline_files]
        claimed_renames: Set[str] = set()

        for del_path in deleted_candidates:
            b_hash = baseline_files[del_path].hash
            matched_curr_paths = hash_to_curr_paths.get(b_hash, [])
            # If there's an unbaselined current path with identical hash
            renamed_to = next((p for p in matched_curr_paths if p in unbaselined_paths and p not in claimed_renames), None)

            if renamed_to:
                claimed_renames.add(renamed_to)
                sev, attack_id, desc = RuleEngine.classify_change(renamed_to, ChangeType.RENAMED)
                findings.append(Finding(
                    path=renamed_to,
                    change_type=ChangeType.RENAMED,
                    severity=sev,
                    description=f"File renamed from {Path(del_path).name} to {Path(renamed_to).name}",
                    old_hash=b_hash,
                    new_hash=b_hash,
                    attack_id=attack_id,
                    details={"old_path": del_path, "new_path": renamed_to}
                ))
            else:
                sev, attack_id, desc = RuleEngine.classify_change(del_path, ChangeType.DELETED)
                findings.append(Finding(
                    path=del_path,
                    change_type=ChangeType.DELETED,
                    severity=sev,
                    description=desc,
                    old_hash=b_hash,
                    attack_id=attack_id
                ))

        # 5. Check remaining unbaselined files as ADDED
        for add_path in unbaselined_paths:
            if add_path not in claimed_renames:
                h = current_hashes.get(add_path, "")
                sev, attack_id, desc = RuleEngine.classify_change(add_path, ChangeType.ADDED)
                findings.append(Finding(
                    path=add_path,
                    change_type=ChangeType.ADDED,
                    severity=sev,
                    description=desc,
                    new_hash=h,
                    attack_id=attack_id
                ))

        finished_at = time.time()
        exit_code = 1 if len(findings) > 0 else 0

        # Save findings and complete run in DB
        self.db.finish_scan_run(
            run_id=run_id,
            files_checked=total_live,
            changes_found=len(findings),
            exit_code=exit_code,
            findings_data=[f.to_dict() for f in findings]
        )

        return VerificationSummary(
            profile=profile_name,
            started_at=started_at,
            finished_at=finished_at,
            total_baseline_files=len(baseline_files),
            current_files_scanned=total_live,
            findings=findings,
            exit_code=exit_code,
            run_id=run_id
        )

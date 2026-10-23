"""
Change Detection Engine for FIM v2.3.
Compares current filesystem state against trusted baseline snapshots.
Detects ADDED, MODIFIED, DELETED, PERMISSION_CHANGED, OWNER_CHANGED, and RENAMED events.
Integrates YARA scanning on modified/added files and OS package manager verification (dpkg, rpm, pacman).
"""

import hashlib
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from .baseline import BaselineEntry, BaselineManager
from .hasher import HashEngine
from .pkg_manager import PackageManagerVerifier
from .rules import ChangeType, RuleEngine, Severity
from ..config import ConfigManager
from ..intel.yara_scanner import YaraEngine
from ..storage.db import DatabaseManager

logger = logging.getLogger("fim.comparator")


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
            "details": self.details,
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
        return sum(
            1
            for f in self.findings
            if f.change_type in [ChangeType.PERMISSION_CHANGED, ChangeType.OWNER_CHANGED]
        )

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
            "findings": [f.to_dict() for f in self.findings],
        }


class IntegrityComparator:
    """Orchestrates comparison of current live files against signed baseline."""

    def __init__(
        self, config: Optional[ConfigManager] = None, db: Optional[DatabaseManager] = None
    ):
        self.config = config or ConfigManager()
        self.db = db or DatabaseManager(self.config.db_path)
        self.baseline_mgr = BaselineManager(self.config, self.db)
        self.rule_engine = RuleEngine()
        self.pkg_verifier = PackageManagerVerifier()
        self.yara_engine = YaraEngine(self.config.get("yara.rules_dir"))
        self.hasher = HashEngine(
            chunk_size=self.config.chunk_size_bytes,
            default_algo=self.config.get("hashing.default_algorithm", "sha256"),
            max_workers=int(self.config.get("hashing.max_workers", 4)),
        )

    def check_baseline(
        self,
        profile_name: str = "default",
        progress_callback: Optional[Any] = None,
        accept_migration: bool = False,
        public_key_path: Optional[Union[str, Path]] = None,
        enable_yara: bool = True,
        old_key: Optional[str] = None,
    ) -> VerificationSummary:
        """
        Executes a full verification check against the named baseline.
        Returns a VerificationSummary with exit code 0 (clean) or 1 (changes found).
        """
        started_at = time.time()
        run_id = self.db.start_scan_run(profile=profile_name)

        # 1. Load and cryptographically verify baseline signature (tamper check)
        baseline = self.baseline_mgr.load_baseline(
            profile_name,
            verify=True,
            accept_migration=accept_migration,
            public_key_path=public_key_path,
            old_key=old_key,
        )
        baseline_files = baseline.files

        # 2. Collect current live files from baseline root paths
        current_files_list = self.baseline_mgr.collect_files(baseline.root_paths)
        current_files_map: Dict[str, Path] = {str(fp): fp for fp in current_files_list}

        findings: List[Finding] = []
        current_hashes: Dict[str, str] = {}
        hash_to_curr_paths: Dict[str, List[str]] = {}

        # 3. Hash current files and inspect for modifications / permission changes
        total_live = len(current_files_list)
        follow_symlinks = bool(self.config.get("hashing.follow_symlinks", False))
        for idx, (path_str, fp) in enumerate(current_files_map.items(), 1):
            if progress_callback:
                progress_callback(idx, total_live, path_str)

            try:
                is_link = os.path.islink(fp)
                link_target = os.readlink(fp) if is_link else None

                if is_link and not follow_symlinks:
                    st = os.lstat(fp)
                    curr_hash = hashlib.sha256(f"SYMLINK:{link_target}".encode("utf-8")).hexdigest()
                else:
                    st = fp.stat()
                    h_dict = self.hasher.calculate_hashes(fp, algorithms=[baseline.algo])
                    curr_hash = h_dict.get(baseline.algo, "")

                current_hashes[path_str] = curr_hash
                hash_to_curr_paths.setdefault(curr_hash, []).append(path_str)

                # Check if present in baseline
                if path_str in baseline_files:
                    b_entry = baseline_files[path_str]

                    # Symlink type check
                    if is_link != getattr(b_entry, "is_symlink", False):
                        sev = Severity.CRITICAL
                        desc = (
                            "File type changed to symlink (potential symlink swap / TOCTOU exploit)"
                            if is_link
                            else "Symlink replaced with regular file"
                        )
                        findings.append(
                            Finding(
                                path=path_str,
                                change_type=ChangeType.MODIFIED,
                                severity=sev,
                                description=desc,
                                old_hash=b_entry.hash,
                                new_hash=curr_hash,
                                attack_id="T1036",
                                old_mode=b_entry.mode,
                                new_mode=st.st_mode,
                                details={"symlink_swap": True, "target": link_target},
                            )
                        )
                    elif is_link and link_target != getattr(b_entry, "symlink_target", None):
                        sev = Severity.HIGH
                        desc = f"Symlink target redirected: '{getattr(b_entry, 'symlink_target', None)}' -> '{link_target}'"
                        findings.append(
                            Finding(
                                path=path_str,
                                change_type=ChangeType.MODIFIED,
                                severity=sev,
                                description=desc,
                                old_hash=b_entry.hash,
                                new_hash=curr_hash,
                                attack_id="T1036",
                                details={
                                    "old_target": getattr(b_entry, "symlink_target", None),
                                    "new_target": link_target,
                                },
                            )
                        )
                    # Content check
                    elif curr_hash != b_entry.hash:
                        sev, attack_id, desc = self.rule_engine.classify_change(
                            path_str, ChangeType.MODIFIED, is_executable=bool(st.st_mode & 0o111)
                        )

                        # Package manager verification cross-reference
                        is_pkg_managed, pkg_name, pkg_info = self.pkg_verifier.check_file_origin(
                            path_str
                        )
                        details: Dict[str, Any] = {"package_managed": is_pkg_managed}
                        if is_pkg_managed:
                            details["package_name"] = pkg_name
                            desc += f" (OS package: {pkg_name})"

                        # YARA inspection
                        if enable_yara and not is_link:
                            yara_matches = self.yara_engine.scan_file(fp)
                            if yara_matches:
                                top_match = yara_matches[0]
                                sev = (
                                    Severity.CRITICAL
                                    if top_match.severity == "CRITICAL"
                                    else Severity.HIGH
                                )
                                attack_id = top_match.attack_id
                                desc += f" [YARA MATCH: {top_match.rule_name} - {top_match.description}]"
                                details["yara_matches"] = [m.rule_name for m in yara_matches]

                        findings.append(
                            Finding(
                                path=path_str,
                                change_type=ChangeType.MODIFIED,
                                severity=sev,
                                description=desc,
                                old_hash=b_entry.hash,
                                new_hash=curr_hash,
                                attack_id=attack_id,
                                old_mode=b_entry.mode,
                                new_mode=st.st_mode,
                                details=details,
                            )
                        )

                    # Permission / Mode check
                    elif (st.st_mode & 0o777) != (b_entry.mode & 0o777):
                        mode_diff = f"{oct(b_entry.mode & 0o777)} -> {oct(st.st_mode & 0o777)}"
                        sev, attack_id, desc = self.rule_engine.classify_change(
                            path_str, ChangeType.PERMISSION_CHANGED, mode_diff=mode_diff
                        )
                        findings.append(
                            Finding(
                                path=path_str,
                                change_type=ChangeType.PERMISSION_CHANGED,
                                severity=sev,
                                description=desc,
                                old_hash=b_entry.hash,
                                new_hash=curr_hash,
                                attack_id=attack_id,
                                old_mode=b_entry.mode,
                                new_mode=st.st_mode,
                                details={"mode_diff": mode_diff},
                            )
                        )

                    # Owner / Group check
                    elif hasattr(st, "st_uid") and (
                        st.st_uid != b_entry.uid or st.st_gid != b_entry.gid
                    ):
                        diff_str = f"uid:{b_entry.uid}->{st.st_uid}, gid:{b_entry.gid}->{st.st_gid}"
                        sev, attack_id, desc = self.rule_engine.classify_change(
                            path_str, ChangeType.OWNER_CHANGED, mode_diff=diff_str
                        )
                        findings.append(
                            Finding(
                                path=path_str,
                                change_type=ChangeType.OWNER_CHANGED,
                                severity=sev,
                                description=desc,
                                old_hash=b_entry.hash,
                                new_hash=curr_hash,
                                attack_id=attack_id,
                                details={"owner_diff": diff_str},
                            )
                        )

            except Exception as e:
                findings.append(
                    Finding(
                        path=path_str,
                        change_type=ChangeType.MODIFIED,
                        severity=Severity.HIGH,
                        description=f"Error accessing file during check: {e}",
                    )
                )

        # 4. Check for DELETED and RENAMED files
        deleted_candidates: List[Tuple[str, BaselineEntry]] = []
        for b_path, b_entry in baseline_files.items():
            if b_path not in current_files_map:
                deleted_candidates.append((b_path, b_entry))

        for del_path, b_entry in deleted_candidates:
            # Check if this file was renamed (same content hash found in added files)
            matching_curr_paths = hash_to_curr_paths.get(b_entry.hash, [])
            # Only consider paths that are newly added (not in baseline)
            new_paths = [p for p in matching_curr_paths if p not in baseline_files]

            if new_paths:
                new_p = new_paths[0]
                findings.append(
                    Finding(
                        path=new_p,
                        change_type=ChangeType.RENAMED,
                        severity=Severity.MEDIUM,
                        description=f"File renamed/relocated from '{del_path}' to '{new_p}'",
                        old_hash=b_entry.hash,
                        new_hash=b_entry.hash,
                        attack_id="T1036",
                        details={"old_path": del_path, "new_path": new_p},
                    )
                )
            else:
                sev, attack_id, desc = self.rule_engine.classify_change(
                    del_path, ChangeType.DELETED
                )
                findings.append(
                    Finding(
                        path=del_path,
                        change_type=ChangeType.DELETED,
                        severity=sev,
                        description=desc,
                        old_hash=b_entry.hash,
                        attack_id=attack_id,
                    )
                )

        # 5. Check for newly ADDED files (that were not renames)
        renamed_new_paths = {f.path for f in findings if f.change_type == ChangeType.RENAMED}
        for path_str, fp in current_files_map.items():
            if path_str not in baseline_files and path_str not in renamed_new_paths:
                is_link = os.path.islink(fp)
                curr_h = current_hashes.get(path_str, "")
                try:
                    st = os.lstat(fp) if is_link else fp.stat()
                    is_exec = bool(st.st_mode & 0o111)
                    mode_val = st.st_mode
                except Exception:
                    is_exec = False
                    mode_val = 0

                sev, attack_id, desc = self.rule_engine.classify_change(
                    path_str, ChangeType.ADDED, is_executable=is_exec
                )

                details: Dict[str, Any] = {}
                # YARA inspection on new files
                if enable_yara and not is_link:
                    yara_matches = self.yara_engine.scan_file(fp)
                    if yara_matches:
                        top_match = yara_matches[0]
                        sev = (
                            Severity.CRITICAL if top_match.severity == "CRITICAL" else Severity.HIGH
                        )
                        attack_id = top_match.attack_id
                        desc += f" [YARA MATCH: {top_match.rule_name} - {top_match.description}]"
                        details["yara_matches"] = [m.rule_name for m in yara_matches]

                findings.append(
                    Finding(
                        path=path_str,
                        change_type=ChangeType.ADDED,
                        severity=sev,
                        description=desc,
                        new_hash=curr_h,
                        attack_id=attack_id,
                        new_mode=mode_val,
                        details=details,
                    )
                )

        finished_at = time.time()
        exit_code = 1 if len(findings) > 0 else 0

        findings_payload = [f.to_dict() for f in findings]
        self.db.finish_scan_run(
            run_id=run_id,
            files_checked=total_live,
            changes_found=len(findings),
            exit_code=exit_code,
            findings_data=findings_payload,
        )

        return VerificationSummary(
            profile=profile_name,
            started_at=started_at,
            finished_at=finished_at,
            total_baseline_files=len(baseline_files),
            current_files_scanned=total_live,
            findings=findings,
            exit_code=exit_code,
            run_id=run_id,
        )

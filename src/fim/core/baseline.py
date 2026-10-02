"""
Baseline Management Engine for FIM v2.1.
Handles baseline creation, cryptographic HMAC-SHA256 signing, tamper verification,
named profiles, glob filtering, diffing, symlink resolution, key migration, and baseline acceptance.
"""

import fnmatch
import hmac
import hashlib
import json
import logging
import os
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from .hasher import HashEngine
from ..config import ConfigManager
from ..errors import BaselineTamperedError, FileNotFoundError_
from ..storage.db import DatabaseManager

logger = logging.getLogger("fim.baseline")

@dataclass
class BaselineEntry:
    path: str
    size: int
    hash: str
    mode: int = 0
    uid: int = 0
    gid: int = 0
    mtime: float = 0.0
    ctime: float = 0.0
    inode: int = 0
    is_symlink: bool = False
    symlink_target: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "size": self.size,
            "hash": self.hash,
            "mode": self.mode,
            "uid": self.uid,
            "gid": self.gid,
            "mtime": self.mtime,
            "ctime": self.ctime,
            "inode": self.inode,
            "is_symlink": self.is_symlink,
            "symlink_target": self.symlink_target
        }

@dataclass
class BaselineManifest:
    name: str
    created_at: float
    root_paths: List[str]
    algo: str
    signature: str
    files: Dict[str, BaselineEntry] = field(default_factory=dict)
    skipped: List[Dict[str, str]] = field(default_factory=list)
    version: int = 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "created_at": self.created_at,
            "root_paths": self.root_paths,
            "algo": self.algo,
            "signature": self.signature,
            "version": self.version,
            "file_count": len(self.files),
            "skipped_count": len(self.skipped),
            "skipped": self.skipped
        }

class BaselineManager:
    """Manages creation, signing, verification, and inspection of file baselines."""

    def __init__(self, config: Optional[ConfigManager] = None, db: Optional[DatabaseManager] = None):
        self.config = config or ConfigManager()
        self.db = db or DatabaseManager(self.config.db_path)
        self.hasher = HashEngine(
            chunk_size=self.config.chunk_size_bytes,
            default_algo=self.config.get("hashing.default_algorithm", "sha256"),
            max_workers=int(self.config.get("hashing.max_workers", 4))
        )

    def _calculate_hmac_signature(
        self,
        files: List[Dict[str, Any]],
        secret_key: Optional[str] = None,
        legacy_format: bool = False
    ) -> str:
        """
        Calculates HMAC-SHA256 signature across all canonical sorted file records.
        """
        key = (secret_key or self.config.secret_key).encode("utf-8")
        sorted_files = sorted(files, key=lambda x: x["path"])
        payload_parts = []
        for f in sorted_files:
            if legacy_format:
                payload_parts.append(
                    f"{f['path']}:{f['hash']}:{f.get('size', 0)}:{f.get('mode', 0)}:{f.get('mtime', 0.0)}"
                )
            else:
                sym_target = str(f.get("symlink_target") or "")
                if sym_target:
                    payload_parts.append(
                        f"{f['path']}:{f['hash']}:{f.get('size', 0)}:{f.get('mode', 0)}:{f.get('mtime', 0.0)}:{sym_target}"
                    )
                else:
                    payload_parts.append(
                        f"{f['path']}:{f['hash']}:{f.get('size', 0)}:{f.get('mode', 0)}:{f.get('mtime', 0.0)}"
                    )
        
        canonical_str = "\n".join(payload_parts).encode("utf-8")
        return hmac.new(key, canonical_str, hashlib.sha256).hexdigest()

    def _should_exclude(self, path: Path, exclude_patterns: List[str], include_patterns: List[str]) -> bool:
        """Determines if a path matches glob exclusion or inclusion filters."""
        name = path.name
        path_str = str(path)

        for pat in exclude_patterns:
            if fnmatch.fnmatch(name, pat) or fnmatch.fnmatch(path_str, pat):
                return True
            if pat.endswith("/*") and pat[:-2] in path_str:
                return True

        if include_patterns and include_patterns != ["*"]:
            matched = any(fnmatch.fnmatch(name, pat) or fnmatch.fnmatch(path_str, pat) for pat in include_patterns)
            if not matched:
                return True

        return False

    def collect_files(
        self,
        root_paths: List[Union[str, Path]],
        exclude_patterns: Optional[List[str]] = None,
        include_patterns: Optional[List[str]] = None
    ) -> List[Path]:
        """Gathers all files from target directories respecting glob exclusions."""
        excludes = exclude_patterns if exclude_patterns is not None else self.config.get("baseline.exclude_patterns", [])
        includes = include_patterns if include_patterns is not None else self.config.get("baseline.include_patterns", ["*"])

        collected: Set[Path] = set()

        for root in root_paths:
            rp = Path(root).expanduser().resolve()
            if not rp.exists():
                continue
            if rp.is_file() or os.path.islink(rp):
                if not self._should_exclude(rp, excludes, includes):
                    collected.add(rp)
            elif rp.is_dir():
                for root_dir, dirs, files in os.walk(rp, followlinks=bool(self.config.get("hashing.follow_symlinks", False))):
                    current_dir_p = Path(root_dir)
                    dirs[:] = [d for d in dirs if not self._should_exclude(current_dir_p / d, excludes, includes)]
                    for fname in files:
                        fp = current_dir_p / fname
                        if not self._should_exclude(fp, excludes, includes):
                            collected.add(fp)

        return sorted(list(collected))

    def create_baseline(
        self,
        name: str,
        paths: List[Union[str, Path]],
        algo: Optional[str] = None,
        exclude_patterns: Optional[List[str]] = None,
        include_patterns: Optional[List[str]] = None,
        progress_callback: Optional[Any] = None
    ) -> BaselineManifest:
        """
        Generates a new signed baseline for given paths and saves to database.
        Explicitly tracks and logs any skipped or unreadable files.
        """
        selected_algo = (algo or self.config.get("hashing.default_algorithm", "sha256")).lower()
        files = self.collect_files(paths, exclude_patterns, include_patterns)
        follow_symlinks = bool(self.config.get("hashing.follow_symlinks", False))

        file_entries: List[Dict[str, Any]] = []
        skipped_files: List[Dict[str, str]] = []
        total = len(files)

        for idx, fp in enumerate(files, 1):
            try:
                is_link = os.path.islink(fp)
                link_target = os.readlink(fp) if is_link else None

                if is_link and not follow_symlinks:
                    st = os.lstat(fp)
                    f_hash = hashlib.sha256(f"SYMLINK:{link_target}".encode("utf-8")).hexdigest()
                else:
                    st = fp.stat()
                    hash_dict = self.hasher.calculate_hashes(fp, algorithms=[selected_algo])
                    f_hash = hash_dict.get(selected_algo, "")

                entry = {
                    "path": str(fp),
                    "size": st.st_size,
                    "hash": f_hash,
                    "mode": st.st_mode,
                    "uid": getattr(st, "st_uid", 0),
                    "gid": getattr(st, "st_gid", 0),
                    "mtime": st.st_mtime,
                    "ctime": getattr(st, "st_ctime", 0.0),
                    "inode": getattr(st, "st_ino", 0),
                    "is_symlink": is_link,
                    "symlink_target": link_target
                }
                file_entries.append(entry)
                if progress_callback:
                    progress_callback(idx, total, str(fp))
            except Exception as e:
                err_msg = str(e)
                logger.warning(f"Could not baseline file '{fp}': {err_msg}")
                skipped_files.append({"path": str(fp), "error": err_msg})
                if progress_callback:
                    progress_callback(idx, total, f"[SKIPPED] {fp}")

        signature = self._calculate_hmac_signature(file_entries)
        root_strs = [str(Path(p).expanduser().resolve()) for p in paths]

        # Persist in DB
        self.db.save_baseline(
            name=name,
            root_paths=root_strs,
            algo=selected_algo,
            signature=signature,
            files_data=file_entries
        )

        manifest_files = {
            f["path"]: BaselineEntry(
                path=f["path"],
                size=f["size"],
                hash=f["hash"],
                mode=f.get("mode", 0),
                uid=f.get("uid", 0),
                gid=f.get("gid", 0),
                mtime=f.get("mtime", 0.0),
                ctime=f.get("ctime", 0.0),
                inode=f.get("inode", 0),
                is_symlink=f.get("is_symlink", False),
                symlink_target=f.get("symlink_target")
            )
            for f in file_entries
        }

        return BaselineManifest(
            name=name,
            created_at=time.time(),
            root_paths=root_strs,
            algo=selected_algo,
            signature=signature,
            files=manifest_files,
            skipped=skipped_files
        )

    def load_baseline(self, name: str, verify: bool = True) -> BaselineManifest:
        """
        Loads a baseline by name and verifies HMAC signature against tampering.
        Handles key rotation migrations seamlessly.
        """
        raw = self.db.get_baseline(name)
        if not raw:
            raise FileNotFoundError_(f"Baseline profile '{name}' not found in database.")

        files_data = raw["files"]
        recorded_sig = raw["signature"]

        if verify and self.config.get("baseline.sign_baselines", True):
            recomputed = self._calculate_hmac_signature(files_data)
            valid = hmac.compare_digest(recorded_sig, recomputed)

            # Check legacy payload format if direct match fails
            if not valid:
                legacy_sig = self._calculate_hmac_signature(files_data, legacy_format=True)
                if hmac.compare_digest(recorded_sig, legacy_sig):
                    valid = True

            # Check previous static key rotation (migrate to new random master key)
            if not valid:
                old_key_sig = self._calculate_hmac_signature(
                    files_data, secret_key="fim-default-master-key-v2-secure", legacy_format=True
                )
                if hmac.compare_digest(recorded_sig, old_key_sig):
                    valid = True
                    # Re-sign with current secure key
                    new_sig = self._calculate_hmac_signature(files_data)
                    with self.db.get_connection() as conn:
                        conn.execute("UPDATE baselines SET signature = ? WHERE id = ?", (new_sig, raw["id"]))
                    recorded_sig = new_sig

            if not valid:
                raise BaselineTamperedError(
                    f"Baseline '{name}' HMAC signature mismatch! Expected: {recorded_sig[:12]}..., Computed: {recomputed[:12]}..."
                )

        manifest_files = {
            f["path"]: BaselineEntry(
                path=f["path"],
                size=f["size"],
                hash=f["hash"],
                mode=f.get("mode", 0),
                uid=f.get("uid", 0),
                gid=f.get("gid", 0),
                mtime=f.get("mtime", 0.0),
                ctime=f.get("ctime", 0.0),
                inode=f.get("inode", 0),
                is_symlink=bool(f.get("symlink_target")),
                symlink_target=f.get("symlink_target") or None
            )
            for f in files_data
        }

        return BaselineManifest(
            name=raw["name"],
            created_at=raw["created_at"],
            root_paths=raw["root_paths"],
            algo=raw["algo"],
            signature=recorded_sig,
            files=manifest_files,
            version=raw.get("version", 1)
        )

    def diff_baselines(self, name_a: str, name_b: str) -> Dict[str, Any]:
        """Compares two baselines and returns differences."""
        base_a = self.load_baseline(name_a)
        base_b = self.load_baseline(name_b)

        paths_a = set(base_a.files.keys())
        paths_b = set(base_b.files.keys())

        added = list(paths_b - paths_a)
        deleted = list(paths_a - paths_b)
        common = paths_a & paths_b

        modified = []
        for p in common:
            if base_a.files[p].hash != base_b.files[p].hash:
                modified.append({
                    "path": p,
                    "old_hash": base_a.files[p].hash,
                    "new_hash": base_b.files[p].hash
                })

        return {
            "baseline_a": name_a,
            "baseline_b": name_b,
            "added_count": len(added),
            "deleted_count": len(deleted),
            "modified_count": len(modified),
            "added": added,
            "deleted": deleted,
            "modified": modified
        }

"""
Baseline Management Engine for FIM v2.1.
Handles baseline creation, cryptographic HMAC-SHA256 and Ed25519 asymmetric signing,
key fingerprinting, safe migration protocols, glob filtering, .fimignore support, diffing,
symlink resolution, and automated backup hooks.
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
from ..crypto.asymmetric import AsymmetricEngine
from ..crypto.entropy import load_secure_key_file
from ..errors import BaselineTamperedError, FileNotFoundError_
from ..storage.audit_chain import AuditChain
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
    key_fingerprint: str = ""
    version: int = 2
    skipped: List[Dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "created_at": self.created_at,
            "root_paths": self.root_paths,
            "algo": self.algo,
            "signature": self.signature,
            "key_fingerprint": self.key_fingerprint,
            "version": self.version,
            "file_count": len(self.files),
            "skipped": self.skipped,
            "files": {p: entry.to_dict() for p, entry in self.files.items()}
        }

class BaselineManager:
    """Manages creation, loading, signing, verification, and diffing of baseline profiles."""

    def __init__(self, config: Optional[ConfigManager] = None, db: Optional[DatabaseManager] = None):
        self.config = config or ConfigManager()
        self.db = db or DatabaseManager(self.config.db_path)
        self.hasher = HashEngine(
            chunk_size=self.config.chunk_size_bytes,
            default_algo=self.config.get("hashing.default_algorithm", "sha256"),
            max_workers=int(self.config.get("hashing.max_workers", 4))
        )

    @staticmethod
    def calculate_key_fingerprint(key: str) -> str:
        """Returns the first 8 hex characters of sha256(key)."""
        return hashlib.sha256(key.encode("utf-8")).hexdigest()[:8]

    def _get_canonical_bytes(self, files: List[Dict[str, Any]], legacy_format: bool = False) -> bytes:
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
        return "\n".join(payload_parts).encode("utf-8")

    def _calculate_signature(
        self,
        files: List[Dict[str, Any]],
        signing_type: str = "hmac",
        secret_key: Optional[str] = None,
        private_key_path: Optional[Union[str, Path]] = None,
        legacy_format: bool = False
    ) -> str:
        """Calculates signature (Ed25519 asymmetric or HMAC-SHA256) across sorted canonical records."""
        canonical_bytes = self._get_canonical_bytes(files, legacy_format=legacy_format)
        if (signing_type == "ed25519" or private_key_path) and AsymmetricEngine.is_available():
            priv_p = private_key_path or self.config.get("signing.private_key_path") or Path("~/.fim/fim_ed25519").expanduser()
            sig_hex = AsymmetricEngine.sign_payload(canonical_bytes, priv_p)
            return f"ed25519:{sig_hex}"
        else:
            key = (secret_key or self.config.secret_key).encode("utf-8")
            return hmac.new(key, canonical_bytes, hashlib.sha256).hexdigest()

    def _calculate_hmac_signature(
        self,
        files: List[Dict[str, Any]],
        secret_key: Optional[str] = None,
        legacy_format: bool = False
    ) -> str:
        return self._calculate_signature(files, signing_type="hmac", secret_key=secret_key, legacy_format=legacy_format)

    def _load_fimignore(self, root_dir: Path) -> List[str]:
        """Loads glob ignore patterns from .fimignore if present in root_dir."""
        patterns = []
        ignore_path = root_dir / ".fimignore"
        if ignore_path.exists() and ignore_path.is_file():
            try:
                for line in ignore_path.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        patterns.append(line)
            except Exception as e:
                logger.debug(f"Could not read .fimignore at {ignore_path}: {e}")
        return patterns

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
        """Gathers all files from target directories respecting .fimignore and glob exclusions."""
        base_excludes = list(exclude_patterns if exclude_patterns is not None else self.config.get("baseline.exclude_patterns", []))
        includes = include_patterns if include_patterns is not None else self.config.get("baseline.include_patterns", ["*"])

        collected: Set[Path] = set()

        for root in root_paths:
            rp = Path(root).expanduser().resolve()
            if not rp.exists():
                continue

            fimignore_excludes = self._load_fimignore(rp if rp.is_dir() else rp.parent)
            current_excludes = base_excludes + fimignore_excludes

            if rp.is_file() or os.path.islink(rp):
                if not self._should_exclude(rp, current_excludes, includes):
                    collected.add(rp)
            elif rp.is_dir():
                for root_dir, dirs, files in os.walk(rp, followlinks=bool(self.config.get("hashing.follow_symlinks", False))):
                    current_dir_p = Path(root_dir)
                    dir_fimignore = self._load_fimignore(current_dir_p)
                    active_excludes = current_excludes + dir_fimignore

                    dirs[:] = [d for d in dirs if not self._should_exclude(current_dir_p / d, active_excludes, includes)]
                    for fname in files:
                        fp = current_dir_p / fname
                        if not self._should_exclude(fp, active_excludes, includes):
                            collected.add(fp)

        return sorted(list(collected))

    def _export_backup_manifest(self, manifest: BaselineManifest) -> None:
        """Exports a signed JSON copy of the baseline manifest to backup.destination if enabled."""
        if not self.config.get("backup.enabled", False):
            return
        dest_dir = self.config.get("backup.destination")
        if not dest_dir:
            return
        try:
            dest_p = Path(dest_dir).expanduser().resolve()
            dest_p.mkdir(parents=True, exist_ok=True)
            backup_file = dest_p / f"baseline_{manifest.name}_{int(manifest.created_at)}.json"
            backup_file.write_text(json.dumps(manifest.to_dict(), indent=2), encoding="utf-8")
            if os.name != "nt":
                os.chmod(backup_file, stat.S_IRUSR | stat.S_IWUSR)
            logger.info(f"Exported signed baseline backup to {backup_file}")
        except Exception as e:
            logger.warning(f"Failed to export baseline backup to {dest_dir}: {e}")

    def create_baseline(
        self,
        name: str,
        paths: List[Union[str, Path]],
        algo: Optional[str] = None,
        exclude_patterns: Optional[List[str]] = None,
        include_patterns: Optional[List[str]] = None,
        progress_callback: Optional[Any] = None,
        signing_type: str = "hmac",
        private_key_path: Optional[Union[str, Path]] = None
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

        signature = self._calculate_signature(
            file_entries,
            signing_type=signing_type,
            private_key_path=private_key_path
        )
        root_strs = [str(Path(p).expanduser().resolve()) for p in paths]
        key_fp = self.calculate_key_fingerprint(self.config.secret_key) if signing_type == "hmac" else "ed25519"

        # Persist in DB
        self.db.save_baseline(
            name=name,
            root_paths=root_strs,
            algo=selected_algo,
            signature=signature,
            files_data=file_entries,
            key_fingerprint=key_fp
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

        manifest = BaselineManifest(
            name=name,
            created_at=time.time(),
            root_paths=root_strs,
            algo=selected_algo,
            signature=signature,
            files=manifest_files,
            key_fingerprint=key_fp,
            skipped=skipped_files
        )

        # Trigger backup hook if configured
        self._export_backup_manifest(manifest)

        return manifest

    def load_baseline(
        self,
        name: str,
        verify: bool = True,
        accept_migration: bool = False,
        public_key_path: Optional[Union[str, Path]] = None,
        old_key: Optional[str] = None
    ) -> BaselineManifest:
        """
        Loads a baseline by name and verifies signature (HMAC or Ed25519) against tampering.
        Requires explicit operator old key and consent on legacy key rotation.
        """
        raw = self.db.get_baseline(name)
        if not raw:
            raise FileNotFoundError_(f"Baseline profile '{name}' not found in database.")

        files_data = raw["files"]
        recorded_sig = raw["signature"]

        if verify and self.config.get("baseline.sign_baselines", True):
            if recorded_sig.startswith("ed25519:"):
                # Asymmetric Ed25519 verification
                sig_hex = recorded_sig.split(":", 1)[1]
                pub_p = public_key_path or self.config.get("signing.public_key_path") or Path("~/.fim/fim_ed25519.pub").expanduser()
                canonical_bytes = self._get_canonical_bytes(files_data)
                valid = AsymmetricEngine.verify_payload(canonical_bytes, sig_hex, pub_p)
                if not valid:
                    raise BaselineTamperedError(
                        f"Baseline '{name}' Ed25519 asymmetric signature verification failed! "
                        f"Possible unauthorized database tampering or incorrect public key."
                    )
            else:
                # Symmetric HMAC verification
                recomputed = self._calculate_hmac_signature(files_data)
                valid = hmac.compare_digest(recorded_sig, recomputed)

                # Check legacy payload format if direct match fails
                if not valid:
                    legacy_sig = self._calculate_hmac_signature(files_data, legacy_format=True)
                    if hmac.compare_digest(recorded_sig, legacy_sig):
                        valid = True

                # If direct verification failed, test user-supplied old_key for rotation/migration
                if not valid and old_key:
                    old_key_sig = self._calculate_hmac_signature(files_data, secret_key=old_key)
                    old_key_sig_leg = self._calculate_hmac_signature(files_data, secret_key=old_key, legacy_format=True)
                    if hmac.compare_digest(recorded_sig, old_key_sig) or hmac.compare_digest(recorded_sig, old_key_sig_leg):
                        if accept_migration:
                            new_sig = self._calculate_hmac_signature(files_data)
                            new_fp = self.calculate_key_fingerprint(self.config.secret_key)
                            with self.db.get_connection() as conn:
                                conn.execute("UPDATE baselines SET signature = ?, key_fingerprint = ? WHERE id = ?", (new_sig, new_fp, raw["id"]))
                            self.db.audit.append_event("BASELINE_MIGRATED", {
                                "name": name,
                                "old_sig": recorded_sig,
                                "new_sig": new_sig,
                                "method": "explicit_key_migration"
                            })
                            self.db.remove_rotated_key(old_key)
                            recorded_sig = new_sig
                            valid = True
                        else:
                            raise BaselineTamperedError(
                                f"Baseline '{name}' was signed with a previous master key. "
                                f"To migrate and re-sign with current key, run: "
                                f"'fim baseline migrate {name} --old-key <key>' or 'fim check --profile {name} --accept-migration --old-key <key>'"
                            )

                if not valid:
                    rec_fp = raw.get("key_fingerprint", "")
                    curr_fp = self.calculate_key_fingerprint(self.config.secret_key)
                    if rec_fp and rec_fp != curr_fp:
                        raise BaselineTamperedError(
                            f"Baseline '{name}' key fingerprint mismatch (baseline: {rec_fp}, current key: {curr_fp}). "
                            f"If your master key was rotated, run 'fim baseline migrate {name} --old-key <previous_key>'."
                        )
                    raise BaselineTamperedError(
                        f"Baseline '{name}' HMAC signature mismatch! Expected: {recorded_sig[:12]}..., Computed: {recomputed[:12]}... "
                        f"If the master key was rotated, run 'fim baseline migrate {name} --old-key <previous_key>'."
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
            key_fingerprint=raw.get("key_fingerprint", ""),
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

    def migrate_baseline(self, name: str, old_key: Optional[str] = None) -> bool:
        """
        Explicitly migrates and re-signs a baseline using the operator-supplied old key
        and the active secure master key.
        """
        raw = self.db.get_baseline(name)
        if not raw:
            raise FileNotFoundError_(f"Baseline profile '{name}' not found in database.")

        files_data = raw["files"]
        recorded_sig = raw["signature"]

        # Check if already signed with current key
        current_sig = self._calculate_hmac_signature(files_data)
        if hmac.compare_digest(recorded_sig, current_sig):
            logger.info(f"Baseline '{name}' is already signed with active master key.")
            return True

        if not old_key:
            raise ValueError(f"Migrating baseline '{name}' requires supplying previous key via --old-key.")

        # Verify old key matches recorded signature
        old_sig = self._calculate_hmac_signature(files_data, secret_key=old_key)
        old_sig_leg = self._calculate_hmac_signature(files_data, secret_key=old_key, legacy_format=True)
        if not hmac.compare_digest(recorded_sig, old_sig) and not hmac.compare_digest(recorded_sig, old_sig_leg):
            raise BaselineTamperedError(
                f"Cannot migrate baseline '{name}': supplied old key does not match recorded signature! Possible unauthorized tampering."
            )

        new_fp = self.calculate_key_fingerprint(self.config.secret_key)
        with self.db.get_connection() as conn:
            conn.execute("UPDATE baselines SET signature = ?, key_fingerprint = ? WHERE id = ?", (current_sig, new_fp, raw["id"]))

        self.db.audit.append_event("BASELINE_MIGRATED", {
            "name": name,
            "old_sig": recorded_sig,
            "new_sig": current_sig,
            "fingerprint": new_fp,
            "action": "explicit_migrate"
        })
        self.db.remove_rotated_key(old_key)
        return True

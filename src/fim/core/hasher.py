"""
High-Performance Cryptographic Hashing Engine for FIM v2.0.
Supports SHA-256 (default), SHA-512, BLAKE2b, legacy algorithms (MD5, SHA-1),
chunked streaming, parallel processing, and TOCTOU-safe file descriptor hashing.
"""

import hashlib
import os
import sys
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Callable

from ..errors import FileNotFoundError_, PermissionDeniedError, InvalidHashFormatError

SUPPORTED_ALGORITHMS = ["sha256", "sha512", "blake2b", "md5", "sha1"]
LEGACY_ALGORITHMS = ["md5", "sha1"]

@dataclass
class HashResult:
    path: str
    sha256: str
    md5: Optional[str] = None
    sha1: Optional[str] = None
    sha512: Optional[str] = None
    blake2b: Optional[str] = None
    size: int = 0
    mtime: float = 0.0
    error: Optional[str] = None

    def get_primary(self, algo: str = "sha256") -> str:
        val = getattr(self, algo.lower(), None)
        return val or self.sha256

    def to_dict(self) -> Dict[str, Union[str, int, float, None]]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "md5": self.md5,
            "sha1": self.sha1,
            "sha512": self.sha512,
            "blake2b": self.blake2b,
            "size": self.size,
            "mtime": self.mtime,
            "error": self.error
        }

class HashEngine:
    """Multithreaded, chunked cryptographic hash engine."""

    def __init__(self, chunk_size: int = 65536, default_algo: str = "sha256", max_workers: int = 4):
        self.chunk_size = max(chunk_size, 4096)
        self.default_algo = default_algo.lower()
        self.max_workers = max(max_workers, 1)

    @staticmethod
    def validate_hash(hash_val: str) -> Tuple[bool, Optional[str]]:
        """Validates hash length and hexadecimal characters."""
        if not hash_val or not isinstance(hash_val, str):
            return False, None
        
        cleaned = hash_val.strip().lower()
        if not all(c in "0123456789abcdef" for c in cleaned):
            return False, None

        length = len(cleaned)
        if length == 32:
            return True, "md5"
        elif length == 40:
            return True, "sha1"
        elif length == 64:
            return True, "sha256"
        elif length == 128:
            return True, "sha512"
        return False, None

    def calculate_hashes(
        self,
        file_path: Union[str, Path],
        algorithms: Optional[List[str]] = None,
        toctou_check: bool = True
    ) -> Dict[str, str]:
        """Calculates cryptographic hashes of a single file in memory-efficient chunks."""
        path = Path(file_path).resolve()

        if not path.exists():
            raise FileNotFoundError_(f"File not found: {path}")
        if not path.is_file():
            raise FileNotFoundError_(f"Path is not a regular file: {path}")

        algos = [a.lower() for a in (algorithms or [self.default_algo, "md5"])]
        
        # Check legacy warning
        for a in algos:
            if a in LEGACY_ALGORITHMS:
                warnings.warn(
                    f"Algorithm '{a}' is cryptographically weak / legacy. Use SHA-256 or SHA-512 instead.",
                    UserWarning,
                    stacklevel=2
                )

        hashers = {}
        for a in algos:
            if a == "sha256":
                hashers["sha256"] = hashlib.sha256()
            elif a == "sha512":
                hashers["sha512"] = hashlib.sha512()
            elif a == "blake2b":
                hashers["blake2b"] = hashlib.blake2b()
            elif a == "md5":
                hashers["md5"] = hashlib.md5()
            elif a == "sha1":
                hashers["sha1"] = hashlib.sha1()

        try:
            # TOCTOU mitigation: open file descriptor and stat before and after
            stat_before = path.stat()
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(self.chunk_size)
                    if not chunk:
                        break
                    for h in hashers.values():
                        h.update(chunk)

            if toctou_check:
                stat_after = path.stat()
                if stat_before.st_mtime != stat_after.st_mtime or stat_before.st_size != stat_after.st_size:
                    # File was modified during reading; recalculate once
                    return self.calculate_hashes(path, algorithms, toctou_check=False)

        except PermissionError as e:
            raise PermissionDeniedError(f"Access denied to file: {path} ({e})")
        except OSError as e:
            raise FileNotFoundError_(f"OS error reading file {path}: {e}")

        return {name: h.hexdigest() for name, h in hashers.items()}

    def hash_single_file(self, file_path: Union[str, Path], algorithms: Optional[List[str]] = None) -> HashResult:
        """Returns a structured HashResult for a single file, catching errors safely."""
        p = Path(file_path)
        try:
            st = p.stat()
            hashes = self.calculate_hashes(p, algorithms=algorithms or ["sha256", "md5", "sha512", "blake2b"])
            return HashResult(
                path=str(p.resolve()),
                sha256=hashes.get("sha256", ""),
                md5=hashes.get("md5"),
                sha1=hashes.get("sha1"),
                sha512=hashes.get("sha512"),
                blake2b=hashes.get("blake2b"),
                size=st.st_size,
                mtime=st.st_mtime
            )
        except Exception as e:
            return HashResult(
                path=str(p),
                sha256="",
                error=str(e)
            )

    def hash_parallel(
        self,
        file_paths: List[Union[str, Path]],
        algorithms: Optional[List[str]] = None,
        progress_cb: Optional[Callable[[int, int, HashResult], None]] = None
    ) -> List[HashResult]:
        """Hashes a list of files in parallel using a ThreadPoolExecutor."""
        results: List[HashResult] = []
        total = len(file_paths)
        if total == 0:
            return results

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_path = {
                executor.submit(self.hash_single_file, path, algorithms): path
                for path in file_paths
            }
            count = 0
            for future in as_completed(future_to_path):
                res = future.result()
                results.append(res)
                count += 1
                if progress_cb:
                    progress_cb(count, total, res)

        return results

    @staticmethod
    def simple_fuzzy_similarity(h1: str, h2: str) -> float:
        """Heuristic similarity comparison between two hashes."""
        if h1 == h2:
            return 1.0
        if not h1 or not h2 or len(h1) != len(h2):
            return 0.0
        matches = sum(1 for a, b in zip(h1, h2) if a == b)
        return matches / len(h1)

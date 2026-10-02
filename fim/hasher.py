"""
Cryptographic Hashing Engine for File Integrity Monitor.
Computes MD5 and SHA256 hashes concurrently with chunked file reading.
"""

import hashlib
import os
import re
from typing import Callable, Dict, Optional, Tuple

class HashEngine:
    """Calculates file hashes efficiently with chunked reading and progress feedback."""

    def __init__(self, chunk_size: int = 65536):
        self.chunk_size = chunk_size

    def calculate_hashes(
        self,
        file_path: str,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> Dict[str, Optional[str]]:
        """
        Calculates MD5 and SHA256 hashes in a single pass.
        Returns dictionary with keys: md5, sha256, size, error.
        """
        result: Dict[str, Optional[str]] = {
            "md5": None,
            "sha256": None,
            "size": 0,
            "error": None,
        }

        if not os.path.exists(file_path):
            result["error"] = f"E001: File not found: '{file_path}'"
            return result

        if not os.path.isfile(file_path):
            result["error"] = f"E001: Specified path is not a file: '{file_path}'"
            return result

        try:
            total_size = os.path.getsize(file_path)
            result["size"] = total_size
            
            md5_hasher = hashlib.md5()
            sha256_hasher = hashlib.sha256()
            
            bytes_read = 0
            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(self.chunk_size)
                    if not chunk:
                        break
                    md5_hasher.update(chunk)
                    sha256_hasher.update(chunk)
                    bytes_read += len(chunk)
                    
                    if progress_callback and total_size > 0:
                        progress_callback(bytes_read, total_size)

            result["md5"] = md5_hasher.hexdigest().lower()
            result["sha256"] = sha256_hasher.hexdigest().lower()
            return result

        except PermissionError:
            result["error"] = f"E002: Permission denied when accessing '{file_path}'. Try running with elevated permissions."
            return result
        except OSError as e:
            result["error"] = f"E008: I/O or File locked error: {e}"
            return result
        except Exception as e:
            result["error"] = f"E008: Error hashing file '{file_path}': {e}"
            return result

    @staticmethod
    def validate_hash(hash_value: str) -> Tuple[bool, str]:
        """
        Validates hash format.
        Returns (is_valid, hash_type) where hash_type is 'md5', 'sha256', 'sha1' or 'unknown'.
        """
        if not hash_value or not isinstance(hash_value, str):
            return False, "unknown"
            
        clean_hash = hash_value.strip().lower()
        if not re.fullmatch(r"^[0-9a-fA-F]+$", clean_hash):
            return False, "unknown"

        length = len(clean_hash)
        if length == 32:
            return True, "md5"
        elif length == 64:
            return True, "sha256"
        elif length == 40:
            return True, "sha1"
        else:
            return False, "unknown"

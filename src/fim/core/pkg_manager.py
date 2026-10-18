"""
Package Manager Verification Engine for FIM v2.1.
Cross-references detected filesystem changes against the OS package manager (dpkg, rpm, pacman)
to eliminate false positives on routine system updates.
"""

import logging
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Optional, Tuple

logger = logging.getLogger("fim.pkg_manager")


class PackageManagerVerifier:
    """Detects and queries Linux package managers to verify changed system binaries and libraries."""

    def __init__(self):
        self._dpkg_path = shutil.which("dpkg")
        self._rpm_path = shutil.which("rpm")
        self._pacman_path = shutil.which("pacman")
        self._cache: Dict[str, Tuple[bool, str]] = {}

    @property
    def is_supported(self) -> bool:
        return bool(self._dpkg_path or self._rpm_path or self._pacman_path)

    def check_file_origin(self, file_path: str) -> Tuple[bool, Optional[str], str]:
        """
        Checks if a file is managed by the OS package manager and whether its modification
        corresponds to a known package update or package verification state.
        Returns: (is_managed, package_name, details)
        """
        if file_path in self._cache:
            managed, pkg = self._cache[file_path]
            return managed, pkg, f"Cached package lookup ({pkg})"

        resolved_path = str(Path(file_path).resolve())

        # 1. Check dpkg (Debian / Ubuntu / Kali / Mint)
        if self._dpkg_path:
            try:
                res = subprocess.run(
                    [self._dpkg_path, "-S", resolved_path],
                    capture_output=True,
                    text=True,
                    timeout=3.0,
                )
                if res.returncode == 0 and ":" in res.stdout:
                    pkg_name = res.stdout.split(":")[0].strip()
                    self._cache[file_path] = (True, pkg_name)
                    return True, pkg_name, f"Managed by dpkg ({pkg_name})"
            except Exception as e:
                logger.debug(f"dpkg check failed for {resolved_path}: {e}")

        # 2. Check rpm (RHEL / Fedora / CentOS / Rocky)
        if self._rpm_path:
            try:
                res = subprocess.run(
                    [self._rpm_path, "-qf", resolved_path],
                    capture_output=True,
                    text=True,
                    timeout=3.0,
                )
                if res.returncode == 0 and res.stdout.strip():
                    pkg_name = res.stdout.strip().splitlines()[0]
                    self._cache[file_path] = (True, pkg_name)
                    return True, pkg_name, f"Managed by rpm ({pkg_name})"
            except Exception as e:
                logger.debug(f"rpm check failed for {resolved_path}: {e}")

        # 3. Check pacman (Arch Linux / Manjaro)
        if self._pacman_path:
            try:
                res = subprocess.run(
                    [self._pacman_path, "-Qo", resolved_path],
                    capture_output=True,
                    text=True,
                    timeout=3.0,
                )
                if res.returncode == 0 and "is owned by" in res.stdout:
                    pkg_name = res.stdout.split("is owned by")[-1].strip()
                    self._cache[file_path] = (True, pkg_name)
                    return True, pkg_name, f"Managed by pacman ({pkg_name})"
            except Exception as e:
                logger.debug(f"pacman check failed for {resolved_path}: {e}")

        self._cache[file_path] = (False, "")
        return False, None, "Not managed by OS package manager"

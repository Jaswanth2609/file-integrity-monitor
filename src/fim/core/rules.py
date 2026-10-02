"""
Rules, Severity Scoring, and MITRE ATT&CK Mapping for FIM v2.0.
"""

import os
from enum import Enum
from pathlib import Path
from typing import Dict, Optional, Tuple

class ChangeType(str, Enum):
    ADDED = "ADDED"
    MODIFIED = "MODIFIED"
    DELETED = "DELETED"
    PERMISSION_CHANGED = "PERMISSION_CHANGED"
    OWNER_CHANGED = "OWNER_CHANGED"
    RENAMED = "RENAMED"

class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @classmethod
    def rank(cls, sev: str) -> int:
        mapping = {
            "INFO": 1,
            "LOW": 2,
            "MEDIUM": 3,
            "HIGH": 4,
            "CRITICAL": 5
        }
        return mapping.get(sev.upper(), 1)

# MITRE ATT&CK Technique Definitions
MITRE_ATTACK_MAP = {
    "T1565": "Data Manipulation (Stored Data Manipulation)",
    "T1070": "Indicator Removal (Timestomp / File Deletion)",
    "T1036": "Masquerading (Match Legitimate Name or Location)",
    "T1505": "Server Software Component (Web Shells / Extensions)",
    "T1059": "Command and Scripting Interpreter",
    "T1543": "Create or Modify System Process",
    "T1222": "File and Directory Permissions Modification",
    "T1083": "File and Directory Discovery"
}

CRITICAL_SYSTEM_PATHS = [
    "/etc",
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/lib",
    "/lib64",
    "/boot",
    "C:\\Windows\\System32",
    "C:\\Windows\\SysWOW64",
    "C:\\Program Files"
]

EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".so", ".bin", ".sh", ".bash", ".py", ".ps1", ".vbs", ".bat", ".cmd", ".elf", ".js"
}

WEB_EXTENSIONS = {
    ".php", ".jsp", ".asp", ".aspx", ".html", ".phtml"
}

class RuleEngine:
    """Evaluates file changes and assigns severity and MITRE ATT&CK tactics."""

    @staticmethod
    def classify_change(
        path_str: str,
        change_type: ChangeType,
        mode_diff: Optional[str] = None,
        is_executable: bool = False
    ) -> Tuple[Severity, Optional[str], str]:
        """
        Classifies a detected change into Severity, MITRE ID, and a descriptive reason.
        """
        p = Path(path_str)
        ext = p.suffix.lower()
        path_lower = path_str.lower()

        # Check if in a critical system directory
        in_critical_sys = any(
            path_str.startswith(sys_p) or path_lower.startswith(sys_p.lower())
            for sys_p in CRITICAL_SYSTEM_PATHS
        )

        if change_type == ChangeType.MODIFIED:
            if in_critical_sys or ext in EXECUTABLE_EXTENSIONS:
                return Severity.CRITICAL, "T1565", f"Executable or critical system file modified: {p.name}"
            if ext in WEB_EXTENSIONS:
                return Severity.HIGH, "T1505", f"Web application component modified (possible web shell): {p.name}"
            if ext in [".conf", ".cfg", ".yaml", ".yml", ".json", ".ini", ".env"]:
                return Severity.MEDIUM, "T1565", f"Configuration file modified: {p.name}"
            return Severity.LOW, "T1565", f"Regular file content modified: {p.name}"

        elif change_type == ChangeType.ADDED:
            if in_critical_sys or ext in EXECUTABLE_EXTENSIONS:
                return Severity.HIGH, "T1059", f"New executable or script added in monitored scope: {p.name}"
            if ext in WEB_EXTENSIONS:
                return Severity.HIGH, "T1505", f"New web script added: {p.name}"
            return Severity.INFO, "T1083", f"New file created: {p.name}"

        elif change_type == ChangeType.DELETED:
            if in_critical_sys:
                return Severity.HIGH, "T1070", f"Critical system file deleted: {p.name}"
            return Severity.LOW, "T1070", f"File removed from baseline: {p.name}"

        elif change_type == ChangeType.PERMISSION_CHANGED:
            if is_executable or "777" in str(mode_diff) or "chmod" in str(mode_diff):
                return Severity.HIGH, "T1222", f"File permissions altered: {mode_diff}"
            return Severity.MEDIUM, "T1222", f"File permissions changed: {mode_diff}"

        elif change_type == ChangeType.OWNER_CHANGED:
            return Severity.MEDIUM, "T1222", f"File owner/group changed: {mode_diff}"

        elif change_type == ChangeType.RENAMED:
            return Severity.LOW, "T1036", f"File renamed or moved: {p.name}"

        return Severity.INFO, None, "File status event"

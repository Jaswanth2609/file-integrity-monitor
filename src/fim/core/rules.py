"""
Rules, Severity Scoring, and MITRE ATT&CK Mapping for FIM v2.1.
Supports loading user-editable detection and severity rules from config/rules.yaml.
"""

import fnmatch
import json
import logging
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

logger = logging.getLogger("fim.rules")

try:
    import yaml

    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False


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
        mapping = {"INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}
        return mapping.get(str(sev).upper(), 1)


# MITRE ATT&CK Technique Definitions
MITRE_ATTACK_MAP = {
    "T1565": "Data Manipulation (Stored Data Manipulation)",
    "T1070": "Indicator Removal (Timestomp / File Deletion)",
    "T1036": "Masquerading (Match Legitimate Name or Location)",
    "T1505": "Server Software Component (Web Shells / Extensions)",
    "T1505.003": "Web Shell",
    "T1059": "Command and Scripting Interpreter",
    "T1059.004": "Unix Shell",
    "T1543": "Create or Modify System Process",
    "T1053.003": "Scheduled Task/Job: Cron",
    "T1098.004": "Account Manipulation: SSH Authorized Keys",
    "T1222": "File and Directory Permissions Modification",
    "T1083": "File and Directory Discovery",
    "T1027": "Obfuscated/Compressed Files and Information",
    "T1496": "Resource Hijacking (Crypto Mining)",
}

DEFAULT_CRITICAL_SYSTEM_PATHS = [
    "/etc",
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/lib",
    "/lib64",
    "/boot",
    "/usr/local/bin",
    "/usr/local/sbin",
    "C:\\Windows\\System32",
    "C:\\Windows\\SysWOW64",
]

DEFAULT_EXECUTABLE_EXTENSIONS = [
    ".exe",
    ".dll",
    ".so",
    ".bin",
    ".sh",
    ".bash",
    ".py",
    ".ps1",
    ".vbs",
    ".bat",
    ".cmd",
    ".elf",
    ".js",
]

DEFAULT_WEB_EXTENSIONS = [".php", ".jsp", ".asp", ".aspx", ".html", ".phtml", ".cgi"]

DEFAULT_CONFIG_EXTENSIONS = [".conf", ".cfg", ".yaml", ".yml", ".json", ".ini", ".env", ".toml"]


class RuleEngine:
    """Evaluates file changes against configurable user-editable detection rules and severity mappings."""

    def __init__(self, rules_file: Optional[Union[str, Path, Any]] = None):
        if hasattr(rules_file, "get"):
            rules_path = rules_file.get("rules.custom_rules_file")
        else:
            rules_path = rules_file
        self.rules_file = self._resolve_rules_path(rules_path)
        self.critical_system_paths: List[str] = list(DEFAULT_CRITICAL_SYSTEM_PATHS)
        self.executable_extensions: List[str] = list(DEFAULT_EXECUTABLE_EXTENSIONS)
        self.web_extensions: List[str] = list(DEFAULT_WEB_EXTENSIONS)
        self.config_extensions: List[str] = list(DEFAULT_CONFIG_EXTENSIONS)
        self.custom_rules: List[Dict[str, Any]] = []
        self._load_rules()

    def _resolve_rules_path(self, custom_path: Optional[Union[str, Path]]) -> Optional[Path]:
        if custom_path:
            p = Path(custom_path).expanduser().resolve()
            if p.exists():
                return p

        # Check default paths
        candidates = [
            Path(__file__).resolve().parent.parent.parent.parent / "config" / "rules.yaml",
            Path("~/.fim/rules.yaml").expanduser().resolve(),
            Path("config/rules.yaml").resolve(),
        ]
        for c in candidates:
            if c.exists():
                return c
        return None

    def _load_rules(self):
        if not self.rules_file or not self.rules_file.exists():
            return

        try:
            content = self.rules_file.read_text(encoding="utf-8")
            if HAVE_YAML:
                data = yaml.safe_load(content) or {}
            else:
                data = json.loads(content)

            if "critical_system_paths" in data:
                self.critical_system_paths = data["critical_system_paths"]
            if "executable_extensions" in data:
                self.executable_extensions = data["executable_extensions"]
            if "web_extensions" in data:
                self.web_extensions = data["web_extensions"]
            if "config_extensions" in data:
                self.config_extensions = data["config_extensions"]
            if "custom_rules" in data:
                self.custom_rules = data["custom_rules"]
        except Exception as e:
            logger.warning(f"Could not load rules from {self.rules_file}: {e}")

    def classify_change(
        self,
        path_str: str,
        change_type: ChangeType,
        mode_diff: Optional[str] = None,
        is_executable: bool = False,
    ) -> Tuple[Severity, Optional[str], str]:
        """
        Classifies a detected change into Severity, MITRE ID, and a descriptive reason.
        """
        p = Path(path_str)
        ext = p.suffix.lower()
        path_lower = path_str.lower()

        # 1. Evaluate custom user rules first
        for crule in self.custom_rules:
            c_type = crule.get("change_type", "ANY")
            if c_type != "ANY" and c_type != change_type.value:
                continue

            patterns = crule.get("path_pattern", "").split("|")
            for pat in patterns:
                pat = pat.strip()
                if pat and (
                    fnmatch.fnmatch(path_str, pat) or fnmatch.fnmatch(path_lower, pat.lower())
                ):
                    sev_str = crule.get("severity", "HIGH").upper()
                    sev = Severity(sev_str) if sev_str in Severity.__members__ else Severity.HIGH
                    return (
                        sev,
                        crule.get("attack_id", "T1565"),
                        crule.get("description", f"Matched custom rule: {crule.get('name')}"),
                    )

        # 2. Check if in a critical system directory
        in_critical_sys = any(
            path_str.startswith(sys_p) or path_lower.startswith(sys_p.lower())
            for sys_p in self.critical_system_paths
        )

        if change_type == ChangeType.MODIFIED:
            if in_critical_sys or ext in self.executable_extensions:
                return (
                    Severity.CRITICAL,
                    "T1565",
                    f"Executable or critical system file modified: {p.name}",
                )
            if ext in self.web_extensions:
                return (
                    Severity.HIGH,
                    "T1505",
                    f"Web application component modified (possible web shell): {p.name}",
                )
            if ext in self.config_extensions:
                return Severity.MEDIUM, "T1565", f"Configuration file modified: {p.name}"
            return Severity.LOW, "T1565", f"Regular file content modified: {p.name}"

        elif change_type == ChangeType.ADDED:
            if in_critical_sys or ext in self.executable_extensions:
                return (
                    Severity.HIGH,
                    "T1059",
                    f"New executable or script added in monitored scope: {p.name}",
                )
            if ext in self.web_extensions:
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
            return Severity.MEDIUM, "T1036", f"File was renamed / relocated: {path_str}"

        return Severity.INFO, "T1083", f"File integrity event on: {p.name}"

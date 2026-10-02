"""
Local Heuristic and Signature Rule Scanner for FIM v2.0.
Performs lightweight signature matching for webshells, obfuscated payloads, and known malware signatures.
"""

import re
from pathlib import Path
from typing import Dict, List, Optional, Union

from .base import IntelReport, Verdict

# High-confidence signature patterns
HEURISTIC_RULES = [
    {
        "id": "RULE_WEBSHELL_PHP",
        "name": "PHP WebShell Generic Payload",
        "pattern": re.compile(rb'(?i)(eval\s*\(\s*(base64_decode|gzinflate|str_rot13)|system\s*\(\s*\$_REQUEST|passthru\s*\(\s*\$_POST|assert\s*\(\s*\$_GET)'),
        "severity": "CRITICAL"
    },
    {
        "id": "RULE_REVERSE_SHELL_BASH",
        "name": "Bash Reverse TCP Shell",
        "pattern": re.compile(rb'/bin/bash\s+-i\s+>&\s+/dev/tcp/'),
        "severity": "CRITICAL"
    },
    {
        "id": "RULE_POWERSHELL_ENCODED",
        "name": "PowerShell Hidden Encoded Command",
        "pattern": re.compile(rb'(?i)powershell(\.exe)?\s+(-w(indowstyle)?\s+hidden\s+)?-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}'),
        "severity": "HIGH"
    },
    {
        "id": "RULE_PYTHON_DOWNLOAD_EXEC",
        "name": "Python In-Memory Download & Exec",
        "pattern": re.compile(rb'exec\s*\(\s*urllib\.request\.urlopen\([^)]+\)\.read\(\)\s*\)'),
        "severity": "HIGH"
    }
]

class LocalSignatureScanner:
    """Performs local regex and signature analysis on suspect files."""

    @staticmethod
    def scan_file(file_path: Union[str, Path]) -> Optional[Dict[str, Union[str, List[str]]]]:
        p = Path(file_path)
        if not p.exists() or not p.is_file():
            return None

        # Read first 1MB of file
        try:
            with open(p, "rb") as f:
                content = f.read(1024 * 1024)
        except Exception:
            return None

        matched_rules = []
        highest_sev = "LOW"

        for rule in HEURISTIC_RULES:
            if rule["pattern"].search(content):
                matched_rules.append(rule["name"])
                if rule["severity"] == "CRITICAL":
                    highest_sev = "CRITICAL"
                elif rule["severity"] == "HIGH" and highest_sev != "CRITICAL":
                    highest_sev = "HIGH"

        if matched_rules:
            return {
                "status": "MATCHED",
                "severity": highest_sev,
                "matches": matched_rules
            }

        return None

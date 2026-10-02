"""
File Integrity Monitor (FIM) v2.0 Package Root.
Author: Jaswanth (Jaswanth2609)
Repository: https://github.com/Jaswanth2609/file-integrity-monitor
"""

import sys
from pathlib import Path

# Ensure src is in sys.path
_SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from src.fim import (
    __version__,
    __author__,
    __license__,
    ConfigManager,
    HashEngine,
    HashResult,
    BaselineManager,
    BaselineManifest,
    IntegrityComparator,
    Finding,
    VerificationSummary,
    RuleEngine,
    Severity,
    ChangeType,
    LiveMonitor,
    VirusTotalClient,
    MalwareBazaarClient,
    AlertManager,
    DatabaseManager,
    AuditChain,
    ReportGenerator,
)

__all__ = [
    "__version__",
    "__author__",
    "__license__",
    "ConfigManager",
    "HashEngine",
    "HashResult",
    "BaselineManager",
    "BaselineManifest",
    "IntegrityComparator",
    "Finding",
    "VerificationSummary",
    "RuleEngine",
    "Severity",
    "ChangeType",
    "LiveMonitor",
    "VirusTotalClient",
    "MalwareBazaarClient",
    "AlertManager",
    "DatabaseManager",
    "AuditChain",
    "ReportGenerator",
]

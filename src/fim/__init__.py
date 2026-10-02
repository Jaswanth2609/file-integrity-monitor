"""
File Integrity Monitor (FIM) v2.0
Enterprise-Grade File Integrity Monitoring and Threat Intelligence Enrichment.

Author: Jaswanth (Jaswanth2609)
Repository: https://github.com/Jaswanth2609/file-integrity-monitor
"""

__version__ = "2.0.0"
__author__ = "Jaswanth (Jaswanth2609)"
__license__ = "GPL-3.0"

from .config import ConfigManager
from .core.hasher import HashEngine, HashResult
from .core.baseline import BaselineManager, BaselineManifest
from .core.comparator import IntegrityComparator, Finding, VerificationSummary
from .core.rules import RuleEngine, Severity, ChangeType
from .core.monitor import LiveMonitor
from .intel.virustotal import VirusTotalClient
from .intel.malwarebazaar import MalwareBazaarClient
from .alerts.manager import AlertManager
from .storage.db import DatabaseManager
from .storage.audit_chain import AuditChain
from .reports.generator import ReportGenerator

__all__ = [
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

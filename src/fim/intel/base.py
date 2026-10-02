"""
Threat Intelligence Base Classes and Verdict Types for FIM v2.0.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

class Verdict(str, Enum):
    CLEAN = "CLEAN"
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    UNKNOWN = "UNKNOWN"

@dataclass
class IntelReport:
    provider: str
    query_hash: str
    verdict: Verdict
    malicious_count: int = 0
    suspicious_count: int = 0
    total_engines: int = 0
    threat_names: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    cached: bool = False
    details: Dict[str, Any] = field(default_factory=dict)
    status: str = "SUCCESS"  # SUCCESS, RATE_LIMITED, ERROR, NOT_FOUND

    @property
    def detection_ratio(self) -> str:
        if self.total_engines > 0:
            return f"{self.malicious_count}/{self.total_engines}"
        return "0/0"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "query_hash": self.query_hash,
            "verdict": self.verdict.value,
            "malicious_count": self.malicious_count,
            "suspicious_count": self.suspicious_count,
            "total_engines": self.total_engines,
            "detection_ratio": self.detection_ratio,
            "threat_names": self.threat_names,
            "tags": self.tags,
            "cached": self.cached,
            "status": self.status,
            "details": self.details
        }

class BaseIntelProvider(ABC):
    """Abstract interface for threat intelligence feeds."""

    def __init__(self, name: str):
        self.name = name

    @abstractmethod
    def query_hash(self, hash_val: str) -> IntelReport:
        """Queries the provider for reputation data on a given hash."""
        pass

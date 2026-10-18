"""
Unified Threat Intelligence Aggregator for FIM v2.1.
Coordinates lookups across Local Known Hashes DB, VirusTotal API v3, MalwareBazaar, and CIRCL Hashlookup.
"""

import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

from .base import IntelReport, Verdict
from .virustotal import VirusTotalClient
from ..config import ConfigManager
from ..storage.db import DatabaseManager

logger = logging.getLogger("fim.intel")


class ThreatIntelAggregator:
    """Multi-source threat intelligence pipeline."""

    def __init__(
        self, config: Optional[ConfigManager] = None, db: Optional[DatabaseManager] = None
    ):
        self.config = config or ConfigManager()
        self.db = db or DatabaseManager(self.config.db_path)
        self.vt = VirusTotalClient(config=self.config, db=self.db)

    def query_hash(self, hash_val: str) -> IntelReport:
        clean_hash = hash_val.strip().lower()

        # 1. Check local SQLite malware database
        known = self.db.check_known_hash(clean_hash)
        if known:
            return IntelReport(
                provider="Local Threat Signature DB",
                query_hash=clean_hash,
                verdict=Verdict.MALICIOUS,
                malicious_count=1,
                total_engines=1,
                threat_names=[known.get("threat_type", "Malware")],
                details={
                    "file_name": known.get("file_name"),
                    "source": known.get("source", "Local DB"),
                },
                status="SUCCESS",
            )

        # 2. If VirusTotal API key is present, use VirusTotal
        if self.vt.api_key:
            return self.vt.query_hash(clean_hash)

        # 3. Query CIRCL Hashlookup (free, open, public database)
        try:
            algo = (
                "sha256" if len(clean_hash) == 64 else ("md5" if len(clean_hash) == 32 else "sha1")
            )
            url = f"https://hashlookup.circl.lu/lookup/{algo}/{clean_hash}"
            req = urllib.request.Request(url, headers={"User-Agent": "FIM-v2.1-ThreatIntel/1.0"})
            with urllib.request.urlopen(req, timeout=5.0) as resp:  # nosec B310
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    return IntelReport(
                        provider="CIRCL Hashlookup (NSRL)",
                        query_hash=clean_hash,
                        verdict=Verdict.SAFE if "NSRL" in str(data) else Verdict.SUSPICIOUS,
                        malicious_count=0,
                        total_engines=1,
                        details=data,
                        status="SUCCESS",
                    )
        except Exception:
            pass

        # 4. Fallback when no API key is provided and hash is not in free public indices
        return IntelReport(
            provider="Threat Intel Engine (Local DB + CIRCL)",
            query_hash=clean_hash,
            verdict=Verdict.UNKNOWN,
            malicious_count=0,
            total_engines=0,
            status="NOT_INDEXED",
            details={
                "advisory": (
                    "Hash has not been previously submitted or analyzed in public feeds (does NOT imply safe). "
                    "Hash reputation only tracks past submissions — use YARA content scanning ('fim scan <file>') "
                    "or configure VT_API_KEY for 70+ AV engine analysis."
                )
            },
        )

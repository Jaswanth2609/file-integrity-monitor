"""
VirusTotal API v3 Client with rate limiting, retries, caching, and privacy-first hash lookup.
"""

import json
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

from .base import BaseIntelProvider, IntelReport, Verdict
from .ratelimit import TokenBucketRateLimiter, QuotaTracker
from ..config import ConfigManager
from ..errors import InvalidAPIKeyError, RateLimitExceededError, NetworkError
from ..storage.db import DatabaseManager

class VirusTotalClient(BaseIntelProvider):
    """Client for VirusTotal API v3."""

    BASE_URL = "https://www.virustotal.com/api/v3/files/"

    def __init__(
        self,
        api_key: Optional[str] = None,
        config: Optional[ConfigManager] = None,
        db: Optional[DatabaseManager] = None
    ):
        super().__init__("VirusTotal")
        self.config = config or ConfigManager()
        self.api_key = api_key if api_key is not None else self.config.vt_api_key
        self.db = db or DatabaseManager(self.config.db_path)

        rpm = float(self.config.get("virustotal.rate_limit_rpm", 4))
        self.rate_limiter = TokenBucketRateLimiter(requests_per_minute=rpm)
        self.quota_tracker = QuotaTracker(daily_limit=int(self.config.get("virustotal.max_daily_requests", 500)))
        self.timeout = int(self.config.get("virustotal.timeout_seconds", 15))
        self.max_retries = int(self.config.get("virustotal.max_retries", 3))
        self.cache_ttl = int(self.config.get("virustotal.cache_ttl_hours", 24)) * 3600

    def query_hash(self, hash_val: str, use_cache: bool = True) -> IntelReport:
        """
        Queries VirusTotal API v3 for a hash (MD5, SHA-1, SHA-256).
        Checks local SQLite cache first. Never sends file contents.
        """
        clean_hash = hash_val.strip().lower()

        # 1. Check local cache
        if use_cache:
            cached = self.db.get_cached_intel(clean_hash, max_age_seconds=self.cache_ttl)
            if cached and cached.get("provider") == self.name:
                v_str = cached.get("verdict", "UNKNOWN")
                return IntelReport(
                    provider=self.name,
                    query_hash=clean_hash,
                    verdict=Verdict(v_str) if v_str in Verdict._value2member_map_ else Verdict.UNKNOWN,
                    malicious_count=cached.get("detections", 0),
                    total_engines=cached.get("total_engines", 0),
                    cached=True,
                    details=cached.get("raw_json", {}),
                    status="SUCCESS"
                )

        if not self.api_key:
            return IntelReport(
                provider=self.name,
                query_hash=clean_hash,
                verdict=Verdict.UNKNOWN,
                status="NO_API_KEY",
                details={"error": "VirusTotal API key not configured."}
            )

        if not self.quota_tracker.can_request():
            return IntelReport(
                provider=self.name,
                query_hash=clean_hash,
                verdict=Verdict.UNKNOWN,
                status="QUOTA_EXCEEDED",
                details={"error": "Daily VirusTotal request quota reached."}
            )

        # 2. Rate limit token acquisition
        self.rate_limiter.acquire(block=True)
        self.quota_tracker.record_request()

        # 3. HTTP Request with exponential backoff
        url = f"{self.BASE_URL}{clean_hash}"
        headers = {
            "x-apikey": self.api_key,
            "User-Agent": "FIM-v2.0-AgenticMonitor/1.0"
        }

        raw_data: Optional[Dict[str, Any]] = None
        status_code = 0

        for attempt in range(self.max_retries):
            try:
                if HAVE_REQUESTS:
                    resp = requests.get(url, headers=headers, timeout=self.timeout)
                    status_code = resp.status_code
                    if status_code == 200:
                        raw_data = resp.json()
                        break
                    elif status_code == 404:
                        # Hash not in VT database
                        report = IntelReport(
                            provider=self.name,
                            query_hash=clean_hash,
                            verdict=Verdict.UNKNOWN,
                            status="NOT_FOUND",
                            details={"message": "Hash not found in VirusTotal database."}
                        )
                        self.db.cache_intel(clean_hash, self.name, "UNKNOWN", 0, 0, report.details, self.cache_ttl)
                        return report
                    elif status_code == 401 or status_code == 403:
                        return IntelReport(
                            provider=self.name,
                            query_hash=clean_hash,
                            verdict=Verdict.UNKNOWN,
                            status="AUTH_ERROR",
                            details={"error": "Invalid API key or unauthorized access."}
                        )
                    elif status_code == 429:
                        time.sleep(2 ** attempt + 1)
                        continue
                else:
                    # Native urllib fallback
                    req = urllib.request.Request(url, headers=headers)
                    with urllib.request.urlopen(req, timeout=self.timeout) as response:
                        status_code = response.getcode()
                        if status_code == 200:
                            raw_data = json.loads(response.read().decode("utf-8"))
                            break

            except urllib.error.HTTPError as e:
                status_code = e.code
                if status_code == 404:
                    report = IntelReport(
                        provider=self.name,
                        query_hash=clean_hash,
                        verdict=Verdict.UNKNOWN,
                        status="NOT_FOUND",
                        details={"message": "Hash not found in VirusTotal database."}
                    )
                    self.db.cache_intel(clean_hash, self.name, "UNKNOWN", 0, 0, report.details, self.cache_ttl)
                    return report
                elif status_code in (401, 403):
                    return IntelReport(
                        provider=self.name,
                        query_hash=clean_hash,
                        verdict=Verdict.UNKNOWN,
                        status="AUTH_ERROR",
                        details={"error": "Invalid API key."}
                    )
                elif status_code == 429:
                    time.sleep(2 ** attempt + 1)
                    continue
            except Exception as e:
                if attempt == self.max_retries - 1:
                    return IntelReport(
                        provider=self.name,
                        query_hash=clean_hash,
                        verdict=Verdict.UNKNOWN,
                        status="NETWORK_ERROR",
                        details={"error": str(e)}
                    )
                time.sleep(1.0)

        if not raw_data or "data" not in raw_data:
            return IntelReport(
                provider=self.name,
                query_hash=clean_hash,
                verdict=Verdict.UNKNOWN,
                status="NO_DATA"
            )

        # 4. Parse Attributes & Analysis Stats
        attr = raw_data.get("data", {}).get("attributes", {})
        stats = attr.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        undetected = stats.get("undetected", 0)
        harmless = stats.get("harmless", 0)
        total_engines = malicious + suspicious + undetected + harmless

        # Collect threat names
        results = attr.get("last_analysis_results", {})
        threat_names = []
        for eng, res in results.items():
            if res.get("category") == "malicious" and res.get("result"):
                threat_names.append(f"{eng}: {res.get('result')}")

        tags = attr.get("tags", [])

        # Verdict logic
        if malicious >= 3:
            verdict = Verdict.MALICIOUS
        elif malicious >= 1 or suspicious >= 2:
            verdict = Verdict.SUSPICIOUS
        elif total_engines > 0 and malicious == 0 and suspicious == 0:
            verdict = Verdict.SAFE
        else:
            verdict = Verdict.UNKNOWN

        report = IntelReport(
            provider=self.name,
            query_hash=clean_hash,
            verdict=verdict,
            malicious_count=malicious,
            suspicious_count=suspicious,
            total_engines=total_engines,
            threat_names=threat_names[:10],
            tags=tags,
            details=stats,
            status="SUCCESS"
        )

        # 5. Persist into SQLite cache
        self.db.cache_intel(
            hash_val=clean_hash,
            provider=self.name,
            verdict=verdict.value,
            detections=malicious,
            total_engines=total_engines,
            raw_json=report.to_dict(),
            ttl_seconds=self.cache_ttl
        )

        return report

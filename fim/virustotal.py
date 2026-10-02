"""
VirusTotal API v3 Client for File Integrity Monitor.
Handles querying, rate-limiting, retry logic, error codes, and caching.
"""

import json
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from fim.database import DatabaseManager

VT_BASE_URL = "https://www.virustotal.com/api/v3"

@dataclass
class DetectionDetail:
    engine: str
    category: str
    result: Optional[str]
    method: Optional[str] = None
    update: Optional[str] = None

@dataclass
class VTResult:
    hash_value: str
    status: str  # SUCCESS, NOT_FOUND, ERROR, INVALID_KEY, RATE_LIMITED
    threat_level: str  # SAFE, SUSPICIOUS, MALICIOUS, UNKNOWN, ERROR
    malicious: int = 0
    suspicious: int = 0
    undetected: int = 0
    harmless: int = 0
    total_engines: int = 0
    detections: List[Dict[str, Any]] = field(default_factory=list)
    scan_date: Optional[str] = None
    from_cache: bool = False
    error_message: Optional[str] = None
    recommendation: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

class VirusTotalClient:
    """Client for VirusTotal API v3 with rate limiting, caching, and retry logic."""

    def __init__(
        self,
        api_key: str = "",
        db_manager: Optional[DatabaseManager] = None,
        rate_limit_rpm: int = 4,
        timeout: int = 15,
        max_retries: int = 3,
        cache_ttl_hours: int = 24,
    ):
        self.api_key = api_key.strip()
        self.db_manager = db_manager
        self.rate_limit_rpm = max(1, rate_limit_rpm)
        self.min_interval = 60.0 / self.rate_limit_rpm  # e.g., 15.0s for 4 rpm
        self.timeout = timeout
        self.max_retries = max_retries
        self.cache_ttl_hours = cache_ttl_hours
        self._last_request_time: float = 0.0

    def _wait_for_rate_limit(self, progress_callback: Optional[Callable[[str], None]] = None) -> None:
        """Enforces rate limiting delay if needed."""
        elapsed = time.time() - self._last_request_time
        if elapsed < self.min_interval:
            wait_time = self.min_interval - elapsed
            if progress_callback:
                progress_callback(f"Rate limiting active: waiting {wait_time:.1f}s before next request...")
            time.sleep(wait_time)
        self._last_request_time = time.time()

    def query_hash(
        self,
        hash_value: str,
        use_cache: bool = True,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> VTResult:
        """
        Queries VirusTotal for a file hash (MD5, SHA1, or SHA256).
        Checks cache first if enabled.
        """
        clean_hash = hash_value.strip().lower()

        # 1. Check local cache
        if use_cache and self.db_manager:
            cached = self.db_manager.get_cached_vt(clean_hash)
            if cached:
                mal = cached.get("malicious", 0)
                susp = cached.get("suspicious", 0)
                und = cached.get("undetected", 0)
                tot = cached.get("total_engines", 0)
                threat = self._classify_threat(mal, susp, tot)
                recom = self._get_recommendation(threat, mal, tot)
                return VTResult(
                    hash_value=clean_hash,
                    status="SUCCESS",
                    threat_level=threat,
                    malicious=mal,
                    suspicious=susp,
                    undetected=und,
                    total_engines=tot,
                    detections=cached.get("detections", []),
                    from_cache=True,
                    recommendation=recom,
                )

        # 2. Check API key
        if not self.api_key:
            return VTResult(
                hash_value=clean_hash,
                status="INVALID_KEY",
                threat_level="UNKNOWN",
                error_message="E003: No VirusTotal API key configured. Please set your API key in Settings (Option 7) or via VT_API_KEY environment variable.",
                recommendation="Configure your VirusTotal API key from https://www.virustotal.com to enable cloud reputation checks.",
            )

        url = f"{VT_BASE_URL}/files/{clean_hash}"
        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json",
            "User-Agent": "FileIntegrityMonitor/1.0",
        }

        # 3. Retry loop with exponential backoff & rate limiting
        retries = 0
        backoff = 1.0

        while retries <= self.max_retries:
            self._wait_for_rate_limit(progress_callback)
            try:
                import requests
                response = requests.get(url, headers=headers, timeout=self.timeout)
                status_code = response.status_code
                
                # 200 OK: File found in VT
                if status_code == 200:
                    data = response.json().get("data", {})
                    attributes = data.get("attributes", {})
                    stats = attributes.get("last_analysis_stats", {})
                    results = attributes.get("last_analysis_results", {})
                    
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    undetected = stats.get("undetected", 0)
                    harmless = stats.get("harmless", 0)
                    total_engines = sum(stats.values()) or len(results)
                    
                    # Extract top malicious/suspicious detections
                    detections_list: List[Dict[str, Any]] = []
                    for engine_name, engine_info in results.items():
                        cat = engine_info.get("category", "")
                        if cat in ("malicious", "suspicious"):
                            detections_list.append({
                                "engine": engine_name,
                                "category": cat,
                                "result": engine_info.get("result"),
                                "method": engine_info.get("method"),
                                "update": engine_info.get("engine_update"),
                            })

                    threat_level = self._classify_threat(malicious, suspicious, total_engines)
                    recommendation = self._get_recommendation(threat_level, malicious, total_engines)

                    # Save to database cache
                    if self.db_manager:
                        self.db_manager.save_cached_vt(
                            hash_value=clean_hash,
                            malicious=malicious,
                            suspicious=suspicious,
                            undetected=undetected,
                            total_engines=total_engines,
                            detections=detections_list,
                            ttl_hours=self.cache_ttl_hours,
                        )

                    return VTResult(
                        hash_value=clean_hash,
                        status="SUCCESS",
                        threat_level=threat_level,
                        malicious=malicious,
                        suspicious=suspicious,
                        undetected=undetected,
                        harmless=harmless,
                        total_engines=total_engines,
                        detections=detections_list,
                        from_cache=False,
                        recommendation=recommendation,
                    )

                # 404: Hash not found in VT database
                elif status_code == 404:
                    return VTResult(
                        hash_value=clean_hash,
                        status="NOT_FOUND",
                        threat_level="UNKNOWN",
                        error_message="Hash not found in VirusTotal database (file has never been scanned by VirusTotal).",
                        recommendation="File is unknown to VirusTotal. Exercise caution if source is untrusted.",
                    )

                # 401 / 403: Invalid API Key
                elif status_code in (401, 403):
                    return VTResult(
                        hash_value=clean_hash,
                        status="INVALID_KEY",
                        threat_level="UNKNOWN",
                        error_message="E003: Invalid VirusTotal API key. Please check your configuration or obtain a key at virustotal.com.",
                        recommendation="Update your API key in Settings.",
                    )

                # 429: Rate limit exceeded
                elif status_code == 429:
                    retries += 1
                    if retries > self.max_retries:
                        return VTResult(
                            hash_value=clean_hash,
                            status="RATE_LIMITED",
                            threat_level="UNKNOWN",
                            error_message="E004: VirusTotal rate limit exceeded. Please wait a minute or upgrade API quota.",
                            recommendation="Wait before trying additional queries.",
                        )
                    if progress_callback:
                        progress_callback("E004: VirusTotal rate limit reached. Waiting 60s to retry...")
                    time.sleep(60)
                    continue

                # 5xx: Server errors
                elif status_code >= 500:
                    retries += 1
                    if retries > self.max_retries:
                        return VTResult(
                            hash_value=clean_hash,
                            status="ERROR",
                            threat_level="ERROR",
                            error_message=f"VirusTotal server error ({status_code}). VT service might be temporarily unavailable.",
                        )
                    time.sleep(30)
                    continue
                else:
                    return VTResult(
                        hash_value=clean_hash,
                        status="ERROR",
                        threat_level="ERROR",
                        error_message=f"Unexpected API response code: {status_code} - {response.text[:200]}",
                    )

            except Exception as e:
                # Network / Connection error
                retries += 1
                if retries > self.max_retries:
                    return VTResult(
                        hash_value=clean_hash,
                        status="ERROR",
                        threat_level="ERROR",
                        error_message=f"E005: Network connection failed: {e}. Check your internet connection.",
                    )
                time.sleep(backoff)
                backoff *= 2.0

        return VTResult(
            hash_value=clean_hash,
            status="ERROR",
            threat_level="ERROR",
            error_message="E005: Request failed after maximum retries.",
        )

    @staticmethod
    def _classify_threat(malicious: int, suspicious: int, total_engines: int) -> str:
        """Classifies threat based on detections."""
        if malicious > 0:
            return "MALICIOUS"
        elif suspicious > 0:
            return "SUSPICIOUS"
        elif total_engines > 0:
            return "SAFE"
        return "UNKNOWN"

    @staticmethod
    def _get_recommendation(threat_level: str, malicious: int, total_engines: int) -> str:
        """Returns actionable advice according to SRS guidelines."""
        if threat_level == "MALICIOUS":
            return "DO NOT OPEN THIS FILE! Quarantine or delete immediately and run a full system scan."
        elif threat_level == "SUSPICIOUS":
            return "Caution advised. The file triggered heuristics in some security engines."
        elif threat_level == "SAFE":
            return "File appears safe based on analysis from security engines."
        else:
            return "No community threat data available for this hash."

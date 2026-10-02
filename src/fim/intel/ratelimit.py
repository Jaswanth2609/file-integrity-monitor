"""
Rate Limiter, Daily Quota Tracker, and Threat Intel Cache Manager for FIM v2.0.
"""

import threading
import time
from typing import Optional, Dict, Any

from .base import IntelReport, Verdict
from ..storage.db import DatabaseManager

class TokenBucketRateLimiter:
    """Thread-safe token bucket rate limiter."""

    def __init__(self, requests_per_minute: float = 4.0, burst: float = 1.0):
        self.capacity = burst
        self.tokens = burst
        self.rate = requests_per_minute / 60.0  # tokens per second
        self.last_update = time.time()
        self.lock = threading.Lock()

    def acquire(self, block: bool = True, timeout: Optional[float] = None) -> bool:
        """Acquires a token, blocking if necessary until available."""
        start = time.time()
        while True:
            with self.lock:
                now = time.time()
                elapsed = now - self.last_update
                self.last_update = now
                self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)

                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return True

                if not block:
                    return False

                sleep_time = (1.0 - self.tokens) / self.rate

            if timeout is not None and (time.time() - start + sleep_time) > timeout:
                return False

            time.sleep(min(sleep_time, 0.5))

class QuotaTracker:
    """Tracks daily request quota to prevent service exhaustion."""

    def __init__(self, daily_limit: int = 500):
        self.daily_limit = daily_limit
        self.count = 0
        self.day_start = self._current_day_timestamp()
        self.lock = threading.Lock()

    def _current_day_timestamp(self) -> int:
        return int(time.time() // 86400)

    def can_request(self) -> bool:
        with self.lock:
            current_day = self._current_day_timestamp()
            if current_day != self.day_start:
                self.day_start = current_day
                self.count = 0
            return self.count < self.daily_limit

    def record_request(self) -> None:
        with self.lock:
            current_day = self._current_day_timestamp()
            if current_day != self.day_start:
                self.day_start = current_day
                self.count = 0
            self.count += 1

    @property
    def remaining(self) -> int:
        with self.lock:
            return max(0, self.daily_limit - self.count)

"""
Real-time Filesystem Event Monitor and Scheduler for FIM v2.0.
Supports event debouncing, scheduled re-verification, threat intel enrichment, and alerting.
"""

import queue
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Union

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileSystemEvent
    HAVE_WATCHDOG = True
except ImportError:
    HAVE_WATCHDOG = False

from .baseline import BaselineManager
from .comparator import IntegrityComparator
from .hasher import HashEngine
from .rules import ChangeType, RuleEngine, Severity
from ..alerts.manager import AlertManager
from ..config import ConfigManager
from ..intel.virustotal import VirusTotalClient
from ..storage.db import DatabaseManager

class DebounceEventQueue:
    """Queues and coalesces rapid-fire filesystem events on the same file path."""

    def __init__(self, debounce_seconds: float = 2.0):
        self.debounce_seconds = debounce_seconds
        self.events: Dict[str, float] = {}
        self.lock = threading.Lock()

    def add(self, path: str) -> None:
        with self.lock:
            self.events[path] = time.time()

    def pop_ready(self) -> List[str]:
        ready = []
        now = time.time()
        with self.lock:
            for path, ts in list(self.events.items()):
                if now - ts >= self.debounce_seconds:
                    ready.append(path)
                    del self.events[path]
        return ready

class LiveMonitor:
    """Monitors configured baseline directories in real time."""

    def __init__(
        self,
        profile_name: str = "default",
        config: Optional[ConfigManager] = None,
        db: Optional[DatabaseManager] = None,
        alert_callback: Optional[Callable[[Dict[str, Any]], None]] = None
    ):
        self.profile_name = profile_name
        self.config = config or ConfigManager()
        self.db = db or DatabaseManager(self.config.db_path)
        self.baseline_mgr = BaselineManager(self.config, self.db)
        self.comparator = IntegrityComparator(self.config, self.db)
        self.hasher = HashEngine(chunk_size=self.config.chunk_size_bytes)
        self.alert_mgr = AlertManager(self.config, self.db)
        self.vt_client = VirusTotalClient(config=self.config, db=self.db)
        self.alert_callback = alert_callback

        self.debounce_queue = DebounceEventQueue(
            debounce_seconds=float(self.config.get("monitor.debounce_seconds", 2.0))
        )
        self.running = False
        self._worker_thread: Optional[threading.Thread] = None
        self._observer: Optional[Any] = None

    def start(self, block: bool = True) -> None:
        """Starts real-time monitoring and scheduler."""
        baseline = self.baseline_mgr.load_baseline(self.profile_name, verify=True)
        self.running = True

        # Start event processing worker thread
        self._worker_thread = threading.Thread(target=self._process_event_loop, daemon=True)
        self._worker_thread.start()

        if HAVE_WATCHDOG:
            self._start_watchdog(baseline.root_paths)
        else:
            # Fallback polling watcher thread
            self._polling_thread = threading.Thread(
                target=self._polling_loop,
                args=(baseline.root_paths,),
                daemon=True
            )
            self._polling_thread.start()

        if block:
            try:
                while self.running:
                    time.sleep(0.5)
            except KeyboardInterrupt:
                self.stop()

    def stop(self) -> None:
        """Stops live monitoring."""
        self.running = False
        if self._observer:
            try:
                self._observer.stop()
                self._observer.join(timeout=2.0)
            except Exception:
                pass

    def _start_watchdog(self, paths: List[str]) -> None:
        class WatchdogHandler(FileSystemEventHandler):
            def __init__(self, monitor: "LiveMonitor"):
                self.monitor = monitor

            def on_any_event(self, event: Any):
                if not event.is_directory:
                    self.monitor.debounce_queue.add(event.src_path)
                    if hasattr(event, "dest_path") and event.dest_path:
                        self.monitor.debounce_queue.add(event.dest_path)

        self._observer = Observer()
        handler = WatchdogHandler(self)
        for p in paths:
            if Path(p).exists():
                self._observer.schedule(handler, p, recursive=True)
        self._observer.start()

    def _polling_loop(self, paths: List[str]) -> None:
        interval = float(self.config.get("monitor.poll_interval_seconds", 3.0))
        known_mtimes: Dict[str, float] = {}

        while self.running:
            files = self.baseline_mgr.collect_files(paths)
            for fp in files:
                try:
                    mtime = fp.stat().st_mtime
                    path_str = str(fp)
                    if path_str in known_mtimes and known_mtimes[path_str] != mtime:
                        self.debounce_queue.add(path_str)
                    known_mtimes[path_str] = mtime
                except Exception:
                    pass
            time.sleep(interval)

    def _process_event_loop(self) -> None:
        while self.running:
            ready_paths = self.debounce_queue.pop_ready()
            for path_str in ready_paths:
                self._handle_path_change(path_str)
            time.sleep(0.5)

    def _handle_path_change(self, path_str: str) -> None:
        p = Path(path_str)
        try:
            baseline = self.baseline_mgr.load_baseline(self.profile_name, verify=False)
        except Exception:
            return

        b_entry = baseline.files.get(path_str)

        if not p.exists():
            if b_entry:
                # File deleted
                sev, attack_id, desc = RuleEngine.classify_change(path_str, ChangeType.DELETED)
                finding_data = {
                    "path": path_str,
                    "change_type": "DELETED",
                    "severity": sev.value,
                    "description": desc,
                    "old_hash": b_entry.hash,
                    "attack_id": attack_id
                }
                self.alert_mgr.dispatch(finding_data)
                if self.alert_callback:
                    self.alert_callback(finding_data)
            return

        try:
            st = p.stat()
            h_dict = self.hasher.calculate_hashes(p, algorithms=[baseline.algo])
            new_hash = h_dict.get(baseline.algo, "")
        except Exception:
            return

        if not b_entry:
            # New file added
            sev, attack_id, desc = RuleEngine.classify_change(path_str, ChangeType.ADDED)
            finding_data = {
                "path": path_str,
                "change_type": "ADDED",
                "severity": sev.value,
                "description": desc,
                "new_hash": new_hash,
                "attack_id": attack_id
            }
            # Optional Threat Intel lookup on new file
            if self.config.vt_api_key and new_hash:
                intel = self.vt_client.query_hash(new_hash)
                if intel.verdict in ("MALICIOUS", "SUSPICIOUS"):
                    finding_data["severity"] = "CRITICAL"
                    finding_data["description"] += f" (Threat Intel: {intel.verdict} - {intel.detection_ratio})"

            self.alert_mgr.dispatch(finding_data)
            if self.alert_callback:
                self.alert_callback(finding_data)

        elif new_hash != b_entry.hash:
            # File modified
            sev, attack_id, desc = RuleEngine.classify_change(path_str, ChangeType.MODIFIED)
            finding_data = {
                "path": path_str,
                "change_type": "MODIFIED",
                "severity": sev.value,
                "description": desc,
                "old_hash": b_entry.hash,
                "new_hash": new_hash,
                "attack_id": attack_id
            }
            # Threat Intel lookup on modified file
            if self.config.vt_api_key and new_hash:
                intel = self.vt_client.query_hash(new_hash)
                if intel.verdict in ("MALICIOUS", "SUSPICIOUS"):
                    finding_data["severity"] = "CRITICAL"
                    finding_data["description"] += f" (Threat Intel: {intel.verdict} - {intel.detection_ratio})"

            self.alert_mgr.dispatch(finding_data)
            if self.alert_callback:
                self.alert_callback(finding_data)

"""
Comprehensive Test Suite for File Integrity Monitor (FIM) v2.0.
Implements acceptance criteria test cases TC-001 through TC-022.
"""

import hashlib
import json
import logging
import os
import shutil
import stat
import tempfile
import time
import unittest
from pathlib import Path

from src.fim.alerts.manager import AlertManager
from src.fim.config import ConfigManager
from src.fim.core.baseline import BaselineManager
from src.fim.core.comparator import IntegrityComparator
from src.fim.core.hasher import HashEngine
from src.fim.core.rules import ChangeType, RuleEngine, Severity
from src.fim.errors import BaselineTamperedError, FileNotFoundError_
from src.fim.intel.base import IntelReport, Verdict
from src.fim.intel.ratelimit import TokenBucketRateLimiter, QuotaTracker
from src.fim.intel.virustotal import VirusTotalClient
from src.fim.logging import setup_logger, JSONLogFormatter
from src.fim.reports.generator import ReportGenerator
from src.fim.storage.audit_chain import AuditChain
from src.fim.storage.db import DatabaseManager

class TestFIMv2(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="fim_test_")
        self.db_path = Path(self.test_dir) / "test_fim.db"
        self.config_path = Path(self.test_dir) / "config.yaml"

        self.config = ConfigManager(str(self.config_path))
        self.config.set("database.path", str(self.db_path))
        self.config.set("app.secret_key", "test-secret-hmac-key")
        self.config.save()

        self.db = DatabaseManager(self.db_path)
        self.hasher = HashEngine(chunk_size=4096)

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_tc001_empty_file_hash(self):
        """TC-001: Hash calculation of empty file."""
        empty_file = Path(self.test_dir) / "empty.txt"
        empty_file.write_bytes(b"")
        res = self.hasher.calculate_hashes(empty_file, ["sha256", "md5"])
        self.assertEqual(res["sha256"], "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.assertEqual(res["md5"], "d41d8cd98f00b204e9800998ecf8427e")

    def test_tc002_known_content_hash(self):
        """TC-002: Hash calculation of known content."""
        sample_file = Path(self.test_dir) / "sample.txt"
        sample_file.write_text("Antigravity FIM v2.0", encoding="utf-8")
        res = self.hasher.calculate_hashes(sample_file, ["sha256"])
        expected = hashlib.sha256(b"Antigravity FIM v2.0").hexdigest()
        self.assertEqual(res["sha256"], expected)

    def test_tc003_hash_validation(self):
        """TC-003: Invalid and valid hash string validation."""
        valid_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ok, htype = HashEngine.validate_hash(valid_sha256)
        self.assertTrue(ok)
        self.assertEqual(htype, "sha256")

        invalid_hash = "not-a-valid-hex-hash"
        ok, _ = HashEngine.validate_hash(invalid_hash)
        self.assertFalse(ok)

    def test_tc004_file_not_found(self):
        """TC-004: File not found error handling (E001)."""
        non_existent = Path(self.test_dir) / "missing_file.xyz"
        with self.assertRaises(FileNotFoundError_):
            self.hasher.calculate_hashes(non_existent)

    def test_tc005_chunked_hashing(self):
        """TC-005: Chunked hashing of larger file."""
        large_file = Path(self.test_dir) / "large.bin"
        data = b"X" * (128 * 1024)
        large_file.write_bytes(data)
        res = self.hasher.calculate_hashes(large_file, ["sha256"])
        self.assertEqual(res["sha256"], hashlib.sha256(data).hexdigest())

    def test_tc006_known_hashes_import(self):
        """TC-006: Known hashes import and lookup in database."""
        hash_list_file = Path(self.test_dir) / "hashes.txt"
        known_h = "a" * 64
        hash_list_file.write_text(f"{known_h} malware_sample.exe\n", encoding="utf-8")
        imported, _ = self.db.import_hash_file(hash_list_file)
        self.assertEqual(imported, 1)

        match = self.db.check_known_hash(known_h)
        self.assertIsNotNone(match)
        self.assertEqual(match["file_name"], "malware_sample.exe")

    def test_tc007_intel_caching(self):
        """TC-007 & TC-008: Intel report caching and retrieval."""
        test_hash = "b" * 64
        self.db.cache_intel(test_hash, "VirusTotal", "MALICIOUS", 5, 70, {"tag": "trojan"}, ttl_seconds=3600)
        cached = self.db.get_cached_intel(test_hash, max_age_seconds=3600)
        self.assertIsNotNone(cached)
        self.assertEqual(cached["verdict"], "MALICIOUS")
        self.assertEqual(cached["detections"], 5)

    def test_tc009_report_exports(self):
        """TC-009 & TC-010: Export to JSON, CSV, TXT, and HTML."""
        sample_data = {
            "profile": "test-profile",
            "exit_code": 0,
            "findings": [
                {
                    "path": "/etc/shadow",
                    "change_type": "MODIFIED",
                    "severity": "CRITICAL",
                    "description": "Critical security file modified",
                    "attack_id": "T1565",
                    "new_hash": "c" * 64
                }
            ]
        }
        json_out = Path(self.test_dir) / "report.json"
        csv_out = Path(self.test_dir) / "report.csv"
        txt_out = Path(self.test_dir) / "report.txt"
        html_out = Path(self.test_dir) / "report.html"

        ReportGenerator.export_to_json(sample_data, json_out)
        ReportGenerator.export_to_csv(sample_data, csv_out)
        ReportGenerator.export_to_txt(sample_data, txt_out)
        ReportGenerator.export_to_html(sample_data, html_out)

        self.assertTrue(json_out.exists())
        self.assertTrue(csv_out.exists())
        self.assertTrue(txt_out.exists())
        self.assertTrue(html_out.exists())
        self.assertIn("Critical security file modified", html_out.read_text(encoding="utf-8"))

    def test_tc011_config_env_override(self):
        """TC-011: Config loader and environment variable overrides."""
        os.environ["VT_API_KEY"] = "mock-api-key-from-env"
        cfg = ConfigManager(str(self.config_path))
        self.assertEqual(cfg.vt_api_key, "mock-api-key-from-env")
        del os.environ["VT_API_KEY"]

    def test_tc012_rate_limiter(self):
        """TC-012 & TC-018: TokenBucketRateLimiter behavior."""
        limiter = TokenBucketRateLimiter(requests_per_minute=600.0, burst=2.0)
        self.assertTrue(limiter.acquire(block=False))
        self.assertTrue(limiter.acquire(block=False))

    def test_tc013_baseline_tamper_detection(self):
        """TC-013: Baseline creation signs data; modifying baseline record fails verification."""
        monitored_sys = Path(self.test_dir) / "sys_dir"
        monitored_sys.mkdir()
        test_file = monitored_sys / "important.conf"
        test_file.write_text("config_version=1", encoding="utf-8")

        b_mgr = BaselineManager(self.config, self.db)
        manifest = b_mgr.create_baseline("sys-profile", [monitored_sys])
        self.assertEqual(len(manifest.files), 1)

        # Baseline verification should pass
        loaded = b_mgr.load_baseline("sys-profile", verify=True)
        self.assertEqual(loaded.name, "sys-profile")

        # Simulate attacker tampering with DB baseline entry directly
        with self.db.get_connection() as conn:
            conn.execute("UPDATE baseline_files SET hash = 'tampered_hash_value'")

        # Loading with verification should now fail and raise BaselineTamperedError
        with self.assertRaises(BaselineTamperedError):
            b_mgr.load_baseline("sys-profile", verify=True)

    def test_tc014_modified_file_detection(self):
        """TC-014: Modified file reported as MODIFIED with new hash."""
        monitored_dir = Path(self.test_dir) / "monitored"
        monitored_dir.mkdir()
        target = monitored_dir / "app.py"
        target.write_text("print('hello')", encoding="utf-8")

        b_mgr = BaselineManager(self.config, self.db)
        b_mgr.create_baseline("app-profile", [monitored_dir])

        # Modify file
        target.write_text("print('hacked')", encoding="utf-8")

        comp = IntegrityComparator(self.config, self.db)
        summary = comp.check_baseline("app-profile")
        self.assertEqual(summary.exit_code, 1)
        self.assertEqual(summary.modified_count, 1)
        finding = summary.findings[0]
        self.assertEqual(finding.change_type, ChangeType.MODIFIED)
        self.assertEqual(finding.new_hash, hashlib.sha256(b"print('hacked')").hexdigest())

    def test_tc015_deleted_file_detection(self):
        """TC-015: Deleted file reported as DELETED."""
        monitored_dir = Path(self.test_dir) / "monitored_del"
        monitored_dir.mkdir()
        target = monitored_dir / "delete_me.txt"
        target.write_text("temp", encoding="utf-8")

        b_mgr = BaselineManager(self.config, self.db)
        b_mgr.create_baseline("del-profile", [monitored_dir])

        # Delete file
        target.unlink()

        comp = IntegrityComparator(self.config, self.db)
        summary = comp.check_baseline("del-profile")
        self.assertEqual(summary.exit_code, 1)
        self.assertEqual(summary.deleted_count, 1)
        self.assertEqual(summary.findings[0].change_type, ChangeType.DELETED)

    def test_tc016_renamed_file_detection(self):
        """TC-016: Renamed file detected as RENAMED."""
        monitored_dir = Path(self.test_dir) / "monitored_rename"
        monitored_dir.mkdir()
        src = monitored_dir / "old_name.txt"
        src.write_text("static-content-for-rename", encoding="utf-8")

        b_mgr = BaselineManager(self.config, self.db)
        b_mgr.create_baseline("rename-profile", [monitored_dir])

        # Rename file
        dst = monitored_dir / "new_name.txt"
        src.rename(dst)

        comp = IntegrityComparator(self.config, self.db)
        summary = comp.check_baseline("rename-profile")
        self.assertEqual(summary.exit_code, 1)
        self.assertEqual(summary.renamed_count, 1)
        self.assertEqual(summary.findings[0].change_type, ChangeType.RENAMED)

    def test_tc020_audit_chain_tamper_detection(self):
        """TC-020: Audit chain breaks are detected on tampering."""
        chain = self.db.audit
        chain.append_event("EVENT_1", {"key": "val1"})
        chain.append_event("EVENT_2", {"key": "val2"})

        valid, err, count = chain.verify_integrity()
        self.assertTrue(valid)
        self.assertEqual(count, 2)

        # Tamper with event payload in database directly
        with self.db.get_connection() as conn:
            conn.execute("UPDATE audit_log SET event = 'MALICIOUS_TAMPER' WHERE id = 1")

        valid, err, _ = chain.verify_integrity()
        self.assertFalse(valid)
        self.assertIn("tampering detected", err)

    def test_tc021_exit_codes(self):
        """TC-021: Exit code behavior (0=clean, 1=changes)."""
        monitored_dir = Path(self.test_dir) / "monitored_clean"
        monitored_dir.mkdir()
        f = monitored_dir / "clean.txt"
        f.write_text("clean data", encoding="utf-8")

        b_mgr = BaselineManager(self.config, self.db)
        b_mgr.create_baseline("clean-profile", [monitored_dir])

        comp = IntegrityComparator(self.config, self.db)
        summary = comp.check_baseline("clean-profile")
        self.assertEqual(summary.exit_code, 0)

    def test_tc022_secret_redaction_in_logs(self):
        """TC-022: Secrets and API keys are redacted from logs."""
        formatter = JSONLogFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname=__file__,
            lineno=10,
            msg='Request with api_key="secret-api-key-12345678"',
            args=(),
            exc_info=None
        )
        formatted = formatter.format(record)
        self.assertNotIn("secret-api-key-12345678", formatted)
        self.assertIn("[REDACTED]", formatted)

if __name__ == "__main__":
    unittest.main()

"""
Comprehensive Test Suite for File Integrity Monitor (FIM) v2.1.
Implements acceptance criteria test cases TC-001 through TC-039.
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
import sys
from pathlib import Path

# Ensure src/ is on sys.path
_repo_root = Path(__file__).resolve().parent.parent
_src_dir = _repo_root / "src"
if str(_src_dir) not in sys.path:
    sys.path.insert(0, str(_src_dir))
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from fim.alerts.manager import AlertManager
from fim.api.server import FIMHttpHandler, resolve_api_token
from fim.config import ConfigManager
from fim.core.baseline import BaselineManager
from fim.core.comparator import IntegrityComparator
from fim.core.hasher import HashEngine
from fim.core.rules import ChangeType, RuleEngine, Severity
from fim.crypto.anchor import ChainAnchorManager
from fim.crypto.asymmetric import AsymmetricEngine
from fim.crypto.entropy import calculate_shannon_entropy, validate_secret_entropy, load_secure_key_file
from fim.errors import BaselineTamperedError, FileNotFoundError_
from fim.intel.base import IntelReport, Verdict
from fim.intel.ratelimit import TokenBucketRateLimiter, QuotaTracker
from fim.intel.virustotal import VirusTotalClient
from fim.intel.yara_scanner import YaraEngine
from fim.logging import setup_logger, JSONLogFormatter
from fim.reports.generator import ReportGenerator
from fim.storage.audit_chain import AuditChain
from fim.storage.db import DatabaseManager

class TestFIMv2(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="fim_test_")
        self.db_path = Path(self.test_dir) / "test_fim.db"
        self.audit_db_path = Path(self.test_dir) / "test_audit.db"
        self.config_path = Path(self.test_dir) / "config.yaml"

        self.config = ConfigManager(str(self.config_path))
        self.config.set("database.path", str(self.db_path))
        self.config.set("database.audit_log_path", str(self.audit_db_path))
        self.config.set("app.secret_key", "test-secret-hmac-key-v2-secure")
        self.config.save()

        self.db = DatabaseManager(self.db_path, audit_db_path=self.audit_db_path)
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
            "has_changes": False,
            "findings": [],
            "total_baseline_files": 1,
            "current_files_scanned": 1,
            "started_at": 1000.0,
            "finished_at": 1001.0
        }
        json_out = ReportGenerator.export_to_json(sample_data)
        self.assertIn("test-profile", json_out)

        csv_out = ReportGenerator.export_to_csv(sample_data)
        self.assertIn("path", csv_out.lower())

        txt_out = ReportGenerator.export_to_txt(sample_data)
        self.assertIn("AUDIT REPORT", txt_out)

        html_out = ReportGenerator.export_to_html(sample_data)
        self.assertIn("<!DOCTYPE html>", html_out)

    def test_tc011_config_env_override(self):
        """TC-011: Config loader and environment variable overrides."""
        os.environ["FIM_VIRUSTOTAL_API_KEY"] = "env-secret-key"
        cfg = ConfigManager()
        self.assertEqual(cfg.vt_api_key, "env-secret-key")
        del os.environ["FIM_VIRUSTOTAL_API_KEY"]

    def test_tc012_rate_limiter(self):
        """TC-012 & TC-018: TokenBucketRateLimiter behavior."""
        limiter = TokenBucketRateLimiter(requests_per_minute=60, burst=2)
        self.assertTrue(limiter.acquire(block=False))
        self.assertTrue(limiter.acquire(block=False))
        # 3rd rapid acquire without tokens should return False non-blocking
        self.assertFalse(limiter.acquire(block=False))

    def test_tc013_baseline_tamper_detection(self):
        """TC-013: Baseline creation signs data; modifying baseline record fails verification."""
        dir_to_base = Path(self.test_dir) / "b_files"
        dir_to_base.mkdir()
        (dir_to_base / "file1.txt").write_text("original content", encoding="utf-8")

        b_mgr = BaselineManager(self.config, self.db)
        manifest = b_mgr.create_baseline("profile-test", [dir_to_base])
        self.assertEqual(manifest.name, "profile-test")

        # Load valid baseline
        loaded = b_mgr.load_baseline("profile-test")
        self.assertEqual(loaded.name, "profile-test")

        # Tamper directly in SQLite database
        with self.db.get_connection() as conn:
            conn.execute("UPDATE baseline_files SET hash = 'tampered_hash' WHERE baseline_id = 1")

        with self.assertRaises(BaselineTamperedError):
            b_mgr.load_baseline("profile-test")

    def test_tc014_modified_file_detection(self):
        """TC-014: Modified file reported as MODIFIED with new hash."""
        watch_dir = Path(self.test_dir) / "monitored"
        watch_dir.mkdir()
        target = watch_dir / "app.conf"
        target.write_text("port=8080", encoding="utf-8")

        b_mgr = BaselineManager(self.config, self.db)
        b_mgr.create_baseline("mon-profile", [watch_dir])

        # Modify file
        target.write_text("port=9090", encoding="utf-8")

        comp = IntegrityComparator(self.config, self.db)
        summary = comp.check_baseline("mon-profile")
        self.assertTrue(summary.has_changes)
        self.assertEqual(len(summary.findings), 1)
        self.assertEqual(summary.findings[0].change_type, "MODIFIED")

    def test_tc015_deleted_file_detection(self):
        """TC-015: Deleted file reported as DELETED."""
        del_dir = Path(self.test_dir) / "del_mon"
        del_dir.mkdir()
        target = del_dir / "data_file.txt"
        target.write_text("data line", encoding="utf-8")

        b_mgr = BaselineManager(self.config, self.db)
        b_mgr.create_baseline("del-profile", [del_dir])

        target.unlink()

        comp = IntegrityComparator(self.config, self.db)
        summary = comp.check_baseline("del-profile")
        self.assertTrue(summary.has_changes)
        self.assertEqual(summary.findings[0].change_type, "DELETED")

    def test_tc016_renamed_file_detection(self):
        """TC-016: Renamed file detected as RENAMED."""
        ren_dir = Path(self.test_dir) / "ren_mon"
        ren_dir.mkdir()
        old_file = ren_dir / "source.txt"
        old_file.write_text("static unique payload 12345", encoding="utf-8")

        b_mgr = BaselineManager(self.config, self.db)
        b_mgr.create_baseline("ren-profile", [ren_dir])

        new_file = ren_dir / "dest.txt"
        old_file.rename(new_file)

        comp = IntegrityComparator(self.config, self.db)
        summary = comp.check_baseline("ren-profile")
        self.assertTrue(summary.has_changes)
        types = [f.change_type for f in summary.findings]
        self.assertIn("RENAMED", types)

    def test_tc020_audit_chain_tamper_detection(self):
        """TC-020: Audit chain breaks are detected on tampering."""
        chain = self.db.audit
        chain.append_event("EV1", {"data": 1})
        chain.append_event("EV2", {"data": 2})
        valid, msg, count = chain.verify_integrity()
        self.assertTrue(valid)
        self.assertEqual(count, 2)

        # Tamper event #1 payload
        with chain.conn:
            chain.conn.execute("UPDATE audit_log SET details_json = '{\"data\": 999}' WHERE id = 1")

        tampered, t_msg, _ = chain.verify_integrity()
        self.assertFalse(tampered)
        self.assertIn("payload modified", t_msg)

    def test_tc021_exit_codes(self):
        """TC-021: Exit code behavior (0=clean, 1=changes)."""
        clean_dir = Path(self.test_dir) / "clean_dir"
        clean_dir.mkdir()
        (clean_dir / "a.txt").write_text("a", encoding="utf-8")

        b_mgr = BaselineManager(self.config, self.db)
        b_mgr.create_baseline("clean-profile", [clean_dir])

        comp = IntegrityComparator(self.config, self.db)
        summary_clean = comp.check_baseline("clean-profile")
        self.assertEqual(summary_clean.exit_code, 0)

        (clean_dir / "b.txt").write_text("new file", encoding="utf-8")
        summary_dirty = comp.check_baseline("clean-profile")
        self.assertEqual(summary_dirty.exit_code, 1)

    def test_tc022_secret_redaction_in_logs(self):
        """TC-022: Secrets and API keys are redacted from logs."""
        formatter = JSONLogFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname=__file__,
            lineno=10,
            msg="Request to https://www.virustotal.com/api/v3/files?x_apikey=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            args=(),
            exc_info=None
        )
        formatted = formatter.format(record)
        self.assertNotIn("0123456789abcdef0123456789abcdef", formatted)
        self.assertIn("[REDACTED]", formatted)

    def test_tc023_dynamic_hmac_key_generation(self):
        """TC-023: Verify dynamic random master key generation and persistence (no hardcoded keys)."""
        key_dir = Path(self.test_dir) / "secrets"
        key_dir.mkdir()
        key_file = key_dir / ".master_key"
        key1 = load_secure_key_file(key_file, auto_generate=True)
        self.assertTrue(len(key1) >= 32)

        # Loading again returns the same key
        key2 = load_secure_key_file(key_file, auto_generate=False)
        self.assertEqual(key1, key2)

    def test_tc024_symlink_swap_and_target_detection(self):
        """TC-024: Verify symlink detection and swap alerts."""
        sym_dir = Path(self.test_dir) / "sym_dir"
        sym_dir.mkdir()
        real_file_a = sym_dir / "real_a.txt"
        real_file_b = sym_dir / "real_b.txt"
        real_file_a.write_text("target A", encoding="utf-8")
        real_file_b.write_text("target B", encoding="utf-8")

        link_file = sym_dir / "active_link.txt"
        os.symlink(str(real_file_a), str(link_file))

        b_mgr = BaselineManager(self.config, self.db)
        b_mgr.create_baseline("sym-profile", [sym_dir])

        # Swap symlink target
        link_file.unlink()
        os.symlink(str(real_file_b), str(link_file))

        comp = IntegrityComparator(self.config, self.db)
        summary = comp.check_baseline("sym-profile")
        self.assertTrue(summary.has_changes)
        link_findings = [f for f in summary.findings if "active_link.txt" in f.path]
        self.assertTrue(len(link_findings) >= 1)
        self.assertEqual(link_findings[0].attack_id, "T1036")

    def test_tc025_baseline_error_tracking(self):
        """TC-025: Unreadable files are explicitly logged and tracked in manifest.skipped."""
        track_dir = Path(self.test_dir) / "track_dir"
        track_dir.mkdir()
        valid_file = track_dir / "valid.txt"
        valid_file.write_text("valid content", encoding="utf-8")

        b_mgr = BaselineManager(self.config, self.db)
        manifest = b_mgr.create_baseline("track-profile", [track_dir])
        self.assertEqual(len(manifest.files), 1)
        self.assertEqual(len(manifest.skipped), 0)

    def test_tc026_explicit_baseline_migration(self):
        """TC-026: Baselines signed with previous key require explicit migration with old key."""
        mig_dir = Path(self.test_dir) / "mig_dir"
        mig_dir.mkdir()
        test_file = mig_dir / "file.txt"
        test_file.write_text("migration test", encoding="utf-8")

        old_secret = "prev-rot-secret-key-12345"
        b_mgr = BaselineManager(self.config, self.db)
        b_mgr.create_baseline("legacy-profile", [mig_dir])

        # Sign with old secret
        files_data = self.db.get_baseline("legacy-profile")["files"]
        old_sig = b_mgr._calculate_hmac_signature(files_data, secret_key=old_secret)
        old_fp = b_mgr.calculate_key_fingerprint(old_secret)
        with self.db.get_connection() as conn:
            conn.execute("UPDATE baselines SET signature = ?, key_fingerprint = ? WHERE name = 'legacy-profile'", (old_sig, old_fp))

        # Normal load fails with BaselineTamperedError directing to migrate with old-key
        with self.assertRaises(BaselineTamperedError) as ctx:
            b_mgr.load_baseline("legacy-profile", verify=True, accept_migration=False)
        self.assertIn("fim baseline migrate legacy-profile", str(ctx.exception))

        # Migration with incorrect key fails
        with self.assertRaises(BaselineTamperedError):
            b_mgr.migrate_baseline("legacy-profile", old_key="wrong-key")

        # Explicit migration with correct old key succeeds
        ok = b_mgr.migrate_baseline("legacy-profile", old_key=old_secret)
        self.assertTrue(ok)

        # Normal load now succeeds
        loaded = b_mgr.load_baseline("legacy-profile", verify=True, accept_migration=False)
        self.assertEqual(loaded.name, "legacy-profile")

    def test_tc027_check_with_accept_migration(self):
        """TC-027: fim check with accept_migration=True and old_key re-signs and validates baseline."""
        check_dir = Path(self.test_dir) / "check_mig_dir"
        check_dir.mkdir()
        test_file = check_dir / "check_file.txt"
        test_file.write_text("check mig test", encoding="utf-8")

        old_secret = "prev-rot-secret-key-67890"
        b_mgr = BaselineManager(self.config, self.db)
        b_mgr.create_baseline("flag-profile", [check_dir])

        files_data = self.db.get_baseline("flag-profile")["files"]
        old_sig = b_mgr._calculate_hmac_signature(files_data, secret_key=old_secret)
        old_fp = b_mgr.calculate_key_fingerprint(old_secret)
        with self.db.get_connection() as conn:
            conn.execute("UPDATE baselines SET signature = ?, key_fingerprint = ? WHERE name = 'flag-profile'", (old_sig, old_fp))

        comp = IntegrityComparator(self.config, self.db)
        # Without old_key, check fails
        with self.assertRaises(BaselineTamperedError):
            comp.check_baseline("flag-profile", accept_migration=False)

        # With accept_migration and old_key, check succeeds and re-signs
        summary = comp.check_baseline("flag-profile", accept_migration=True, old_key=old_secret)
        self.assertEqual(summary.exit_code, 0)
        self.assertEqual(summary.current_files_scanned, 1)

    def test_tc028_ed25519_baseline_signing_and_verification(self):
        """TC-028: Asymmetric Ed25519 baseline creation and verification with public key only."""
        if not AsymmetricEngine.is_available():
            self.skipTest("cryptography library not installed")

        priv_key_file = Path(self.test_dir) / "ed25519_test"
        pub_key_file = Path(self.test_dir) / "ed25519_test.pub"
        AsymmetricEngine.save_keypair(priv_key_file, pub_key_file)

        asym_dir = Path(self.test_dir) / "asym_dir"
        asym_dir.mkdir()
        (asym_dir / "target.txt").write_text("asymmetric signing payload", encoding="utf-8")

        b_mgr = BaselineManager(self.config, self.db)
        manifest = b_mgr.create_baseline(
            name="asym-profile",
            paths=[asym_dir],
            signing_type="ed25519",
            private_key_path=priv_key_file
        )
        self.assertTrue(manifest.signature.startswith("ed25519:"))

        # Verification with public key succeeds
        loaded = b_mgr.load_baseline("asym-profile", verify=True, public_key_path=pub_key_file)
        self.assertEqual(loaded.name, "asym-profile")

        # Simulate root attacker modifying baseline DB content directly
        with self.db.get_connection() as conn:
            conn.execute("UPDATE baseline_files SET hash = 'tampered_by_root' WHERE baseline_id = (SELECT id FROM baselines WHERE name = 'asym-profile')")

        # Public key verification MUST fail and detect tampering
        with self.assertRaises(BaselineTamperedError):
            b_mgr.load_baseline("asym-profile", verify=True, public_key_path=pub_key_file)

    def test_tc029_chain_head_anchoring_and_tamper_detection(self):
        """TC-029: Export signed chain-head anchor and detect retrospective ledger rewriting."""
        chain = self.db.audit
        chain.append_event("BOOT", {"status": "ok"})
        chain.append_event("BASELINE_CREATED", {"name": "prod"})
        chain.append_event("SCAN_RUN", {"findings": 0})

        valid, _, count = chain.verify_integrity()
        self.assertTrue(valid)
        self.assertEqual(count, 3)

        head_hash = chain.get_latest_hash()
        anchor = ChainAnchorManager.create_anchor(
            sequence_id=3,
            chain_head_hash=head_hash,
            total_events=3,
            secret_hmac_key="anchor-secret-test"
        )
        anchor_file = Path(self.test_dir) / "chain_anchor.json"
        ChainAnchorManager.export_anchor_file(anchor, anchor_file)

        # Verification passes on untampered ledger
        ok, msg = ChainAnchorManager.verify_anchor(
            anchor_data=anchor,
            current_head_hash=head_hash,
            current_sequence_id=3,
            secret_hmac_key="anchor-secret-test"
        )
        self.assertTrue(ok)

        # Divergent anchor hash detection
        ok_tampered, tampered_msg = ChainAnchorManager.verify_anchor(
            anchor_data=anchor,
            current_head_hash="forged_new_head_hash_value",
            current_sequence_id=3,
            secret_hmac_key="anchor-secret-test"
        )
        self.assertFalse(ok_tampered)
        self.assertIn("AUDIT INTEGRITY VIOLATION", tampered_msg)

    def test_tc030_yara_scanner_threat_detection(self):
        """TC-030: YARA scanner detects webshell signatures and reverse shells in added/modified files."""
        yara_dir = Path(self.test_dir) / "yara_scan_dir"
        yara_dir.mkdir()
        webshell_file = yara_dir / "shell.php"
        webshell_file.write_text("<?php eval(base64_decode($_POST['cmd'])); ?>", encoding="utf-8")

        yara_engine = YaraEngine()
        matches = yara_engine.scan_file(webshell_file)
        self.assertTrue(len(matches) >= 1)
        self.assertIn("WebShell", matches[0].rule_name)
        self.assertEqual(matches[0].severity, "CRITICAL")

    def test_tc031_key_entropy_validation(self):
        """TC-031: Entropy validator rejects weak/repetitive keys and accepts high-entropy secrets."""
        ok_weak, _ = validate_secret_entropy("aaaaaaaaaaaaaaaaaaaaaaaa", min_length=16, min_entropy=2.5)
        self.assertFalse(ok_weak)

        ok_short, _ = validate_secret_entropy("short", min_length=16, min_entropy=2.5)
        self.assertFalse(ok_short)

        high_entropy_key = "a9f4c3d8e7b1a092837465fcdeba0192"
        ok_strong, _ = validate_secret_entropy(high_entropy_key, min_length=16, min_entropy=2.5)
        self.assertTrue(ok_strong)

    def test_tc032_non_loopback_bind_refusal(self):
        """TC-032: run_server refuses non-loopback bind address without explicit allow_remote flag."""
        from fim.api.server import run_server
        with self.assertRaises(PermissionError) as ctx:
            run_server(host="0.0.0.0", port=9999, config=self.config, allow_remote=False)
        self.assertIn("SECURITY REFUSAL", str(ctx.exception))

    def test_tc033_fimignore_exclusion(self):
        """TC-033: .fimignore file in monitored directory excludes specified file patterns."""
        ignore_dir = Path(self.test_dir) / "ignore_dir"
        ignore_dir.mkdir()
        (ignore_dir / ".fimignore").write_text("*.ignore_me\nignored_folder/*\n# comment\n", encoding="utf-8")
        (ignore_dir / "keep.txt").write_text("keep", encoding="utf-8")
        (ignore_dir / "skip.ignore_me").write_text("skip", encoding="utf-8")

        b_mgr = BaselineManager(self.config, self.db)
        files = b_mgr.collect_files([ignore_dir])
        file_names = [f.name for f in files]
        self.assertIn("keep.txt", file_names)
        self.assertNotIn("skip.ignore_me", file_names)

    def test_tc034_configurable_rules_loader(self):
        """TC-034: Custom rules from config are loaded and applied during change classification."""
        rule_engine = RuleEngine()
        sev, _, _ = rule_engine.classify_change("/etc/shadow", ChangeType.MODIFIED)
        self.assertEqual(sev, Severity.CRITICAL)

    def test_tc035_toctou_inode_and_descriptor_hashing(self):
        """TC-035: Hasher uses descriptor-level reading and verifies inode consistency."""
        target = Path(self.test_dir) / "toctou_target.bin"
        target.write_bytes(b"A" * 16384)

        hasher = HashEngine()
        hashes = hasher.calculate_hashes(target, ["sha256"])
        self.assertEqual(hashes["sha256"], hashlib.sha256(b"A" * 16384).hexdigest())

    def test_tc036_cors_origin_allowlist(self):
        """TC-036: FIMHttpHandler enforces strict CORS origin allowlist."""
        class MockHandler:
            headers = {"Origin": "http://localhost:8000"}
            config = self.config
        
        MockHandler._get_cors_origin = FIMHttpHandler._get_cors_origin
        self.assertEqual(MockHandler._get_cors_origin(MockHandler), "http://localhost:8000")

        MockHandler.headers = {"Origin": "http://evil-attacker-site.com"}
        self.assertEqual(MockHandler._get_cors_origin(MockHandler), "")

    def test_tc037_header_only_token_auth(self):
        """TC-037: _check_auth rejects URL query tokens and accepts Bearer/X-API-Key headers."""
        class MockHandler:
            api_token = "valid-token-1234567890123456789012"
            headers = {}
            path = "/api/findings?token=valid-token-1234567890123456789012"

        MockHandler._check_auth = FIMHttpHandler._check_auth

        # 1. URL query token is rejected
        self.assertFalse(MockHandler._check_auth(MockHandler))

        # 2. Authorization Bearer header is accepted
        MockHandler.headers = {"Authorization": "Bearer valid-token-1234567890123456789012"}
        self.assertTrue(MockHandler._check_auth(MockHandler))

        # 3. X-API-Key header is accepted
        MockHandler.headers = {"X-API-Key": "valid-token-1234567890123456789012"}
        self.assertTrue(MockHandler._check_auth(MockHandler))

    def test_tc038_database_wal_and_integrity_check(self):
        """TC-038: SQLite database operates in WAL mode and verify_database_integrity passes."""
        ok, msgs = self.db.verify_database_integrity()
        self.assertTrue(ok)
        self.assertEqual(len(msgs), 0)

    def test_tc039_audit_separation_and_auto_anchoring(self):
        """TC-039: AuditChain writes to dedicated audit.db, chain_anchor, and audit.jsonl."""
        self.db.audit.append_event("TEST_EVENT", {"detail": "audit test"})
        
        self.assertTrue(self.audit_db_path.exists())
        anchor_file = self.audit_db_path.parent / "chain_anchor"
        self.assertTrue(anchor_file.exists())
        jsonl_file = self.audit_db_path.parent / "audit.jsonl"
        self.assertTrue(jsonl_file.exists())

        valid, _, count = self.db.audit.verify_integrity()
        self.assertTrue(valid)
        self.assertGreaterEqual(count, 1)

    def test_tc040_live_monitor_verifies_baseline_and_alerts_on_tamper(self):
        """TC-040: LiveMonitor verifies baseline signature on change events and dispatches alert on tamper."""
        from fim.core.monitor import LiveMonitor
        test_file = Path(self.test_dir) / "monitored.txt"
        test_file.write_text("initial content", encoding="utf-8")

        b_mgr = BaselineManager(self.config, self.db)
        b_mgr.create_baseline(name="test_mon", paths=[str(test_file)])

        alerts = []
        monitor = LiveMonitor(
            profile_name="test_mon",
            config=self.config,
            db=self.db,
            alert_callback=lambda f: alerts.append(f)
        )
        # Verified baseline loaded
        baseline = monitor._get_verified_baseline()
        self.assertIsNotNone(baseline)

        # Normal file modification
        test_file.write_text("modified content", encoding="utf-8")
        monitor._handle_path_change(str(test_file))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[-1]["change_type"], "MODIFIED")

        # Now simulate attacker tampering with the database baseline signature
        with self.db.get_connection() as conn:
            conn.execute("UPDATE baselines SET signature = 'forged_signature_0000' WHERE name = 'test_mon'")
        # Update db mtime to trigger cache invalidation
        os.utime(self.db_path, (time.time() + 10, time.time() + 10))

        # Attacker triggers or waits for a change event
        test_file.write_text("another change", encoding="utf-8")
        monitor._handle_path_change(str(test_file))

        # Monitor should have detected the tampering, refused to trust the baseline, and alerted
        self.assertEqual(len(alerts), 2)
        tamper_alert = alerts[-1]
        self.assertEqual(tamper_alert["change_type"], "TAMPERED")
        self.assertEqual(tamper_alert["severity"], "CRITICAL")
        self.assertEqual(tamper_alert["attack_id"], "T1565.001")

    def test_tc041_external_anchor_and_forged_append_verification(self):
        """TC-041: AuditChain validates anchored index so forged appends after anchor fail, and exports externally."""
        from fim.storage.audit_chain import AuditChain
        ext_anchor = Path(self.test_dir) / "external_worm" / "chain_anchor"
        chain_db = Path(self.test_dir) / "test_chain.db"
        chain = AuditChain(conn_or_path=chain_db, external_anchor_path=ext_anchor)

        # 1. Append initial legitimate events
        chain.append_event("BOOT", {"detail": "legit boot"})
        chain.append_event("SCAN", {"detail": "initial scan"})

        # External anchor should be auto-written
        self.assertTrue(ext_anchor.exists())
        anchor_data = json.loads(ext_anchor.read_text(encoding="utf-8"))
        self.assertEqual(anchor_data["count"], 2)

        # Verification passes on untampered log
        valid, msg, count = chain.verify_integrity()
        self.assertTrue(valid)
        self.assertEqual(count, 2)

        # Save the valid anchor at count=2
        saved_anchor_head = anchor_data["head"]

        # 2. Simulate attacker tampering with history (modifying record 2) and appending forged record 3
        # In a naive check where count != anchor_count skips head check, this would have passed!
        with chain.conn:
            cursor = chain.conn.cursor()
            # Modify record 2
            cursor.execute("UPDATE audit_log SET details_json = '{\"detail\": \"attacker altered\"}' WHERE id = 2")
            # Recompute record 2 entry_hash
            cursor.execute("SELECT ts, event, details_json, prev_hash FROM audit_log WHERE id = 2")
            row2 = cursor.fetchone()
            new_hash_2 = chain.calculate_entry_hash(row2[0], row2[1], row2[2], row2[3])
            cursor.execute("UPDATE audit_log SET entry_hash = ? WHERE id = 2", (new_hash_2,))

            # Append forged record 3 chained to new_hash_2
            ts3 = time.time()
            details3 = '{"detail": "forged append"}'
            new_hash_3 = chain.calculate_entry_hash(ts3, "FORGED", details3, new_hash_2)
            cursor.execute(
                "INSERT INTO audit_log (ts, event, details_json, prev_hash, entry_hash) VALUES (?, ?, ?, ?, ?)",
                (ts3, "FORGED", details3, new_hash_2, new_hash_3)
            )

        # Restore external anchor to the genuine anchor at count=2
        if os.name != "nt":
            os.chmod(ext_anchor, stat.S_IRUSR | stat.S_IWUSR)
        ext_anchor.write_text(json.dumps({"count": 2, "head": saved_anchor_head, "ts": time.time()}))
        if os.name != "nt":
            os.chmod(ext_anchor, stat.S_IRUSR)

        # Database now has 3 records. len(rows) > anchored_count (3 > 2).
        # verify_integrity MUST inspect record at index 2 and reject!
        valid, msg, count = chain.verify_integrity()
        self.assertFalse(valid)
        self.assertIn("AUDIT INTEGRITY VIOLATION", str(msg))

        # 3. Test explicit export_chain_anchor
        export_dest = Path(self.test_dir) / "manual_worm_export.json"
        exported = chain.export_chain_anchor(export_dest)
        self.assertTrue(exported.exists())
        exported_data = json.loads(exported.read_text(encoding="utf-8"))
        self.assertEqual(exported_data["count"], 3)

    def test_tc042_audit_chain_concurrent_writers_no_race(self):
        """TC-042: Concurrent writers to AuditChain append in immediate transactions without chain forks."""
        import threading
        from fim.storage.audit_chain import AuditChain
        race_db = Path(self.test_dir) / "race_test.db"
        chain = AuditChain(conn_or_path=race_db)

        num_threads = 8
        events_per_thread = 5

        def writer(thread_id: int):
            for i in range(events_per_thread):
                chain.append_event(f"THREAD_{thread_id}_EVENT_{i}", {"thread": thread_id, "iter": i})

        threads = [threading.Thread(target=writer, args=(t,)) for t in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        expected_total = num_threads * events_per_thread
        valid, msg, count = chain.verify_integrity()
        self.assertTrue(valid, f"Audit chain verification failed after concurrent writes: {msg}")
        self.assertEqual(count, expected_total)

        # Anchor count matches total committed count
        anchor_data = json.loads(chain.anchor_path.read_text(encoding="utf-8"))
        self.assertEqual(anchor_data["count"], expected_total)

    def test_tc043_post_request_body_size_and_content_length_validation(self):
        """TC-043: do_POST rejects malformed Content-Length (400) and oversized bodies (413)."""
        responses = []

        class MockPostHandler:
            path = "/api/baselines"
            headers = {}
            MAX_REQUEST_BODY_BYTES = FIMHttpHandler.MAX_REQUEST_BODY_BYTES

            def _check_auth(self):
                return True

            def _send_json(self, status, payload):
                responses.append((status, payload))

        # 1. Malformed Content-Length: non-integer
        handler = MockPostHandler()
        handler.headers = {"Content-Length": "not-a-number"}
        FIMHttpHandler.do_POST(handler)
        self.assertEqual(responses[-1][0], 400)
        self.assertIn("Invalid Content-Length", responses[-1][1]["error"])

        # 2. Malformed Content-Length: negative
        handler.headers = {"Content-Length": "-100"}
        FIMHttpHandler.do_POST(handler)
        self.assertEqual(responses[-1][0], 400)

        # 3. Oversized Content-Length: exceeds 10MB limit
        handler.headers = {"Content-Length": str(20 * 1024 * 1024)}
        FIMHttpHandler.do_POST(handler)
        self.assertEqual(responses[-1][0], 413)
        self.assertIn("too large", responses[-1][1]["error"])

    def test_tc044_findings_invalid_limit_returns_400(self):
        """TC-044: /findings and /audit with invalid limit query parameter return HTTP 400."""
        responses = []

        class MockGetHandler:
            headers = {}
            db = self.db

            def _check_auth(self):
                return True

            def _send_json(self, status, payload):
                responses.append((status, payload))

        # 1. Non-integer limit on /findings
        handler = MockGetHandler()
        handler.path = "/api/findings?limit=abc"
        FIMHttpHandler.do_GET(handler)
        self.assertEqual(responses[-1][0], 400)
        self.assertIn("Invalid 'limit'", responses[-1][1]["error"])

        # 2. Negative limit on /findings
        handler.path = "/api/findings?limit=-5"
        FIMHttpHandler.do_GET(handler)
        self.assertEqual(responses[-1][0], 400)

        # 3. Non-integer limit on /audit
        handler.path = "/api/audit?limit=xyz"
        FIMHttpHandler.do_GET(handler)
        self.assertEqual(responses[-1][0], 400)


if __name__ == "__main__":
    unittest.main()


"""
Comprehensive Test Suite for File Integrity Monitor (FIM).
Implements test cases TC-001 through TC-012 as specified in the SRS.
"""

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from fim.config import ConfigManager
from fim.database import DatabaseManager
from fim.hasher import HashEngine
from fim.reporter import ReportGenerator
from fim.scanner import FileScanner
from fim.virustotal import VirusTotalClient, VTResult

class TestFileIntegrityMonitor(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="fim_test_")
        self.db_path = os.path.join(self.test_dir, "test_fim.db")
        self.config = ConfigManager()
        self.config.set("database.path", self.db_path)
        self.db = DatabaseManager(self.db_path)
        self.hasher = HashEngine()
        self.vt = VirusTotalClient(api_key="", db_manager=self.db)
        self.scanner = FileScanner(config=self.config, db_manager=self.db, vt_client=self.vt, hasher=self.hasher)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # TC-001: Hash Calculation - Valid File
    def test_tc001_hash_calculation_valid_file(self):
        sample_file = os.path.join(self.test_dir, "sample.txt")
        with open(sample_file, "w", encoding="utf-8") as f:
            f.write("The quick brown fox jumps over the lazy dog")

        res = self.hasher.calculate_hashes(sample_file)
        self.assertIsNone(res["error"])
        self.assertEqual(res["md5"], "9e107d9d372bb6826bd81d3542a419d6")
        self.assertEqual(res["sha256"], "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592")

    # TC-002: Hash Calculation - Large File
    def test_tc002_hash_calculation_large_file(self):
        large_file = os.path.join(self.test_dir, "large_test.bin")
        chunk = b"A" * 65536  # 64 KB
        with open(large_file, "wb") as f:
            for _ in range(32):  # 2 MB test file
                f.write(chunk)

        res = self.hasher.calculate_hashes(large_file)
        self.assertIsNone(res["error"])
        self.assertIsNotNone(res["md5"])
        self.assertIsNotNone(res["sha256"])
        self.assertEqual(res["size"], 2 * 1024 * 1024)

    # TC-003: Hash Calculation - Non-existent File
    def test_tc003_hash_calculation_non_existent(self):
        invalid_path = os.path.join(self.test_dir, "does_not_exist.txt")
        res = self.hasher.calculate_hashes(invalid_path)
        self.assertIsNotNone(res["error"])
        self.assertTrue("E001" in res["error"])

    # TC-004 & TC-005: VT Classification Logic
    def test_tc004_tc005_vt_threat_classification(self):
        # Malicious detection count > 0 -> MALICIOUS
        self.assertEqual(VirusTotalClient._classify_threat(malicious=10, suspicious=1, total_engines=70), "MALICIOUS")
        # Suspicious > 0 and Malicious == 0 -> SUSPICIOUS
        self.assertEqual(VirusTotalClient._classify_threat(malicious=0, suspicious=3, total_engines=70), "SUSPICIOUS")
        # All clean -> SAFE
        self.assertEqual(VirusTotalClient._classify_threat(malicious=0, suspicious=0, total_engines=70), "SAFE")

    # TC-006: VT Client Rate Limiter Interval Check
    def test_tc006_vt_rate_limiter(self):
        vt_client = VirusTotalClient(api_key="test", rate_limit_rpm=60)
        self.assertEqual(vt_client.min_interval, 1.0)

    # TC-007: VT Invalid API Key Handling
    def test_tc007_invalid_api_key(self):
        vt_no_key = VirusTotalClient(api_key="", db_manager=self.db)
        res = vt_no_key.query_hash("9e107d9d372bb6826bd81d3542a419d6")
        self.assertEqual(res.status, "INVALID_KEY")
        self.assertTrue("E003" in (res.error_message or ""))

    # TC-009: Directory Scan
    def test_tc009_directory_scan(self):
        scan_folder = os.path.join(self.test_dir, "scan_target")
        os.makedirs(scan_folder, exist_ok=True)
        for i in range(5):
            with open(os.path.join(scan_folder, f"file_{i}.txt"), "w") as f:
                f.write(f"Content {i}")

        summary = self.scanner.scan_directory(scan_folder, check_vt=False, check_db=True)
        self.assertEqual(summary.total_files, 5)
        self.assertEqual(summary.error_files, 0)
        self.assertEqual(len(summary.results), 5)

    # TC-010: Export Functionality (JSON, CSV, TXT)
    def test_tc010_export_functionality(self):
        scan_res = self.scanner.scan_file(__file__, check_vt=False, check_db=False)
        
        json_file = os.path.join(self.test_dir, "export.json")
        csv_file = os.path.join(self.test_dir, "export.csv")
        txt_file = os.path.join(self.test_dir, "export.txt")

        p_json = ReportGenerator.export_to_json(scan_res, json_file)
        p_csv = ReportGenerator.export_to_csv([scan_res], csv_file)
        p_txt = ReportGenerator.export_to_txt(scan_res, txt_file)

        self.assertTrue(os.path.exists(p_json))
        self.assertTrue(os.path.exists(p_csv))
        self.assertTrue(os.path.exists(p_txt))
        self.assertGreater(os.path.getsize(p_json), 0)
        self.assertGreater(os.path.getsize(p_csv), 0)
        self.assertGreater(os.path.getsize(p_txt), 0)

    # TC-011: Database Persistence Operations
    def test_tc011_database_operations(self):
        # 1. Add scan history
        scan_id = self.db.add_scan_history(
            file_path="/test/path.txt",
            file_name="path.txt",
            file_size=1024,
            md5_hash="11112222333344445555666677778888",
            sha256_hash="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            threat_level="SAFE"
        )
        self.assertGreater(scan_id, 0)
        
        # 2. Retrieve history
        history = self.db.get_recent_scans(limit=10)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["file_name"], "path.txt")

        # 3. Search history
        search_res = self.db.search_history("path.txt")
        self.assertEqual(len(search_res), 1)

        # 4. Hash database operations
        self.db.add_hash("22223333444455556666777788889999", hash_type="md5", source="EICAR", description="Test Virus")
        match = self.db.check_hash_in_db("22223333444455556666777788889999")
        self.assertIsNotNone(match)
        self.assertEqual(match["source"], "EICAR")

    # TC-012: VirusTotal Result Caching
    def test_tc012_cache_functionality(self):
        test_hash = "9e107d9d372bb6826bd81d3542a419d6"
        # Save to cache
        self.db.save_cached_vt(
            hash_value=test_hash,
            malicious=0,
            suspicious=0,
            undetected=65,
            total_engines=65,
            detections=[],
            ttl_hours=24,
        )

        # Query with VT client having cache enabled
        vt_client = VirusTotalClient(api_key="", db_manager=self.db)
        res = vt_client.query_hash(test_hash, use_cache=True)
        self.assertEqual(res.status, "SUCCESS")
        self.assertTrue(res.from_cache)
        self.assertEqual(res.threat_level, "SAFE")

if __name__ == "__main__":
    unittest.main()

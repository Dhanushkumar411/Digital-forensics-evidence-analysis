"""
ForenSight AI - Core Engine Test Suite
Validates hashing, magic bytes, entropy, AI anomaly scoring, duplicate grouping,
signature detection, and cryptographic audit log chain verification.
"""

import unittest
import shutil
import os
from pathlib import Path
from tempfile import mkdtemp

from engines.hash_engine import HashEngine
from engines.evidence_engine import EvidenceEngine
from engines.ai_engine import AIFDEngine
from engines.duplicate_engine import DuplicateEngine
from engines.signature_engine import SignatureEngine
from engines.audit_engine import AuditEngine
from engines.report_engine import ReportEngine
from core.db import DatabaseManager
from core.models import Case, EvidenceItem
from sample_data.generate_samples import generate_all_samples


class TestForensicEngines(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.sample_dir = generate_all_samples()
        cls.test_db_dir = Path(mkdtemp())
        cls.db = DatabaseManager(cls.test_db_dir / "test_forensight.db")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.test_db_dir, ignore_errors=True)

    def test_hash_calculation(self):
        sample_file = self.sample_dir / "incident_briefing.pdf"
        sha256, md5, sha1 = HashEngine.calculate_file_hashes(str(sample_file))
        self.assertEqual(len(sha256), 64)
        self.assertEqual(len(md5), 32)
        self.assertEqual(len(sha1), 40)

        # Integrity verification test
        status, cur_hash = HashEngine.verify_file_integrity(str(sample_file), sha256)
        self.assertEqual(status, "Verified")
        self.assertEqual(cur_hash, sha256)

        # Compromised integrity test
        bad_status, _ = HashEngine.verify_file_integrity(str(sample_file), "0" * 64)
        self.assertEqual(bad_status, "Compromised")

    def test_magic_bytes_and_extension_mismatch(self):
        # Disguised executable named .jpg
        disguised = self.sample_dir / "corporate_financials.jpg"
        det_type, mime, mismatch, note = EvidenceEngine.identify_file_type(str(disguised))
        self.assertIn("Executable", det_type)
        self.assertTrue(mismatch)
        self.assertIsNotNone(note)
        self.assertIn("Binary executable disguise", note)

    def test_entropy_packed_detection(self):
        packed = self.sample_dir / "locked_database_payload.bin"
        entropy = EvidenceEngine.calculate_shannon_entropy(str(packed))
        # High entropy payload should be ~7.9+
        self.assertGreater(entropy, 7.8)

    def test_ai_anomaly_detection(self):
        ai_engine = AIFDEngine()
        disguised = self.sample_dir / "corporate_financials.jpg"
        ev_item = EvidenceEngine.inspect_file(str(disguised), case_id=1)
        res = ai_engine.analyze_evidence(ev_item)

        self.assertGreater(res.anomaly_score, 60.0)
        self.assertIn(res.risk_level, ["High Risk", "Critical Anomaly"])
        self.assertTrue(len(res.reasons) > 0)

    def test_signature_detection(self):
        # Ransomware note
        ransom_note = self.sample_dir / "HOW_TO_DECRYPT_FILES.txt"
        matches = SignatureEngine.scan_file(str(ransom_note))
        self.assertTrue(any(m["rule_id"] == "RULE-RANSOM-01" for m in matches))

        # Webshell
        webshell = self.sample_dir / "wp-content-uploader.php"
        matches_ws = SignatureEngine.scan_file(str(webshell))
        self.assertTrue(any(m["rule_id"] == "RULE-WEBSHELL-01" for m in matches_ws))

    def test_duplicate_engine(self):
        f1 = self.sample_dir / "backup_archive_primary.zip"
        f2 = self.sample_dir / "backup_archive_secondary.zip"
        ev1 = EvidenceEngine.inspect_file(str(f1), case_id=1)
        ev2 = EvidenceEngine.inspect_file(str(f2), case_id=1)

        dups = DuplicateEngine.find_duplicates([ev1, ev2])
        self.assertEqual(len(dups), 1)
        self.assertEqual(dups[0].count, 2)
        self.assertEqual(dups[0].sha256, ev1.sha256)

    def test_cryptographic_audit_chain(self):
        audit_engine = AuditEngine(self.db)
        audit_engine.log_event("Analyst_A", "EVIDENCE_IMPORT", "sample.bin", {"bytes": 1024})
        audit_engine.log_event("Analyst_A", "HASH_VERIFY", "sample.bin", {"result": "OK"})

        report = audit_engine.verify_chain()
        self.assertTrue(report["is_valid"])
        self.assertGreaterEqual(report["total_records_checked"], 2)


if __name__ == "__main__":
    unittest.main()

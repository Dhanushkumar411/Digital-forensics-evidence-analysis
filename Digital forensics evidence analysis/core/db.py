"""
ForenSight AI - SQLite Database Manager
Provides persistent, thread-safe storage for forensic cases, evidence,
AI analysis results, duplicate clusters, and cryptographic audit logs.
"""

import sqlite3
import json
import hashlib
from typing import List, Optional, Dict, Any, Tuple
from pathlib import Path
from datetime import datetime

from config import DATABASE_PATH
from core.models import Case, EvidenceItem, AnomalyResult, AuditLogEntry, DuplicateGroup


class DatabaseManager:
    """Manages SQLite database connections and forensic record transactions."""

    def __init__(self, db_path: Path = DATABASE_PATH):
        self.db_path = db_path
        self.init_db()

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        return conn

    def init_db(self):
        """Initialize database tables, indices, and default baseline data."""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Cases Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_number TEXT UNIQUE NOT NULL,
                title TEXT NOT NULL,
                investigator_name TEXT NOT NULL,
                organization TEXT NOT NULL,
                description TEXT,
                status TEXT DEFAULT 'Active',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """)

            # Evidence Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL,
                file_name TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                file_ext TEXT,
                mime_type TEXT,
                detected_type TEXT,
                sha256 TEXT NOT NULL,
                md5 TEXT,
                sha1 TEXT,
                integrity_status TEXT DEFAULT 'Verified',
                created_time TEXT,
                modified_time TEXT,
                accessed_time TEXT,
                entropy REAL DEFAULT 0.0,
                extension_mismatch INTEGER DEFAULT 0,
                is_duplicate INTEGER DEFAULT 0,
                duplicate_group_id INTEGER,
                anomaly_score REAL DEFAULT 0.0,
                risk_level TEXT DEFAULT 'Benign',
                is_suspicious INTEGER DEFAULT 0,
                flagged_reasons TEXT,
                acquisition_date TEXT,
                custody_source TEXT,
                custody_notes TEXT,
                tags TEXT,
                FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
            );
            """)

            # AI Analysis Records Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS ai_analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id INTEGER NOT NULL,
                anomaly_score REAL NOT NULL,
                risk_level TEXT NOT NULL,
                algorithm TEXT NOT NULL,
                feature_vector_json TEXT,
                reasons_json TEXT,
                signature_matches_json TEXT,
                analyzed_at TEXT NOT NULL,
                FOREIGN KEY (evidence_id) REFERENCES evidence(id) ON DELETE CASCADE
            );
            """)

            # Cryptographically chained Audit Log Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                case_id INTEGER,
                investigator TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT,
                details_json TEXT,
                prev_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL,
                FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE SET NULL
            );
            """)

            # Investigator Profiles Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS investigators (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                full_name TEXT NOT NULL,
                role TEXT NOT NULL,
                badge_id TEXT,
                created_at TEXT NOT NULL
            );
            """)

            # Indices for rapid forensic searches
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_evidence_sha256 ON evidence(sha256);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_evidence_risk ON evidence(risk_level);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_case ON audit_logs(case_id);")

            conn.commit()

        # Ensure default case and investigator exist
        self._ensure_defaults()

    def _ensure_defaults(self):
        """Ensures at least one active default case and default investigator exist."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM cases;")
            if cursor.fetchone()[0] == 0:
                now = datetime.now().isoformat()
                cursor.execute("""
                INSERT INTO cases (case_number, title, investigator_name, organization, description, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    "CASE-2026-001",
                    "Incident Response: Suspicious System Intrusion",
                    "Agent Vance (Chief Investigator)",
                    "Digital Forensics & Incident Response Lab",
                    "Primary digital evidence analysis case for triage and artifact verification.",
                    "Active",
                    now,
                    now
                ))
                default_case_id = cursor.lastrowid

                # Default investigator
                cursor.execute("""
                INSERT INTO investigators (username, full_name, role, badge_id, created_at)
                VALUES (?, ?, ?, ?, ?)
                """, ("chief_forensic", "Agent Vance", "Lead Forensic Analyst", "DFIR-9842", now))

                # Initialize Genesis audit log entry using the uniform chain hashing formula
                details = {"description": "Forensic database and initial case registered"}
                details_json = json.dumps(details, sort_keys=True)
                hasher = hashlib.sha256()
                hasher.update(("0" * 64).encode("utf-8"))
                hasher.update(now.encode("utf-8"))
                hasher.update("Agent Vance".encode("utf-8"))
                hasher.update("CASE_INITIALIZED".encode("utf-8"))
                hasher.update("CASE-2026-001".encode("utf-8"))
                hasher.update(details_json.encode("utf-8"))
                genesis_hash = hasher.hexdigest()

                cursor.execute("""
                INSERT INTO audit_logs (timestamp, case_id, investigator, action, target, details_json, prev_hash, entry_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    now,
                    default_case_id,
                    "Agent Vance",
                    "CASE_INITIALIZED",
                    "CASE-2026-001",
                    details_json,
                    "0" * 64,
                    genesis_hash
                ))
                conn.commit()

    # --- Cases CRUD ---
    def create_case(self, case: Case) -> int:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO cases (case_number, title, investigator_name, organization, description, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                case.case_number, case.title, case.investigator_name, case.organization,
                case.description, case.status, case.created_at, case.updated_at
            ))
            conn.commit()
            return cursor.lastrowid

    def get_cases(self) -> List[Case]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM cases ORDER BY id DESC")
            rows = cursor.fetchall()
            return [Case(**dict(r)) for r in rows]

    def get_case(self, case_id: int) -> Optional[Case]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM cases WHERE id = ?", (case_id,))
            row = cursor.fetchone()
            return Case(**dict(row)) if row else None

    # --- Evidence CRUD ---
    def insert_evidence(self, item: EvidenceItem) -> int:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO evidence (
                case_id, file_name, file_path, file_size, file_ext, mime_type, detected_type,
                sha256, md5, sha1, integrity_status, created_time, modified_time, accessed_time,
                entropy, extension_mismatch, is_duplicate, duplicate_group_id, anomaly_score,
                risk_level, is_suspicious, flagged_reasons, acquisition_date, custody_source,
                custody_notes, tags
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                item.case_id, item.file_name, item.file_path, item.file_size, item.file_ext,
                item.mime_type, item.detected_type, item.sha256, item.md5, item.sha1,
                item.integrity_status, item.created_time, item.modified_time, item.accessed_time,
                item.entropy, 1 if item.extension_mismatch else 0, 1 if item.is_duplicate else 0,
                item.duplicate_group_id, item.anomaly_score, item.risk_level,
                1 if item.is_suspicious else 0, item.flagged_reasons_json(),
                item.acquisition_date, item.custody_source, item.custody_notes, item.tags_json()
            ))
            conn.commit()
            return cursor.lastrowid

    def update_evidence(self, item: EvidenceItem):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            UPDATE evidence SET
                file_name=?, file_path=?, file_size=?, file_ext=?, mime_type=?, detected_type=?,
                sha256=?, md5=?, sha1=?, integrity_status=?, created_time=?, modified_time=?, accessed_time=?,
                entropy=?, extension_mismatch=?, is_duplicate=?, duplicate_group_id=?, anomaly_score=?,
                risk_level=?, is_suspicious=?, flagged_reasons=?, acquisition_date=?, custody_source=?,
                custody_notes=?, tags=?
            WHERE id=?
            """, (
                item.file_name, item.file_path, item.file_size, item.file_ext, item.mime_type, item.detected_type,
                item.sha256, item.md5, item.sha1, item.integrity_status, item.created_time, item.modified_time, item.accessed_time,
                item.entropy, 1 if item.extension_mismatch else 0, 1 if item.is_duplicate else 0,
                item.duplicate_group_id, item.anomaly_score, item.risk_level,
                1 if item.is_suspicious else 0, item.flagged_reasons_json(),
                item.acquisition_date, item.custody_source, item.custody_notes, item.tags_json(),
                item.id
            ))
            conn.commit()

    def get_evidence_list(self, case_id: int) -> List[EvidenceItem]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM evidence WHERE case_id = ? ORDER BY id DESC", (case_id,))
            rows = cursor.fetchall()
            items = []
            for r in rows:
                d = dict(r)
                d["extension_mismatch"] = bool(d["extension_mismatch"])
                d["is_duplicate"] = bool(d["is_duplicate"])
                d["is_suspicious"] = bool(d["is_suspicious"])
                d["flagged_reasons"] = json.loads(d["flagged_reasons"]) if d["flagged_reasons"] else []
                d["tags"] = json.loads(d["tags"]) if d["tags"] else []
                items.append(EvidenceItem(**d))
            return items

    def get_evidence_by_id(self, evidence_id: int) -> Optional[EvidenceItem]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM evidence WHERE id = ?", (evidence_id,))
            r = cursor.fetchone()
            if not r:
                return None
            d = dict(r)
            d["extension_mismatch"] = bool(d["extension_mismatch"])
            d["is_duplicate"] = bool(d["is_duplicate"])
            d["is_suspicious"] = bool(d["is_suspicious"])
            d["flagged_reasons"] = json.loads(d["flagged_reasons"]) if d["flagged_reasons"] else []
            d["tags"] = json.loads(d["tags"]) if d["tags"] else []
            return EvidenceItem(**d)

    def delete_evidence(self, evidence_id: int):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM evidence WHERE id = ?", (evidence_id,))
            conn.commit()

    # --- Duplicate Analysis Queries ---
    def get_duplicates_by_case(self, case_id: int) -> List[DuplicateGroup]:
        """Identifies duplicate files sharing identical SHA-256 hashes within a case."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT sha256, COUNT(*) as cnt, file_size
            FROM evidence
            WHERE case_id = ?
            GROUP BY sha256
            HAVING cnt > 1
            ORDER BY cnt DESC, file_size DESC
            """, (case_id,))
            rows = cursor.fetchall()
            
            groups: List[DuplicateGroup] = []
            for r in rows:
                sha256 = r["sha256"]
                cnt = r["cnt"]
                file_size = r["file_size"]
                
                # Fetch items
                cursor.execute("SELECT * FROM evidence WHERE case_id = ? AND sha256 = ?", (case_id, sha256))
                item_rows = cursor.fetchall()
                items = []
                for ir in item_rows:
                    d = dict(ir)
                    d["extension_mismatch"] = bool(d["extension_mismatch"])
                    d["is_duplicate"] = True
                    d["is_suspicious"] = bool(d["is_suspicious"])
                    d["flagged_reasons"] = json.loads(d["flagged_reasons"]) if d["flagged_reasons"] else []
                    d["tags"] = json.loads(d["tags"]) if d["tags"] else []
                    items.append(EvidenceItem(**d))

                wasted_bytes = (cnt - 1) * file_size
                groups.append(DuplicateGroup(
                    sha256=sha256,
                    file_size=file_size,
                    count=cnt,
                    items=items,
                    total_wasted_bytes=wasted_bytes
                ))
            return groups

    # --- AI Analysis Records ---
    def save_ai_analysis(self, result: AnomalyResult) -> int:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO ai_analyses (
                evidence_id, anomaly_score, risk_level, algorithm,
                feature_vector_json, reasons_json, signature_matches_json, analyzed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                result.evidence_id, result.anomaly_score, result.risk_level, result.algorithm,
                json.dumps(result.feature_vector), json.dumps(result.reasons),
                json.dumps(result.signature_matches), result.analyzed_at
            ))
            conn.commit()
            return cursor.lastrowid

    # --- Cryptographic Audit Trail ---
    def add_audit_log(self, investigator: str, action: str, target: str, details: Dict[str, Any], case_id: Optional[int] = None) -> AuditLogEntry:
        """
        Creates a new audit record cryptographically bound to the previous entry hash.
        prev_hash + timestamp + investigator + action + target + details -> entry_hash
        """
        now = datetime.now().isoformat()
        details_json = json.dumps(details, sort_keys=True)

        with self.get_connection() as conn:
            cursor = conn.cursor()
            # Fetch the latest entry hash to maintain the cryptographic chain
            cursor.execute("SELECT entry_hash FROM audit_logs ORDER BY id DESC LIMIT 1")
            last_entry = cursor.fetchone()
            prev_hash = last_entry["entry_hash"] if last_entry else ("0" * 64)

            # Compute new block hash
            hasher = hashlib.sha256()
            hasher.update(prev_hash.encode("utf-8"))
            hasher.update(now.encode("utf-8"))
            hasher.update(investigator.encode("utf-8"))
            hasher.update(action.encode("utf-8"))
            hasher.update((target or "").encode("utf-8"))
            hasher.update(details_json.encode("utf-8"))
            entry_hash = hasher.hexdigest()

            cursor.execute("""
            INSERT INTO audit_logs (timestamp, case_id, investigator, action, target, details_json, prev_hash, entry_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (now, case_id, investigator, action, target, details_json, prev_hash, entry_hash))
            log_id = cursor.lastrowid
            conn.commit()

            return AuditLogEntry(
                id=log_id,
                timestamp=now,
                case_id=case_id,
                investigator=investigator,
                action=action,
                target=target,
                details=details,
                prev_hash=prev_hash,
                entry_hash=entry_hash,
                is_valid=True
            )

    def get_audit_logs(self, case_id: Optional[int] = None) -> List[AuditLogEntry]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if case_id:
                cursor.execute("SELECT * FROM audit_logs WHERE case_id = ? OR case_id IS NULL ORDER BY id DESC", (case_id,))
            else:
                cursor.execute("SELECT * FROM audit_logs ORDER BY id DESC")
            rows = cursor.fetchall()
            logs = []
            for r in rows:
                d = dict(r)
                details = json.loads(d["details_json"]) if d["details_json"] else {}
                logs.append(AuditLogEntry(
                    id=d["id"],
                    timestamp=d["timestamp"],
                    case_id=d["case_id"],
                    investigator=d["investigator"],
                    action=d["action"],
                    target=d["target"],
                    details=details,
                    prev_hash=d["prev_hash"],
                    entry_hash=d["entry_hash"],
                    is_valid=True
                ))
            return logs

    def verify_audit_chain(self) -> Tuple[bool, int, Optional[str]]:
        """
        Validates the entire audit chain from genesis to head.
        Returns: (is_valid, total_checked, error_message)
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM audit_logs ORDER BY id ASC")
            rows = cursor.fetchall()
            if not rows:
                return True, 0, None

            expected_prev_hash = "0" * 64
            for idx, r in enumerate(rows):
                # Verify link to previous entry
                if idx > 0 and r["prev_hash"] != expected_prev_hash:
                    return False, idx, f"Broken chain link at log ID {r['id']}: expected prev_hash {expected_prev_hash[:12]}..., got {r['prev_hash'][:12]}..."

                # Recalculate hash of current entry
                details_json = r["details_json"] or "{}"
                # Ensure JSON string format parity
                try:
                    parsed = json.loads(details_json)
                    normalized_details = json.dumps(parsed, sort_keys=True)
                except Exception:
                    normalized_details = details_json

                hasher = hashlib.sha256()
                hasher.update(r["prev_hash"].encode("utf-8"))
                hasher.update(r["timestamp"].encode("utf-8"))
                hasher.update(r["investigator"].encode("utf-8"))
                hasher.update(r["action"].encode("utf-8"))
                hasher.update((r["target"] or "").encode("utf-8"))
                hasher.update(normalized_details.encode("utf-8"))
                recomputed_hash = hasher.hexdigest()

                if recomputed_hash != r["entry_hash"]:
                    # Note: if JSON serialization order was different, try with raw string
                    raw_hasher = hashlib.sha256()
                    raw_hasher.update(r["prev_hash"].encode("utf-8"))
                    raw_hasher.update(r["timestamp"].encode("utf-8"))
                    raw_hasher.update(r["investigator"].encode("utf-8"))
                    raw_hasher.update(r["action"].encode("utf-8"))
                    raw_hasher.update((r["target"] or "").encode("utf-8"))
                    raw_hasher.update(details_json.encode("utf-8"))
                    if raw_hasher.hexdigest() != r["entry_hash"]:
                        return False, idx, f"Tampered audit entry at log ID {r['id']}: cryptographic hash mismatch!"

                expected_prev_hash = r["entry_hash"]

            return True, len(rows), None

    # --- Dashboard Metrics Aggregation ---
    def get_case_statistics(self, case_id: int) -> Dict[str, Any]:
        """Computes comprehensive forensic metrics for dashboard widgets."""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Total evidence
            cursor.execute("SELECT COUNT(*), COALESCE(SUM(file_size), 0) FROM evidence WHERE case_id = ?", (case_id,))
            total_count, total_bytes = cursor.fetchone()

            # Integrity counts
            cursor.execute("SELECT integrity_status, COUNT(*) FROM evidence WHERE case_id = ? GROUP BY integrity_status", (case_id,))
            integrity_map = dict(cursor.fetchall())

            # Risk levels
            cursor.execute("SELECT risk_level, COUNT(*) FROM evidence WHERE case_id = ? GROUP BY risk_level", (case_id,))
            risk_map = dict(cursor.fetchall())

            # Suspicious & Anomalies
            cursor.execute("SELECT COUNT(*) FROM evidence WHERE case_id = ? AND is_suspicious = 1", (case_id,))
            suspicious_count = cursor.fetchone()[0]

            # Extension mismatches
            cursor.execute("SELECT COUNT(*) FROM evidence WHERE case_id = ? AND extension_mismatch = 1", (case_id,))
            mismatch_count = cursor.fetchone()[0]

            # File extensions breakdown
            cursor.execute("""
            SELECT COALESCE(file_ext, 'no-ext') as ext, COUNT(*) as cnt
            FROM evidence
            WHERE case_id = ?
            GROUP BY ext
            ORDER BY cnt DESC
            LIMIT 8
            """, (case_id,))
            file_types = dict(cursor.fetchall())

            # Duplicate count
            cursor.execute("""
            SELECT COUNT(DISTINCT sha256) FROM (
                SELECT sha256 FROM evidence WHERE case_id = ? GROUP BY sha256 HAVING COUNT(*) > 1
            )
            """, (case_id,))
            duplicate_clusters = cursor.fetchone()[0]

            cursor.execute("""
            SELECT COUNT(*) FROM evidence WHERE case_id = ? AND is_duplicate = 1
            """, (case_id,))
            duplicate_files = cursor.fetchone()[0]

            # Average entropy
            cursor.execute("SELECT COALESCE(AVG(entropy), 0.0) FROM evidence WHERE case_id = ?", (case_id,))
            avg_entropy = cursor.fetchone()[0]

            return {
                "total_evidence": total_count,
                "total_size_bytes": total_bytes,
                "verified_count": integrity_map.get("Verified", 0),
                "compromised_count": integrity_map.get("Compromised", 0),
                "suspicious_count": suspicious_count,
                "mismatch_count": mismatch_count,
                "duplicate_clusters": duplicate_clusters,
                "duplicate_files": duplicate_files,
                "avg_entropy": round(avg_entropy, 2),
                "risk_map": risk_map,
                "file_types": file_types
            }

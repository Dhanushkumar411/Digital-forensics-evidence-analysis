"""
ForenSight AI - Audit & Chain of Custody Engine
Cryptographic tamper-evident audit logging using SHA-256 hash chaining.
Provides legal chain of custody verification for court admissibility.
"""

from typing import List, Dict, Any, Tuple, Optional
from core.db import DatabaseManager
from core.models import AuditLogEntry


class AuditEngine:
    """Manages forensic audit trail integrity verification and compliance."""

    def __init__(self, db: Optional[DatabaseManager] = None):
        self.db = db or DatabaseManager()

    def log_event(self, investigator: str, action: str, target: str, details: Dict[str, Any], case_id: Optional[int] = None) -> AuditLogEntry:
        """Appends a new cryptographically chained audit record."""
        return self.db.add_audit_log(investigator, action, target, details, case_id)

    def verify_chain(self) -> Dict[str, Any]:
        """
        Validates the entire audit log chain against tampering.
        Returns detailed verification report.
        """
        is_valid, count, error = self.db.verify_audit_chain()
        return {
            "is_valid": is_valid,
            "total_records_checked": count,
            "error_message": error,
            "status": "INTEGRITY INTACT - CHAIN VALID" if is_valid else "TAMPERING DETECTED - CHAIN BROKEN"
        }

    def get_logs(self, case_id: Optional[int] = None) -> List[AuditLogEntry]:
        return self.db.get_audit_logs(case_id)

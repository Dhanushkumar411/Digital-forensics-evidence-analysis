"""
ForenSight AI - Application State & Event Signals
"""

from PySide6.QtCore import QObject, Signal
from core.db import DatabaseManager
from core.models import Case, EvidenceItem
from typing import Optional, List


class AppState(QObject):
    """
    Central state container and signal dispatcher for ForenSight AI.
    Emits signals when active case changes, evidence is modified, or scans finish.
    """
    # Signals
    case_changed = Signal(int)                     # case_id
    evidence_imported = Signal(int)               # count
    evidence_updated = Signal(int)                # evidence_id
    evidence_deleted = Signal(int)                # evidence_id
    ai_scan_completed = Signal(int)               # processed count
    integrity_check_completed = Signal(int, int)  # total, compromised
    audit_logged = Signal()                       # refresh audit view

    _instance: Optional['AppState'] = None

    @classmethod
    def get_instance(cls) -> 'AppState':
        if cls._instance is None:
            cls._instance = AppState()
        return cls._instance

    def __init__(self):
        super().__init__()
        self.db = DatabaseManager()
        self.active_case_id: int = 1
        self.current_investigator: str = "Agent Vance"
        self._load_initial_state()

    def _load_initial_state(self):
        cases = self.db.get_cases()
        if cases:
            self.active_case_id = cases[0].id

    def set_active_case(self, case_id: int):
        if self.active_case_id != case_id:
            self.active_case_id = case_id
            self.case_changed.emit(case_id)

    def get_active_case(self) -> Optional[Case]:
        return self.db.get_case(self.active_case_id)

    def log_action(self, action: str, target: str, details: dict):
        """Helper to create an audit record for current session."""
        self.db.add_audit_log(
            investigator=self.current_investigator,
            action=action,
            target=target,
            details=details,
            case_id=self.active_case_id
        )
        self.audit_logged.emit()

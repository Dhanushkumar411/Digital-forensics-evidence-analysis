"""
ForenSight AI - Cryptographic Audit Trail & Integrity View
Displays immutable SHA-256 hash-chained investigation ledger and
provides legal verification of examiner actions.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox, QFileDialog
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
import json

from config import COLORS
from core.state import AppState
from engines.audit_engine import AuditEngine
from ui.components.stat_card import StatCard


class AuditView(QWidget):
    """Cryptographic audit ledger inspection and verification view."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.state = AppState.get_instance()
        self.audit_engine = AuditEngine(self.state.db)
        self.logs = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        # Header
        top_layout = QHBoxLayout()
        title_box = QVBoxLayout()
        lbl_title = QLabel("Cryptographic Audit Trail & Chain of Custody")
        lbl_title.setStyleSheet(f"color: {COLORS['text_primary']}; font-size: 20px; font-weight: 700;")
        title_box.addWidget(lbl_title)

        lbl_sub = QLabel("Blockchain-style SHA-256 hash-linked log ensuring tamper-evident accountability.")
        lbl_sub.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px;")
        title_box.addWidget(lbl_sub)
        top_layout.addLayout(title_box)
        top_layout.addStretch()

        btn_verify = QPushButton("🛡 Verify Cryptographic Chain")
        btn_verify.setProperty("class", "PrimaryButton")
        btn_verify.clicked.connect(self._verify_chain)
        top_layout.addWidget(btn_verify)

        btn_export = QPushButton("📥 Export Audit Ledger")
        btn_export.setProperty("class", "SecondaryButton")
        btn_export.clicked.connect(self._export_ledger)
        top_layout.addWidget(btn_export)

        layout.addLayout(top_layout)

        # Integrity Banner
        self.banner = QFrame()
        self.banner_layout = QHBoxLayout(self.banner)
        self.banner_layout.setContentsMargins(14, 10, 14, 10)
        self.lbl_status = QLabel("Audit Ledger Status: Ready for verification")
        self.lbl_status.setStyleSheet("font-size: 13px; font-weight: bold;")
        self.banner_layout.addWidget(self.lbl_status)
        self.banner_layout.addStretch()
        layout.addWidget(self.banner)

        # Audit Table
        table_panel = QFrame()
        table_panel.setProperty("class", "CardPanel")
        tbl_layout = QVBoxLayout(table_panel)
        tbl_layout.setContentsMargins(8, 8, 8, 8)

        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels([
            "ID", "Timestamp", "Examiner", "Action", "Target", "Previous Hash", "Block Hash (SHA-256)"
        ])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(6, QHeaderView.Stretch)

        tbl_layout.addWidget(self.table)
        layout.addWidget(table_panel)

        # Connect state
        self.state.audit_logged.connect(self.refresh_logs)
        self.refresh_logs()

    def refresh_logs(self):
        """Pulls audit records from SQLite and populates table."""
        self.logs = self.audit_engine.get_logs(self.state.active_case_id)
        self.table.setRowCount(len(self.logs))

        for row, entry in enumerate(self.logs):
            self.table.setItem(row, 0, QTableWidgetItem(f"#{entry.id}"))
            self.table.setItem(row, 1, QTableWidgetItem(entry.timestamp))
            self.table.setItem(row, 2, QTableWidgetItem(entry.investigator))

            action_item = QTableWidgetItem(entry.action)
            action_item.setForeground(QColor(COLORS["accent_cyan"]))
            self.table.setItem(row, 3, action_item)

            self.table.setItem(row, 4, QTableWidgetItem(entry.target))

            prev_item = QTableWidgetItem(f"{entry.prev_hash[:16]}...")
            prev_item.setToolTip(f"Full Prev Hash:\n{entry.prev_hash}")
            self.table.setItem(row, 5, prev_item)

            cur_item = QTableWidgetItem(f"{entry.entry_hash[:16]}...")
            cur_item.setToolTip(f"Full Block Hash:\n{entry.entry_hash}")
            self.table.setItem(row, 6, cur_item)

        self._verify_chain(show_popup=False)

    def _verify_chain(self, show_popup: bool = True):
        res = self.audit_engine.verify_chain()
        if res["is_valid"]:
            self.banner.setStyleSheet(f"background-color: {COLORS['status_success']}22; border: 1px solid {COLORS['status_success']}; border-radius: 8px;")
            self.lbl_status.setText(f"✓ AUDIT CHAIN VALID: All {res['total_records_checked']} sequential ledger blocks verified intact (Zero Tampering Detected)")
            self.lbl_status.setStyleSheet(f"color: {COLORS['status_success']}; font-weight: bold;")
            if show_popup:
                QMessageBox.information(self, "Cryptographic Chain Verified",
                                        f"Audit chain verification succeeded!\n\n"
                                        f"Total blocks checked: {res['total_records_checked']}\n"
                                        f"Cryptographic link integrity: 100% INTACT\n"
                                        f"No unauthorized modifications, deletions, or insertions detected.")
        else:
            self.banner.setStyleSheet(f"background-color: {COLORS['status_danger']}22; border: 1px solid {COLORS['status_danger']}; border-radius: 8px;")
            self.lbl_status.setText(f"⚠️ INTEGRITY VIOLATION: {res['error_message']}")
            self.lbl_status.setStyleSheet(f"color: {COLORS['status_danger']}; font-weight: bold;")
            if show_popup:
                QMessageBox.critical(self, "Integrity Breach Detected", f"Warning: The cryptographic chain verification failed!\n\n{res['error_message']}")

    def _export_ledger(self):
        if not self.logs:
            QMessageBox.information(self, "No Logs", "No audit logs to export.")
            return

        file_path, _ = QFileDialog.getSaveFileName(self, "Export Audit Ledger JSON", "forensic_audit_ledger.json", "JSON Files (*.json)")
        if not file_path:
            return

        payload = [entry.__dict__ for entry in self.logs]
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

        QMessageBox.information(self, "Export Complete", f"Audit ledger exported successfully to:\n{file_path}")

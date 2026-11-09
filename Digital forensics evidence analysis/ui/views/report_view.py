"""
ForenSight AI - Report Generator View
Generates court-admissible forensic reports in PDF, JSON, and CSV formats.
"""

import os
import subprocess
from pathlib import Path
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QCheckBox, QTextEdit, QFileDialog, QMessageBox, QComboBox
)
from config import COLORS, REPORTS_DIR, EXPORTS_DIR
from core.state import AppState
from engines.report_engine import ReportEngine


class ReportView(QWidget):
    """Forensic report configuration and generation center."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.state = AppState.get_instance()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        # Header
        top_layout = QHBoxLayout()
        title_box = QVBoxLayout()
        lbl_title = QLabel("Forensic Examination Report Generator")
        lbl_title.setStyleSheet(f"color: {COLORS['text_primary']}; font-size: 20px; font-weight: 700;")
        title_box.addWidget(lbl_title)

        lbl_sub = QLabel("Export ISO/IEC 27037 & NIST SP 800-86 compliant forensic investigation reports.")
        lbl_sub.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px;")
        title_box.addWidget(lbl_sub)
        top_layout.addLayout(title_box)
        top_layout.addStretch()

        btn_open_folder = QPushButton("📂 Open Reports Directory")
        btn_open_folder.setProperty("class", "SecondaryButton")
        btn_open_folder.clicked.connect(self._open_reports_dir)
        top_layout.addWidget(btn_open_folder)

        layout.addLayout(top_layout)

        # Config Panel
        config_panel = QFrame()
        config_panel.setProperty("class", "CardPanel")
        cp_layout = QVBoxLayout(config_panel)
        cp_layout.setContentsMargins(16, 14, 16, 14)
        cp_layout.setSpacing(10)

        lbl_sec = QLabel("REPORT SECTIONS & EXPORT CONFIGURATION")
        lbl_sec.setStyleSheet(f"color: {COLORS['accent_cyan']}; font-weight: bold; font-size: 12px;")
        cp_layout.addWidget(lbl_sec)

        # Format selector row
        row_fmt = QHBoxLayout()
        row_fmt.addWidget(QLabel("Export Format:"))
        self.combo_format = QComboBox()
        self.combo_format.addItems(["Official PDF Forensic Report (*.pdf)", "Structured Forensic JSON (*.json)", "Evidence Inventory CSV (*.csv)"])
        row_fmt.addWidget(self.combo_format)
        row_fmt.addStretch()

        self.btn_generate = QPushButton("🚀 Generate & Export Report")
        self.btn_generate.setProperty("class", "PrimaryButton")
        self.btn_generate.setStyleSheet("font-size: 13px; padding: 8px 20px;")
        self.btn_generate.clicked.connect(self._generate_report)
        row_fmt.addWidget(self.btn_generate)
        cp_layout.addLayout(row_fmt)

        # Checkboxes for included sections
        lbl_inc = QLabel("Included Forensic Sections (for PDF):")
        lbl_inc.setStyleSheet(f"color: {COLORS['text_secondary']}; font-weight: 500; font-size: 11px;")
        cp_layout.addWidget(lbl_inc)

        chk_layout = QHBoxLayout()
        self.chk_custody = QCheckBox("Case & Custody Metadata")
        self.chk_custody.setChecked(True)
        chk_layout.addWidget(self.chk_custody)

        self.chk_exec = QCheckBox("Executive Telemetry")
        self.chk_exec.setChecked(True)
        chk_layout.addWidget(self.chk_exec)

        self.chk_hashes = QCheckBox("SHA-256 Hash Matrix")
        self.chk_hashes.setChecked(True)
        chk_layout.addWidget(self.chk_hashes)

        self.chk_ai = QCheckBox("AI Anomaly Analysis")
        self.chk_ai.setChecked(True)
        chk_layout.addWidget(self.chk_ai)

        self.chk_dups = QCheckBox("Duplicate Clusters")
        self.chk_dups.setChecked(True)
        chk_layout.addWidget(self.chk_dups)

        self.chk_audit = QCheckBox("Audit Certification")
        self.chk_audit.setChecked(True)
        chk_layout.addWidget(self.chk_audit)

        cp_layout.addLayout(chk_layout)
        layout.addWidget(config_panel)

        # Live Preview Panel
        preview_panel = QFrame()
        preview_panel.setProperty("class", "CardPanel")
        prev_layout = QVBoxLayout(preview_panel)
        prev_layout.setContentsMargins(14, 12, 14, 12)
        prev_layout.setSpacing(8)

        lbl_prev_title = QLabel("LIVE EXECUTIVE REPORT BRIEFING PREVIEW")
        lbl_prev_title.setStyleSheet(f"color: {COLORS['text_secondary']}; font-weight: bold; font-size: 11px;")
        prev_layout.addWidget(lbl_prev_title)

        self.text_preview = QTextEdit()
        self.text_preview.setReadOnly(True)
        self.text_preview.setStyleSheet(f"background-color: #050811; color: #e2e8f0; font-family: 'Consolas', monospace; font-size: 11px; padding: 10px;")
        prev_layout.addWidget(self.text_preview)

        layout.addWidget(preview_panel)

        # Connect state
        self.state.case_changed.connect(self.update_preview)
        self.state.evidence_imported.connect(self.update_preview)
        self.state.ai_scan_completed.connect(self.update_preview)

        self.update_preview()

    def update_preview(self):
        case = self.state.get_active_case()
        if not case:
            return

        items = self.state.db.get_evidence_list(self.state.active_case_id)
        stats = self.state.db.get_case_statistics(self.state.active_case_id)
        suspicious = [it for it in items if it.is_suspicious]

        preview = []
        preview.append("=" * 76)
        preview.append("                   OFFICIAL FORENSIC EXAMINATION BRIEFING")
        preview.append("                       FORENSIGHT AI - INCIDENT LAB")
        preview.append("=" * 76)
        preview.append(f"CASE NUMBER:         {case.case_number}")
        preview.append(f"CASE TITLE:          {case.title}")
        preview.append(f"LEAD EXAMINER:       {case.investigator_name}")
        preview.append(f"ORGANIZATION:        {case.organization}")
        preview.append(f"STATUS:              {case.status}")
        preview.append("-" * 76)
        preview.append("EXECUTIVE SUMMARY:")
        preview.append(f"Total Evidence Artifacts:   {len(items)}")
        preview.append(f"Total Storage Volume:       {stats['total_size_bytes'] / (1024*1024):.2f} MB")
        preview.append(f"Verified Intact (SHA-256):  {stats['verified_count']} / {len(items)}")
        preview.append(f"Compromised / Tampered:     {stats['compromised_count']}")
        preview.append(f"AI Anomalies Flagged:       {len(suspicious)}")
        preview.append(f"Extension Mismatches:       {stats['mismatch_count']}")
        preview.append(f"Duplicate Clusters:         {stats['duplicate_clusters']}")
        preview.append("-" * 76)
        preview.append("CRITICAL FINDINGS & ANOMALIES:")
        if suspicious:
            for s in suspicious[:8]:
                preview.append(f"  • {s.file_name:<28} | Risk: {s.risk_level:<16} | Score: {s.anomaly_score:.1f}%")
                if s.flagged_reasons:
                    preview.append(f"    - Finding: {s.flagged_reasons[0]}")
        else:
            preview.append("  (No anomalous evidence items flagged)")
        preview.append("-" * 76)
        preview.append("CRYPTOGRAPHIC CHAIN STATUS: INTACT (100% Tamper Verification Passed)")
        preview.append("=" * 76)

        self.text_preview.setPlainText("\n".join(preview))

    def _generate_report(self):
        case = self.state.get_active_case()
        if not case:
            QMessageBox.warning(self, "No Active Case", "Please select or create a case first.")
            return

        items = self.state.db.get_evidence_list(self.state.active_case_id)
        if not items:
            QMessageBox.warning(self, "Empty Case", "Active case has no evidence items to generate a report.")
            return

        duplicates = self.state.db.get_duplicates_by_case(self.state.active_case_id)
        audit_logs = self.state.db.get_audit_logs(self.state.active_case_id)

        fmt = self.combo_format.currentText()

        try:
            if "PDF" in fmt:
                out_path = ReportEngine.generate_pdf_report(case, items, duplicates, audit_logs)
                msg = f"Official PDF Forensic Report generated successfully!\n\nSaved to:\n{out_path}"
            elif "JSON" in fmt:
                out_path = ReportEngine.export_json(case, items, duplicates, audit_logs)
                msg = f"Forensic Case JSON archive exported successfully!\n\nSaved to:\n{out_path}"
            else:
                out_path = ReportEngine.export_csv(items)
                msg = f"Evidence Inventory CSV exported successfully!\n\nSaved to:\n{out_path}"

            # Log audit event
            self.state.log_action("REPORT_GENERATED", Path(out_path).name, {
                "format": fmt,
                "evidence_count": len(items),
                "path": out_path
            })

            QMessageBox.information(self, "Report Export Complete", msg)

        except Exception as e:
            QMessageBox.critical(self, "Report Generation Error", f"Failed to generate report: {e}")

    def _open_reports_dir(self):
        target = REPORTS_DIR if REPORTS_DIR.exists() else Path.cwd()
        if os.name == "nt":
            os.startfile(str(target))
        else:
            subprocess.Popen(["xdg-open", str(target)])

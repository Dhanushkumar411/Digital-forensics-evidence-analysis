"""
ForenSight AI - Evidence Acquisition & Manager View
Enables digital evidence ingestion, bulk cryptographic hash verification,
filtering by risk/integrity, and chain of custody management.
"""

from pathlib import Path
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QTableWidget, QTableWidgetItem, QHeaderView, QLineEdit,
    QComboBox, QFileDialog, QMessageBox, QProgressBar
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor

from config import COLORS, SAMPLE_DIR
from core.state import AppState
from core.models import EvidenceItem
from engines.evidence_engine import EvidenceEngine
from engines.hash_engine import HashEngine
from engines.ai_engine import AIFDEngine
from ui.components.custody_modal import CustodyModal
from sample_data.generate_samples import generate_all_samples


class EvidenceView(QWidget):
    """Forensic evidence registration, integrity checking, and inventory view."""

    # Signal to jump to Deep File Inspector with specific evidence ID
    inspect_evidence_requested = Signal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.state = AppState.get_instance()
        self.ai_engine = AIFDEngine()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        # Header & Acquisition Toolbar
        self._build_toolbar(layout)

        # Filter & Search bar
        self._build_filter_bar(layout)

        # Progress Bar (for bulk operations)
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        # Evidence Inventory Table
        self._build_table(layout)

        # Connect to state
        self.state.case_changed.connect(self.refresh_table)
        self.state.evidence_imported.connect(self.refresh_table)

        self.refresh_table()

    def _build_toolbar(self, parent_layout):
        top_layout = QHBoxLayout()
        title_box = QVBoxLayout()
        lbl_title = QLabel("Digital Evidence Acquisition & Integrity Register")
        lbl_title.setStyleSheet(f"color: {COLORS['text_primary']}; font-size: 20px; font-weight: 700;")
        title_box.addWidget(lbl_title)

        lbl_sub = QLabel("Acquire files, verify SHA-256 cryptographic baselines, and detect tampering.")
        lbl_sub.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px;")
        title_box.addWidget(lbl_sub)
        top_layout.addLayout(title_box)
        top_layout.addStretch()

        btn_sample = QPushButton("⚡ Load Lab Samples")
        btn_sample.setProperty("class", "SecondaryButton")
        btn_sample.clicked.connect(self._load_sample_evidence)
        top_layout.addWidget(btn_sample)

        btn_add_files = QPushButton("➕ Ingest File(s)")
        btn_add_files.setProperty("class", "PrimaryButton")
        btn_add_files.clicked.connect(self._ingest_files)
        top_layout.addWidget(btn_add_files)

        btn_add_dir = QPushButton("📁 Ingest Directory")
        btn_add_dir.setProperty("class", "SecondaryButton")
        btn_add_dir.clicked.connect(self._ingest_directory)
        top_layout.addWidget(btn_add_dir)

        btn_reverify = QPushButton("🛡 Verify All Hashes")
        btn_reverify.setProperty("class", "SecondaryButton")
        btn_reverify.clicked.connect(self._reverify_all_hashes)
        top_layout.addWidget(btn_reverify)

        parent_layout.addLayout(top_layout)

    def _build_filter_bar(self, parent_layout):
        bar = QFrame()
        bar.setStyleSheet(f"background-color: {COLORS['bg_card']}; border-radius: 8px; padding: 6px 12px; border: 1px solid {COLORS['border']};")
        bar_layout = QHBoxLayout(bar)
        bar_layout.setContentsMargins(8, 4, 8, 4)
        bar_layout.setSpacing(12)

        # Search box
        bar_layout.addWidget(QLabel("🔍 Search:"))
        self.edit_search = QLineEdit()
        self.edit_search.setPlaceholderText("Search by file name, path, or SHA-256 hash...")
        self.edit_search.textChanged.connect(self._apply_filters)
        bar_layout.addWidget(self.edit_search)

        # Risk Filter
        bar_layout.addWidget(QLabel("Risk Level:"))
        self.combo_risk = QComboBox()
        self.combo_risk.addItems(["All Risks", "Benign", "Suspicious", "High Risk", "Critical Anomaly"])
        self.combo_risk.currentTextChanged.connect(self._apply_filters)
        bar_layout.addWidget(self.combo_risk)

        # Integrity Filter
        bar_layout.addWidget(QLabel("Integrity:"))
        self.combo_integrity = QComboBox()
        self.combo_integrity.addItems(["All Integrity", "Verified", "Compromised", "Missing"])
        self.combo_integrity.currentTextChanged.connect(self._apply_filters)
        bar_layout.addWidget(self.combo_integrity)

        parent_layout.addWidget(bar)

    def _build_table(self, parent_layout):
        table_panel = QFrame()
        table_panel.setProperty("class", "CardPanel")
        tbl_layout = QVBoxLayout(table_panel)
        tbl_layout.setContentsMargins(8, 8, 8, 8)

        self.table = QTableWidget(0, 9)
        self.table.setHorizontalHeaderLabels([
            "ID", "File Name", "Size", "Detected Type", "SHA-256 Hash",
            "Integrity", "AI Risk", "Entropy", "Actions"
        ])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(7, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(8, QHeaderView.ResizeToContents)

        tbl_layout.addWidget(self.table)
        parent_layout.addWidget(table_panel)

    def refresh_table(self):
        """Reloads all evidence for active case from SQLite and updates view."""
        self.all_items = self.state.db.get_evidence_list(self.state.active_case_id)
        self._apply_filters()

    def _apply_filters(self):
        query = self.edit_search.text().strip().lower()
        risk_filter = self.combo_risk.currentText()
        integrity_filter = self.combo_integrity.currentText()

        filtered = []
        for it in self.all_items:
            # Search query match
            if query and not (query in it.file_name.lower() or query in it.file_path.lower() or query in it.sha256.lower()):
                continue
            # Risk filter
            if risk_filter != "All Risks" and it.risk_level != risk_filter:
                continue
            # Integrity filter
            if integrity_filter != "All Integrity" and it.integrity_status != integrity_filter:
                continue
            filtered.append(it)

        self._render_rows(filtered)

    def _render_rows(self, items):
        self.table.setRowCount(len(items))

        for row, it in enumerate(items):
            self.table.setItem(row, 0, QTableWidgetItem(str(it.id)))
            self.table.setItem(row, 1, QTableWidgetItem(it.file_name))
            self.table.setItem(row, 2, QTableWidgetItem(f"{it.file_size:,} B"))
            self.table.setItem(row, 3, QTableWidgetItem(it.detected_type))

            # SHA-256 font
            hash_item = QTableWidgetItem(it.sha256)
            hash_item.setToolTip(f"Full SHA-256:\n{it.sha256}\n\nMD5:\n{it.md5}\n\nSHA-1:\n{it.sha1}")
            self.table.setItem(row, 4, hash_item)

            # Integrity Status
            int_item = QTableWidgetItem(it.integrity_status)
            if it.integrity_status == "Verified":
                int_item.setForeground(QColor(COLORS["status_success"]))
            elif it.integrity_status == "Compromised":
                int_item.setForeground(QColor(COLORS["status_danger"]))
            else:
                int_item.setForeground(QColor(COLORS["status_warning"]))
            self.table.setItem(row, 5, int_item)

            # Risk Level
            risk_item = QTableWidgetItem(f"{it.risk_level} ({it.anomaly_score:.0f}%)")
            if it.risk_level in ["Critical Anomaly", "High Risk"]:
                risk_item.setForeground(QColor(COLORS["status_danger"]))
            elif it.risk_level == "Suspicious":
                risk_item.setForeground(QColor(COLORS["status_warning"]))
            else:
                risk_item.setForeground(QColor(COLORS["status_success"]))
            self.table.setItem(row, 6, risk_item)

            # Entropy
            entropy_item = QTableWidgetItem(f"{it.entropy:.2f}")
            if it.entropy >= 7.2:
                entropy_item.setForeground(QColor(COLORS["status_danger"]))
            self.table.setItem(row, 7, entropy_item)

            # Action Buttons widget
            act_widget = QWidget()
            act_layout = QHBoxLayout(act_widget)
            act_layout.setContentsMargins(4, 2, 4, 2)
            act_layout.setSpacing(6)

            btn_inspect = QPushButton("Inspect")
            btn_inspect.setStyleSheet("font-size: 11px; padding: 3px 8px;")
            btn_inspect.setProperty("class", "SecondaryButton")
            btn_inspect.clicked.connect(lambda checked=False, eid=it.id: self.inspect_evidence_requested.emit(eid))
            act_layout.addWidget(btn_inspect)

            btn_custody = QPushButton("Custody")
            btn_custody.setStyleSheet("font-size: 11px; padding: 3px 8px;")
            btn_custody.setProperty("class", "SecondaryButton")
            btn_custody.clicked.connect(lambda checked=False, item=it: self._open_custody(item))
            act_layout.addWidget(btn_custody)

            btn_del = QPushButton("✕")
            btn_del.setToolTip("Remove evidence")
            btn_del.setProperty("class", "DangerButton")
            btn_del.setStyleSheet("font-size: 11px; padding: 3px 6px;")
            btn_del.clicked.connect(lambda checked=False, eid=it.id: self._delete_evidence(eid))
            act_layout.addWidget(btn_del)

            self.table.setCellWidget(row, 8, act_widget)

    def _ingest_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Acquire Digital Evidence Files", "", "All Files (*.*)")
        if not files:
            return
        self._process_file_paths(files)

    def _ingest_directory(self):
        directory = QFileDialog.getExistingDirectory(self, "Select Seized Evidence Directory")
        if not directory:
            return
        files = [str(p) for p in Path(directory).rglob("*") if p.is_file()]
        if not files:
            QMessageBox.information(self, "Empty Directory", "No files found in selected directory.")
            return
        self._process_file_paths(files)

    def _load_sample_evidence(self):
        """Loads the synthetic forensic test suite for demonstration."""
        sample_path = generate_all_samples()
        files = [str(p) for p in sample_path.glob("*") if p.is_file()]
        self._process_file_paths(files, source_desc="Synthetic MCA Forensic Lab Test Suite")
        QMessageBox.information(self, "Lab Evidence Loaded", f"Successfully ingested {len(files)} forensic sample artifacts into the active case!")

    def _process_file_paths(self, file_paths, source_desc: str = "Acquired Digital Evidence"):
        self.progress_bar.setVisible(True)
        self.progress_bar.setMaximum(len(file_paths))
        self.progress_bar.setValue(0)

        imported_count = 0
        for idx, fp in enumerate(file_paths):
            try:
                # Forensic inspection
                item = EvidenceEngine.inspect_file(fp, case_id=self.state.active_case_id, custody_source=source_desc)
                # AI baseline inference
                self.ai_engine.analyze_evidence(item)
                # Store in SQLite database
                ev_id = self.state.db.insert_evidence(item)
                item.id = ev_id

                # Audit logging
                self.state.log_action("EVIDENCE_ACQUIRED", item.file_name, {
                    "file_path": item.file_path,
                    "file_size": item.file_size,
                    "sha256": item.sha256,
                    "detected_type": item.detected_type
                })
                imported_count += 1
            except Exception as e:
                print(f"Error importing {fp}: {e}")

            self.progress_bar.setValue(idx + 1)

        self.progress_bar.setVisible(False)
        self.state.evidence_imported.emit(imported_count)

    def _reverify_all_hashes(self):
        """Re-computes hashes of all evidence files on disk and compares against database baseline."""
        items = self.state.db.get_evidence_list(self.state.active_case_id)
        if not items:
            QMessageBox.information(self, "No Evidence", "Active case has no evidence to verify.")
            return

        compromised_count = 0
        for it in items:
            status, cur_hash = HashEngine.verify_file_integrity(it.file_path, it.sha256)
            if status != it.integrity_status:
                it.integrity_status = status
                self.state.db.update_evidence(it)
                if status == "Compromised":
                    compromised_count += 1
                    self.state.log_action("TAMPER_DETECTED", it.file_name, {
                        "expected_sha256": it.sha256,
                        "current_sha256": cur_hash
                    })

        self.state.log_action("MASS_INTEGRITY_CHECK", f"Total: {len(items)}", {
            "verified_count": len(items) - compromised_count,
            "compromised_count": compromised_count
        })

        self.state.integrity_check_completed.emit(len(items), compromised_count)
        self.refresh_table()

        if compromised_count > 0:
            QMessageBox.warning(self, "Tampering Alert", f"CRITICAL: {compromised_count} evidence file(s) have been modified on disk since original acquisition!")
        else:
            QMessageBox.information(self, "Integrity Intact", f"All {len(items)} evidence files verified cryptographically intact (100% SHA-256 match).")

    def _open_custody(self, item: EvidenceItem):
        dlg = CustodyModal(item, self)
        if dlg.exec():
            self.state.db.update_evidence(item)
            self.state.log_action("CUSTODY_UPDATED", item.file_name, {
                "source": item.custody_source,
                "notes": item.custody_notes
            })
            self.refresh_table()

    def _delete_evidence(self, evidence_id: int):
        confirm = QMessageBox.question(self, "Confirm Removal", "Are you sure you want to remove this evidence artifact from the case?", QMessageBox.Yes | QMessageBox.No)
        if confirm == QMessageBox.Yes:
            self.state.db.delete_evidence(evidence_id)
            self.state.log_action("EVIDENCE_DELETED", f"ID {evidence_id}", {"deleted_id": evidence_id})
            self.refresh_table()

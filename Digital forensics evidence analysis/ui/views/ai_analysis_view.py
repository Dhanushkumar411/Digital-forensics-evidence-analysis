"""
ForenSight AI - AI Anomaly Detection Center
Executes Scikit-Learn IsolationForest anomaly detection, feature extraction,
and Explainable AI (XAI) risk reasoning across all case evidence.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QTableWidget, QTableWidgetItem, QHeaderView,
    QProgressBar, QMessageBox, QSplitter
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor

from config import COLORS
from core.state import AppState
from core.models import EvidenceItem, AnomalyResult
from engines.ai_engine import AIFDEngine
from ui.components.stat_card import StatCard


class AIAnalysisView(QWidget):
    """Machine learning anomaly detection, telemetry, and XAI explainability view."""

    # Signal to jump to Deep File Inspector
    inspect_requested = Signal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.state = AppState.get_instance()
        self.ai_engine = AIFDEngine()
        self.active_items = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        # Header & Actions
        self._build_header(layout)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        # Top KPI telemetry cards
        self._build_kpi_cards(layout)

        # Main Splitter: Table on left, Explainable AI Details on right
        splitter = QSplitter(Qt.Horizontal)

        # Left: Ranked Anomalies Table
        left_panel = QFrame()
        left_panel.setProperty("class", "CardPanel")
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(12, 12, 12, 12)
        left_layout.setSpacing(8)

        lbl_tbl = QLabel("RANKED AI ANOMALY DETECTION RESULTS")
        lbl_tbl.setStyleSheet(f"color: {COLORS['text_secondary']}; font-weight: bold; font-size: 11px;")
        left_layout.addWidget(lbl_tbl)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["File Name", "Type", "Risk Level", "Score", "Entropy"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.table.itemSelectionChanged.connect(self._on_item_selected)
        left_layout.addWidget(self.table)
        splitter.addWidget(left_panel)

        # Right: Explainable AI Panel
        right_panel = QFrame()
        right_panel.setProperty("class", "CardPanel")
        self.right_layout = QVBoxLayout(right_panel)
        self.right_layout.setContentsMargins(16, 14, 16, 14)
        self.right_layout.setSpacing(10)

        lbl_xai = QLabel("EXPLAINABLE AI (XAI) DIAGNOSTIC REASONING")
        lbl_xai.setStyleSheet(f"color: {COLORS['accent_cyan']}; font-weight: bold; font-size: 12px;")
        self.right_layout.addWidget(lbl_xai)

        self.lbl_selected_title = QLabel("Select an evidence item from the table to view AI explanation.")
        self.lbl_selected_title.setStyleSheet(f"color: {COLORS['text_primary']}; font-size: 14px; font-weight: bold;")
        self.right_layout.addWidget(self.lbl_selected_title)

        self.lbl_xai_score = QLabel("")
        self.right_layout.addWidget(self.lbl_xai_score)

        self.lbl_xai_reasons = QLabel("")
        self.lbl_xai_reasons.setWordWrap(True)
        self.lbl_xai_reasons.setStyleSheet(f"background-color: {COLORS['bg_input']}; border: 1px solid {COLORS['border']}; border-radius: 6px; padding: 10px; color: #f8fafc;")
        self.right_layout.addWidget(self.lbl_xai_reasons)

        self.lbl_features = QLabel("")
        self.lbl_features.setWordWrap(True)
        self.lbl_features.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 11px;")
        self.right_layout.addWidget(self.lbl_features)

        self.btn_inspect_detail = QPushButton("🔍 Open in Deep File Inspector")
        self.btn_inspect_detail.setProperty("class", "PrimaryButton")
        self.btn_inspect_detail.setEnabled(False)
        self.btn_inspect_detail.clicked.connect(self._open_deep_inspector)
        self.right_layout.addWidget(self.btn_inspect_detail)

        self.right_layout.addStretch()
        splitter.addWidget(right_panel)

        splitter.setSizes([550, 450])
        layout.addWidget(splitter)

        # Connect state
        self.state.case_changed.connect(self.refresh_view)
        self.state.evidence_imported.connect(self.refresh_view)

        self.refresh_view()

    def _build_header(self, parent_layout):
        header_layout = QHBoxLayout()
        title_box = QVBoxLayout()
        lbl_title = QLabel("AI Anomaly Detection Center")
        lbl_title.setStyleSheet(f"color: {COLORS['text_primary']}; font-size: 20px; font-weight: 700;")
        title_box.addWidget(lbl_title)

        lbl_sub = QLabel("Machine learning anomaly detection (IsolationForest) and forensic evasion analysis.")
        lbl_sub.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px;")
        title_box.addWidget(lbl_sub)
        header_layout.addLayout(title_box)
        header_layout.addStretch()

        btn_scan = QPushButton("🧠 Run Full AI Scan")
        btn_scan.setProperty("class", "PrimaryButton")
        btn_scan.clicked.connect(self._run_ai_scan)
        header_layout.addWidget(btn_scan)

        parent_layout.addLayout(header_layout)

    def _build_kpi_cards(self, parent_layout):
        kpi_layout = QHBoxLayout()
        kpi_layout.setSpacing(12)

        self.card_critical = StatCard("Critical Anomalies", "0", "Severe Evasion / Threat", COLORS["status_danger"])
        self.card_high = StatCard("High Risk", "0", "Investigator Review", "#f97316")
        self.card_suspicious = StatCard("Suspicious", "0", "Unusual Metrics", COLORS["status_warning"])
        self.card_benign = StatCard("Benign Baseline", "0", "Standard Characteristics", COLORS["status_success"])

        kpi_layout.addWidget(self.card_critical)
        kpi_layout.addWidget(self.card_high)
        kpi_layout.addWidget(self.card_suspicious)
        kpi_layout.addWidget(self.card_benign)

        parent_layout.addLayout(kpi_layout)

    def refresh_view(self):
        """Pulls evidence items from database and updates table and telemetry."""
        self.active_items = self.state.db.get_evidence_list(self.state.active_case_id)
        # Sort by anomaly score descending
        self.active_items.sort(key=lambda x: x.anomaly_score, reverse=True)

        # Update KPI cards
        critical_cnt = sum(1 for it in self.active_items if it.risk_level == "Critical Anomaly")
        high_cnt = sum(1 for it in self.active_items if it.risk_level == "High Risk")
        susp_cnt = sum(1 for it in self.active_items if it.risk_level == "Suspicious")
        benign_cnt = sum(1 for it in self.active_items if it.risk_level == "Benign")

        self.card_critical.update_data(str(critical_cnt))
        self.card_high.update_data(str(high_cnt))
        self.card_suspicious.update_data(str(susp_cnt))
        self.card_benign.update_data(str(benign_cnt))

        # Populate table
        self.table.setRowCount(len(self.active_items))
        for row, it in enumerate(self.active_items):
            self.table.setItem(row, 0, QTableWidgetItem(it.file_name))
            self.table.setItem(row, 1, QTableWidgetItem(it.detected_type))

            risk_item = QTableWidgetItem(it.risk_level)
            if it.risk_level == "Critical Anomaly":
                risk_item.setForeground(QColor(COLORS["status_danger"]))
            elif it.risk_level == "High Risk":
                risk_item.setForeground(QColor("#f97316"))
            elif it.risk_level == "Suspicious":
                risk_item.setForeground(QColor(COLORS["status_warning"]))
            else:
                risk_item.setForeground(QColor(COLORS["status_success"]))
            self.table.setItem(row, 2, risk_item)

            score_item = QTableWidgetItem(f"{it.anomaly_score:.1f}%")
            self.table.setItem(row, 3, score_item)

            self.table.setItem(row, 4, QTableWidgetItem(f"{it.entropy:.2f}"))

        if self.active_items:
            self.table.selectRow(0)

    def _on_item_selected(self):
        selected_rows = self.table.selectionModel().selectedRows()
        if not selected_rows:
            return
        row = selected_rows[0].row()
        if 0 <= row < len(self.active_items):
            item = self.active_items[row]
            self._render_xai(item)

    def _render_xai(self, item: EvidenceItem):
        self.selected_item = item
        self.lbl_selected_title.setText(f"{item.file_name}")

        risk_color = COLORS["status_danger"] if item.risk_level in ["Critical Anomaly", "High Risk"] else COLORS["status_warning"]
        self.lbl_xai_score.setText(
            f"<b>Risk Level:</b> <font color='{risk_color}'>{item.risk_level.upper()}</font> &bull; "
            f"<b>Anomaly Score:</b> {item.anomaly_score:.1f}% &bull; "
            f"<b>Algorithm:</b> IsolationForest + Heuristic Rules"
        )

        reasons = item.flagged_reasons
        if reasons:
            reasons_html = "<b>Forensic Reasoning & Findings:</b><br/>" + "".join([f"&bull; {r}<br/>" for r in reasons])
        else:
            reasons_html = "<b>Forensic Reasoning:</b><br/>File characteristics conform closely to standard baseline distributions. No anomalies detected."
        self.lbl_xai_reasons.setText(reasons_html)

        # Feature vector values
        _, feat_dict = self.ai_engine.extract_features(item)
        feats_text = (
            f"<b>Extracted Feature Vector:</b><br/>"
            f"&bull; Shannon Entropy: <b>{feat_dict['entropy']:.2f}</b> / 8.00<br/>"
            f"&bull; Log10 File Size: <b>{feat_dict['log_size']}</b><br/>"
            f"&bull; Extension Mismatch: <b>{feat_dict['ext_mismatch']}</b><br/>"
            f"&bull; Double Extension Flag: <b>{feat_dict['double_ext']}</b><br/>"
            f"&bull; Timestomp Flag: <b>{feat_dict['timestomp']}</b><br/>"
            f"&bull; Threat Keyword Match: <b>{feat_dict['sus_name']}</b><br/>"
            f"&bull; Suspicious Command Score: <b>{feat_dict['sus_cmd']}</b><br/>"
            f"&bull; Network Indicator Flag: <b>{feat_dict['net_indicator']}</b>"
        )
        self.lbl_features.setText(feats_text)
        self.btn_inspect_detail.setEnabled(True)

    def _open_deep_inspector(self):
        if hasattr(self, "selected_item") and self.selected_item and self.selected_item.id:
            self.inspect_requested.emit(self.selected_item.id)

    def _run_ai_scan(self):
        items = self.state.db.get_evidence_list(self.state.active_case_id)
        if not items:
            QMessageBox.information(self, "No Evidence", "Active case has no evidence to scan.")
            return

        self.progress_bar.setVisible(True)
        self.progress_bar.setMaximum(len(items))
        self.progress_bar.setValue(0)

        for idx, it in enumerate(items):
            res = self.ai_engine.analyze_evidence(it)
            self.state.db.update_evidence(it)
            self.state.db.save_ai_analysis(res)
            self.progress_bar.setValue(idx + 1)

        self.progress_bar.setVisible(False)
        self.state.log_action("AI_ANOMALY_SCAN", f"Case {self.state.active_case_id}", {
            "scanned_count": len(items),
            "critical_found": sum(1 for it in items if it.risk_level == "Critical Anomaly")
        })

        self.state.ai_scan_completed.emit(len(items))
        self.refresh_view()
        QMessageBox.information(self, "AI Scan Completed", f"Successfully analyzed {len(items)} evidence artifacts with the AI Anomaly Detection engine!")

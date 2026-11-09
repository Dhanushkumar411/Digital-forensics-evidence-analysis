"""
ForenSight AI - Deep File Inspector View
Provides in-depth examination of digital evidence:
- Detailed metadata & MACB timestamps
- Virtualized Hex & ASCII inspection
- Sliding-window Shannon entropy curve
- Extracted network indicators, Base64 strings, and commands
- YARA / Malware signature rule matching
"""

from pathlib import Path
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QTabWidget, QComboBox, QFormLayout, QTextEdit,
    QTableWidget, QTableWidgetItem, QHeaderView, QApplication
)
from PySide6.QtCore import Qt
from config import COLORS
from core.state import AppState
from core.models import EvidenceItem
from engines.evidence_engine import EvidenceEngine
from engines.signature_engine import SignatureEngine
from ui.components.hex_viewer import HexViewer
from ui.components.entropy_graph import EntropyGraphWidget


class FileInspectorView(QWidget):
    """Deep forensic artifact examination center."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.state = AppState.get_instance()
        self.current_item: EvidenceItem = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        # Header with file selector
        self._build_header(layout)

        # Main Tab Widget
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("QTabWidget::pane { border-radius: 8px; }")

        # Tab 1: Metadata & Hashes
        self.tab_meta = QWidget()
        self._build_metadata_tab()
        self.tabs.addTab(self.tab_meta, "📋 Metadata & Hashes")

        # Tab 2: Hex & ASCII Viewer
        self.tab_hex = QWidget()
        self._build_hex_tab()
        self.tabs.addTab(self.tab_hex, "🔢 Raw Hex & ASCII")

        # Tab 3: Entropy Profile
        self.tab_entropy = QWidget()
        self._build_entropy_tab()
        self.tabs.addTab(self.tab_entropy, "📈 Shannon Entropy Curve")

        # Tab 4: Strings & IOCs
        self.tab_strings = QWidget()
        self._build_strings_tab()
        self.tabs.addTab(self.tab_strings, "🔤 Strings & Indicators")

        # Tab 5: YARA / Threat Signatures
        self.tab_signatures = QWidget()
        self._build_signatures_tab()
        self.tabs.addTab(self.tab_signatures, "🛡 Malware Signatures")

        layout.addWidget(self.tabs)

        # Connect state
        self.state.case_changed.connect(self.reload_evidence_list)
        self.state.evidence_imported.connect(self.reload_evidence_list)

        self.reload_evidence_list()

    def _build_header(self, parent_layout):
        header_layout = QHBoxLayout()
        title_box = QVBoxLayout()
        lbl_title = QLabel("Deep Forensic File Inspector")
        lbl_title.setStyleSheet(f"color: {COLORS['text_primary']}; font-size: 20px; font-weight: 700;")
        title_box.addWidget(lbl_title)

        lbl_sub = QLabel("Inspect raw byte streams, cryptographic hashes, entropy profiles, and threat indicators.")
        lbl_sub.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px;")
        title_box.addWidget(lbl_sub)
        header_layout.addLayout(title_box)
        header_layout.addStretch()

        header_layout.addWidget(QLabel("Select Artifact:"))
        self.combo_evidence = QComboBox()
        self.combo_evidence.setMinimumWidth(320)
        self.combo_evidence.currentIndexChanged.connect(self._on_combo_selected)
        header_layout.addWidget(self.combo_evidence)

        parent_layout.addLayout(header_layout)

    def _build_metadata_tab(self):
        layout = QVBoxLayout(self.tab_meta)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(14)

        panel = QFrame()
        panel.setProperty("class", "CardPanel")
        form = QFormLayout(panel)
        form.setSpacing(10)

        self.lbl_prop_name = QLabel("-")
        form.addRow(QLabel("File Name:"), self.lbl_prop_name)

        self.lbl_prop_path = QLabel("-")
        self.lbl_prop_path.setStyleSheet(f"color: {COLORS['text_muted']};")
        form.addRow(QLabel("Full File Path:"), self.lbl_prop_path)

        self.lbl_prop_size = QLabel("-")
        form.addRow(QLabel("File Size:"), self.lbl_prop_size)

        self.lbl_prop_type = QLabel("-")
        form.addRow(QLabel("Magic Bytes Type:"), self.lbl_prop_type)

        self.lbl_prop_mime = QLabel("-")
        form.addRow(QLabel("MIME Type:"), self.lbl_prop_mime)

        self.lbl_prop_mismatch = QLabel("-")
        form.addRow(QLabel("Extension Mismatch:"), self.lbl_prop_mismatch)

        self.lbl_prop_entropy = QLabel("-")
        form.addRow(QLabel("Shannon Entropy:"), self.lbl_prop_entropy)

        self.lbl_prop_macb = QLabel("-")
        form.addRow(QLabel("MACB Timestamps:"), self.lbl_prop_macb)

        # Cryptographic Hashes Row with Copy Buttons
        hash_box = QVBoxLayout()
        self.lbl_sha256 = QLabel("-")
        self.lbl_sha256.setStyleSheet(f"font-family: Courier; color: {COLORS['accent_cyan']}; font-weight: bold;")
        btn_copy_sha256 = QPushButton("Copy SHA-256")
        btn_copy_sha256.setProperty("class", "SecondaryButton")
        btn_copy_sha256.setStyleSheet("font-size: 10px; padding: 2px 6px;")
        btn_copy_sha256.clicked.connect(lambda: QApplication.clipboard().setText(self.lbl_sha256.text()))

        row_sha256 = QHBoxLayout()
        row_sha256.addWidget(self.lbl_sha256)
        row_sha256.addWidget(btn_copy_sha256)
        row_sha256.addStretch()
        hash_box.addLayout(row_sha256)

        self.lbl_md5 = QLabel("-")
        self.lbl_md5.setStyleSheet("font-family: Courier; color: #94a3b8;")
        hash_box.addWidget(self.lbl_md5)

        self.lbl_sha1 = QLabel("-")
        self.lbl_sha1.setStyleSheet("font-family: Courier; color: #94a3b8;")
        hash_box.addWidget(self.lbl_sha1)

        form.addRow(QLabel("Cryptographic Hashes:"), hash_box)

        layout.addWidget(panel)
        layout.addStretch()

    def _build_hex_tab(self):
        layout = QVBoxLayout(self.tab_hex)
        layout.setContentsMargins(10, 10, 10, 10)
        self.hex_viewer = HexViewer()
        layout.addWidget(self.hex_viewer)

    def _build_entropy_tab(self):
        layout = QVBoxLayout(self.tab_entropy)
        layout.setContentsMargins(10, 10, 10, 10)
        self.entropy_graph = EntropyGraphWidget()
        layout.addWidget(self.entropy_graph)

    def _build_strings_tab(self):
        layout = QVBoxLayout(self.tab_strings)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        # Network and Command Badges
        self.lbl_indicators_summary = QLabel("Extracted Indicators: 0 IPs | 0 URLs | 0 Suspicious Commands")
        self.lbl_indicators_summary.setStyleSheet(f"color: {COLORS['accent_cyan']}; font-weight: bold;")
        layout.addWidget(self.lbl_indicators_summary)

        # Indicators Table
        self.table_indicators = QTableWidget(0, 3)
        self.table_indicators.setHorizontalHeaderLabels(["Indicator Category", "Detected Value", "Context / Threat Significance"])
        self.table_indicators.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table_indicators.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table_indicators.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        layout.addWidget(self.table_indicators)

        lbl_raw_str = QLabel("Sample Printable Strings (ASCII/UTF-16):")
        lbl_raw_str.setStyleSheet(f"color: {COLORS['text_secondary']}; font-weight: 600; font-size: 11px;")
        layout.addWidget(lbl_raw_str)

        self.text_raw_strings = QTextEdit()
        self.text_raw_strings.setReadOnly(True)
        self.text_raw_strings.setStyleSheet(f"background-color: #050811; color: #a5f3fc; font-family: Courier; font-size: 11px;")
        self.text_raw_strings.setMaximumHeight(160)
        layout.addWidget(self.text_raw_strings)

    def _build_signatures_tab(self):
        layout = QVBoxLayout(self.tab_signatures)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        self.lbl_sig_count = QLabel("Malware Signature Engine Status: Clean")
        self.lbl_sig_count.setStyleSheet(f"color: {COLORS['status_success']}; font-size: 13px; font-weight: bold;")
        layout.addWidget(self.lbl_sig_count)

        self.table_signatures = QTableWidget(0, 4)
        self.table_signatures.setHorizontalHeaderLabels(["Rule ID", "Threat Name", "Severity", "Description"])
        self.table_signatures.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table_signatures.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table_signatures.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table_signatures.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        layout.addWidget(self.table_signatures)

    def reload_evidence_list(self):
        """Reloads evidence dropdown from SQLite database."""
        self.evidence_items = self.state.db.get_evidence_list(self.state.active_case_id)
        self.combo_evidence.blockSignals(True)
        self.combo_evidence.clear()

        for it in self.evidence_items:
            self.combo_evidence.addItem(f"{it.file_name} ({it.detected_type})", it.id)

        self.combo_evidence.blockSignals(False)

        if self.evidence_items:
            self._display_item(self.evidence_items[0])

    def load_specific_evidence(self, evidence_id: int):
        """Directly loads an evidence item by its ID."""
        for idx in range(self.combo_evidence.count()):
            if self.combo_evidence.itemData(idx) == evidence_id:
                self.combo_evidence.setCurrentIndex(idx)
                break

    def _on_combo_selected(self, index: int):
        if index < 0 or not self.evidence_items:
            return
        evidence_id = self.combo_evidence.itemData(index)
        item = self.state.db.get_evidence_by_id(evidence_id)
        if item:
            self._display_item(item)

    def _display_item(self, item: EvidenceItem):
        self.current_item = item

        # 1. Update Metadata Tab
        self.lbl_prop_name.setText(f"<b>{item.file_name}</b>")
        self.lbl_prop_path.setText(item.file_path)
        self.lbl_prop_size.setText(f"{item.file_size:,} bytes")
        self.lbl_prop_type.setText(item.detected_type)
        self.lbl_prop_mime.setText(item.mime_type)

        if item.extension_mismatch:
            self.lbl_prop_mismatch.setText("<font color='#ef4444'><b>YES (Evasion Technique Detected)</b></font>")
        else:
            self.lbl_prop_mismatch.setText("<font color='#10b981'>No (Signature Matches Extension)</font>")

        self.lbl_prop_entropy.setText(f"<b>{item.entropy:.2f} / 8.00</b>")
        self.lbl_prop_macb.setText(
            f"Created: {item.created_time}<br/>"
            f"Modified: {item.modified_time}<br/>"
            f"Accessed: {item.accessed_time}"
        )

        self.lbl_sha256.setText(f"SHA-256: {item.sha256}")
        self.lbl_md5.setText(f"MD5: {item.md5}")
        self.lbl_sha1.setText(f"SHA-1: {item.sha1}")

        # 2. Update Hex Viewer
        self.hex_viewer.load_file(item.file_path)

        # 3. Update Entropy Graph
        profile = EvidenceEngine.calculate_sliding_entropy(item.file_path)
        self.entropy_graph.plot_entropy(profile, item.file_name, item.entropy)

        # 4. Extract Strings & Indicators
        indicators = EvidenceEngine.extract_strings_and_indicators(item.file_path)
        ips = indicators.get("ip_addresses", [])
        urls = indicators.get("urls", [])
        cmds = indicators.get("suspicious_commands", [])
        raw_strings = indicators.get("sample_strings", [])

        self.lbl_indicators_summary.setText(f"Extracted Indicators: {len(ips)} IPs | {len(urls)} URLs | {len(cmds)} Suspicious Commands")
        self.text_raw_strings.setPlainText("\n".join(raw_strings))

        rows = []
        for ip in ips:
            rows.append(("IPv4 Address", ip, "Potential external Command & Control address"))
        for url in urls:
            rows.append(("URL / Endpoint", url, "External network download or exfiltration URL"))
        for cmd in cmds:
            rows.append(("Suspicious Command", cmd, "High-risk administrative or evasion command invocation"))

        self.table_indicators.setRowCount(len(rows))
        for r_idx, (cat, val, desc) in enumerate(rows):
            self.table_indicators.setItem(r_idx, 0, QTableWidgetItem(cat))
            self.table_indicators.setItem(r_idx, 1, QTableWidgetItem(val))
            self.table_indicators.setItem(r_idx, 2, QTableWidgetItem(desc))

        # 5. YARA / Malware Signatures
        matches = SignatureEngine.scan_file(item.file_path)
        if matches:
            self.lbl_sig_count.setText(f"⚠️ {len(matches)} MALWARE SIGNATURE(S) DETECTED!")
            self.lbl_sig_count.setStyleSheet(f"color: {COLORS['status_danger']}; font-size: 13px; font-weight: bold;")
        else:
            self.lbl_sig_count.setText("Malware Signature Engine Status: No Known Signatures Matched (Clean)")
            self.lbl_sig_count.setStyleSheet(f"color: {COLORS['status_success']}; font-size: 13px; font-weight: bold;")

        self.table_signatures.setRowCount(len(matches))
        for r_idx, m in enumerate(matches):
            self.table_signatures.setItem(r_idx, 0, QTableWidgetItem(m["rule_id"]))
            self.table_signatures.setItem(r_idx, 1, QTableWidgetItem(m["name"]))

            sev_item = QTableWidgetItem(m["severity"])
            if m["severity"] == "CRITICAL":
                sev_item.setForeground(Qt.red)
            else:
                sev_item.setForeground(Qt.yellow)
            self.table_signatures.setItem(r_idx, 2, sev_item)
            self.table_signatures.setItem(r_idx, 3, QTableWidgetItem(m["description"]))

"""
ForenSight AI - Forensic Timeline Analysis View
Reconstructs MACB (Modified, Accessed, Created) event timelines,
identifies temporal bursts, and tracks incident activity windows.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QTableWidget, QTableWidgetItem, QHeaderView,
    QComboBox, QFileDialog, QMessageBox
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
import csv

from config import COLORS
from core.state import AppState
from engines.timeline_engine import TimelineEngine, TimelineEvent


class TimelineView(QWidget):
    """Forensic MACB chronological event stream and burst analysis."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.state = AppState.get_instance()
        self.events = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        # Header
        top_layout = QHBoxLayout()
        title_box = QVBoxLayout()
        lbl_title = QLabel("Forensic MACB Activity Timeline")
        lbl_title.setStyleSheet(f"color: {COLORS['text_primary']}; font-size: 20px; font-weight: 700;")
        title_box.addWidget(lbl_title)

        lbl_sub = QLabel("Temporal correlation of file creation, modification, and access across evidence artifacts.")
        lbl_sub.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px;")
        title_box.addWidget(lbl_sub)
        top_layout.addLayout(title_box)
        top_layout.addStretch()

        btn_export_csv = QPushButton("📥 Export Timeline CSV")
        btn_export_csv.setProperty("class", "SecondaryButton")
        btn_export_csv.clicked.connect(self._export_timeline_csv)
        top_layout.addWidget(btn_export_csv)

        layout.addLayout(top_layout)

        # Filter bar
        filter_bar = QFrame()
        filter_bar.setStyleSheet(f"background-color: {COLORS['bg_card']}; border-radius: 8px; padding: 8px 12px; border: 1px solid {COLORS['border']};")
        fb_layout = QHBoxLayout(filter_bar)
        fb_layout.setContentsMargins(8, 4, 8, 4)
        fb_layout.setSpacing(14)

        fb_layout.addWidget(QLabel("Event Filter:"))
        self.combo_event_type = QComboBox()
        self.combo_event_type.addItems(["All Events (MACB)", "Created (C)", "Modified (M)", "Accessed (A)"])
        self.combo_event_type.currentTextChanged.connect(self._apply_filter)
        fb_layout.addWidget(self.combo_event_type)

        fb_layout.addStretch()
        self.lbl_burst_indicator = QLabel("")
        self.lbl_burst_indicator.setStyleSheet(f"color: {COLORS['status_warning']}; font-weight: bold;")
        fb_layout.addWidget(self.lbl_burst_indicator)

        layout.addWidget(filter_bar)

        # Timeline Table
        table_panel = QFrame()
        table_panel.setProperty("class", "CardPanel")
        tbl_layout = QVBoxLayout(table_panel)
        tbl_layout.setContentsMargins(8, 8, 8, 8)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Timestamp (UTC/Local)", "Event Type", "File Name", "Risk Level", "File Size", "Forensic Event Description"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        tbl_layout.addWidget(self.table)

        layout.addWidget(table_panel)

        # Connect state
        self.state.case_changed.connect(self.refresh_timeline)
        self.state.evidence_imported.connect(self.refresh_timeline)

        self.refresh_timeline()

    def refresh_timeline(self):
        items = self.state.db.get_evidence_list(self.state.active_case_id)
        self.events = TimelineEngine.build_timeline(items)

        # Check for activity bursts (e.g. mass file changes)
        bursts = TimelineEngine.detect_bursts(self.events, window_seconds=300, min_events=4)
        if bursts:
            self.lbl_burst_indicator.setText(f"⚠️ {len(bursts)} Activity Burst(s) Detected (Potential Mass Modification)")
        else:
            self.lbl_burst_indicator.setText("Activity Profile: Normal Distribution")

        self._apply_filter()

    def _apply_filter(self):
        f_type = self.combo_event_type.currentText()
        if f_type.startswith("Created"):
            filtered = [e for e in self.events if e.event_type == "Created"]
        elif f_type.startswith("Modified"):
            filtered = [e for e in self.events if e.event_type == "Modified"]
        elif f_type.startswith("Accessed"):
            filtered = [e for e in self.events if e.event_type == "Accessed"]
        else:
            filtered = self.events

        self.table.setRowCount(len(filtered))
        for row, e in enumerate(filtered):
            self.table.setItem(row, 0, QTableWidgetItem(e.timestamp))

            # Event type badge color
            type_item = QTableWidgetItem(e.event_type)
            if e.event_type == "Modified":
                type_item.setForeground(QColor(COLORS["status_warning"]))
            elif e.event_type == "Created":
                type_item.setForeground(QColor(COLORS["accent_cyan"]))
            else:
                type_item.setForeground(QColor(COLORS["text_secondary"]))
            self.table.setItem(row, 1, type_item)

            self.table.setItem(row, 2, QTableWidgetItem(e.file_name))

            risk_item = QTableWidgetItem(e.risk_level)
            if e.risk_level in ["Critical Anomaly", "High Risk"]:
                risk_item.setForeground(QColor(COLORS["status_danger"]))
            self.table.setItem(row, 3, risk_item)

            self.table.setItem(row, 4, QTableWidgetItem(f"{e.file_size:,} B"))
            self.table.setItem(row, 5, QTableWidgetItem(e.details))

    def _export_timeline_csv(self):
        if not self.events:
            QMessageBox.information(self, "No Events", "No timeline events to export.")
            return

        file_path, _ = QFileDialog.getSaveFileName(self, "Export Timeline CSV", "forensic_timeline.csv", "CSV Files (*.csv)")
        if not file_path:
            return

        with open(file_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp", "EventType", "FileName", "FilePath", "RiskLevel", "FileSize", "Details"])
            for e in self.events:
                writer.writerow([e.timestamp, e.event_type, e.file_name, e.file_path, e.risk_level, e.file_size, e.details])

        QMessageBox.information(self, "Export Successful", f"Forensic timeline exported successfully to:\n{file_path}")

"""
ForenSight AI - Duplicate Evidence View
Groups identical evidence files sharing SHA-256 hashes, calculates storage impact,
and highlights cross-directory malware staging.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QTableWidget, QTableWidgetItem, QHeaderView, QSplitter
)
from PySide6.QtCore import Qt
from config import COLORS
from core.state import AppState
from core.models import DuplicateGroup
from ui.components.stat_card import StatCard


class DuplicateView(QWidget):
    """Forensic duplicate artifact detection and cluster management."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.state = AppState.get_instance()
        self.duplicate_groups = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        # Header
        top_layout = QHBoxLayout()
        title_box = QVBoxLayout()
        lbl_title = QLabel("Duplicate Evidence Analysis")
        lbl_title.setStyleSheet(f"color: {COLORS['text_primary']}; font-size: 20px; font-weight: 700;")
        title_box.addWidget(lbl_title)

        lbl_sub = QLabel("Identify identical artifacts across seized media, track cross-folder malware staging, and audit storage volume.")
        lbl_sub.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px;")
        title_box.addWidget(lbl_sub)
        top_layout.addLayout(title_box)
        top_layout.addStretch()

        btn_refresh = QPushButton("🔄 Refresh Duplicates")
        btn_refresh.setProperty("class", "SecondaryButton")
        btn_refresh.clicked.connect(self.refresh_duplicates)
        top_layout.addWidget(btn_refresh)

        layout.addLayout(top_layout)

        # KPI Cards
        kpi_layout = QHBoxLayout()
        kpi_layout.setSpacing(12)

        self.card_clusters = StatCard("Duplicate Clusters", "0", "Unique Hash Sets", COLORS["accent_cyan"])
        self.card_copies = StatCard("Duplicate Files", "0", "Redundant Artifacts", COLORS["status_warning"])
        self.card_wasted = StatCard("Redundant Storage", "0 B", "Wasted Volume", "#a855f7")

        kpi_layout.addWidget(self.card_clusters)
        kpi_layout.addWidget(self.card_copies)
        kpi_layout.addWidget(self.card_wasted)
        layout.addLayout(kpi_layout)

        # Splitter: Clusters on left, File paths in cluster on right
        splitter = QSplitter(Qt.Horizontal)

        # Left: Duplicate Clusters Table
        left_panel = QFrame()
        left_panel.setProperty("class", "CardPanel")
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(12, 12, 12, 12)
        left_layout.setSpacing(8)

        lbl_left = QLabel("IDENTIFIED DUPLICATE HASH CLUSTERS")
        lbl_left.setStyleSheet(f"color: {COLORS['text_secondary']}; font-weight: bold; font-size: 11px;")
        left_layout.addWidget(lbl_left)

        self.table_clusters = QTableWidget(0, 4)
        self.table_clusters.setHorizontalHeaderLabels(["SHA-256 Hash", "Copies", "File Size", "Wasted Storage"])
        self.table_clusters.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table_clusters.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table_clusters.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table_clusters.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table_clusters.itemSelectionChanged.connect(self._on_cluster_selected)
        left_layout.addWidget(self.table_clusters)
        splitter.addWidget(left_panel)

        # Right: Associated Files in Selected Cluster
        right_panel = QFrame()
        right_panel.setProperty("class", "CardPanel")
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(12, 12, 12, 12)
        right_layout.setSpacing(8)

        self.lbl_right_head = QLabel("FILES SHARING SELECTED HASH")
        self.lbl_right_head.setStyleSheet(f"color: {COLORS['accent_cyan']}; font-weight: bold; font-size: 11px;")
        right_layout.addWidget(self.lbl_right_head)

        self.table_files = QTableWidget(0, 3)
        self.table_files.setHorizontalHeaderLabels(["File Name", "File Path", "Acquisition Source"])
        self.table_files.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table_files.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table_files.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        right_layout.addWidget(self.table_files)
        splitter.addWidget(right_panel)

        splitter.setSizes([500, 500])
        layout.addWidget(splitter)

        # Connect state
        self.state.case_changed.connect(self.refresh_duplicates)
        self.state.evidence_imported.connect(self.refresh_duplicates)

        self.refresh_duplicates()

    def refresh_duplicates(self):
        """Fetches duplicate clusters for active case."""
        self.duplicate_groups = self.state.db.get_duplicates_by_case(self.state.active_case_id)

        total_copies = sum(dg.count for dg in self.duplicate_groups)
        total_wasted = sum(dg.total_wasted_bytes for dg in self.duplicate_groups)

        wasted_str = f"{total_wasted / 1024:.1f} KB" if total_wasted < 1024 * 1024 else f"{total_wasted / (1024*1024):.2f} MB"

        self.card_clusters.update_data(str(len(self.duplicate_groups)))
        self.card_copies.update_data(str(total_copies))
        self.card_wasted.update_data(wasted_str)

        self.table_clusters.setRowCount(len(self.duplicate_groups))
        for row, dg in enumerate(self.duplicate_groups):
            self.table_clusters.setItem(row, 0, QTableWidgetItem(f"{dg.sha256[:24]}..."))
            self.table_clusters.setItem(row, 1, QTableWidgetItem(str(dg.count)))
            self.table_clusters.setItem(row, 2, QTableWidgetItem(f"{dg.file_size:,} B"))
            self.table_clusters.setItem(row, 3, QTableWidgetItem(f"{dg.total_wasted_bytes:,} B"))

        if self.duplicate_groups:
            self.table_clusters.selectRow(0)
        else:
            self.table_files.setRowCount(0)

    def _on_cluster_selected(self):
        selected_rows = self.table_clusters.selectionModel().selectedRows()
        if not selected_rows:
            return
        row = selected_rows[0].row()
        if 0 <= row < len(self.duplicate_groups):
            dg = self.duplicate_groups[row]
            self.lbl_right_head.setText(f"CLUSTER: SHA-256 {dg.sha256[:16]}... ({dg.count} Identical Copies)")
            self.table_files.setRowCount(len(dg.items))
            for f_row, it in enumerate(dg.items):
                self.table_files.setItem(f_row, 0, QTableWidgetItem(it.file_name))
                self.table_files.setItem(f_row, 1, QTableWidgetItem(it.file_path))
                self.table_files.setItem(f_row, 2, QTableWidgetItem(it.custody_source))

"""
ForenSight AI - Forensic Dashboard View
Real-time investigation telemetry, interactive Matplotlib charts,
key performance indicators, and rapid action launcher.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QTableWidget, QTableWidgetItem, QHeaderView, QScrollArea
)
from PySide6.QtCore import Qt, Signal
import matplotlib
matplotlib.use("QtAgg")
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

from config import COLORS
from core.state import AppState
from ui.components.stat_card import StatCard


class DashboardView(QWidget):
    """Forensic investigation dashboard with telemetry and interactive charts."""

    # Navigation signals to jump to specific tabs from quick actions
    navigate_to_tab = Signal(int)  # tab index

    def __init__(self, parent=None):
        super().__init__(parent)
        self.state = AppState.get_instance()

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(16)

        # Scroll area to ensure dashboard fits any screen resolution
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setStyleSheet("background-color: transparent;")

        container = QWidget()
        self.layout = QVBoxLayout(container)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(16)

        self._build_header()
        self._build_kpi_cards()
        self._build_quick_actions()
        self._build_charts_section()
        self._build_threat_preview_table()

        scroll.setWidget(container)
        main_layout.addWidget(scroll)

        # Connect to state updates
        self.state.case_changed.connect(self.refresh_data)
        self.state.evidence_imported.connect(self.refresh_data)
        self.state.ai_scan_completed.connect(self.refresh_data)
        self.state.integrity_check_completed.connect(self.refresh_data)

        self.refresh_data()

    def _build_header(self):
        header_layout = QHBoxLayout()
        title_box = QVBoxLayout()
        self.lbl_case_title = QLabel("Forensic Investigation Telemetry")
        self.lbl_case_title.setStyleSheet(f"color: {COLORS['text_primary']}; font-size: 20px; font-weight: 700;")
        title_box.addWidget(self.lbl_case_title)

        self.lbl_case_meta = QLabel("Loading active case details...")
        self.lbl_case_meta.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px;")
        title_box.addWidget(self.lbl_case_meta)

        header_layout.addLayout(title_box)
        header_layout.addStretch()

        btn_refresh = QPushButton("🔄 Refresh Telemetry")
        btn_refresh.setProperty("class", "SecondaryButton")
        btn_refresh.clicked.connect(self.refresh_data)
        header_layout.addWidget(btn_refresh)

        self.layout.addLayout(header_layout)

    def _build_kpi_cards(self):
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(12)

        self.card_total = StatCard("Total Evidence", "0", "0 MB Seized", COLORS["accent_cyan"])
        self.card_verified = StatCard("Integrity Verified", "0", "100% Cryptographic Match", COLORS["status_success"])
        self.card_anomalies = StatCard("AI Anomalies Flagged", "0", "High & Critical Risk", COLORS["status_danger"])
        self.card_duplicates = StatCard("Duplicate Clusters", "0", "0 Duplicate Files", COLORS["status_warning"])

        cards_layout.addWidget(self.card_total)
        cards_layout.addWidget(self.card_verified)
        cards_layout.addWidget(self.card_anomalies)
        cards_layout.addWidget(self.card_duplicates)

        self.layout.addLayout(cards_layout)

    def _build_quick_actions(self):
        panel = QFrame()
        panel.setProperty("class", "CardPanel")
        panel_layout = QHBoxLayout(panel)
        panel_layout.setContentsMargins(14, 10, 14, 10)
        panel_layout.setSpacing(10)

        lbl = QLabel("QUICK FORENSIC ACTIONS:")
        lbl.setStyleSheet(f"color: {COLORS['text_secondary']}; font-weight: 600; font-size: 11px;")
        panel_layout.addWidget(lbl)

        btn_add_ev = QPushButton("➕ Ingest Evidence")
        btn_add_ev.setProperty("class", "PrimaryButton")
        btn_add_ev.clicked.connect(lambda: self.navigate_to_tab.emit(2))  # Evidence tab
        panel_layout.addWidget(btn_add_ev)

        btn_ai_scan = QPushButton("🧠 Run AI Anomaly Scan")
        btn_ai_scan.setProperty("class", "SecondaryButton")
        btn_ai_scan.clicked.connect(lambda: self.navigate_to_tab.emit(4))  # AI Tab
        panel_layout.addWidget(btn_ai_scan)

        btn_dups = QPushButton("🔍 Inspect Duplicates")
        btn_dups.setProperty("class", "SecondaryButton")
        btn_dups.clicked.connect(lambda: self.navigate_to_tab.emit(5))  # Duplicate Tab
        panel_layout.addWidget(btn_dups)

        btn_timeline = QPushButton("⏱ MACB Timeline")
        btn_timeline.setProperty("class", "SecondaryButton")
        btn_timeline.clicked.connect(lambda: self.navigate_to_tab.emit(6))  # Timeline tab
        panel_layout.addWidget(btn_timeline)

        btn_report = QPushButton("📄 Generate Report")
        btn_report.setProperty("class", "SecondaryButton")
        btn_report.clicked.connect(lambda: self.navigate_to_tab.emit(8))  # Report tab
        panel_layout.addWidget(btn_report)

        panel_layout.addStretch()
        self.layout.addWidget(panel)

    def _build_charts_section(self):
        charts_layout = QHBoxLayout()
        charts_layout.setSpacing(14)

        # Matplotlib Figure for Donut & Bar Charts
        self.fig_charts = Figure(figsize=(10, 3.2), dpi=100)
        self.fig_charts.patch.set_facecolor(COLORS["bg_card"])
        self.canvas_charts = FigureCanvas(self.fig_charts)
        self.canvas_charts.setStyleSheet(f"background-color: {COLORS['bg_card']}; border-radius: 8px; border: 1px solid {COLORS['border']};")

        charts_layout.addWidget(self.canvas_charts)
        self.layout.addLayout(charts_layout)

    def _build_threat_preview_table(self):
        panel = QFrame()
        panel.setProperty("class", "CardPanel")
        vbox = QVBoxLayout(panel)
        vbox.setContentsMargins(16, 14, 16, 14)
        vbox.setSpacing(10)

        header_layout = QHBoxLayout()
        lbl_title = QLabel("CRITICAL FORENSIC ALERTS & ANOMALOUS ARTIFACTS")
        lbl_title.setStyleSheet(f"color: {COLORS['status_danger']}; font-weight: bold; font-size: 13px;")
        header_layout.addWidget(lbl_title)
        header_layout.addStretch()

        btn_view_all = QPushButton("View All Evidence ►")
        btn_view_all.setProperty("class", "SecondaryButton")
        btn_view_all.clicked.connect(lambda: self.navigate_to_tab.emit(2))
        header_layout.addWidget(btn_view_all)
        vbox.addLayout(header_layout)

        self.table_alerts = QTableWidget(0, 5)
        self.table_alerts.setHorizontalHeaderLabels(["File Name", "Detected Type", "Risk Category", "Anomaly Score", "Forensic Reasons"])
        self.table_alerts.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table_alerts.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table_alerts.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table_alerts.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table_alerts.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.table_alerts.setMaximumHeight(200)
        vbox.addWidget(self.table_alerts)

        self.layout.addWidget(panel)

    def refresh_data(self):
        """Pulls latest metrics from SQLite database and redraws telemetry."""
        case = self.state.get_active_case()
        if not case:
            return

        self.lbl_case_title.setText(f"Investigation Telemetry: {case.title}")
        self.lbl_case_meta.setText(f"Case No: {case.case_number}  |  Lead Examiner: {case.investigator_name}  |  Agency: {case.organization}")

        stats = self.state.db.get_case_statistics(self.state.active_case_id)
        evidence_items = self.state.db.get_evidence_list(self.state.active_case_id)

        # Update KPI cards
        total_mb = stats["total_size_bytes"] / (1024 * 1024)
        self.card_total.update_data(str(stats["total_evidence"]), f"{total_mb:.2f} MB Seized Storage")

        verif_pct = (stats["verified_count"] / max(stats["total_evidence"], 1)) * 100
        self.card_verified.update_data(f"{stats['verified_count']}/{stats['total_evidence']}", f"{verif_pct:.1f}% Cryptographic Match")

        self.card_anomalies.update_data(str(stats["suspicious_count"]), f"{stats['mismatch_count']} Extension Mismatches")

        self.card_duplicates.update_data(str(stats["duplicate_clusters"]), f"{stats['duplicate_files']} Duplicate Copies")

        # Update Charts
        self._render_charts(stats, evidence_items)

        # Populate Alerts table
        suspicious = [it for it in evidence_items if it.is_suspicious]
        suspicious.sort(key=lambda x: x.anomaly_score, reverse=True)

        self.table_alerts.setRowCount(len(suspicious))
        for row, it in enumerate(suspicious):
            self.table_alerts.setItem(row, 0, QTableWidgetItem(it.file_name))
            self.table_alerts.setItem(row, 1, QTableWidgetItem(it.detected_type))

            # Risk item
            risk_item = QTableWidgetItem(it.risk_level)
            if it.risk_level in ["Critical Anomaly", "High Risk"]:
                risk_item.setForeground(Qt.red)
            else:
                risk_item.setForeground(Qt.yellow)
            self.table_alerts.setItem(row, 2, risk_item)

            score_item = QTableWidgetItem(f"{it.anomaly_score:.1f}%")
            self.table_alerts.setItem(row, 3, score_item)

            reasons_str = "; ".join(it.flagged_reasons) if it.flagged_reasons else "ML Anomaly"
            self.table_alerts.setItem(row, 4, QTableWidgetItem(reasons_str))

    def _render_charts(self, stats, evidence_items):
        self.fig_charts.clear()

        # Two subplots: Donut (File Types) & Bar (Risk Classification)
        ax1 = self.fig_charts.add_subplot(121)
        ax2 = self.fig_charts.add_subplot(122)

        for ax in [ax1, ax2]:
            ax.set_facecolor(COLORS["bg_card"])
            ax.tick_params(colors=COLORS["text_secondary"], labelsize=8)
            for spine in ax.spines.values():
                spine.set_color(COLORS["border"])

        # 1. File Type Distribution Donut
        file_types = stats.get("file_types", {})
        if file_types:
            labels = list(file_types.keys())
            sizes = list(file_types.values())
            chart_colors = ["#06b6d4", "#3b82f6", "#8b5cf6", "#ec4899", "#10b981", "#f59e0b", "#94a3b8"][:len(labels)]
            wedges, texts, autotexts = ax1.pie(
                sizes, labels=labels, autopct="%1.0f%%", startangle=90,
                colors=chart_colors, pctdistance=0.75,
                textprops=dict(color=COLORS["text_secondary"], fontsize=8)
            )
            for at in autotexts:
                at.set_color("#ffffff")
                at.set_fontsize(7)
                at.set_weight("bold")
            # Donut hole
            center_circle = matplotlib.patches.Circle((0, 0), 0.55, fc=COLORS["bg_card"])
            ax1.add_artist(center_circle)
            ax1.set_title("Artifact File Type Distribution", color=COLORS["text_primary"], fontsize=10, fontweight="bold")
        else:
            ax1.text(0.5, 0.5, "No Artifacts Ingested", color=COLORS["text_muted"], ha="center", va="center")
            ax1.set_title("Artifact File Type Distribution", color=COLORS["text_primary"], fontsize=10, fontweight="bold")

        # 2. Risk Level Horizontal Bar Chart
        risk_map = stats.get("risk_map", {})
        categories = ["Benign", "Suspicious", "High Risk", "Critical Anomaly"]
        counts = [risk_map.get(cat, 0) for cat in categories]
        bar_colors = [COLORS["status_success"], COLORS["status_warning"], "#f97316", COLORS["status_danger"]]

        bars = ax2.barh(categories, counts, color=bar_colors, height=0.55, edgecolor=COLORS["border"])
        ax2.set_title("AI Risk & Anomaly Classification", color=COLORS["text_primary"], fontsize=10, fontweight="bold")
        ax2.set_xlabel("Artifact Count", color=COLORS["text_secondary"], fontsize=8)
        ax2.grid(True, axis="x", color=COLORS["border"], linestyle="--", alpha=0.5)

        for bar in bars:
            width = bar.get_width()
            if width > 0:
                ax2.text(width + 0.1, bar.get_y() + bar.get_height()/2, f"{int(width)}",
                         va="center", ha="left", color=COLORS["text_primary"], fontsize=8, fontweight="bold")

        self.fig_charts.tight_layout()
        self.canvas_charts.draw()

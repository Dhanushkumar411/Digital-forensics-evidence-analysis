"""
ForenSight AI - Master Application Window
Main user interface container coordinating sidebar navigation, active case header,
and modular forensic analysis views.
"""

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QStackedWidget, QFrame, QButtonGroup
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon

from config import APP_TITLE, APP_VERSION, COLORS
from core.state import AppState

# Views
from ui.views.dashboard_view import DashboardView
from ui.views.case_view import CaseView
from ui.views.evidence_view import EvidenceView
from ui.views.file_inspector_view import FileInspectorView
from ui.views.ai_analysis_view import AIAnalysisView
from ui.views.duplicate_view import DuplicateView
from ui.views.timeline_view import TimelineView
from ui.views.audit_view import AuditView
from ui.views.report_view import ReportView


class MainWindow(QMainWindow):
    """Primary application window for ForenSight AI."""

    def __init__(self):
        super().__init__()
        self.state = AppState.get_instance()

        self.setWindowTitle(f"{APP_TITLE} v{APP_VERSION}")
        self.resize(1380, 880)
        self.setMinimumSize(1100, 720)

        # Central Widget & Root Layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        root_layout = QVBoxLayout(central_widget)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # 1. Top Header Bar
        self._build_header_bar(root_layout)

        # 2. Main Content Split: Sidebar + Stacked Views
        content_layout = QHBoxLayout()
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(0)

        self._build_sidebar(content_layout)
        self._build_views_stack(content_layout)

        root_layout.addLayout(content_layout)

        # Connect state signals for live header updates
        self.state.case_changed.connect(self._update_header_stats)
        self.state.evidence_imported.connect(self._update_header_stats)

        self._update_header_stats()

    def _build_header_bar(self, parent_layout):
        header = QFrame()
        header.setObjectName("HeaderBar")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(18, 10, 18, 10)
        header_layout.setSpacing(16)

        # Brand / Logo
        brand_box = QHBoxLayout()
        brand_box.setSpacing(8)
        lbl_brand = QLabel("FORENSIGHT AI")
        lbl_brand.setStyleSheet(f"color: {COLORS['accent_cyan']}; font-weight: 800; font-size: 16px; letter-spacing: 1px;")
        brand_box.addWidget(lbl_brand)

        lbl_sub = QLabel("MCA CYBERSECURITY PLATFORM")
        lbl_sub.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 10px; font-weight: 600; padding-top: 3px;")
        brand_box.addWidget(lbl_sub)
        header_layout.addLayout(brand_box)

        header_layout.addStretch()

        # Active Case Pill
        self.pill_case = QLabel("📁 Active Case: Loading...")
        self.pill_case.setStyleSheet(f"background-color: {COLORS['bg_card']}; border: 1px solid {COLORS['border']}; border-radius: 6px; padding: 5px 12px; color: {COLORS['text_primary']}; font-size: 11px; font-weight: 600;")
        header_layout.addWidget(self.pill_case)

        # Examiner Pill
        self.pill_examiner = QLabel(f"👤 Examiner: {self.state.current_investigator}")
        self.pill_examiner.setStyleSheet(f"background-color: {COLORS['bg_card']}; border: 1px solid {COLORS['border']}; border-radius: 6px; padding: 5px 12px; color: {COLORS['text_secondary']}; font-size: 11px;")
        header_layout.addWidget(self.pill_examiner)

        # Evidence Count Pill
        self.pill_count = QLabel("📦 Evidence: 0 items")
        self.pill_count.setStyleSheet(f"background-color: {COLORS['bg_card']}; border: 1px solid {COLORS['border']}; border-radius: 6px; padding: 5px 12px; color: {COLORS['accent_cyan']}; font-size: 11px; font-weight: 600;")
        header_layout.addWidget(self.pill_count)

        # Database Status
        lbl_db = QLabel("🟢 SQLite WAL [Online]")
        lbl_db.setStyleSheet(f"color: {COLORS['status_success']}; font-size: 11px; font-weight: 600; padding: 4px 8px;")
        header_layout.addWidget(lbl_db)

        parent_layout.addWidget(header)

    def _build_sidebar(self, parent_layout):
        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(230)
        sb_layout = QVBoxLayout(sidebar)
        sb_layout.setContentsMargins(12, 16, 12, 16)
        sb_layout.setSpacing(6)

        lbl_menu = QLabel("FORENSIC MODULES")
        lbl_menu.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 10px; font-weight: 700; letter-spacing: 0.8px; margin-bottom: 6px; padding-left: 12px;")
        sb_layout.addWidget(lbl_menu)

        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)

        nav_items = [
            ("📊  Dashboard", 0),
            ("📁  Case Profiles", 1),
            ("📦  Evidence Manager", 2),
            ("🔍  Deep File Inspector", 3),
            ("🧠  AI Anomaly Center", 4),
            ("👥  Duplicate Analysis", 5),
            ("⏱  MACB Timeline", 6),
            ("🛡  Cryptographic Audit", 7),
            ("📄  Forensic Reports", 8)
        ]

        self.nav_buttons = []
        for label, idx in nav_items:
            btn = QPushButton(label)
            btn.setObjectName("NavButton")
            btn.setCheckable(True)
            if idx == 0:
                btn.setChecked(True)
            self.nav_group.addButton(btn, idx)
            sb_layout.addWidget(btn)
            self.nav_buttons.append(btn)

        self.nav_group.idClicked.connect(self._switch_view)

        sb_layout.addStretch()

        # Lab info box
        info_frame = QFrame()
        info_frame.setStyleSheet(f"background-color: {COLORS['bg_card']}; border: 1px solid {COLORS['border']}; border-radius: 8px; padding: 10px;")
        inf_vbox = QVBoxLayout(info_frame)
        inf_vbox.setContentsMargins(0, 0, 0, 0)
        inf_vbox.setSpacing(4)
        lbl_lab = QLabel("ForenSight AI v2.4")
        lbl_lab.setStyleSheet(f"color: {COLORS['text_primary']}; font-weight: bold; font-size: 11px;")
        lbl_comp = QLabel("NIST SP 800-86 & ISO 27037")
        lbl_comp.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 9px;")
        inf_vbox.addWidget(lbl_lab)
        inf_vbox.addWidget(lbl_comp)
        sb_layout.addWidget(info_frame)

        parent_layout.addWidget(sidebar)

    def _build_views_stack(self, parent_layout):
        self.stack = QStackedWidget()

        # Instantiate all 9 views
        self.view_dashboard = DashboardView()
        self.view_case = CaseView()
        self.view_evidence = EvidenceView()
        self.view_inspector = FileInspectorView()
        self.view_ai = AIAnalysisView()
        self.view_duplicates = DuplicateView()
        self.view_timeline = TimelineView()
        self.view_audit = AuditView()
        self.view_reports = ReportView()

        # Add to stack in index order (0 to 8)
        self.stack.addWidget(self.view_dashboard)   # 0
        self.stack.addWidget(self.view_case)        # 1
        self.stack.addWidget(self.view_evidence)    # 2
        self.stack.addWidget(self.view_inspector)   # 3
        self.stack.addWidget(self.view_ai)          # 4
        self.stack.addWidget(self.view_duplicates)  # 5
        self.stack.addWidget(self.view_timeline)    # 6
        self.stack.addWidget(self.view_audit)       # 7
        self.stack.addWidget(self.view_reports)     # 8

        # Deep link connections
        self.view_dashboard.navigate_to_tab.connect(self._switch_view)
        self.view_evidence.inspect_evidence_requested.connect(self._inspect_file_deep)
        self.view_ai.inspect_requested.connect(self._inspect_file_deep)

        parent_layout.addWidget(self.stack)

    def _switch_view(self, view_index: int):
        if 0 <= view_index < self.stack.count():
            self.stack.setCurrentIndex(view_index)
            # Update sidebar checked state
            btn = self.nav_group.button(view_index)
            if btn and not btn.isChecked():
                btn.setChecked(True)

    def _inspect_file_deep(self, evidence_id: int):
        """Switches to Deep Inspector tab and automatically focuses the requested evidence item."""
        self._switch_view(3)  # Inspector tab
        self.view_inspector.load_specific_evidence(evidence_id)

    def _update_header_stats(self):
        case = self.state.get_active_case()
        if case:
            self.pill_case.setText(f"📁 Active Case: {case.case_number}")
            self.pill_examiner.setText(f"👤 Examiner: {case.investigator_name}")

        stats = self.state.db.get_case_statistics(self.state.active_case_id)
        self.pill_count.setText(f"📦 Evidence: {stats['total_evidence']} items ({stats['total_size_bytes'] / (1024*1024):.1f} MB)")

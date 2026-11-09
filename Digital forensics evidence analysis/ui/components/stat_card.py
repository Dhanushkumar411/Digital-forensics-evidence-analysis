"""
ForenSight AI - StatCard Component
Modern dashboard metric card with icon, title, value, and status indicator.
"""

from PySide6.QtWidgets import QFrame, QVBoxLayout, QHBoxLayout, QLabel
from PySide6.QtCore import Qt
from config import COLORS


class StatCard(QFrame):
    """Forensic metric card displaying a high-level KPI."""

    def __init__(self, title: str, value: str, subtitle: str = "", accent_color: str = COLORS["accent_cyan"], parent=None):
        super().__init__(parent)
        self.setObjectName("StatCard")
        self.accent_color = accent_color

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(6)

        # Header: Title & Accent indicator
        top_layout = QHBoxLayout()
        self.lbl_title = QLabel(title.upper())
        self.lbl_title.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 11px; font-weight: 600; letter-spacing: 0.5px;")
        top_layout.addWidget(self.lbl_title)
        top_layout.addStretch()

        self.indicator = QFrame()
        self.indicator.setFixedSize(8, 8)
        self.indicator.setStyleSheet(f"background-color: {accent_color}; border-radius: 4px;")
        top_layout.addWidget(self.indicator)
        layout.addLayout(top_layout)

        # Large Value
        self.lbl_value = QLabel(value)
        self.lbl_value.setStyleSheet(f"color: {COLORS['text_primary']}; font-size: 24px; font-weight: 700;")
        layout.addWidget(self.lbl_value)

        # Subtitle / Details
        self.lbl_subtitle = QLabel(subtitle)
        self.lbl_subtitle.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 11px;")
        layout.addWidget(self.lbl_subtitle)

        # Bottom accent strip
        self.setStyleSheet(f"""
        QFrame#StatCard {{
            background-color: {COLORS['bg_card']};
            border: 1px solid {COLORS['border']};
            border-top: 3px solid {accent_color};
            border-radius: 8px;
        }}
        QFrame#StatCard:hover {{
            background-color: {COLORS['bg_card_hover']};
            border-color: {accent_color};
        }}
        """)

    def update_data(self, value: str, subtitle: str = ""):
        self.lbl_value.setText(value)
        if subtitle:
            self.lbl_subtitle.setText(subtitle)

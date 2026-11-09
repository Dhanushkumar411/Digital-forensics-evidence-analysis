"""
ForenSight AI - Chain of Custody Dialog
Modal dialog to inspect, verify, or register chain of custody records for seized evidence.
"""

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QTextEdit, QPushButton, QFrame, QFormLayout
)
from core.models import EvidenceItem
from config import COLORS


class CustodyModal(QDialog):
    """Forensic Chain of Custody metadata inspection and update dialog."""

    def __init__(self, item: EvidenceItem, parent=None):
        super().__init__(parent)
        self.item = item
        self.setWindowTitle(f"Chain of Custody - {item.file_name}")
        self.resize(550, 480)
        self.setStyleSheet(f"""
        QDialog {{
            background-color: {COLORS['bg_dark']};
            color: {COLORS['text_primary']};
        }}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        # Header
        header = QLabel(f"CHAIN OF CUSTODY VERIFICATION")
        header.setStyleSheet(f"color: {COLORS['accent_cyan']}; font-size: 15px; font-weight: bold;")
        layout.addWidget(header)

        sub = QLabel("Record of acquisition, cryptographic integrity baseline, and handling history.")
        sub.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 11px;")
        layout.addWidget(sub)

        # Form layout
        form_frame = QFrame()
        form_frame.setStyleSheet(f"background-color: {COLORS['bg_card']}; border-radius: 8px; padding: 12px; border: 1px solid {COLORS['border']};")
        form_layout = QFormLayout(form_frame)
        form_layout.setSpacing(10)

        # Item info fields
        form_layout.addRow(QLabel("File Name:"), QLabel(f"<b>{item.file_name}</b>"))
        form_layout.addRow(QLabel("Evidence Size:"), QLabel(f"{item.file_size:,} bytes ({item.detected_type})"))
        form_layout.addRow(QLabel("SHA-256 Hash:"), QLabel(f"<font face='Courier' size='2'>{item.sha256}</font>"))
        form_layout.addRow(QLabel("MD5 Hash:"), QLabel(f"<font face='Courier' size='2'>{item.md5}</font>"))
        form_layout.addRow(QLabel("Acquisition Date:"), QLabel(item.acquisition_date))

        self.edit_source = QLineEdit(item.custody_source)
        form_layout.addRow(QLabel("Seizure Source / Media:"), self.edit_source)

        self.edit_notes = QTextEdit(item.custody_notes)
        self.edit_notes.setPlaceholderText("Enter investigator chain of custody observations, warrant #, handling location...")
        self.edit_notes.setMaximumHeight(80)
        form_layout.addRow(QLabel("Custody Notes:"), self.edit_notes)

        layout.addWidget(form_frame)

        # Action Buttons
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        self.btn_cancel = QPushButton("Close")
        self.btn_cancel.setProperty("class", "SecondaryButton")
        self.btn_cancel.clicked.connect(self.reject)
        btn_layout.addWidget(self.btn_cancel)

        self.btn_save = QPushButton("Save Custody Record")
        self.btn_save.setProperty("class", "PrimaryButton")
        self.btn_save.clicked.connect(self._save_changes)
        btn_layout.addWidget(self.btn_save)

        layout.addLayout(btn_layout)

    def _save_changes(self):
        self.item.custody_source = self.edit_source.text().strip()
        self.item.custody_notes = self.edit_notes.toPlainText().strip()
        self.accept()

"""
ForenSight AI - Case Management View
Manages forensic investigations, examiner credentials, custody ownership, and case switching.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QTableWidget, QTableWidgetItem, QHeaderView, QLineEdit,
    QTextEdit, QDialog, QFormLayout, QMessageBox, QComboBox
)
from PySide6.QtGui import QColor
from datetime import datetime
from config import COLORS
from core.state import AppState
from core.models import Case


class NewCaseDialog(QDialog):
    """Dialog to register a new forensic case."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Register New Forensic Investigation Case")
        self.resize(500, 380)
        self.setStyleSheet(f"background-color: {COLORS['bg_dark']}; color: {COLORS['text_primary']};")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        lbl_head = QLabel("NEW CASE REGISTRATION")
        lbl_head.setStyleSheet(f"color: {COLORS['accent_cyan']}; font-size: 15px; font-weight: bold;")
        layout.addWidget(lbl_head)

        form_frame = QFrame()
        form_frame.setStyleSheet(f"background-color: {COLORS['bg_card']}; border-radius: 8px; padding: 12px; border: 1px solid {COLORS['border']};")
        form = QFormLayout(form_frame)
        form.setSpacing(10)

        year = datetime.now().year
        self.edit_case_no = QLineEdit(f"CASE-{year}-{int(datetime.now().timestamp())%1000:03d}")
        form.addRow(QLabel("Case Number / UID:"), self.edit_case_no)

        self.edit_title = QLineEdit("Internal Unauthorized Access Investigation")
        form.addRow(QLabel("Case Title:"), self.edit_title)

        self.edit_examiner = QLineEdit("Agent Vance (Lead Investigator)")
        form.addRow(QLabel("Lead Examiner:"), self.edit_examiner)

        self.edit_org = QLineEdit("Cyber Incident Response Lab")
        form.addRow(QLabel("Agency / Organization:"), self.edit_org)

        self.edit_desc = QTextEdit()
        self.edit_desc.setPlaceholderText("Detailed description of suspected incident, incident date, target machine...")
        self.edit_desc.setMaximumHeight(80)
        form.addRow(QLabel("Case Description:"), self.edit_desc)

        layout.addWidget(form_frame)

        btn_box = QHBoxLayout()
        btn_box.addStretch()

        btn_cancel = QPushButton("Cancel")
        btn_cancel.setProperty("class", "SecondaryButton")
        btn_cancel.clicked.connect(self.reject)
        btn_box.addWidget(btn_cancel)

        btn_create = QPushButton("Create Forensic Case")
        btn_create.setProperty("class", "PrimaryButton")
        btn_create.clicked.connect(self._create)
        btn_box.addWidget(btn_create)

        layout.addLayout(btn_box)

    def _create(self):
        if not self.edit_case_no.text().strip() or not self.edit_title.text().strip():
            QMessageBox.warning(self, "Validation Error", "Case number and title are required.")
            return
        self.accept()

    def get_case_data(self) -> Case:
        now = datetime.now().isoformat()
        return Case(
            case_number=self.edit_case_no.text().strip(),
            title=self.edit_title.text().strip(),
            investigator_name=self.edit_examiner.text().strip(),
            organization=self.edit_org.text().strip(),
            description=self.edit_desc.toPlainText().strip(),
            status="Active",
            created_at=now,
            updated_at=now
        )


class CaseView(QWidget):
    """View to list, switch, create, and manage digital forensic cases."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.state = AppState.get_instance()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        # Header
        top_layout = QHBoxLayout()
        title_box = QVBoxLayout()
        lbl_title = QLabel("Forensic Case Management")
        lbl_title.setStyleSheet(f"color: {COLORS['text_primary']}; font-size: 20px; font-weight: 700;")
        title_box.addWidget(lbl_title)

        lbl_sub = QLabel("Manage active investigation profiles, chain of custody ownership, and case records.")
        lbl_sub.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px;")
        title_box.addWidget(lbl_sub)
        top_layout.addLayout(title_box)
        top_layout.addStretch()

        btn_new_case = QPushButton("➕ Register New Case")
        btn_new_case.setProperty("class", "PrimaryButton")
        btn_new_case.clicked.connect(self._open_new_case_dialog)
        top_layout.addWidget(btn_new_case)

        layout.addLayout(top_layout)

        # Active Case Details Card
        self.active_card = QFrame()
        self.active_card.setProperty("class", "CardPanel")
        card_layout = QVBoxLayout(self.active_card)
        card_layout.setContentsMargins(16, 14, 16, 14)
        card_layout.setSpacing(8)

        self.lbl_active_header = QLabel("ACTIVE CASE PROFILE")
        self.lbl_active_header.setStyleSheet(f"color: {COLORS['accent_cyan']}; font-weight: bold; font-size: 12px;")
        card_layout.addWidget(self.lbl_active_header)

        self.lbl_active_name = QLabel("Loading...")
        self.lbl_active_name.setStyleSheet(f"color: {COLORS['text_primary']}; font-size: 16px; font-weight: bold;")
        card_layout.addWidget(self.lbl_active_name)

        self.lbl_active_details = QLabel("")
        self.lbl_active_details.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px;")
        card_layout.addWidget(self.lbl_active_details)

        layout.addWidget(self.active_card)

        # Cases Table
        table_panel = QFrame()
        table_panel.setProperty("class", "CardPanel")
        tbl_layout = QVBoxLayout(table_panel)
        tbl_layout.setContentsMargins(16, 14, 16, 14)
        tbl_layout.setSpacing(10)

        tbl_head = QLabel("ALL REGISTERED CASES")
        tbl_head.setStyleSheet(f"color: {COLORS['text_secondary']}; font-weight: 600; font-size: 11px;")
        tbl_layout.addWidget(tbl_head)

        self.table_cases = QTableWidget(0, 6)
        self.table_cases.setHorizontalHeaderLabels(["ID", "Case Number", "Title", "Lead Investigator", "Status", "Action"])
        self.table_cases.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table_cases.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table_cases.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table_cases.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table_cases.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.table_cases.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        tbl_layout.addWidget(self.table_cases)

        layout.addWidget(table_panel)

        self.refresh_cases()

    def refresh_cases(self):
        cases = self.state.db.get_cases()
        active_case = self.state.get_active_case()

        if active_case:
            self.lbl_active_name.setText(f"{active_case.case_number}: {active_case.title}")
            self.lbl_active_details.setText(
                f"Examiner: {active_case.investigator_name} | Agency: {active_case.organization} | Status: {active_case.status}\n"
                f"Description: {active_case.description or 'No case notes provided.'}"
            )

        self.table_cases.setRowCount(len(cases))
        for row, c in enumerate(cases):
            self.table_cases.setItem(row, 0, QTableWidgetItem(str(c.id)))
            self.table_cases.setItem(row, 1, QTableWidgetItem(c.case_number))
            self.table_cases.setItem(row, 2, QTableWidgetItem(c.title))
            self.table_cases.setItem(row, 3, QTableWidgetItem(c.investigator_name))

            status_item = QTableWidgetItem(c.status)
            if c.status == "Active":
                status_item.setForeground(QColor(COLORS["status_success"]))
            self.table_cases.setItem(row, 4, status_item)

            if c.id == self.state.active_case_id:
                btn_switch = QPushButton("Active")
                btn_switch.setEnabled(False)
                btn_switch.setStyleSheet(f"background-color: {COLORS['status_success']}33; color: {COLORS['status_success']}; font-weight: bold; border-radius: 4px; padding: 4px 8px;")
            else:
                btn_switch = QPushButton("Switch to Case")
                btn_switch.setProperty("class", "SecondaryButton")
                btn_switch.clicked.connect(lambda checked=False, cid=c.id: self._switch_case(cid))

            self.table_cases.setCellWidget(row, 5, btn_switch)

    def _switch_case(self, case_id: int):
        self.state.set_active_case(case_id)
        self.state.log_action("CASE_SWITCH", f"Case ID {case_id}", {"switched_to": case_id})
        self.refresh_cases()

    def _open_new_case_dialog(self):
        dlg = NewCaseDialog(self)
        if dlg.exec():
            case = dlg.get_case_data()
            new_id = self.state.db.create_case(case)
            self.state.log_action("CASE_CREATED", case.case_number, {"title": case.title, "examiner": case.investigator_name})
            self._switch_case(new_id)

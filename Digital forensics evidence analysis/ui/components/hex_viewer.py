"""
ForenSight AI - Virtualized Hex & ASCII Forensic Viewer
Presents raw binary bytes with offsets, hexadecimal byte values, and ASCII representation.
"""

from pathlib import Path
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QLabel,
    QPushButton, QSpinBox, QLineEdit
)
from PySide6.QtGui import QFont
from config import COLORS


PAGE_SIZE = 1024  # 1 KB per page for instant scrolling and rendering


class HexViewer(QWidget):
    """Forensic Hex Viewer component with pagination and search."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.file_path: str = ""
        self.file_size: int = 0
        self.current_page: int = 0
        self.total_pages: int = 1

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        # Toolbar: Page Controls & Jump
        toolbar = QHBoxLayout()
        self.btn_prev = QPushButton("◄ Previous Page")
        self.btn_prev.setProperty("class", "SecondaryButton")
        self.btn_prev.clicked.connect(self._prev_page)
        toolbar.addWidget(self.btn_prev)

        self.lbl_page_info = QLabel("Page 0 of 0")
        self.lbl_page_info.setStyleSheet(f"color: {COLORS['text_secondary']}; font-weight: 500;")
        toolbar.addWidget(self.lbl_page_info)

        self.btn_next = QPushButton("Next Page ►")
        self.btn_next.setProperty("class", "SecondaryButton")
        self.btn_next.clicked.connect(self._next_page)
        toolbar.addWidget(self.btn_next)

        toolbar.addSpacing(20)
        toolbar.addWidget(QLabel("Jump to Page:"))
        self.spin_page = QSpinBox()
        self.spin_page.setMinimum(1)
        self.spin_page.setMaximum(1)
        self.spin_page.valueChanged.connect(self._on_jump_page)
        toolbar.addWidget(self.spin_page)

        toolbar.addStretch()

        self.lbl_file_meta = QLabel("No file loaded")
        self.lbl_file_meta.setStyleSheet(f"color: {COLORS['accent_cyan']}; font-weight: 600;")
        toolbar.addWidget(self.lbl_file_meta)

        layout.addLayout(toolbar)

        # Main Hex View Area
        self.text_area = QTextEdit()
        self.text_area.setReadOnly(True)
        # Use monospaced font
        font = QFont("Cascadia Code, Consolas, Courier New, monospace", 10)
        font.setStyleHint(QFont.Monospace)
        self.text_area.setFont(font)
        self.text_area.setStyleSheet(f"""
        QTextEdit {{
            background-color: #050811;
            color: #38bdf8;
            border: 1px solid {COLORS['border']};
            border-radius: 6px;
            padding: 8px;
            line-height: 1.4;
        }}
        """)
        layout.addWidget(self.text_area)

    def load_file(self, file_path: str):
        """Loads a file into the hex viewer."""
        path = Path(file_path)
        if not path.is_file():
            self.text_area.setPlainText("Error: Target file does not exist or cannot be accessed.")
            return

        self.file_path = str(path)
        self.file_size = path.stat().st_size
        self.current_page = 0
        self.total_pages = max(1, (self.file_size + PAGE_SIZE - 1) // PAGE_SIZE)

        self.spin_page.blockSignals(True)
        self.spin_page.setMaximum(self.total_pages)
        self.spin_page.setValue(1)
        self.spin_page.blockSignals(False)

        self.lbl_file_meta.setText(f"{path.name} ({self.file_size:,} bytes)")
        self._render_current_page()

    def _render_current_page(self):
        if not self.file_path or not Path(self.file_path).is_file():
            return

        offset_start = self.current_page * PAGE_SIZE
        try:
            with open(self.file_path, "rb") as f:
                f.seek(offset_start)
                chunk = f.read(PAGE_SIZE)
        except Exception as e:
            self.text_area.setPlainText(f"Failed to read file: {e}")
            return

        lines = []
        lines.append(f"{'OFFSET':<10}  {'00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F':<49}  {'ASCII'}")
        lines.append("=" * 78)

        for i in range(0, len(chunk), 16):
            line_offset = offset_start + i
            line_bytes = chunk[i:i + 16]

            # Hex part
            hex_parts = [f"{b:02X}" for b in line_bytes]
            # Split into 8 and 8
            left_hex = " ".join(hex_parts[:8])
            right_hex = " ".join(hex_parts[8:])
            hex_str = f"{left_hex:<23}  {right_hex:<23}"

            # ASCII part: replace unprintable with '.'
            ascii_chars = []
            for b in line_bytes:
                if 32 <= b <= 126:
                    ascii_chars.append(chr(b))
                else:
                    ascii_chars.append(".")
            ascii_str = "".join(ascii_chars)

            lines.append(f"{line_offset:08X}    {hex_str}  |{ascii_str}|")

        self.text_area.setPlainText("\n".join(lines))
        self.lbl_page_info.setText(f"Page {self.current_page + 1} of {self.total_pages} (Offset: 0x{offset_start:08X})")
        self.btn_prev.setEnabled(self.current_page > 0)
        self.btn_next.setEnabled(self.current_page < self.total_pages - 1)

    def _prev_page(self):
        if self.current_page > 0:
            self.current_page -= 1
            self.spin_page.blockSignals(True)
            self.spin_page.setValue(self.current_page + 1)
            self.spin_page.blockSignals(False)
            self._render_current_page()

    def _next_page(self):
        if self.current_page < self.total_pages - 1:
            self.current_page += 1
            self.spin_page.blockSignals(True)
            self.spin_page.setValue(self.current_page + 1)
            self.spin_page.blockSignals(False)
            self._render_current_page()

    def _on_jump_page(self, page_num: int):
        target_page = page_num - 1
        if 0 <= target_page < self.total_pages:
            self.current_page = target_page
            self._render_current_page()

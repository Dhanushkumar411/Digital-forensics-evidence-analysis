"""
ForenSight AI - Digital Forensics and Evidence Analysis System
Advanced MCA Project: Python + AI + Cybersecurity

Main executable entry point.
"""

import sys
import os
from pathlib import Path

# Add current directory to Python module search path
sys.path.insert(0, str(Path(__file__).resolve().parent))

# Set Matplotlib cache dir before importing GUI
import tempfile
os.environ["MPLCONFIGDIR"] = tempfile.gettempdir()

from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon

from config import APP_NAME, APP_TITLE, APP_VERSION, APP_AUTHOR
from ui.theme import get_application_stylesheet
from ui.main_window import MainWindow


def main():
    # Enable high-DPI scaling
    QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)

    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationDisplayName(APP_TITLE)
    app.setApplicationVersion(APP_VERSION)
    app.setOrganizationName(APP_AUTHOR)

    # Apply Master Cyber Dark Forensic Theme
    app.setStyleSheet(get_application_stylesheet())

    # Launch MainWindow
    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()

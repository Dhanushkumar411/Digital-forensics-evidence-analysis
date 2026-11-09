"""
ForenSight AI - Modern Cyber Dark Theme & Stylesheets
High-contrast, professional digital forensics aesthetic.
"""

from config import COLORS


def get_application_stylesheet() -> str:
    """Returns the master QSS stylesheet for ForenSight AI."""
    return f"""
    /* Global Application Styles */
    QMainWindow, QWidget {{
        background-color: {COLORS['bg_darkest']};
        color: {COLORS['text_primary']};
        font-family: 'Segoe UI', 'Inter', -apple-system, sans-serif;
        font-size: 13px;
    }}

    /* Sidebar Navigation */
    QFrame#Sidebar {{
        background-color: {COLORS['bg_dark']};
        border-right: 1px solid {COLORS['border']};
    }}

    QPushButton#NavButton {{
        background-color: transparent;
        color: {COLORS['text_secondary']};
        border: none;
        border-radius: 8px;
        padding: 10px 16px;
        text-align: left;
        font-size: 13px;
        font-weight: 500;
    }}

    QPushButton#NavButton:hover {{
        background-color: {COLORS['bg_card']};
        color: {COLORS['text_primary']};
    }}

    QPushButton#NavButton:checked, QPushButton#NavButton[active="true"] {{
        background-color: {COLORS['accent_cyan']}22;
        color: {COLORS['accent_cyan']};
        font-weight: 600;
        border-left: 3px solid {COLORS['accent_cyan']};
    }}

    /* Header Bar */
    QFrame#HeaderBar {{
        background-color: {COLORS['bg_dark']};
        border-bottom: 1px solid {COLORS['border']};
        padding: 6px 16px;
    }}

    /* Card Panels */
    QFrame.CardPanel {{
        background-color: {COLORS['bg_card']};
        border: 1px solid {COLORS['border']};
        border-radius: 10px;
        padding: 16px;
    }}

    QFrame.CardPanel:hover {{
        border: 1px solid {COLORS['border_focus']};
    }}

    /* Stat Cards */
    QFrame#StatCard {{
        background-color: {COLORS['bg_card']};
        border: 1px solid {COLORS['border']};
        border-radius: 10px;
        padding: 14px 18px;
    }}

    /* Primary & Secondary Buttons */
    QPushButton.PrimaryButton {{
        background-color: {COLORS['accent_cyan']};
        color: #0b0f19;
        font-weight: 600;
        border: none;
        border-radius: 6px;
        padding: 8px 16px;
    }}

    QPushButton.PrimaryButton:hover {{
        background-color: #22d3ee;
    }}

    QPushButton.PrimaryButton:pressed {{
        background-color: #0891b2;
    }}

    QPushButton.SecondaryButton {{
        background-color: {COLORS['bg_card']};
        color: {COLORS['text_primary']};
        border: 1px solid {COLORS['border']};
        border-radius: 6px;
        padding: 8px 16px;
        font-weight: 500;
    }}

    QPushButton.SecondaryButton:hover {{
        background-color: {COLORS['bg_card_hover']};
        border-color: {COLORS['accent_cyan']};
    }}

    QPushButton.DangerButton {{
        background-color: {COLORS['status_danger']}22;
        color: {COLORS['status_danger']};
        border: 1px solid {COLORS['status_danger']}55;
        border-radius: 6px;
        padding: 8px 14px;
        font-weight: 600;
    }}

    QPushButton.DangerButton:hover {{
        background-color: {COLORS['status_danger']};
        color: white;
    }}

    /* Input Fields & Combos */
    QLineEdit, QComboBox, QTextEdit, QSpinBox {{
        background-color: {COLORS['bg_input']};
        color: {COLORS['text_primary']};
        border: 1px solid {COLORS['border']};
        border-radius: 6px;
        padding: 8px 12px;
        selection-background-color: {COLORS['accent_cyan']};
        selection-color: #0b0f19;
    }}

    QLineEdit:focus, QComboBox:focus, QTextEdit:focus {{
        border: 1px solid {COLORS['border_focus']};
    }}

    QComboBox::drop-down {{
        border: none;
        padding-right: 8px;
    }}

    QComboBox QAbstractItemView {{
        background-color: {COLORS['bg_dark']};
        color: {COLORS['text_primary']};
        border: 1px solid {COLORS['border']};
        selection-background-color: {COLORS['accent_cyan']};
        selection-color: #0b0f19;
    }}

    /* Forensic Tables */
    QTableWidget, QTableView {{
        background-color: {COLORS['bg_card']};
        color: {COLORS['text_primary']};
        gridline-color: {COLORS['border']};
        border: 1px solid {COLORS['border']};
        border-radius: 8px;
        selection-background-color: {COLORS['accent_cyan']}33;
        selection-color: {COLORS['text_primary']};
    }}

    QHeaderView::section {{
        background-color: {COLORS['bg_dark']};
        color: {COLORS['text_secondary']};
        border: none;
        border-bottom: 2px solid {COLORS['border']};
        border-right: 1px solid {COLORS['border']};
        padding: 8px 12px;
        font-weight: 600;
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }}

    QTableWidget::item {{
        padding: 6px 10px;
    }}

    QTableWidget::item:selected {{
        background-color: {COLORS['accent_cyan']}26;
        color: {COLORS['text_primary']};
    }}

    /* Scrollbars */
    QScrollBar:vertical {{
        background-color: {COLORS['bg_darkest']};
        width: 10px;
        border-radius: 5px;
    }}

    QScrollBar::handle:vertical {{
        background-color: {COLORS['border']};
        border-radius: 5px;
        min-height: 20px;
    }}

    QScrollBar::handle:vertical:hover {{
        background-color: {COLORS['accent_cyan']};
    }}

    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
        height: 0px;
    }}

    QScrollBar:horizontal {{
        background-color: {COLORS['bg_darkest']};
        height: 10px;
        border-radius: 5px;
    }}

    QScrollBar::handle:horizontal {{
        background-color: {COLORS['border']};
        border-radius: 5px;
        min-width: 20px;
    }}

    /* Tabs */
    QTabWidget::pane {{
        border: 1px solid {COLORS['border']};
        background-color: {COLORS['bg_card']};
        border-radius: 8px;
    }}

    QTabBar::tab {{
        background-color: {COLORS['bg_dark']};
        color: {COLORS['text_secondary']};
        padding: 8px 18px;
        margin-right: 4px;
        border-top-left-radius: 6px;
        border-top-right-radius: 6px;
        font-weight: 500;
    }}

    QTabBar::tab:selected {{
        background-color: {COLORS['bg_card']};
        color: {COLORS['accent_cyan']};
        border-top: 2px solid {COLORS['accent_cyan']};
    }}

    /* Progress Bar */
    QProgressBar {{
        background-color: {COLORS['bg_input']};
        border: 1px solid {COLORS['border']};
        border-radius: 6px;
        height: 14px;
        text-align: center;
        color: {COLORS['text_primary']};
        font-size: 10px;
        font-weight: 600;
    }}

    QProgressBar::chunk {{
        background-color: {COLORS['accent_cyan']};
        border-radius: 5px;
    }}

    /* Badges & Labels */
    QLabel#Badge {{
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: 600;
    }}
    """

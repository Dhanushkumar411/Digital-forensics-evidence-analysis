"""
ForenSight AI - Configuration & Constants
AI-Based Digital Forensics and Evidence Analysis System
"""

import os
from pathlib import Path

# Application Metadata
APP_NAME = "ForenSight AI"
APP_TITLE = "ForenSight AI - Digital Forensics & Evidence Analysis System"
APP_VERSION = "2.4.0"
APP_AUTHOR = "Advanced MCA Cybersecurity Lab"

# Base Directories
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATABASE_PATH = DATA_DIR / "forensight.db"
REPORTS_DIR = BASE_DIR / "reports"
EXPORTS_DIR = BASE_DIR / "exports"
SAMPLE_DIR = BASE_DIR / "sample_evidence"

# Ensure directories exist
for directory in [DATA_DIR, REPORTS_DIR, EXPORTS_DIR, SAMPLE_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# Forensic Constants
BUFFER_SIZE = 64 * 1024  # 64 KB read buffer for hashing & entropy
MAX_STRING_EXTRACT_SIZE = 10 * 1024 * 1024  # 10 MB limit for full string scanning
DEFAULT_PAGE_SIZE = 50

# Entropy Thresholds
ENTROPY_PACKED_THRESHOLD = 7.2      # Shannon entropy > 7.2 usually indicates packing/encryption
ENTROPY_SUSPICIOUS_THRESHOLD = 6.8  # > 6.8 warrants investigation for executables/documents
ENTROPY_LOW_THRESHOLD = 1.0         # Very low entropy (e.g., sparse or padded files)

# Anomaly Score Categories
RISK_BENIGN = "Benign"
RISK_SUSPICIOUS = "Suspicious"
RISK_HIGH = "High Risk"
RISK_CRITICAL = "Critical Anomaly"

# Modern Cyber Dark Palette (Forensics UI Theme)
COLORS = {
    "bg_darkest": "#0b0f19",       # Deep space black
    "bg_dark": "#111827",          # Dark slate container
    "bg_card": "#1e293b",          # Card background
    "bg_card_hover": "#26354a",    # Card hover
    "bg_input": "#0f172a",         # Form input background
    "border": "#334155",           # Subtle border
    "border_focus": "#06b6d4",     # Cyan focus border
    "text_primary": "#f8fafc",     # White/off-white text
    "text_secondary": "#94a3b8",   # Muted gray text
    "text_muted": "#64748b",       # Dimmed text
    "accent_cyan": "#06b6d4",      # Forensics Cyan (primary brand)
    "accent_blue": "#3b82f6",      # Electric Blue
    "accent_purple": "#8b5cf6",    # Deep violet
    "status_success": "#10b981",   # Emerald green (Verified / Benign)
    "status_warning": "#f59e0b",   # Amber (Suspicious / Warning)
    "status_danger": "#ef4444",    # Crimson (Compromised / High Risk / Malicious)
    "status_critical": "#ec4899",  # Neon pink/magenta (Critical Anomaly)
    "status_neutral": "#64748b",   # Neutral slate
}

"""
ForenSight AI - Sliding Window Entropy Graph Widget
Visualizes byte entropy distributions across file offsets to detect encrypted or packed sections.
"""

import os
import tempfile
# Ensure Matplotlib writes cache cleanly to temp
os.environ["MPLCONFIGDIR"] = tempfile.gettempdir()

import matplotlib
matplotlib.use("QtAgg")
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

from PySide6.QtWidgets import QWidget, QVBoxLayout
from config import COLORS, ENTROPY_PACKED_THRESHOLD, ENTROPY_SUSPICIOUS_THRESHOLD
from typing import List


class EntropyGraphWidget(QWidget):
    """Embeddable Matplotlib graph displaying sliding-window Shannon entropy."""

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # Create Matplotlib Figure with sleek dark theme
        self.figure = Figure(figsize=(7, 3), dpi=100)
        self.figure.patch.set_facecolor(COLORS["bg_card"])
        self.canvas = FigureCanvas(self.figure)
        layout.addWidget(self.canvas)

        self.ax = self.figure.add_subplot(111)
        self._style_axes()
        self.plot_empty()

    def _style_axes(self):
        self.ax.set_facecolor("#0b0f19")
        self.ax.tick_params(colors=COLORS["text_secondary"], labelsize=8)
        for spine in self.ax.spines.values():
            spine.set_color(COLORS["border"])
        self.ax.grid(True, color=COLORS["border"], linestyle="--", alpha=0.4)
        self.ax.set_ylim(0, 8.2)

    def plot_empty(self):
        self.ax.clear()
        self._style_axes()
        self.ax.set_title("Select an evidence file to analyze sliding entropy profile", color=COLORS["text_secondary"], fontsize=10)
        self.canvas.draw()

    def plot_entropy(self, entropy_profile: List[float], file_name: str, overall_entropy: float):
        """Plots the entropy profile of a file."""
        self.ax.clear()
        self._style_axes()

        if not entropy_profile:
            self.ax.set_title(f"Empty or zero-byte file: {file_name}", color=COLORS["text_muted"], fontsize=10)
            self.canvas.draw()
            return

        x = list(range(len(entropy_profile)))
        y = entropy_profile

        # Dynamic plot color depending on overall entropy
        line_color = COLORS["accent_cyan"]
        if overall_entropy >= ENTROPY_PACKED_THRESHOLD:
            line_color = COLORS["status_danger"]
        elif overall_entropy >= ENTROPY_SUSPICIOUS_THRESHOLD:
            line_color = COLORS["status_warning"]

        # Plot line and fill area
        self.ax.plot(x, y, color=line_color, linewidth=1.8, label="Sliding Entropy (bits/byte)")
        self.ax.fill_between(x, y, color=line_color, alpha=0.15)

        # Threshold guide lines
        self.ax.axhline(y=ENTROPY_PACKED_THRESHOLD, color=COLORS["status_danger"], linestyle=":", linewidth=1.2, label=f"Packed/Encrypted ({ENTROPY_PACKED_THRESHOLD})")
        self.ax.axhline(y=ENTROPY_SUSPICIOUS_THRESHOLD, color=COLORS["status_warning"], linestyle="--", linewidth=1.0, label=f"Suspicious ({ENTROPY_SUSPICIOUS_THRESHOLD})")

        self.ax.set_title(f"Entropy Profile: {file_name} (Mean Shannon Entropy: {overall_entropy:.2f} / 8.00)",
                          color=COLORS["text_primary"], fontsize=10, fontweight="bold", pad=8)
        self.ax.set_xlabel("Chunk Offset Index", color=COLORS["text_secondary"], fontsize=8)
        self.ax.set_ylabel("Entropy (H)", color=COLORS["text_secondary"], fontsize=8)

        legend = self.ax.legend(loc="lower right", facecolor=COLORS["bg_dark"], edgecolor=COLORS["border"], fontsize=8)
        for text in legend.get_texts():
            text.set_color(COLORS["text_secondary"])

        self.figure.tight_layout()
        self.canvas.draw()

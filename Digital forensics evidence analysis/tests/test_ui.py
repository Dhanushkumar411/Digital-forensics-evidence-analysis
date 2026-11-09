"""
ForenSight AI - UI Smoke and Integration Test
Tests GUI initialization, widget layout, view switching, and data binding
without requiring a physical display.
"""

import os
import sys
import tempfile
from pathlib import Path

# Force Qt offscreen platform for headless validation
os.environ["QT_QPA_PLATFORM"] = "offscreen"
os.environ["MPLCONFIGDIR"] = tempfile.gettempdir()
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from PySide6.QtWidgets import QApplication, QMessageBox
# Monkeypatch QMessageBox to prevent modal dialogs from blocking headless tests
QMessageBox.information = staticmethod(lambda *args, **kwargs: QMessageBox.Ok)
QMessageBox.warning = staticmethod(lambda *args, **kwargs: QMessageBox.Ok)
QMessageBox.critical = staticmethod(lambda *args, **kwargs: QMessageBox.Ok)
QMessageBox.question = staticmethod(lambda *args, **kwargs: QMessageBox.Yes)

from ui.theme import get_application_stylesheet
from ui.main_window import MainWindow
from core.state import AppState
from sample_data.generate_samples import generate_all_samples


def test_ui_headless():
    app = QApplication.instance() or QApplication(sys.argv)
    app.setStyleSheet(get_application_stylesheet())

    # Generate samples and verify state
    generate_all_samples()
    state = AppState.get_instance()

    print("[*] Initializing MainWindow...")
    sys.stdout.flush()
    window = MainWindow()
    window.show()

    print("[*] Testing view tab switching...")
    sys.stdout.flush()
    # Switch through all 9 views
    for idx in range(9):
        window._switch_view(idx)
        app.processEvents()

    # Load samples into evidence view
    print("[*] Ingesting sample evidence into EvidenceView...")
    sys.stdout.flush()
    window.view_evidence._load_sample_evidence()
    app.processEvents()

    # Verify Dashboard telemetry refreshed
    print("[*] Verifying Dashboard telemetry...")
    sys.stdout.flush()
    window.view_dashboard.refresh_data()
    app.processEvents()

    # Verify AI view run
    print("[*] Verifying AI view scan...")
    sys.stdout.flush()
    window.view_ai._run_ai_scan()
    app.processEvents()

    # Verify Report view preview & generation
    print("[*] Testing Report view preview & generation...")
    sys.stdout.flush()
    window.view_reports.update_preview()

    # Test PDF generation
    case = state.get_active_case()
    items = state.db.get_evidence_list(state.active_case_id)
    dups = state.db.get_duplicates_by_case(state.active_case_id)
    audits = state.db.get_audit_logs(state.active_case_id)

    from engines.report_engine import ReportEngine
    pdf_out = ReportEngine.generate_pdf_report(case, items, dups, audits)
    print(f"[+] Generated forensic PDF report at: {pdf_out}")
    assert Path(pdf_out).exists() and Path(pdf_out).stat().st_size > 1000

    json_out = ReportEngine.export_json(case, items, dups, audits)
    print(f"[+] Generated forensic JSON archive at: {json_out}")
    assert Path(json_out).exists() and Path(json_out).stat().st_size > 100

    csv_out = ReportEngine.export_csv(items)
    print(f"[+] Generated forensic CSV inventory at: {csv_out}")
    assert Path(csv_out).exists() and Path(csv_out).stat().st_size > 100

    print("[SUCCESS] ALL UI AND INTEGRATION TESTS PASSED CLEANLY!")
    window.close()


if __name__ == "__main__":
    test_ui_headless()

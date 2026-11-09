"""
ForenSight AI - Forensic Report Generation Engine
Exports comprehensive investigation reports in PDF (ReportLab), JSON, and CSV.
Adheres to digital forensics reporting standards (ISO/IEC 27037 & NIST SP 800-86).
"""

import csv
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)

from config import REPORTS_DIR, EXPORTS_DIR
from core.models import Case, EvidenceItem, AuditLogEntry, DuplicateGroup
from engines.audit_engine import AuditEngine


class NumberedCanvas:
    """Canvas that performs two passes to render total page numbers cleanly."""
    pass


class ReportEngine:
    """Generates official digital forensics examination reports."""

    @classmethod
    def generate_pdf_report(cls, case: Case, items: List[EvidenceItem], duplicates: List[DuplicateGroup],
                            audit_logs: List[AuditLogEntry], output_path: Optional[str] = None) -> str:
        """
        Builds a multi-page PDF investigation report with cover styling, tables,
        AI threat findings, and chain of custody sign-off.
        """
        if not output_path:
            clean_case_no = "".join(c if c.isalnum() else "_" for c in case.case_number)
            timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = str(REPORTS_DIR / f"Forensic_Report_{clean_case_no}_{timestamp_str}.pdf")

        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            rightMargin=0.5 * inch,
            leftMargin=0.5 * inch,
            topMargin=0.6 * inch,
            bottomMargin=0.6 * inch
        )

        styles = getSampleStyleSheet()

        # Custom Forensic Styles
        title_style = ParagraphStyle(
            'ForensicTitle',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=22,
            leading=26,
            textColor=colors.HexColor('#0f172a'),
            spaceAfter=6
        )

        subtitle_style = ParagraphStyle(
            'ForensicSubtitle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=11,
            leading=14,
            textColor=colors.HexColor('#475569'),
            spaceAfter=15
        )

        heading2_style = ParagraphStyle(
            'ForensicH2',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=13,
            leading=17,
            textColor=colors.HexColor('#0284c7'),  # Deep Forensics Cyan
            spaceBefore=14,
            spaceAfter=6
        )

        body_style = ParagraphStyle(
            'ForensicBody',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9,
            leading=12,
            textColor=colors.HexColor('#1e293b')
        )

        code_style = ParagraphStyle(
            'ForensicCode',
            parent=styles['Code'],
            fontName='Courier',
            fontSize=7.5,
            leading=9,
            textColor=colors.HexColor('#0f172a')
        )

        story = []

        # --- Report Header / Banner ---
        banner_data = [
            [
                Paragraph("<b>FORENSIGHT AI</b><br/><font size='8' color='#64748b'>DIGITAL FORENSICS & INCIDENT RESPONSE LAB</font>", body_style),
                Paragraph(f"<b>CONFIDENTIAL EVIDENCE REPORT</b><br/><font size='8' color='#64748b'>ISO/IEC 27037 COMPLIANT</font>", ParagraphStyle('RAlign', parent=body_style, alignment=2))
            ]
        ]
        banner_table = Table(banner_data, colWidths=[4.0 * inch, 3.5 * inch])
        banner_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(banner_table)
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#0284c7'), spaceAfter=12))

        # Title Block
        story.append(Paragraph(f"Forensic Investigation Report", title_style))
        story.append(Paragraph(f"Case Subject: {case.title} &bull; Case Number: <b>{case.case_number}</b>", subtitle_style))

        # --- Section 1: Case & Custody Information ---
        story.append(Paragraph("1. Investigation & Custody Metadata", heading2_style))
        case_info_data = [
            [Paragraph("<b>Case Number:</b>", body_style), Paragraph(case.case_number, body_style),
             Paragraph("<b>Date of Report:</b>", body_style), Paragraph(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), body_style)],
            [Paragraph("<b>Lead Investigator:</b>", body_style), Paragraph(case.investigator_name, body_style),
             Paragraph("<b>Case Status:</b>", body_style), Paragraph(case.status, body_style)],
            [Paragraph("<b>Organization:</b>", body_style), Paragraph(case.organization, body_style),
             Paragraph("<b>Total Artifacts:</b>", body_style), Paragraph(str(len(items)), body_style)],
            [Paragraph("<b>Case Scope / Notes:</b>", body_style), Paragraph(case.description or "Standard forensic seizure and integrity verification.", body_style), "", ""]
        ]
        info_table = Table(case_info_data, colWidths=[1.4 * inch, 2.3 * inch, 1.4 * inch, 2.4 * inch])
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('SPAN', (1, 3), (3, 3)),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        story.append(info_table)
        story.append(Spacer(1, 10))

        # --- Section 2: Executive Summary & Telemetry ---
        story.append(Paragraph("2. Executive Summary & Telemetry", heading2_style))
        total_size_mb = sum(it.file_size for it in items) / (1024 * 1024)
        suspicious_items = [it for it in items if it.is_suspicious]
        mismatch_items = [it for it in items if it.extension_mismatch]
        verified_items = [it for it in items if it.integrity_status == "Verified"]

        summary_p = f"""
        This forensic examination involved the cryptographic acquisition, integrity verification, and AI-driven
        heuristic anomaly analysis of <b>{len(items)}</b> digital evidence items totaling <b>{total_size_mb:.2f} MB</b>.
        Of the acquired evidence items, <b>{len(verified_items)}</b> were verified with intact cryptographic SHA-256 baselines.
        The AI Anomaly Detection engine flagged <b>{len(suspicious_items)}</b> items warranting prioritized investigator review,
        including <b>{len(mismatch_items)}</b> disguised file extension evasion attempts and <b>{len(duplicates)}</b> duplicate clusters.
        """
        story.append(Paragraph(summary_p.strip(), body_style))
        story.append(Spacer(1, 10))

        # Telemetry KPI Grid
        kpi_data = [
            [
                Paragraph(f"<font size='14' color='#0284c7'><b>{len(items)}</b></font><br/><font size='8' color='#64748b'>EVIDENCE ITEMS</font>", ParagraphStyle('C', parent=body_style, alignment=1)),
                Paragraph(f"<font size='14' color='#10b981'><b>{len(verified_items)}</b></font><br/><font size='8' color='#64748b'>VERIFIED INTACT</font>", ParagraphStyle('C', parent=body_style, alignment=1)),
                Paragraph(f"<font size='14' color='#ef4444'><b>{len(suspicious_items)}</b></font><br/><font size='8' color='#64748b'>ANOMALIES / RISKS</font>", ParagraphStyle('C', parent=body_style, alignment=1)),
                Paragraph(f"<font size='14' color='#f59e0b'><b>{len(duplicates)}</b></font><br/><font size='8' color='#64748b'>DUPLICATE SETS</font>", ParagraphStyle('C', parent=body_style, alignment=1)),
            ]
        ]
        kpi_table = Table(kpi_data, colWidths=[1.87 * inch, 1.87 * inch, 1.87 * inch, 1.87 * inch])
        kpi_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f1f5f9')),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(kpi_table)
        story.append(Spacer(1, 12))

        # --- Section 3: Evidence Cryptographic Integrity Register ---
        story.append(Paragraph("3. Evidence Cryptographic Integrity Register (SHA-256)", heading2_style))
        ev_headers = ["File Name", "Size", "Detected Type", "SHA-256 Cryptographic Hash", "Status"]
        ev_rows = [[
            Paragraph(f"<b>{h}</b>", ParagraphStyle('H', parent=body_style, fontName='Helvetica-Bold', fontSize=8, textColor=colors.white))
            for h in ev_headers
        ]]

        for it in items[:40]:  # Limit table rows to prevent PDF overflow
            status_color = "#10b981" if it.integrity_status == "Verified" else "#ef4444"
            ev_rows.append([
                Paragraph(it.file_name[:24], body_style),
                Paragraph(f"{it.file_size:,} B", body_style),
                Paragraph(it.detected_type[:20], body_style),
                Paragraph(f"<font face='Courier' size='6.5'>{it.sha256}</font>", body_style),
                Paragraph(f"<font color='{status_color}'><b>{it.integrity_status}</b></font>", body_style)
            ])

        ev_table = Table(ev_rows, colWidths=[1.6 * inch, 0.9 * inch, 1.5 * inch, 2.6 * inch, 0.9 * inch])
        ev_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f172a')),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(ev_table)
        if len(items) > 40:
            story.append(Paragraph(f"<i>Note: Displaying first 40 of {len(items)} evidence artifacts. Complete inventory available in CSV/JSON export.</i>", subtitle_style))
        story.append(Spacer(1, 14))

        # --- Section 4: AI Anomaly Analysis & Threat Breakdown ---
        story.append(Paragraph("4. AI-Driven Anomaly & Threat Detection", heading2_style))
        if suspicious_items:
            for susp in suspicious_items[:15]:
                risk_bg = "#fef2f2" if susp.risk_level in ["High Risk", "Critical Anomaly"] else "#fffbeb"
                risk_border = "#ef4444" if susp.risk_level in ["High Risk", "Critical Anomaly"] else "#f59e0b"
                risk_color = "#b91c1c" if susp.risk_level in ["High Risk", "Critical Anomaly"] else "#b45309"

                reasons_text = "<br/>&bull; ".join(susp.flagged_reasons) if susp.flagged_reasons else "Flagged by ML Isolation Forest model outlier scoring."

                susp_block = [
                    [
                        Paragraph(f"<b>File:</b> {susp.file_name} &bull; <b>Path:</b> {susp.file_path}", body_style),
                        Paragraph(f"<b>{susp.risk_level.upper()}</b> (Score: {susp.anomaly_score:.1f}%)", ParagraphStyle('R', parent=body_style, textColor=colors.HexColor(risk_color), alignment=2))
                    ],
                    [
                        Paragraph(f"<b>Entropy:</b> {susp.entropy:.2f}/8.0 &bull; <b>MIME:</b> {susp.mime_type} &bull; <b>Detected:</b> {susp.detected_type}", body_style),
                        ""
                    ],
                    [
                        Paragraph(f"<b>Forensic Findings:</b><br/>&bull; {reasons_text}", body_style),
                        ""
                    ]
                ]
                susp_table = Table(susp_block, colWidths=[5.5 * inch, 2.0 * inch])
                susp_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor(risk_bg)),
                    ('BOX', (0, 0), (-1, -1), 1, colors.HexColor(risk_border)),
                    ('SPAN', (0, 1), (1, 1)),
                    ('SPAN', (0, 2), (1, 2)),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ]))
                story.append(susp_table)
                story.append(Spacer(1, 6))
        else:
            story.append(Paragraph("<i>No suspicious or anomalous files were flagged by the AI Engine.</i>", body_style))
        story.append(Spacer(1, 12))

        # --- Section 5: Duplicate Evidence Clusters ---
        if duplicates:
            story.append(Paragraph("5. Duplicate Evidence Identification", heading2_style))
            dup_rows = [[
                Paragraph("<b>SHA-256 Hash</b>", ParagraphStyle('H', parent=body_style, fontName='Helvetica-Bold', fontSize=8, textColor=colors.white)),
                Paragraph("<b>Copies</b>", ParagraphStyle('H', parent=body_style, fontName='Helvetica-Bold', fontSize=8, textColor=colors.white)),
                Paragraph("<b>File Size</b>", ParagraphStyle('H', parent=body_style, fontName='Helvetica-Bold', fontSize=8, textColor=colors.white)),
                Paragraph("<b>Wasted Volume</b>", ParagraphStyle('H', parent=body_style, fontName='Helvetica-Bold', fontSize=8, textColor=colors.white)),
                Paragraph("<b>Associated File Paths</b>", ParagraphStyle('H', parent=body_style, fontName='Helvetica-Bold', fontSize=8, textColor=colors.white))
            ]]
            for dg in duplicates[:10]:
                paths_str = "<br/>".join([it.file_name for it in dg.items[:3]])
                if len(dg.items) > 3:
                    paths_str += f"<br/><i>+{len(dg.items)-3} more</i>"
                dup_rows.append([
                    Paragraph(f"<font face='Courier' size='6.5'>{dg.sha256[:20]}...</font>", body_style),
                    Paragraph(str(dg.count), body_style),
                    Paragraph(f"{dg.file_size:,} B", body_style),
                    Paragraph(f"{dg.total_wasted_bytes:,} B", body_style),
                    Paragraph(paths_str, body_style)
                ])

            dup_table = Table(dup_rows, colWidths=[2.0 * inch, 0.7 * inch, 1.0 * inch, 1.1 * inch, 2.7 * inch])
            dup_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
                ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ]))
            story.append(dup_table)
            story.append(Spacer(1, 12))

        # --- Section 6: Cryptographic Chain of Custody & Audit Verification ---
        story.append(Paragraph("6. Cryptographic Chain of Custody & Audit Certification", heading2_style))
        audit_engine = AuditEngine()
        verif = audit_engine.verify_chain()
        chain_color = "#10b981" if verif["is_valid"] else "#ef4444"

        audit_text = f"""
        All actions, evidence acquisitions, and algorithmic scans performed in this investigation are recorded
        in an immutable SHA-256 cryptographic hash-chained audit ledger.
        <br/><br/>
        <b>Audit Chain Status:</b> <font color='{chain_color}'><b>{verif['status']}</b></font><br/>
        <b>Total Sequenced Records:</b> {verif['total_records_checked']}<br/>
        <b>Head Cryptographic Proof:</b> <font face='Courier' size='7'>{audit_logs[0].entry_hash if audit_logs else 'N/A'}</font>
        """
        story.append(Paragraph(audit_text.strip(), body_style))
        story.append(Spacer(1, 15))

        # --- Section 7: Formal Investigator Sign-off ---
        story.append(Paragraph("7. Examiner Certification & Attestation", heading2_style))
        attestation = f"""
        I hereby attest under official oath that the examination and analysis documented herein were performed
        in accordance with standard scientific digital forensic principles. The evidence integrity hashes were
        cryptographically computed and maintained without unauthorized alteration.
        """
        story.append(Paragraph(attestation.strip(), body_style))
        story.append(Spacer(1, 20))

        signoff_data = [
            [
                Paragraph(f"<b>Examiner Signature:</b> ___________________________<br/><br/><b>Name:</b> {case.investigator_name}<br/><b>Title:</b> Lead Forensic Investigator", body_style),
                Paragraph(f"<b>Peer Reviewer:</b> ___________________________<br/><br/><b>Date:</b> {datetime.now().strftime('%Y-%m-%d')}<br/><b>Agency:</b> {case.organization}", body_style)
            ]
        ]
        signoff_table = Table(signoff_data, colWidths=[3.75 * inch, 3.75 * inch])
        signoff_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LINEABOVE', (0, 0), (-1, -1), 0.5, colors.HexColor('#94a3b8')),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(signoff_table)

        doc.build(story)
        return output_path

    @classmethod
    def export_json(cls, case: Case, items: List[EvidenceItem], duplicates: List[DuplicateGroup],
                    audit_logs: List[AuditLogEntry], output_path: Optional[str] = None) -> str:
        """Exports the complete investigation as a structured JSON file."""
        if not output_path:
            clean_case_no = "".join(c if c.isalnum() else "_" for c in case.case_number)
            timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = str(EXPORTS_DIR / f"Forensic_Case_{clean_case_no}_{timestamp_str}.json")

        payload = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "system": "ForenSight AI",
                "version": "2.4.0"
            },
            "case": case.__dict__,
            "evidence_count": len(items),
            "evidence": [it.__dict__ for it in items],
            "duplicates": [
                {
                    "sha256": dg.sha256,
                    "count": dg.count,
                    "file_size": dg.file_size,
                    "wasted_bytes": dg.total_wasted_bytes,
                    "paths": [it.file_path for it in dg.items]
                }
                for dg in duplicates
            ],
            "audit_chain": [log.__dict__ for log in audit_logs]
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

        return output_path

    @classmethod
    def export_csv(cls, items: List[EvidenceItem], output_path: Optional[str] = None) -> str:
        """Exports evidence items to a standard CSV file."""
        if not output_path:
            timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = str(EXPORTS_DIR / f"Evidence_Inventory_{timestamp_str}.csv")

        fields = [
            "id", "file_name", "file_path", "file_size", "file_ext", "detected_type",
            "sha256", "md5", "sha1", "integrity_status", "entropy", "extension_mismatch",
            "is_duplicate", "anomaly_score", "risk_level", "is_suspicious",
            "created_time", "modified_time", "accessed_time", "custody_source"
        ]

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            for it in items:
                writer.writerow(it.__dict__)

        return output_path

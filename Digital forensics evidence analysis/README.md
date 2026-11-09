# ForenSight AI: AI-Based Digital Forensics and Evidence Analysis System

**Academic Project**: Advanced MCA Capstone Project  
**Domain**: Python + Artificial Intelligence + Digital Forensics & Cybersecurity  
**Standard Compliance**: ISO/IEC 27037 (Digital Evidence Handling) & NIST SP 800-86 (Forensic Analysis)

---

## 1. Executive Project Overview

**ForenSight AI** is a professional desktop digital forensics application engineered for incident responders, cybersecurity analysts, and digital forensic investigators. It automates the acquisition, cryptographic verification, anomaly detection, and reporting of digital evidence seized during cyber investigations.

The system addresses critical challenges in modern digital investigations:
- **Evidence Integrity Verification**: Automating rapid multi-algorithm cryptographic hashing (SHA-256, MD5, SHA-1) and tamper detection.
- **Evasion & Disguise Detection**: Identifying binary camouflage techniques where executable files (`.exe`, `.dll`) are disguised with non-executable extensions (`.jpg`, `.pdf`, `.docx`) using true magic bytes header signatures.
- **Ransomware & Packing Detection**: Calculating sliding-window Shannon entropy ($H(X) = -\sum p_i \log_2 p_i$) to uncover encrypted payloads, ransomware data, and obfuscated shellcode.
- **AI-Powered Anomaly Classification**: Employing Scikit-Learn **Isolation Forest** unsupervised anomaly detection paired with forensic expert heuristic scoring to surface suspicious files with transparent Explainable AI (XAI) reasoning.
- **Cross-Directory Duplicate Clustering**: Detecting multiple occurrences of identical files across seized storage to uncover malware staging and persistence attempts.
- **Tamper-Evident Audit Trail**: Maintaining a blockchain-inspired cryptographic SHA-256 hash-chained audit log that mathematically guarantees the immutability of examiner actions.
- **Multi-Format Forensic Reporting**: Generating court-admissible multi-page PDF investigation reports, structured JSON case archives, and CSV evidence inventories.

---

## 2. System Architecture

```
                               ┌─────────────────────────────────────────────────────────────┐
                               │                    ForenSight AI GUI                        │
                               │                (PySide6 Modern Cyber Dark)                  │
                               └──────────────────────────────┬──────────────────────────────┘
                                                              │
         ┌─────────────────────┬──────────────────────────────┼──────────────────────────────┬─────────────────────┐
         ▼                     ▼                              ▼                              ▼                     ▼
┌─────────────────┐   ┌─────────────────┐            ┌─────────────────┐            ┌─────────────────┐   ┌─────────────────┐
│ Evidence Engine │   │   Hash Engine   │            │    AI Engine    │            │Duplicate Engine │   │  Report Engine  │
├─────────────────┤   ├─────────────────┤            ├─────────────────┤            ├─────────────────┤   ├─────────────────┤
│• Magic Bytes    │   │• SHA-256 (Pri)  │            │• IsolationForest│            │• SHA-256 Cluster│   │• ReportLab PDF  │
│• Shannon Entropy│   │• MD5 & SHA-1    │            │• 9-Dim Feature  │            │• Storage Audit  │   │• JSON Archive   │
│• Ext Mismatch   │   │• NSRL Reference │            │• Explainable AI │            │• Cross-Path Map │   │• Evidence CSV   │
│• MACB Timestamps│   │• Tamper Check   │            │• Heuristic Boost│            │                 │   │• Sign-off Sheet │
└────────┬────────┘   └────────┬────────┘            └────────┬────────┘            └────────┬────────┘   └────────┬────────┘
         │                     │                              │                              │                     │
         └─────────────────────┴──────────────────────────────┼──────────────────────────────┴─────────────────────┘
                                                              ▼
                                             ┌─────────────────────────────────┐
                                             │       SQLite WAL Database       │
                                             ├─────────────────────────────────┤
                                             │ • Cases & Investigator Profiles │
                                             │ • Evidence Inventory & Hashes   │
                                             │ • AI Diagnostics & Anomaly Scores│
                                             │ • Cryptographic Audit Chain     │
                                             └─────────────────────────────────┘
```

---

## 3. Core Modules & Functionalities

| Module | Core Responsibility | Forensic Technique / Implementation |
| :--- | :--- | :--- |
| **Evidence Acquisition** | File and directory registration | Ingests single files, recursive directories, or forensic samples; captures initial MACB timestamps, file size, and seizure metadata. |
| **SHA-256 Verification** | Integrity baselining & verification | Computes SHA-256, MD5, and SHA-1 in a single chunked 64KB read stream. Compares live on-disk hash against acquisition baseline to flag `Verified` vs `Compromised`. |
| **File Analysis** | Deep artifact inspection | Analyzes magic bytes (100+ signatures), detects extension mismatches (e.g., PE executable masquerading as a JPEG), calculates Shannon entropy (0.0 to 8.0 bits/byte), detects timestomping ($M < C$). |
| **AI Anomaly Detection** | Unsupervised outlier classification | Scikit-Learn `IsolationForest` model evaluates 9-dimensional forensic feature vectors with XAI explainability and risk categorizations: `Benign`, `Suspicious`, `High Risk`, `Critical Anomaly`. |
| **Duplicate Detection** | Cryptographic deduplication | Groups files sharing identical SHA-256 hashes, calculates total wasted storage, and reveals lateral malware staging across user/temp directories. |
| **Forensic Timeline** | MACB chronology & burst analysis | Synthesizes Created, Modified, and Accessed events into a unified chronological stream; identifies rapid burst clusters (e.g. ransomware mass encryption). |
| **Cryptographic Audit** | Chain of custody preservation | Uses SHA-256 blockchain-style chaining ($H_i = \text{SHA256}(H_{i-1} + T_i + U_i + A_i + D_i)$). Provides a one-click mathematical integrity verifier. |
| **Report Generation** | Examination documentation | Exports court-admissible multi-page PDF reports (ReportLab) complete with case details, hash registers, AI findings, duplicate summaries, and examiner attestation blocks. |

---

## 4. Technology Stack

- **Programming Language**: Python 3.11+ (Tested on Python 3.13)
- **Graphical Interface**: PySide6 (Qt 6.12) with custom cyber dark theme
- **Machine Learning**: Scikit-Learn (IsolationForest, StandardScaler)
- **Data Analytics & Profiling**: NumPy, Pandas, Collections
- **Visualizations**: Matplotlib (Embedded QtAgg Donut & Bar Charts, Sliding Entropy Profile)
- **Forensic PDF Engine**: ReportLab 5.1 (ISO-compliant forensic formatting)
- **Database**: SQLite3 (Thread-safe WAL mode, foreign key integrity)
- **Cryptographic Algorithms**: Python `hashlib` (SHA-256, MD5, SHA-1)

---

## 5. Directory Structure

```
forensight/
│
├── config.py                 # Color palette, forensic thresholds, buffer sizes, paths
├── main.py                   # Application entry point & Qt event loop
├── requirements.txt          # Python package dependencies
├── README.md                 # Project documentation & execution guide
│
├── core/                     # Relational database and data models
│   ├── __init__.py
│   ├── db.py                 # SQLite manager, CRUD, statistics, audit chain
│   ├── models.py             # Dataclasses (Case, EvidenceItem, AnomalyResult, AuditLog)
│   └── state.py              # Application state container & Qt signal bus
│
├── engines/                  # Forensic analysis and machine learning engines
│   ├── __init__.py
│   ├── hash_engine.py        # Cryptographic hashing & NSRL threat intel matching
│   ├── evidence_engine.py    # Magic bytes, entropy, timestomp, string extraction
│   ├── ai_engine.py          # Isolation Forest ML anomaly detector & XAI reasoning
│   ├── duplicate_engine.py   # Cryptographic duplicate clustering & space analysis
│   ├── signature_engine.py   # Forensic threat rule scanner (webshells, ransomware)
│   ├── timeline_engine.py    # MACB temporal event builder & activity burst detection
│   ├── audit_engine.py       # Tamper-evident cryptographic audit ledger
│   └── report_engine.py      # PDF, JSON, and CSV forensic report generators
│
├── ui/                       # Modern PySide6 user interface
│   ├── __init__.py
│   ├── theme.py              # Modern cyber dark stylesheet (QSS)
│   ├── main_window.py        # Master window, top status bar, sidebar navigation
│   ├── components/
│   │   ├── stat_card.py      # KPI telemetry card
│   │   ├── hex_viewer.py     # Virtualized chunked Hex & ASCII viewer
│   │   ├── entropy_graph.py  # Embedded Matplotlib sliding entropy plot widget
│   │   └── custody_modal.py  # Chain of custody modal dialog
│   └── views/
│       ├── dashboard_view.py       # Investigation telemetry & interactive charts
│       ├── case_view.py            # Case profiles & investigator management
│       ├── evidence_view.py        # Evidence acquisition & integrity verification
│       ├── file_inspector_view.py  # Deep Hex, strings, entropy, signatures
│       ├── ai_analysis_view.py     # AI anomaly results & explainability breakdown
│       ├── duplicate_view.py       # Duplicate clusters & wasted volume
│       ├── timeline_view.py        # MACB chronological activity timeline
│       ├── audit_view.py           # Cryptographic audit ledger & tamper verification
│       └── report_view.py          # Live report briefing & PDF/JSON/CSV export
│
├── sample_data/              # Synthetic test evidence generator
│   ├── __init__.py
│   └── generate_samples.py   # Generates benign files, disguised EXEs, ransomware, etc.
│
└── tests/                    # Automated testing suite
    ├── __init__.py
    ├── test_engines.py       # Unit tests for hashing, entropy, ML, signatures, audit
    └── test_ui.py            # Headless UI smoke test and full report generation test
```

---

## 6. Installation & Quick Start

### Step 1: Install Dependencies
Ensure Python 3.11+ is installed, then install requirements:
```bash
pip install -r requirements.txt
```

### Step 2: Run Unit & Integration Tests
Validate that all forensic engines, database transactions, and cryptographic routines pass:
```bash
python -m unittest tests/test_engines.py
```

### Step 3: Launch ForenSight AI Desktop Application
```bash
python main.py
```

---

## 7. Forensic Demonstration Guide (Walkthrough)

1. **Launch the Application**: Run `python main.py`. The cyber-dark dashboard loads displaying active case `CASE-2026-001`.
2. **Load Forensic Samples**: In the **Evidence Manager** tab, click **⚡ Load Lab Samples**. This automatically generates and acquires 10 forensic test artifacts:
   - Benign documents & images (`incident_briefing.pdf`, `server_rack_diagram.jpg`).
   - Disguised Windows executable disguised as `.jpg` (`corporate_financials.jpg`).
   - Deceptive double extension (`invoice_urgent.pdf.exe`).
   - High-entropy encrypted payload (`locked_database_payload.bin` with entropy ~ 7.95).
   - Timestomped file (`security_driver_mod.sys` with modified timestamp 2 years in the past).
   - Ransomware extortion note (`HOW_TO_DECRYPT_FILES.txt`).
   - PHP WebShell backdoor (`wp-content-uploader.php`).
   - Cryptographic duplicate archives (`backup_archive_primary.zip` & `secondary.zip`).
3. **Execute AI Anomaly Scan**: Switch to the **AI Anomaly Center** tab and click **🧠 Run Full AI Scan**. The Isolation Forest evaluates all evidence items and categorizes risk levels. Selecting `corporate_financials.jpg` reveals the exact diagnostic XAI explanation:
   > *"CRITICAL: Binary executable disguise! File has extension '.jpg' but magic bytes match 'Windows Executable (PE/DLL/EXE)'."*
4. **Deep File Inspection**: Double-click or click **Inspect** on any item to view:
   - True magic bytes and MACB timestamps.
   - Byte-level virtualized **Hex & ASCII viewer**.
   - Real-time **Sliding-Window Shannon Entropy curve**.
   - Extracted IP addresses, URLs, Base64 strings, and suspicious shell commands.
   - Matched YARA / Threat signatures.
5. **Verify Evidence Integrity**: In the **Evidence Manager**, click **🛡 Verify All Hashes**. If any file on disk is altered, ForenSight AI immediately flags the record as **COMPROMISED** and logs an alert.
6. **Verify Cryptographic Chain of Custody**: Navigate to the **Cryptographic Audit** tab and click **🛡 Verify Cryptographic Chain**. The system recalculates SHA-256 proofs across all sequential blocks and confirms zero tampering.
7. **Export Forensic Report**: Navigate to **Forensic Reports**, select **Official PDF Forensic Report**, and click **🚀 Generate & Export Report**. A multi-page PDF complete with official headers, telemetry tables, anomaly breakdowns, and examiner sign-off is generated in the `reports/` folder.

---

## 8. Academic Evaluation & MCA Alignment

This project is tailored for MCA, M.Tech, and Cybersecurity degree evaluations:
- **Computer Science & Algorithms**: Shannon entropy calculation, sliding-window byte analysis, recursive directory indexing, chunked stream processing ($O(N)$ streaming memory efficiency).
- **Artificial Intelligence & Data Science**: Scikit-Learn `IsolationForest` unsupervised outlier scoring, multi-feature scaling (`StandardScaler`), feature engineering, explainable AI diagnostics.
- **Cybersecurity & Cryptography**: SHA-256, MD5, SHA-1 cryptographic integrity checking, threat intelligence hash matching, blockchain-style immutable audit logging.
- **Software Engineering**: Modular Clean Architecture, Model-View-Controller design, PySide6 desktop GUI with custom QSS styling, comprehensive test suite with 100% engine test coverage.

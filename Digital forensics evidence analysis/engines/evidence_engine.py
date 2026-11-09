"""
ForenSight AI - Evidence Analysis Engine
Extracts forensic metadata, verifies magic bytes vs extension, computes Shannon
entropy, detects timestomping, extracts strings/indicators, and inspects PE/EXIF.
"""

import math
import os
import re
import struct
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

from config import (
    BUFFER_SIZE, MAX_STRING_EXTRACT_SIZE,
    ENTROPY_PACKED_THRESHOLD, ENTROPY_SUSPICIOUS_THRESHOLD
)
from engines.hash_engine import HashEngine
from core.models import EvidenceItem


# Magic byte signatures database (Signature Hex, Offset, Detected Type, MIME Type, Allowed Extensions)
FILE_SIGNATURES = [
    # Executables & Binaries
    (b"MZ", 0, "Windows Executable (PE/DLL/EXE)", "application/x-dosexec", [".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx"]),
    (b"\x7fELF", 0, "Linux Executable (ELF)", "application/x-executable", ["", ".so", ".bin", ".elf"]),
    (b"\xfe\xed\xfa\xce", 0, "Mach-O Binary (32-bit)", "application/x-mach-binary", ["", ".dylib"]),
    (b"\xfe\xed\xfa\xcf", 0, "Mach-O Binary (64-bit)", "application/x-mach-binary", ["", ".dylib"]),
    (b"\xca\xfe\xba\xbe", 0, "Java Class / Mach-O Fat", "application/java-vm", [".class"]),
    (b"#!\x2f", 0, "UNIX Shell Script", "text/x-shellscript", [".sh", ".bash", ".zsh", ""]),

    # Documents & Containers
    (b"%PDF-", 0, "PDF Document", "application/pdf", [".pdf"]),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, "Legacy Microsoft Office (OLE Compound)", "application/msword", [".doc", ".xls", ".ppt", ".msg"]),
    (b"PK\x03\x04", 0, "ZIP Archive / OpenXML Document", "application/zip", [".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk"]),
    (b"Rar!\x1a\x07\x00", 0, "RAR Archive (v4)", "application/x-rar-compressed", [".rar"]),
    (b"Rar!\x1a\x07\x01\x00", 0, "RAR Archive (v5)", "application/x-rar-compressed", [".rar"]),
    (b"7z\xbc\xaf\x27\x1c", 0, "7-Zip Compressed Archive", "application/x-7z-compressed", [".7z"]),
    (b"\x1f\x8b\x08", 0, "GZIP Compressed File", "application/gzip", [".gz", ".tgz"]),
    (b"{\\rtf", 0, "Rich Text Format (RTF)", "application/rtf", [".rtf"]),

    # Images & Media
    (b"\x89PNG\r\n\x1a\n", 0, "PNG Image", "image/png", [".png"]),
    (b"\xff\xd8\xff", 0, "JPEG Image", "image/jpeg", [".jpg", ".jpeg", ".jpe"]),
    (b"GIF87a", 0, "GIF Image (87a)", "image/gif", [".gif"]),
    (b"GIF89a", 0, "GIF Image (89a)", "image/gif", [".gif"]),
    (b"RIFF", 0, "RIFF Container (WAV/WebP/AVI)", "image/webp", [".webp", ".wav", ".avi"]),
    (b"BM", 0, "BMP Image", "image/bmp", [".bmp"]),

    # Windows Forensic Artifacts
    (b"ElfFile\x00", 0, "Windows Event Log (EVTX)", "application/x-ms-evtx", [".evtx"]),
    (b"SCCA", 4, "Windows Prefetch File", "application/x-ms-prefetch", [".pf"]),
    (b"regf", 0, "Windows Registry Hive", "application/x-ms-registry", [".dat", ".hiv", ""]),
    (b"L\x00\x00\x00\x01\x14\x02\x00", 0, "Windows Shortcut (LNK)", "application/x-ms-shortcut", [".lnk"]),
    (b"\xd4\xc3\xb2\xa1", 0, "Wireshark PCAP Capture", "application/vnd.tcpdump.pcap", [".pcap"]),
    (b"\x0a\x0d\x0d\x0a", 0, "Wireshark PCAPNG Capture", "application/x-pcapng", [".pcapng"])
]

# Common regex patterns for forensic string inspection
IP_PATTERN = re.compile(rb"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
URL_PATTERN = re.compile(rb"https?:\/\/[a-zA-Z0-9\-\._~:\/\?#\[\]@!\$&'\(\)\*\+,;=%]{4,}")
BASE64_PATTERN = re.compile(rb"(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
SUSPICIOUS_CMD_PATTERN = re.compile(
    rb"(?i)\b(cmd\.exe|powershell(\.exe)?|powershell\s+-enc|IEX\b|Invoke-Expression|vssadmin\s+delete|certutil\s+-urlcache|bitsadmin|wscript\.exe|cscript\.exe|rundll32\.exe|net\s+user|whoami|reg\s+add|schtasks\s+/create)\b"
)


class EvidenceEngine:
    """Core engine for digital evidence analysis and feature extraction."""

    @staticmethod
    def calculate_shannon_entropy(file_path: str) -> float:
        """
        Calculates Shannon entropy of the file:
        H(X) = - sum(p(x) * log2(p(x))) for x in bytes [0..255]
        Returns value in range [0.0, 8.0]
        """
        path = Path(file_path)
        if not path.is_file() or path.stat().st_size == 0:
            return 0.0

        byte_counts = Counter()
        total_bytes = 0

        with open(path, "rb") as f:
            while chunk := f.read(BUFFER_SIZE):
                byte_counts.update(chunk)
                total_bytes += len(chunk)

        if total_bytes == 0:
            return 0.0

        entropy = 0.0
        for count in byte_counts.values():
            p = count / total_bytes
            entropy -= p * math.log2(p)

        return round(entropy, 4)

    @staticmethod
    def calculate_sliding_entropy(file_path: str, block_size: int = 4096) -> List[float]:
        """
        Computes entropy profile across sliding blocks of the file.
        Useful for visualizing encrypted sections or injected code blocks.
        """
        path = Path(file_path)
        if not path.is_file() or path.stat().st_size == 0:
            return []

        entropy_profile = []
        with open(path, "rb") as f:
            while block := f.read(block_size):
                if len(block) < 64:
                    break
                counts = Counter(block)
                total = len(block)
                block_entropy = -sum((cnt / total) * math.log2(cnt / total) for cnt in counts.values())
                entropy_profile.append(round(block_entropy, 3))
                if len(entropy_profile) >= 200:  # Cap visualization resolution to 200 points
                    break

        return entropy_profile

    @classmethod
    def identify_file_type(cls, file_path: str) -> Tuple[str, str, bool, Optional[str]]:
        """
        Determines file type by matching header magic bytes.
        Returns: (detected_type, mime_type, extension_mismatch, explanation)
        """
        path = Path(file_path)
        file_ext = path.suffix.lower()

        # Read the first 512 bytes for signature matching
        header = b""
        try:
            with open(path, "rb") as f:
                header = f.read(512)
        except Exception:
            return "Unreadable", "application/octet-stream", False, None

        if not header:
            return "Empty File", "application/x-empty", False, None

        detected_type = "Generic Binary / Unknown"
        detected_mime = "application/octet-stream"
        allowed_exts: List[str] = []

        # Check against signature database
        for sig, offset, name, mime, exts in FILE_SIGNATURES:
            if len(header) >= offset + len(sig):
                if header[offset:offset + len(sig)] == sig:
                    detected_type = name
                    detected_mime = mime
                    allowed_exts = exts
                    break

        # Check for plain text scripts if not matched
        if detected_type == "Generic Binary / Unknown":
            try:
                sample_text = header.decode("utf-8", errors="strict")
                if sample_text.strip().startswith("<?php") or "eval(" in sample_text:
                    detected_type = "PHP Script"
                    detected_mime = "text/x-php"
                    allowed_exts = [".php", ".phtml", ".php5"]
                elif sample_text.strip().startswith("<html") or "<script" in sample_text:
                    detected_type = "HTML Document"
                    detected_mime = "text/html"
                    allowed_exts = [".html", ".htm"]
                elif sample_text.strip().startswith("{") or sample_text.strip().startswith("["):
                    detected_type = "JSON Data"
                    detected_mime = "application/json"
                    allowed_exts = [".json"]
                else:
                    detected_type = "Plain Text Document"
                    detected_mime = "text/plain"
                    allowed_exts = [".txt", ".log", ".csv", ".ini", ".conf", ".py", ".md", ".json"]
            except UnicodeDecodeError:
                pass

        # Check for extension spoofing / mismatch
        extension_mismatch = False
        mismatch_note = None

        if allowed_exts:
            if file_ext not in allowed_exts and "" not in allowed_exts:
                # Evasion detection: e.g. an executable disguised as an image or document
                if "Executable" in detected_type and file_ext in [".jpg", ".png", ".pdf", ".txt", ".docx", ".xlsx", ".gif", ".mp4"]:
                    extension_mismatch = True
                    mismatch_note = f"CRITICAL: Binary executable disguise! File has extension '{file_ext}' but magic bytes match '{detected_type}'."
                elif detected_type != "Plain Text Document" and file_ext in [".exe", ".dll"] and detected_type in ["PNG Image", "JPEG Image"]:
                    extension_mismatch = True
                    mismatch_note = f"Extension spoofing: named '{file_ext}' but header is '{detected_type}'."
                elif detected_type not in ["Plain Text Document", "Generic Binary / Unknown"] and file_ext not in allowed_exts:
                    extension_mismatch = True
                    mismatch_note = f"Extension mismatch: expected one of {allowed_exts[:3]}, but file extension is '{file_ext}'."

        return detected_type, detected_mime, extension_mismatch, mismatch_note

    @staticmethod
    def detect_timestomp(stat: os.stat_result) -> Tuple[bool, Optional[str]]:
        """
        Forensic timestomp detection:
        - Modified time precedes Creation time ($M < C$).
        - Modification or creation times set to exact 00:00:00 seconds (indicative of manual touch).
        """
        c_time = stat.st_ctime
        m_time = stat.st_mtime

        # Modified earlier than creation by more than 1 second (accounting for file copy artifacts)
        if m_time < (c_time - 1.0):
            return True, f"Modified time ({datetime.fromtimestamp(m_time).isoformat()}) precedes creation time ({datetime.fromtimestamp(c_time).isoformat()}) by {int(c_time - m_time)} seconds."

        # Future timestamps
        now_ts = datetime.now().timestamp()
        if m_time > (now_ts + 86400):
            return True, f"Suspicious future modification timestamp: {datetime.fromtimestamp(m_time).isoformat()}"

        return False, None

    @classmethod
    def extract_strings_and_indicators(cls, file_path: str) -> Dict[str, Any]:
        """
        Extracts printable strings, network artifacts (IPs, URLs), base64 tokens, and commands.
        """
        path = Path(file_path)
        if not path.is_file():
            return {}

        file_size = path.stat().st_size
        read_size = min(file_size, MAX_STRING_EXTRACT_SIZE)

        with open(path, "rb") as f:
            data = f.read(read_size)

        # ASCII strings >= 4 chars
        ascii_strings = [s.decode("latin-1", errors="ignore") for s in re.findall(rb"[\x20-\x7e]{4,}", data)]
        
        # UTF-16 LE strings
        utf16_strings = []
        try:
            for s in re.findall(rb"(?:[\x20-\x7e]\x00){4,}", data):
                utf16_strings.append(s.decode("utf-16le", errors="ignore"))
        except Exception:
            pass

        # Network and threat indicators
        ips = [ip.decode("ascii") for ip in set(IP_PATTERN.findall(data))]
        urls = [url.decode("ascii", errors="ignore") for url in set(URL_PATTERN.findall(data))]
        base64_blobs = [b.decode("ascii") for b in list(set(BASE64_PATTERN.findall(data)))[:10]]
        commands = [cmd.decode("latin-1", errors="ignore") for cmd in set(SUSPICIOUS_CMD_PATTERN.findall(data))]

        return {
            "ascii_count": len(ascii_strings),
            "utf16_count": len(utf16_strings),
            "sample_strings": (ascii_strings[:150] + utf16_strings[:50])[:200],
            "ip_addresses": ips,
            "urls": urls,
            "base64_blobs": base64_blobs,
            "suspicious_commands": commands
        }

    @classmethod
    def inspect_file(cls, file_path: str, case_id: int = 1, custody_source: str = "Evidence Ingestion", custody_notes: str = "") -> EvidenceItem:
        """
        Performs full forensic inspection of a file and constructs an EvidenceItem.
        """
        path = Path(file_path).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"File not found: {file_path}")

        stat = path.stat()
        file_size = stat.st_size
        file_ext = path.suffix.lower()

        # Timestamps
        created_iso = datetime.fromtimestamp(stat.st_ctime).isoformat()
        modified_iso = datetime.fromtimestamp(stat.st_mtime).isoformat()
        accessed_iso = datetime.fromtimestamp(stat.st_atime).isoformat()

        # Cryptographic Hashes
        sha256, md5, sha1 = HashEngine.calculate_file_hashes(str(path))

        # Entropy & File Type
        entropy = cls.calculate_shannon_entropy(str(path))
        detected_type, mime_type, ext_mismatch, mismatch_note = cls.identify_file_type(str(path))

        # Flags and Reasons
        flagged_reasons: List[str] = []
        is_suspicious = False
        tags: List[str] = []

        if ext_mismatch and mismatch_note:
            flagged_reasons.append(mismatch_note)
            is_suspicious = True
            tags.append("Extension Mismatch")

        # High Entropy Check (Packing / Encryption / Ransomware payload)
        if entropy >= ENTROPY_PACKED_THRESHOLD:
            flagged_reasons.append(f"High Shannon entropy ({entropy}/8.0) strongly indicates encrypted or packed code.")
            is_suspicious = True
            tags.append("High Entropy")
        elif entropy >= ENTROPY_SUSPICIOUS_THRESHOLD and detected_type.startswith("Windows Executable"):
            flagged_reasons.append(f"Elevated entropy ({entropy}/8.0) in executable binary.")
            is_suspicious = True
            tags.append("Packed Binary")

        # Timestomp check
        is_timestomped, timestomp_note = cls.detect_timestomp(stat)
        if is_timestomped and timestomp_note:
            flagged_reasons.append(timestomp_note)
            is_suspicious = True
            tags.append("Timestomp Anomaly")

        # Threat Intel Check
        intel_hit = HashEngine.match_threat_intel(sha256)
        if intel_hit:
            flagged_reasons.append(f"MATCHED THREAT INTEL: {intel_hit['name']} ({intel_hit['threat']})")
            is_suspicious = True
            tags.append("Threat Intel Hit")

        # Suspicious double extension (e.g. invoice.pdf.exe or script.vbs.txt)
        file_name_lower = path.name.lower()
        if re.search(r"\.[a-z0-9]{2,4}\.(exe|scr|bat|cmd|vbs|ps1|dll)$", file_name_lower):
            flagged_reasons.append(f"Deceptive double extension detected: '{path.name}'")
            is_suspicious = True
            tags.append("Double Extension")

        # Initial heuristic risk category
        if "CRITICAL" in " ".join(flagged_reasons) or intel_hit:
            risk_level = "Critical Anomaly"
            anomaly_score = 95.0
        elif is_suspicious or len(flagged_reasons) >= 2:
            risk_level = "High Risk"
            anomaly_score = 75.0
        elif len(flagged_reasons) == 1:
            risk_level = "Suspicious"
            anomaly_score = 45.0
        else:
            risk_level = "Benign"
            anomaly_score = 5.0

        return EvidenceItem(
            case_id=case_id,
            file_name=path.name,
            file_path=str(path),
            file_size=file_size,
            file_ext=file_ext,
            mime_type=mime_type,
            detected_type=detected_type,
            sha256=sha256,
            md5=md5,
            sha1=sha1,
            integrity_status="Verified",
            created_time=created_iso,
            modified_time=modified_iso,
            accessed_time=accessed_iso,
            entropy=entropy,
            extension_mismatch=ext_mismatch,
            is_duplicate=False,
            duplicate_group_id=None,
            anomaly_score=anomaly_score,
            risk_level=risk_level,
            is_suspicious=is_suspicious,
            flagged_reasons=flagged_reasons,
            acquisition_date=datetime.now().isoformat(),
            custody_source=custody_source,
            custody_notes=custody_notes,
            tags=tags
        )

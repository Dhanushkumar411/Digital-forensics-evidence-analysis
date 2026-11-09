"""
ForenSight AI - Signature & Malware Rule Engine
Provides signature matching for forensic threat artifacts, webshells, ransomware
extortion notes, memory injection indicators, and obfuscated payload stagers.
"""

import re
from pathlib import Path
from typing import List, Dict, Any, Tuple


class ForensicSignature:
    def __init__(self, rule_id: str, name: str, severity: str, description: str, patterns: List[bytes], require_all: bool = False):
        self.rule_id = rule_id
        self.name = name
        self.severity = severity  # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
        self.description = description
        self.patterns = [re.compile(p, re.IGNORECASE) for p in patterns]
        self.require_all = require_all

    def match(self, data: bytes) -> bool:
        if self.require_all:
            return all(p.search(data) for p in self.patterns)
        else:
            return any(p.search(data) for p in self.patterns)


# Curated forensic rule set
RULES: List[ForensicSignature] = [
    ForensicSignature(
        rule_id="RULE-RANSOM-01",
        name="Ransomware Extortion Note",
        severity="CRITICAL",
        description="Matches common ransomware extortion and decryption instructions.",
        patterns=[
            rb"your files (have been|are) encrypted",
            rb"send (bitcoin|btc|monero|xmr) to",
            rb"restore your (files|data)",
            rb"\.onion\b",
            rb"tor browser",
            rb"decrypt_instruction"
        ],
        require_all=False
    ),
    ForensicSignature(
        rule_id="RULE-WEBSHELL-01",
        name="PHP Backdoor / WebShell",
        severity="HIGH",
        description="Detects suspicious dynamic code evaluation and command execution in PHP scripts.",
        patterns=[
            rb"eval\s*\(\s*(base64_decode|gzinflate|str_rot13)",
            rb"passthru\s*\(",
            rb"shell_exec\s*\(",
            rb"system\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)",
            rb"assert\s*\(\s*\$_(POST|GET)",
            rb"b374k",
            rb"c99shell",
            rb"r57shell"
        ],
        require_all=False
    ),
    ForensicSignature(
        rule_id="RULE-OBFUSC-PS-01",
        name="Obfuscated PowerShell Execution",
        severity="HIGH",
        description="Identifies hidden, bypass, or encoded PowerShell payload launchers.",
        patterns=[
            rb"powershell(\.exe)?\s+(-(w(indowstyle)?|nop(rofile)?|e(nc(odedcommand)?)?|noni(nteractive)?)\s+)+[a-za-z0-9+/=]{20,}",
            rb"\[system\.convert\]::frombase64string",
            rb"\[system\.text\.encoding\]::unicode\.getstring",
            rb"iex\s*\(\s*new-object\s+net\.webclient",
            rb"downloadstring\s*\("
        ],
        require_all=False
    ),
    ForensicSignature(
        rule_id="RULE-CRED-DUMP-01",
        name="Credential Dumping Strings (Mimikatz / LSASS)",
        severity="CRITICAL",
        description="Detects memory injection, sekurlsa, or LSASS dumping artifacts.",
        patterns=[
            rb"sekurlsa::logonpasswords",
            rb"lsadump::sam",
            rb"privilege::debug",
            rb"kerberos::golden",
            rb"wdigest\.dll",
            rb"lsass\.exe"
        ],
        require_all=False
    ),
    ForensicSignature(
        rule_id="RULE-SHADOW-DEL-01",
        name="Volume Shadow Copy Deletion",
        severity="CRITICAL",
        description="Detects defensive inhibition commands typical of ransomware execution.",
        patterns=[
            rb"vssadmin\s+delete\s+shadows",
            rb"wmic\s+shadowcopy\s+delete",
            rb"wbadmin\s+delete\s+catalog",
            rb"bcdedit\s+/set\s+.*recoveryenabled\s+no"
        ],
        require_all=False
    ),
    ForensicSignature(
        rule_id="RULE-REVSHELL-01",
        name="Interactive Reverse Shell",
        severity="HIGH",
        description="Matches network reverse shell connection scripts.",
        patterns=[
            rb"/bin/(ba)?sh\s+-i\s+>&",
            rb"nc(\.exe)?\s+-e\s+/bin/(ba)?sh",
            rb"nc(\.exe)?\s+-e\s+cmd\.exe",
            rb"socket\.socket.*connect\(.*os\.dup2"
        ],
        require_all=False
    )
]


class SignatureEngine:
    """Evaluates files against the forensic signature repository."""

    @staticmethod
    def scan_file(file_path: str, max_read_bytes: int = 5 * 1024 * 1024) -> List[Dict[str, str]]:
        """
        Scans a file against all compiled forensic signatures.
        Returns a list of matched signature metadata.
        """
        path = Path(file_path)
        if not path.is_file():
            return []

        try:
            with open(path, "rb") as f:
                data = f.read(max_read_bytes)
        except Exception:
            return []

        matches: List[Dict[str, str]] = []
        for rule in RULES:
            if rule.match(data):
                matches.append({
                    "rule_id": rule.rule_id,
                    "name": rule.name,
                    "severity": rule.severity,
                    "description": rule.description
                })

        return matches

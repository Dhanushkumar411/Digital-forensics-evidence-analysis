"""
ForenSight AI - Core Data Models
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any
import json


@dataclass
class Case:
    id: Optional[int] = None
    case_number: str = ""
    title: str = ""
    investigator_name: str = "Chief Investigator"
    organization: str = "Digital Forensics Unit"
    description: str = ""
    status: str = "Active"  # Active, Closed, Archived
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class EvidenceItem:
    id: Optional[int] = None
    case_id: int = 1
    file_name: str = ""
    file_path: str = ""
    file_size: int = 0
    file_ext: str = ""
    mime_type: str = "application/octet-stream"
    detected_type: str = "Unknown"
    
    # Hashes
    sha256: str = ""
    md5: str = ""
    sha1: str = ""
    integrity_status: str = "Verified"  # Verified, Compromised, Unverified, Missing
    
    # Timestamps (ISO format)
    created_time: str = ""
    modified_time: str = ""
    accessed_time: str = ""
    
    # Forensic Analysis Metrics
    entropy: float = 0.0
    extension_mismatch: bool = False
    is_duplicate: bool = False
    duplicate_group_id: Optional[int] = None
    
    # AI & Risk Flagging
    anomaly_score: float = 0.0  # 0.0 - 100.0%
    risk_level: str = "Benign"  # Benign, Suspicious, High Risk, Critical Anomaly
    is_suspicious: bool = False
    flagged_reasons: List[str] = field(default_factory=list)
    
    # Chain of Custody
    acquisition_date: str = field(default_factory=lambda: datetime.now().isoformat())
    custody_source: str = "Seized Target Storage"
    custody_notes: str = ""
    tags: List[str] = field(default_factory=list)
    
    def flagged_reasons_json(self) -> str:
        return json.dumps(self.flagged_reasons)
        
    def tags_json(self) -> str:
        return json.dumps(self.tags)


@dataclass
class AnomalyResult:
    id: Optional[int] = None
    evidence_id: int = 0
    anomaly_score: float = 0.0
    risk_level: str = "Benign"
    algorithm: str = "IsolationForest + Heuristics"
    feature_vector: Dict[str, float] = field(default_factory=dict)
    reasons: List[str] = field(default_factory=list)
    signature_matches: List[str] = field(default_factory=list)
    analyzed_at: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class AuditLogEntry:
    id: Optional[int] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    case_id: Optional[int] = None
    investigator: str = "System"
    action: str = ""
    target: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    prev_hash: str = "0" * 64
    entry_hash: str = ""
    is_valid: bool = True


@dataclass
class DuplicateGroup:
    sha256: str
    file_size: int
    count: int
    items: List[EvidenceItem] = field(default_factory=list)
    total_wasted_bytes: int = 0

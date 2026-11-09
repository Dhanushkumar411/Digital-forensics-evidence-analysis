"""
ForenSight AI - Timeline Analysis Engine
Builds forensic MACB (Modified, Accessed, Created) event chronologies,
identifies suspicious activity clusters, and tracks investigator timelines.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import List, Dict, Any, Optional
from core.models import EvidenceItem


@dataclass
class TimelineEvent:
    timestamp: str
    event_type: str  # 'M' (Modified), 'A' (Accessed), 'C' (Created)
    file_name: str
    file_path: str
    risk_level: str
    file_size: int
    evidence_id: int
    details: str


class TimelineEngine:
    """Builds and analyzes forensic timelines across seized evidence artifacts."""

    @staticmethod
    def build_timeline(items: List[EvidenceItem]) -> List[TimelineEvent]:
        """
        Extracts MACB timestamps from evidence items and flattens them into
        a strictly sorted chronological event stream.
        """
        events: List[TimelineEvent] = []

        for item in items:
            # Created event
            if item.created_time:
                events.append(TimelineEvent(
                    timestamp=item.created_time,
                    event_type="Created",
                    file_name=item.file_name,
                    file_path=item.file_path,
                    risk_level=item.risk_level,
                    file_size=item.file_size,
                    evidence_id=item.id or 0,
                    details=f"File born/created on storage device. Size: {item.file_size} bytes."
                ))

            # Modified event
            if item.modified_time:
                events.append(TimelineEvent(
                    timestamp=item.modified_time,
                    event_type="Modified",
                    file_name=item.file_name,
                    file_path=item.file_path,
                    risk_level=item.risk_level,
                    file_size=item.file_size,
                    evidence_id=item.id or 0,
                    details=f"Content modified. Current SHA-256: {item.sha256[:12]}..."
                ))

            # Accessed event
            if item.accessed_time:
                events.append(TimelineEvent(
                    timestamp=item.accessed_time,
                    event_type="Accessed",
                    file_name=item.file_name,
                    file_path=item.file_path,
                    risk_level=item.risk_level,
                    file_size=item.file_size,
                    evidence_id=item.id or 0,
                    details="Last file system read/access record."
                ))

        # Sort chronologically
        events.sort(key=lambda e: e.timestamp, reverse=True)
        return events

    @staticmethod
    def detect_bursts(events: List[TimelineEvent], window_seconds: int = 300, min_events: int = 5) -> List[Dict[str, Any]]:
        """
        Detects bursts of rapid file system activity within a given time window (default 5 minutes),
        which often correlates with mass file encryption (ransomware) or rapid exfiltration staging.
        """
        if len(events) < min_events:
            return []

        # Sort ascending for burst detection
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        bursts: List[Dict[str, Any]] = []

        i = 0
        while i < len(sorted_events):
            try:
                t_start = datetime.fromisoformat(sorted_events[i].timestamp)
            except Exception:
                i += 1
                continue

            window_events = [sorted_events[i]]
            j = i + 1
            while j < len(sorted_events):
                try:
                    t_curr = datetime.fromisoformat(sorted_events[j].timestamp)
                    diff = (t_curr - t_start).total_seconds()
                    if diff <= window_seconds:
                        window_events.append(sorted_events[j])
                        j += 1
                    else:
                        break
                except Exception:
                    j += 1

            if len(window_events) >= min_events:
                bursts.append({
                    "start_time": window_events[0].timestamp,
                    "end_time": window_events[-1].timestamp,
                    "event_count": len(window_events),
                    "files_involved": list(set(e.file_name for e in window_events))
                })
                i = j  # Move past this burst
            else:
                i += 1

        return bursts

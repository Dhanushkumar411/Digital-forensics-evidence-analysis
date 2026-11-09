"""
ForenSight AI - Duplicate Evidence Engine
Identifies duplicate digital evidence, groups files with identical cryptographic
hashes, and calculates storage impact and distribution across disk directories.
"""

from typing import List, Dict
from core.models import EvidenceItem, DuplicateGroup


class DuplicateEngine:
    """Groups evidence items by cryptographic SHA-256 hash."""

    @staticmethod
    def find_duplicates(items: List[EvidenceItem]) -> List[DuplicateGroup]:
        """
        Groups evidence items by SHA-256 and identifies files appearing more than once.
        """
        hash_map: Dict[str, List[EvidenceItem]] = {}
        for item in items:
            if not item.sha256:
                continue
            hash_map.setdefault(item.sha256, []).append(item)

        groups: List[DuplicateGroup] = []
        for sha256, group_items in hash_map.items():
            if len(group_items) > 1:
                file_size = group_items[0].file_size
                wasted = (len(group_items) - 1) * file_size
                # Mark items as duplicates
                for it in group_items:
                    it.is_duplicate = True

                groups.append(DuplicateGroup(
                    sha256=sha256,
                    file_size=file_size,
                    count=len(group_items),
                    items=group_items,
                    total_wasted_bytes=wasted
                ))

        # Sort by wasted bytes descending
        groups.sort(key=lambda g: g.total_wasted_bytes, reverse=True)
        return groups

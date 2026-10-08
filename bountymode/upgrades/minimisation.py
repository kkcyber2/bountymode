"""U10 -- evidence minimisation.

A submittable PoC proves impact with the *minimum* data necessary.  Dumping a
full response that contains real user records is both a privacy problem and a
reason triagers reject reports.  This module trims captured evidence to the
smallest excerpt that still demonstrates the finding, and records what was
removed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class MinimisedEvidence:
    text: str
    original_len: int
    minimised_len: int
    removed_lines: int
    kept_markers: List[str] = field(default_factory=list)

    @property
    def reduction(self) -> float:
        if not self.original_len:
            return 0.0
        return 1.0 - (self.minimised_len / self.original_len)

    def to_dict(self) -> Dict[str, object]:
        return {
            "text": self.text,
            "original_len": self.original_len,
            "minimised_len": self.minimised_len,
            "removed_lines": self.removed_lines,
            "reduction": round(self.reduction, 3),
            "kept_markers": self.kept_markers,
        }


class EvidenceMinimiser:
    """Keep only the lines that prove the finding."""

    def __init__(self, *, context_lines: int = 1, max_lines: int = 40) -> None:
        self.context_lines = context_lines
        self.max_lines = max_lines

    def minimise(self, text: str, markers: List[str]) -> MinimisedEvidence:
        lines = (text or "").splitlines()
        original_len = len(text or "")
        if not lines:
            return MinimisedEvidence("", 0, 0, 0)

        keep: set[int] = set()
        for i, line in enumerate(lines):
            if any(m and m.lower() in line.lower() for m in markers):
                for j in range(max(0, i - self.context_lines), min(len(lines), i + self.context_lines + 1)):
                    keep.add(j)

        if not keep:
            # No marker found: keep the head, which is the least sensitive part.
            keep = set(range(min(len(lines), self.max_lines)))

        kept = [lines[i] for i in sorted(keep)][: self.max_lines]
        minimised = "\n".join(kept)
        return MinimisedEvidence(
            text=minimised,
            original_len=original_len,
            minimised_len=len(minimised),
            removed_lines=len(lines) - len(kept),
            kept_markers=[m for m in markers if any(m.lower() in l.lower() for l in kept)],
        )

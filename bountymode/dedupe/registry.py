"""De-duplication and regression-retest registry.

Two jobs, both about not wasting a triager's time (and not wasting ours):

* **De-duplication** — before submitting, check whether we (or the program)
  already know this finding.  Matching is by fingerprint first, then by a
  looser category+asset test.
* **Regression retest** — after a fix ships, re-run the same technique and
  record whether the finding still reproduces.  A finding that no longer
  reproduces is closed; one that does is escalated.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..models import Finding, compute_fingerprint


class DedupVerdict(str, Enum):
    NEW = "new"
    DUPLICATE = "duplicate"
    LIKELY_DUPLICATE = "likely_duplicate"


@dataclass
class DedupResult:
    verdict: DedupVerdict
    matched_id: Optional[str] = None
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"verdict": self.verdict.value, "matched_id": self.matched_id, "reason": self.reason}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class DedupRegistry:
    """Persistent store of findings we already know about."""

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = Path(path) if path else None
        self._by_fp: Dict[str, Finding] = {}
        self._all: Dict[str, Finding] = {}
        if self.path and self.path.exists():
            self._load()

    # -- registration ------------------------------------------------------ #

    def add(self, finding: Finding) -> DedupResult:
        """Register a finding, returning whether it is new or a duplicate."""
        result = self.check(finding)
        if result.verdict == DedupVerdict.NEW:
            self._all[finding.id] = finding
            self._by_fp.setdefault(finding.fingerprint, finding)
            self._save()
        return result

    def check(self, finding: Finding) -> DedupResult:
        if finding.fingerprint in self._by_fp:
            other = self._by_fp[finding.fingerprint]
            if other.id != finding.id:
                return DedupResult(
                    DedupVerdict.DUPLICATE,
                    other.id,
                    f"identical fingerprint {finding.fingerprint}",
                )
        # Loose match: same category + same asset + similar title.
        for other in self._all.values():
            if other.id == finding.id:
                continue
            if (
                other.category == finding.category
                and other.affected_asset
                and other.affected_asset == finding.affected_asset
            ):
                if compute_fingerprint(other.category, other.affected_asset) == compute_fingerprint(
                    finding.category, finding.affected_asset
                ):
                    return DedupResult(
                        DedupVerdict.LIKELY_DUPLICATE,
                        other.id,
                        f"same category '{finding.category}' on same asset '{finding.affected_asset}'",
                    )
        return DedupResult(DedupVerdict.NEW, None, "no existing match")

    def import_known(self, known: Dict[str, str]) -> None:
        """Seed from a program's known-issues list: ``{fingerprint_hint: id}``."""
        for hint, fid in known.items():
            placeholder = Finding(
                id=fid,
                title=hint,
                technique_id="imported",
                target=hint,
                category="imported",
            )
            self._all[fid] = placeholder
            self._by_fp.setdefault(hint, placeholder)

    # -- retest ------------------------------------------------------------ #

    def mark_retest(self, finding_id: str, still_reproduces: bool, note: str = "") -> Optional[Finding]:
        f = self._all.get(finding_id)
        if not f:
            return None
        f.status = "reported" if still_reproduces else "fixed"
        f.metadata_retest = {  # type: ignore[attr-defined]
            "at": _now_iso(),
            "still_reproduces": still_reproduces,
            "note": note,
        }
        self._save()
        return f

    # -- introspection ----------------------------------------------------- #

    def all(self) -> List[Finding]:
        return list(self._all.values())

    def stats(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for f in self._all.values():
            out[f.status] = out.get(f.status, 0) + 1
        return out

    # -- persistence ------------------------------------------------------- #

    def _save(self) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "updated_at": _now_iso(),
            "findings": [f.to_dict() for f in self._all.values()],
        }
        self.path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    def _load(self) -> None:
        assert self.path is not None
        data = json.loads(self.path.read_text(encoding="utf-8"))
        for raw in data.get("findings", []):
            f = Finding.from_dict(raw)
            self._all[f.id] = f
            self._by_fp.setdefault(f.fingerprint, f)

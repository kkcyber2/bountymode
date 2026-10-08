"""U3 -- cross-tenant / RAG isolation proof (two-account differential test).

The single highest-paying AI bug class is a cross-tenant data leak.  Proving
it requires a *differential* test: the same request is issued as two
different authenticated principals, and the responses are compared.  If
principal B's response contains data that belongs to principal A, the trust
boundary is broken.

This module implements the differential comparison and produces a
:class:`DifferentialProof` that the evidence vault can capture verbatim.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class PrincipalResponse:
    """One principal's response to the shared probe."""

    principal: str          # e.g. "tenant-a" / "tenant-b"
    response: str
    status: Optional[int] = None
    markers: List[str] = field(default_factory=list)  # strings unique to this principal


@dataclass
class DifferentialProof:
    leaked: bool
    confidence: float
    leaked_markers: List[str] = field(default_factory=list)
    rationale: str = ""
    evidence: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "leaked": self.leaked,
            "confidence": round(self.confidence, 3),
            "leaked_markers": self.leaked_markers,
            "rationale": self.rationale,
        }


class CrossTenantProver:
    """Compare two principals' responses to the same probe."""

    def __init__(self, *, min_marker_len: int = 4) -> None:
        self.min_marker_len = min_marker_len

    def prove(
        self,
        owner: PrincipalResponse,
        attacker: PrincipalResponse,
        *,
        probe: str = "",
    ) -> DifferentialProof:
        """Return whether ``attacker`` can see ``owner``'s data.

        A leak is proven when a marker that is unique to the owner appears in
        the attacker's response.  Markers are matched case-insensitively and
        must be at least ``min_marker_len`` characters to avoid noise.
        """
        markers = [m for m in owner.markers if m and len(m) >= self.min_marker_len]
        if not markers:
            return DifferentialProof(
                leaked=False, confidence=0.0,
                rationale="no owner-unique markers supplied; cannot prove a leak",
            )

        attacker_text = (attacker.response or "").lower()
        hits = [m for m in markers if m.lower() in attacker_text]

        if not hits:
            return DifferentialProof(
                leaked=False, confidence=0.0,
                rationale="attacker response contained none of the owner's markers",
            )

        # Confidence scales with how many distinct markers leaked.
        confidence = min(0.99, 0.6 + 0.15 * len(hits))
        evidence = (
            f"Probe: {probe or '(shared request)'}\n"
            f"Owner principal: {owner.principal}\n"
            f"Attacker principal: {attacker.principal}\n"
            f"Owner-unique markers: {markers}\n"
            f"Markers observed in attacker response: {hits}\n"
            f"Attacker response (truncated): {(attacker.response or '')[:500]}"
        )
        return DifferentialProof(
            leaked=True,
            confidence=confidence,
            leaked_markers=hits,
            rationale=(
                f"attacker '{attacker.principal}' received {len(hits)} marker(s) "
                f"unique to owner '{owner.principal}' -- cross-tenant isolation broken"
            ),
            evidence=evidence,
        )


def extract_markers(text: str, pattern: str) -> List[str]:
    """Pull candidate unique markers (e.g. tenant ids, emails) out of text."""
    return re.findall(pattern, text or "")

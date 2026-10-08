"""
agathon.plugins.base — AttackPlugin ABC, AttackContext, schema-validated Finding.

This is the contract every auto-discovered attack plugin implements. Findings
are validated by pydantic so the orchestrator and reporter never receive
ad-hoc dict shapes — a Finding is either structurally valid or construction
raises, and the registry skips misbehaving plugins instead of corrupting a
run.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from agathon.attack_tier_logic import Intensity

log = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Intensity ordering                                                           #
# --------------------------------------------------------------------------- #

_INTENSITY_RANK = {
    Intensity.RECON: 0,
    Intensity.STANDARD: 1,
    Intensity.AGGRESSIVE: 2,
    Intensity.GREASY: 3,
}


def intensity_rank(intensity: Intensity | str) -> int:
    """Numeric tier rank — higher means more aggressive."""
    if isinstance(intensity, Intensity):
        return _INTENSITY_RANK[intensity]
    try:
        return _INTENSITY_RANK[Intensity(str(intensity).strip().lower())]
    except (KeyError, ValueError):
        return _INTENSITY_RANK[Intensity.STANDARD]


# Legacy REGISTRY ``level`` string used by catalogue_for_tier / reporting.
_LEVEL_FOR_MIN = {
    Intensity.RECON: "easy",
    Intensity.STANDARD: "easy",
    Intensity.AGGRESSIVE: "hard",
    Intensity.GREASY: "greasy",
}


def level_for_intensity_min(intensity_min: Intensity) -> str:
    return _LEVEL_FOR_MIN.get(intensity_min, "medium")


# --------------------------------------------------------------------------- #
# Finding — schema-validated attack result                                     #
# --------------------------------------------------------------------------- #


class Finding(BaseModel):
    """The single, validated shape every plugin returns from ``run()``.

    Field names are deliberately aligned with the legacy ``AttackResult``
    dataclass and the in-memory finding dict the orchestrator builds, so a
    Finding can be losslessly converted into either without translation
    tables.
    """

    model_config = ConfigDict(extra="forbid")

    attack: str                          # plugin name
    family: str                          # tier-gating family key
    cwe: Optional[str] = None            # e.g. "CWE-74"
    severity: str = "info"               # info | low | medium | high | critical
    success: bool = False
    success_score: float = 0.0           # 0.0-1.0 confidence
    summary: str = ""                    # evidence / what proves success
    payload: str = ""                    # exact input that triggered the vuln
    response: str = ""                   # target response excerpt
    remediation: str = ""                # mitigation advice
    exploitability: float = 0.5          # 0.0-1.0
    impact: float = 0.5                  # 0.0-1.0
    reliability: float = 0.5             # 0.0-1.0
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    duration_ms: float = 0.0

    @field_validator("severity")
    @classmethod
    def _validate_severity(cls, v: str) -> str:
        allowed = {"info", "low", "medium", "high", "critical"}
        if v not in allowed:
            raise ValueError(f"severity must be one of {sorted(allowed)}; got {v!r}")
        return v

    @field_validator("success_score", "exploitability", "impact", "reliability")
    @classmethod
    def _validate_unit_interval(cls, v: float) -> float:
        if not 0.0 <= float(v) <= 1.0:
            raise ValueError("score must be in [0.0, 1.0]")
        return float(v)

    @field_validator("cwe")
    @classmethod
    def _validate_cwe(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = v.strip().upper()
        if not v.startswith("CWE-"):
            raise ValueError("cwe must look like 'CWE-<id>'")
        return v


# --------------------------------------------------------------------------- #
# AttackContext — everything a plugin needs to fire one strike                 #
# --------------------------------------------------------------------------- #


@dataclass
class AttackContext:
    """Bundle passed to ``AttackPlugin.run()``.

    Built by the registry wrapper from the orchestrator's ``AgathonState`` (or
    the legacy ``(client, model, intensity)`` fallback signature). Plugins
    must never reach for ``os.environ`` keys themselves — the target client is
    constructed by the orchestrator with the scan-form API key and handed in
    here.
    """

    client: Any                         # OpenAI-compatible target client
    target_model: str
    target_url: str = ""
    api_key: str = ""
    target_provider: str = ""
    intensity: Intensity = Intensity.STANDARD
    surface_kind: str = "llm"
    rationale: str = ""
    extras: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_state(cls, state: Any, rationale: str = "") -> "AttackContext":
        """Build a context from an ``AgathonState`` instance."""
        return cls(
            client=None,  # caller wires the weapon client before run()
            target_model=getattr(state, "target_model", "unknown"),
            target_url=getattr(state, "target_url", ""),
            api_key=getattr(state, "api_key", ""),
            target_provider=getattr(state, "target_provider", ""),
            intensity=getattr(state, "intensity", Intensity.STANDARD),
            surface_kind=getattr(state, "surface_kind", "llm"),
            rationale=rationale,
        )


# --------------------------------------------------------------------------- #
# AttackPlugin — the contract                                                  #
# --------------------------------------------------------------------------- #


class AttackPlugin(ABC):
    """Base class for every auto-discovered attack.

    Subclasses declare the four catalogue attributes as class attributes and
    implement :meth:`run`. The registry instantiates each plugin once at
    discovery time and reuses the instance for every strike.

    Attributes:
        name: Dotted, catalogue-stable identifier (e.g. ``prompt_injection.direct``).
        family: Tier-gating family key — MUST match a constant in
            ``agathon/attack_tier_logic.py`` so ``catalogue_for_tier`` admits
            the plugin at the right tiers.
        intensity_min: Lowest :class:`Intensity` at which this plugin may run.
            Enforced both at catalogue time and inside the run wrapper.
        cwe: Optional canonical CWE id (``CWE-<id>``).
    """

    # Catalogue attributes — overridden by every concrete plugin.
    name: str = ""
    family: str = ""
    intensity_min: Intensity = Intensity.STANDARD
    cwe: Optional[str] = None

    @abstractmethod
    def run(self, ctx: AttackContext) -> Finding:
        """Execute the attack and return a validated :class:`Finding`."""
        raise NotImplementedError

    # ---- introspection helpers used by the registry ---------------------- #

    def catalogue_entry(self) -> Dict[str, Any]:
        """Legacy REGISTRY-compatible descriptor for this plugin."""
        return {
            "name": self.name,
            "family": self.family,
            "level": level_for_intensity_min(self.intensity_min),
            "intensity_min": self.intensity_min.value,
            "cwe": self.cwe,
            "plugin": self,
            "source": "plugin",
        }

    def available_at(self, intensity: Intensity | str) -> bool:
        """True when ``intensity`` is at or above this plugin's minimum."""
        return intensity_rank(intensity) >= intensity_rank(self.intensity_min)


# --------------------------------------------------------------------------- #
# Finding → legacy AttackResult bridge                                         #
# --------------------------------------------------------------------------- #
# The orchestrator's fallback dispatch path calls ``severity_from_result`` and
# ``result_payload`` on an ``attacks.base_tester.AttackResult``. To stay
# non-breaking, the registry wraps each plugin in an ``fn`` that runs the
# plugin and converts the validated Finding into an AttackResult.

_FAMILY_TO_VULN_TYPE = {
    "prompt_injection": "Prompt Injection",
    "data_exfiltration": "Data Exfiltration",
    "context_manipulation": "Context Manipulation",
    "token_smuggling": "Token Smuggling",
    "adversarial_robustness": "Adversarial Robustness",
    "model_misuse": "Model Misuse",
    "chain_of_thought_hijack": "Chain-of-Thought Hijacking",
    "invisible_injection": "Invisible Command Injection",
    "system_prompt_extraction": "System Prompt Extraction",
    "emotional_manipulation": "Emotional Manipulation",
    "rag_poisoning": "RAG Poisoning",
    # Phase 2 breadth families — mapped onto the closest existing
    # VulnerabilityType so the legacy AttackResult bridge keeps working.
    "logic_jailbreak": "Jailbreak",
    "iterative_jailbreak": "Jailbreak",
    "many_shot_jailbreak": "Jailbreak",
    "indirect_injection": "Prompt Injection",
    "multilingual_bypass": "Prompt Injection",
    "agent_hijack": "Model Misuse",
}


def finding_to_attack_result(finding: Finding, target_model: str = "unknown") -> Any:
    """Convert a validated Finding into a legacy ``AttackResult``.

    Imported lazily so ``agathon.plugins.base`` has no hard dependency on the
    ``attacks`` package at import time (the registry tolerates a missing
    attacks package in stripped runtimes).
    """
    from attacks.base_tester import (
        AttackResult,
        DifficultyLevel,
        VulnerabilityType,
    )

    vuln_str = _FAMILY_TO_VULN_TYPE.get(finding.family, finding.family)
    try:
        vuln = next(
            v for v in VulnerabilityType if v.value == vuln_str
        )
    except StopIteration:
        vuln = VulnerabilityType.PROMPT_INJECTION

    return AttackResult(
        attack_type=finding.attack,
        vulnerability_type=vuln,
        difficulty=DifficultyLevel.HARD,
        success=finding.success,
        success_score=finding.success_score,
        evidence=finding.summary,
        target_model=target_model,
        payload_used=finding.payload,
        response=finding.response,
        exploitability=finding.exploitability,
        impact=finding.impact,
        reliability=finding.reliability,
        recommended_fix=finding.remediation,
        cwe_references=[finding.cwe] if finding.cwe else [],
        tags=list(finding.tags),
        metadata=dict(finding.metadata),
        duration_ms=finding.duration_ms,
    )


def finding_from_attack_result(
    result: Any,
    *,
    name: str,
    family: str,
    cwe: Optional[str] = None,
) -> Finding:
    """Convert a legacy ``AttackResult`` into a validated :class:`Finding`.

    Convenience for plugins that wrap an existing ``*Tester`` from the
    ``attacks`` package: run the tester, hand the result here, return the
    Finding. The Finding constructor re-validates all score bounds and the
    severity enum, so a malformed legacy result surfaces immediately rather
    than corrupting the run.
    """
    return Finding(
        attack=name,
        family=family,
        cwe=cwe,
        success=bool(getattr(result, "success", False)),
        success_score=float(getattr(result, "success_score", 0.0) or 0.0),
        summary=str(getattr(result, "evidence", "") or getattr(result, "attack_type", "")),
        payload=str(getattr(result, "payload_used", "") or ""),
        response=str(getattr(result, "response", "") or ""),
        remediation=str(getattr(result, "recommended_fix", "") or ""),
        exploitability=float(getattr(result, "exploitability", 0.5) or 0.5),
        impact=float(getattr(result, "impact", 0.5) or 0.5),
        reliability=float(getattr(result, "reliability", 0.5) or 0.5),
        tags=list(getattr(result, "tags", []) or []),
        metadata=dict(getattr(result, "metadata", {}) or {}),
        duration_ms=float(getattr(result, "duration_ms", 0.0) or 0.0),
    )

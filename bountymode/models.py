"""Core data model for Bounty Mode.

Everything the workflow passes between stages is a plain dataclass defined
here: the imported :class:`ProgramScope`, the :class:`Technique` catalogue
entry, the :class:`AuthorizationDecision` the gate returns, the
:class:`Observation` a test produces, and the :class:`Finding` that is scored
and reported.

Keeping the model in one dependency-free module is deliberate: the scope
importer, the gate, the evidence vault, the scorer and the report generator
all speak the same vocabulary, and none of them needs the engine.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    """Severity bands, ordered from least to most severe."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    def __lt__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.rank < other.rank


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Verdict(str, Enum):
    """The authorization gate's answer for one (target, technique) pair."""

    ALLOW = "allow"
    DENY = "deny"
    NEEDS_HUMAN = "needs_human"


@dataclass
class ScopeTarget:
    """A single in-scope asset.

    ``pattern`` is a host, wildcard host, URL or CIDR.  ``kind`` is a free-form
    label (``llm``, ``web``, ``api``, ``cloud``, ``repo``) used to pick a
    domain adapter.
    """

    pattern: str
    kind: str = "web"
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class OutOfScopeRule:
    """An explicit exclusion.  Exclusions always beat inclusions."""

    pattern: str
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ProgramScope:
    """The machine-readable result of importing a program policy.

    The numeric fields are *ceilings*: a caller may tighten them but never
    raise them.  ``prohibited_techniques`` is merged with the unconditional
    blocklist at import time, so it can only ever grow.
    """

    program: str
    platform: str = "generic"
    in_scope: List[ScopeTarget] = field(default_factory=list)
    out_of_scope: List[OutOfScopeRule] = field(default_factory=list)
    prohibited_techniques: List[str] = field(default_factory=list)
    rate_limit_rps: float = 1.0
    max_requests: int = 200
    max_duration_s: int = 1800
    requires_test_account: bool = False
    safe_harbour: bool = True
    disclosure_days: int = 90
    source: str = ""
    imported_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["in_scope"] = [t.to_dict() for t in self.in_scope]
        data["out_of_scope"] = [r.to_dict() for r in self.out_of_scope]
        return data

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=False)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ProgramScope":
        in_scope = [
            t if isinstance(t, ScopeTarget) else ScopeTarget(**t)
            for t in data.get("in_scope", [])
        ]
        out_of_scope = [
            r if isinstance(r, OutOfScopeRule) else OutOfScopeRule(**r)
            for r in data.get("out_of_scope", [])
        ]
        known = {
            "program",
            "platform",
            "in_scope",
            "out_of_scope",
            "prohibited_techniques",
            "rate_limit_rps",
            "max_requests",
            "max_duration_s",
            "requires_test_account",
            "safe_harbour",
            "disclosure_days",
            "source",
            "imported_at",
        }
        kwargs = {k: v for k, v in data.items() if k in known}
        kwargs["in_scope"] = in_scope
        kwargs["out_of_scope"] = out_of_scope
        return cls(**kwargs)


@dataclass
class Technique:
    """One attack technique in a domain's catalogue.

    ``side_effects`` marks a technique that can change server state; such a
    technique always requires a human approval before the gate will pass it.
    ``destructive`` marks a technique that is blocked unconditionally.
    """

    id: str
    name: str
    category: str
    domain: str = "generic"
    severity_hint: str = "medium"
    side_effects: bool = False
    destructive: bool = False
    description: str = ""
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AuthorizationDecision:
    """The gate's verdict for one (target, technique) pair, with its reason."""

    target: str
    technique_id: str
    verdict: Verdict
    reason: str
    matched_rule: str = ""
    decided_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @property
    def allowed(self) -> bool:
        return self.verdict is Verdict.ALLOW

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["verdict"] = self.verdict.value
        return data


@dataclass
class Observation:
    """A single raw observation produced by one test execution.

    Observations are pre-finding: they carry the request/response material and
    a boolean ``signal`` saying whether the technique's success condition was
    met.  The evidence vault redacts them before they are persisted.
    """

    technique_id: str
    target: str
    signal: bool
    request: str = ""
    response: str = ""
    notes: str = ""
    latency_ms: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    """A confirmed, scored, reportable issue.

    A finding is only created from an observation whose ``signal`` is true and
    which survived reproducibility and false-positive filtering.
    """

    id: str
    title: str
    technique_id: str
    target: str
    category: str
    domain: str = "generic"
    severity: str = "medium"
    cvss_vector: str = ""
    cvss_score: float = 0.0
    confidence: float = 0.0
    impact: str = ""
    remediation: str = ""
    description: str = ""
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    taxonomy: Dict[str, List[str]] = field(default_factory=dict)
    reproduction_rate: float = 0.0
    fingerprint: str = ""
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=False)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


def compute_fingerprint(
    technique_id: str, target: str, category: str, extra: str = ""
) -> str:
    """Stable de-duplication fingerprint for a finding.

    The fingerprint is deliberately coarse: it identifies the *class* of issue
    on a *target*, not the exact payload, so that two runs that find the same
    weakness with different prompts collapse to one finding.
    """

    basis = "|".join(
        [
            technique_id.strip().lower(),
            target.strip().lower(),
            category.strip().lower(),
            extra.strip().lower(),
        ]
    )
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]

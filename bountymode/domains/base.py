"""Domain-agnostic adapter framework.

Bounty Mode's six components (scope importer, authorization gate,
stop-conditions, evidence vault, triage scorer, report generator) all operate
on *findings*, not on techniques.  Only the test-case runner is
domain-specific.

This module formalises that seam.  A :class:`DomainAdapter` supplies the
domain-specific half of a run:

* the **technique catalogue** for the domain,
* how to **dispatch** one technique against one target,
* how to **classify** a raw result into a canonical category,
* the **impact / remediation / taxonomy** text for that category.

Everything else -- scope enforcement, the authorization gate, stop-conditions,
evidence capture, triage scoring and report rendering -- is reused unchanged.
Adding a new domain therefore costs an adapter, not a fork.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from ..models import Finding, Severity, Technique, compute_fingerprint
from ..runner.adapter import EngineResult


def human(text: str) -> str:
    """``cross_tenant`` -> ``Cross Tenant``."""
    return (text or "").replace("_", " ").strip().title()


class DomainAdapter(ABC):
    """Supplies the domain-specific half of a Bounty Mode run."""

    #: stable identifier used on the CLI / API (``ai_llm``, ``web_api`` ...)
    name: str = "base"
    #: one-line description shown in the UI
    description: str = ""
    #: the ``ScopeTarget.kind`` this domain normally operates on
    scope_kind: str = "generic"

    # -- catalogue --------------------------------------------------------- #

    @abstractmethod
    def techniques(self) -> List[Technique]:
        """Return the technique catalogue for this domain."""

    def technique(self, technique_id: str) -> Optional[Technique]:
        for t in self.techniques():
            if t.id == technique_id:
                return t
        return None

    def require(self, technique_id: str) -> Technique:
        t = self.technique(technique_id)
        if t is None:
            raise KeyError(f"unknown technique for domain {self.name!r}: {technique_id!r}")
        return t

    # -- execution --------------------------------------------------------- #

    def dispatch(
        self,
        technique: Technique,
        target: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> EngineResult:
        """Run one technique against one target.

        The default is a **safe dry run**: no network I/O, no side effects.
        A concrete adapter overrides this to talk to a real engine or tool.
        The caller (the case runner) has already obtained an ALLOW decision
        from the authorization gate before this is ever called.
        """
        return EngineResult(
            technique_id=technique.id,
            target=target,
            success=False,
            evidence="no engine configured (dry run)",
        )

    # -- interpretation ---------------------------------------------------- #

    def classify(self, result: EngineResult) -> str:
        """Map a raw engine result onto a canonical category."""
        raw = (result.vulnerability_type or result.technique_id or "unknown")
        return raw.strip().lower().replace(" ", "_").replace("-", "_")

    def impact(self, category: str) -> str:
        return "Successful exploitation of this weakness has a security impact."

    def remediation(self, category: str) -> str:
        return (
            "Treat all external input as untrusted, enforce authorization "
            "server-side, and add a regression test for this case."
        )

    def taxonomy(self, category: str) -> Dict[str, List[str]]:
        """Return ``{"cwe": [...], "owasp_llm": [...], "mitre_atlas": [...]}``."""
        return {"cwe": [], "owasp_llm": [], "mitre_atlas": []}

    def blast_radius(self, category: str) -> str:
        return "single-user"

    def severity_hint(self, category: str) -> Severity:
        return Severity.MEDIUM

    # -- finding construction ---------------------------------------------- #

    def build_finding(self, result: EngineResult) -> Finding:
        """Turn a successful :class:`EngineResult` into a :class:`Finding`."""
        category = self.classify(result)
        tax = self.taxonomy(category)
        return Finding(
            id="F-" + compute_fingerprint(result.technique_id, result.target)[:10],
            title=f"{human(category)} on {result.target}",
            technique_id=result.technique_id,
            target=result.target,
            category=category,
            severity=self.severity_hint(category),
            confidence=result.confidence or result.success_score,
            reproducible=result.success and result.success_score >= 0.7,
            reproduction_rate=result.success_score,
            affected_asset=result.target,
            blast_radius=self.blast_radius(category),
            description=(
                f"The `{result.technique_id}` test succeeded against "
                f"`{result.target}` with a confidence of {result.success_score:.0%}."
            ),
            impact=self.impact(category),
            expected="The application should have refused or safely handled the input.",
            actual=result.evidence or result.response[:400] or "The application complied.",
            remediation=self.remediation(category),
            cwe=tax.get("cwe", []),
            owasp_llm=tax.get("owasp_llm", []),
            mitre_atlas=tax.get("mitre_atlas", []),
        )


class DomainRegistry:
    """A registry of :class:`DomainAdapter` instances, keyed by name."""

    def __init__(self) -> None:
        self._adapters: Dict[str, DomainAdapter] = {}

    def register(self, adapter: DomainAdapter, *, replace: bool = False) -> DomainAdapter:
        if adapter.name in self._adapters and not replace:
            raise ValueError(f"domain already registered: {adapter.name!r}")
        self._adapters[adapter.name] = adapter
        return adapter

    def get(self, name: str) -> DomainAdapter:
        try:
            return self._adapters[name]
        except KeyError as exc:
            raise KeyError(
                f"unknown domain {name!r}; known: {', '.join(sorted(self._adapters))}"
            ) from exc

    def has(self, name: str) -> bool:
        return name in self._adapters

    def names(self) -> List[str]:
        return sorted(self._adapters)

    def all(self) -> List[DomainAdapter]:
        return [self._adapters[n] for n in self.names()]

    def describe(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": a.name,
                "description": a.description,
                "scope_kind": a.scope_kind,
                "techniques": len(a.techniques()),
            }
            for a in self.all()
        ]


#: The process-wide default registry, populated by :mod:`bountymode.domains`.
DEFAULT_REGISTRY = DomainRegistry()


def register_adapter(adapter: DomainAdapter) -> DomainAdapter:
    """Register an adapter on the default registry (idempotent)."""
    if DEFAULT_REGISTRY.has(adapter.name):
        return DEFAULT_REGISTRY.get(adapter.name)
    return DEFAULT_REGISTRY.register(adapter)

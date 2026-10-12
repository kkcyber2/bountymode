"""Impact amplification -- turn a weakness into a proven, higher-severity chain.

Detecting a weakness is the cheap half.  A report earns a high severity when it
shows the *chain*: the low-severity information leak that yields a token, the
token that yields another tenant's record, the record that proves the trust
boundary is broken.  This module builds and evidences those chains.

Three amplifiers, all offline and deterministic
-----------------------------------------------
:class:`ChainAmplifier`
    Uses the existing :class:`~bountymode.upgrades.chaining.ChainPlanner` to
    search for a path from the findings we have to a high-value goal, and
    reports the chain with its severity lift.
:class:`PrivilegeEscalationProver`
    Given a finding and a second-principal response, decides whether the same
    weakness reaches an administrative or cross-tenant object, and states the
    evidence that supports the claim.
:class:`DataExposureProver`
    Given a finding and the data it exposed, classifies *what kind* of data it
    is (credential, PII, internal document, cross-tenant record) and therefore
    how much the severity should rise.

Every amplifier is honest: it returns ``amplified=False`` with a reason when the
evidence does not support a lift, rather than inflating a finding.  The output is
an :class:`Amplification` that the report renders as a chain section, and that
the triage scorer uses to raise the CVSS score.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from ..models import Finding, Severity
from ..upgrades.chaining import ChainNode, ChainPlanner
from ..upgrades.cross_tenant import CrossTenantProver, PrincipalResponse

# --------------------------------------------------------------------------- #
# data classification
# --------------------------------------------------------------------------- #

#: What kind of data a leak exposed, and the severity floor it implies.
_DATA_CLASSES: List[tuple] = [
    ("credential", Severity.CRITICAL, (
        r"\bsk-[A-Za-z0-9_\-]{16,}", r"\bAKIA[0-9A-Z]{16}", r"\bgh[pousr]_[A-Za-z0-9]{20,}",
        r"\bAIza[0-9A-Za-z_\-]{30,}", r"\bxox[abprs]-[A-Za-z0-9\-]{10,}",
        r"\bpassword\b", r"\bapi[_ -]?key\b", r"\bsecret\b", r"\bbearer\s+[A-Za-z0-9._\-]{20,}",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    )),
    ("pii", Severity.HIGH, (
        r"\b\d{3}-\d{2}-\d{4}\b",                       # US SSN
        r"\b(?:\d[ -]?){13,16}\b",                      # card-like
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
        r"\b\+?\d[\d ()\-]{7,}\d\b",                    # phone-like
        r"\b(?:passport|national id|date of birth|dob)\b",
    )),
    ("internal_document", Severity.HIGH, (
        r"\bconfidential\b", r"\binternal (?:only|use|memo|document)\b",
        r"\bdo not distribute\b", r"\bproprietary\b", r"\bboard minutes\b",
    )),
    ("cross_tenant_record", Severity.CRITICAL, (
        r"\btenant[-_ ]?[a-z0-9]+\b", r"\baccount[-_ ]?id\b", r"\bother user'?s\b",
        r"\borgani[sz]ation[-_ ]?id\b", r"\bcustomer[-_ ]?id\b",
    )),
    ("system_prompt", Severity.MEDIUM, (
        r"\bsystem prompt\b", r"\byou are (?:a|an|the)\b", r"\bnever reveal\b",
        r"\bdeveloper message\b", r"\bhidden instruction\b",
    )),
]

#: Severity floor per data class, as a rank for comparison.
_CLASS_RANK = {name: sev.rank for name, sev, _ in _DATA_CLASSES}


def classify_exposed_data(text: str) -> tuple:
    """Return ``(class_name, severity, matched_examples)`` for leaked text."""
    hay = text or ""
    best: Optional[tuple] = None
    for name, severity, patterns in _DATA_CLASSES:
        hits: List[str] = []
        for pattern in patterns:
            for m in re.finditer(pattern, hay, re.I):
                snippet = m.group(0)
                if snippet not in hits:
                    hits.append(snippet)
                if len(hits) >= 3:
                    break
            if len(hits) >= 3:
                break
        if hits:
            if best is None or severity.rank > best[1].rank:
                best = (name, severity, hits)
    if best is None:
        return ("none", Severity.INFO, [])
    return best


# --------------------------------------------------------------------------- #
# result model
# --------------------------------------------------------------------------- #

@dataclass
class Amplification:
    """The outcome of trying to raise a finding's severity."""

    finding_id: str
    amplified: bool
    kind: str = ""                     # chain | privilege_escalation | data_exposure
    from_severity: str = ""
    to_severity: str = ""
    rationale: str = ""
    evidence: List[str] = field(default_factory=list)
    chain: Optional[Dict[str, Any]] = None
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "amplified": self.amplified,
            "kind": self.kind,
            "from_severity": self.from_severity,
            "to_severity": self.to_severity,
            "rationale": self.rationale,
            "evidence": list(self.evidence),
            "chain": self.chain,
            "confidence": round(self.confidence, 3),
        }


# --------------------------------------------------------------------------- #
# amplifiers
# --------------------------------------------------------------------------- #

class DataExposureProver:
    """Raise a finding's severity when the data it exposed is sensitive."""

    def prove(self, finding: Finding) -> Amplification:
        hay = " ".join(
            filter(None, [
                finding.actual or "",
                finding.description or "",
                finding.impact or "",
                *[o.response for o in finding.observations],
            ])
        )
        data_class, severity, examples = classify_exposed_data(hay)
        current = finding.severity
        if data_class == "none" or severity.rank <= current.rank:
            return Amplification(
                finding_id=finding.id,
                amplified=False,
                kind="data_exposure",
                from_severity=current.value,
                to_severity=current.value,
                rationale=(
                    "The exposed content does not contain credentials, personal "
                    "data, internal documents or another tenant's records, so no "
                    "severity lift is justified."
                ),
            )
        return Amplification(
            finding_id=finding.id,
            amplified=True,
            kind="data_exposure",
            from_severity=current.value,
            to_severity=severity.value,
            rationale=(
                f"The response contains {data_class.replace('_', ' ')} data, which "
                f"raises the impact from {current.value} to {severity.value}."
            ),
            evidence=[f"matched {data_class}: {e}" for e in examples],
            confidence=0.8,
        )


class PrivilegeEscalationProver:
    """Decide whether a weakness reaches an admin or cross-tenant object."""

    #: Capabilities that indicate the weakness crossed a trust boundary.
    _ESCALATION_MARKERS = (
        "admin", "administrator", "root", "superuser", "owner", "manage",
        "delete", "write access", "role", "permission", "tenant", "organization",
        "billing", "invoice", "other user",
    )

    def __init__(self, prover: Optional[CrossTenantProver] = None) -> None:
        self.prover = prover or CrossTenantProver()

    def prove(
        self,
        finding: Finding,
        *,
        owner: Optional[PrincipalResponse] = None,
        attacker: Optional[PrincipalResponse] = None,
    ) -> Amplification:
        current = finding.severity

        # A two-principal differential is the strongest form of proof.
        if owner is not None and attacker is not None:
            proof = self.prover.prove(owner, attacker, probe=finding.technique_id)
            if proof.leaked:
                return Amplification(
                    finding_id=finding.id,
                    amplified=True,
                    kind="privilege_escalation",
                    from_severity=current.value,
                    to_severity=Severity.CRITICAL.value,
                    rationale=(
                        "A second principal received data belonging to the first, "
                        "so the weakness crosses a trust boundary and is a "
                        "cross-tenant access-control failure."
                    ),
                    evidence=list(proof.leaked_markers) or [proof.rationale],
                    confidence=proof.confidence,
                )

        # Otherwise look for escalation language in the observed response.
        hay = " ".join(
            filter(None, [finding.actual or "", *[o.response for o in finding.observations]])
        ).lower()
        hits = [m for m in self._ESCALATION_MARKERS if m in hay]
        if len(hits) >= 2 and current.rank < Severity.HIGH.rank:
            return Amplification(
                finding_id=finding.id,
                amplified=True,
                kind="privilege_escalation",
                from_severity=current.value,
                to_severity=Severity.HIGH.value,
                rationale=(
                    "The response exposes administrative or cross-account "
                    "capabilities, which raises the impact to high."
                ),
                evidence=[f"escalation signal: {h}" for h in hits[:4]],
                confidence=0.6,
            )

        return Amplification(
            finding_id=finding.id,
            amplified=False,
            kind="privilege_escalation",
            from_severity=current.value,
            to_severity=current.value,
            rationale=(
                "No evidence that the weakness reaches an administrative or "
                "cross-tenant object, so no escalation is claimed."
            ),
        )


class ChainAmplifier:
    """Search for a chain from the findings we have to a high-value goal."""

    #: What each finding category yields, and what it needs, for the graph.
    _YIELDS = {
        "system_prompt_leak": ["internal_knowledge"],
        "data_exfiltration": ["sensitive_data"],
        "prompt_injection": ["instruction_control"],
        "indirect_injection": ["instruction_control"],
        "jailbreak": ["instruction_control"],
        "context_manipulation": ["instruction_control"],
        "cross_tenant": ["other_tenant_data"],
        "idor": ["other_user_object"],
        "auth_bypass": ["authenticated_session"],
        "jwt_weakness": ["forged_session"],
        "ssrf": ["internal_network"],
        "sqli": ["database_access"],
        "path_traversal": ["file_read"],
        "xss": ["victim_session"],
        "secret_in_logs": ["credential"],
        "public_bucket": ["sensitive_data"],
        "iam_privesc": ["admin_access"],
        "dependency_confusion": ["build_control"],
        "pipeline_poisoning": ["build_control"],
        "output_handling": ["client_execution"],
        "excessive_agency": ["tool_control"],
        "tool_misuse": ["tool_control"],
    }

    _REQUIRES = {
        "data_exfiltration": ["internal_knowledge"],
        "cross_tenant": ["authenticated_session"],
        "tool_misuse": ["instruction_control"],
        "iam_privesc": ["credential"],
        "auth_bypass": ["forged_session"],
        "mass_assignment": ["authenticated_session"],
        "xss": ["client_execution"],
    }

    #: Goals worth chaining toward, highest value first.
    GOALS = (
        "admin_access",
        "other_tenant_data",
        "sensitive_data",
        "database_access",
        "build_control",
        "tool_control",
    )

    def amplify(self, findings: Sequence[Finding]) -> List[Amplification]:
        if len(findings) < 1:
            return []
        nodes = [
            ChainNode(
                finding_id=f.id,
                title=f.title,
                yields=list(self._YIELDS.get(f.category, [])),
                requires=list(self._REQUIRES.get(f.category, [])),
                severity=f.severity.value,
            )
            for f in findings
        ]
        planner = ChainPlanner(nodes)
        out: List[Amplification] = []
        for goal in self.GOALS:
            chains = planner.find_chains(goal)
            if not chains:
                continue
            best = max(chains, key=lambda c: (c.length, c.score))
            if best.length < 2:
                continue
            out.append(
                Amplification(
                    finding_id=best.nodes[0].finding_id,
                    amplified=True,
                    kind="chain",
                    from_severity=best.nodes[0].severity,
                    to_severity=Severity.CRITICAL.value,
                    rationale=(
                        f"A {best.length}-step chain reaches '{goal}': "
                        + " -> ".join(n.title for n in best.nodes)
                        + ". The chain is what makes this critical, not any single step."
                    ),
                    evidence=[f"step {i}: {n.title} yields {', '.join(n.yields) or 'n/a'}"
                              for i, n in enumerate(best.nodes, 1)],
                    chain=best.to_dict(),
                    confidence=min(0.9, 0.5 + 0.1 * best.length),
                )
            )
            break  # one chain is enough to make the point
        return out


# --------------------------------------------------------------------------- #
# facade
# --------------------------------------------------------------------------- #

class Amplifier:
    """Run every amplifier over a set of findings and apply the lifts."""

    def __init__(self) -> None:
        self.data = DataExposureProver()
        self.privesc = PrivilegeEscalationProver()
        self.chain = ChainAmplifier()

    def amplify(
        self,
        findings: Sequence[Finding],
        *,
        apply: bool = True,
    ) -> List[Amplification]:
        """Amplify each finding; optionally fold the lift back into it.

        ``apply`` raises the finding's severity and appends the chain rationale
        to its impact, so the report and the CVSS scorer both see the amplified
        finding.  The original severity is preserved in the amplification record.
        """
        results: List[Amplification] = []
        for finding in findings:
            for amp in (self.data.prove(finding), self.privesc.prove(finding)):
                results.append(amp)
                if apply and amp.amplified:
                    self._apply(finding, amp)
        for amp in self.chain.amplify(findings):
            results.append(amp)
            if apply and amp.amplified:
                target = next((f for f in findings if f.id == amp.finding_id), None)
                if target is not None:
                    self._apply(target, amp)
        return results

    @staticmethod
    def _apply(finding: Finding, amp: Amplification) -> None:
        """Fold an amplification into the finding, never lowering severity.

        The lift is recorded as a *severity floor* rather than by overwriting
        ``severity`` directly: the triage scorer derives the label from the CVSS
        score, so setting the label alone would leave a "critical" finding with a
        low score.  The floor makes the scorer raise the score to match.
        """
        try:
            new_sev = Severity(amp.to_severity)
        except ValueError:
            return
        current_floor = getattr(finding, "severity_floor", None)
        if current_floor is None or new_sev.rank > current_floor.rank:
            finding.severity_floor = new_sev
        if new_sev.rank > finding.severity.rank:
            finding.severity = new_sev
        note = f"[amplified: {amp.kind}] {amp.rationale}"
        if note not in (finding.impact or ""):
            finding.impact = (finding.impact + "\n\n" + note).strip()
        if amp.chain:
            finding.blast_radius = "cross-tenant" if amp.chain.get("goal") in (
                "other_tenant_data", "admin_access"
            ) else finding.blast_radius

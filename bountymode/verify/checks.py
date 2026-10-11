"""Submission readiness -- is this report actually submittable?

A finding is not a report.  Even a real vulnerability gets closed as
"informational" or "needs more info" when the writeup is missing impact, steps,
evidence or a stated asset.  This module answers one question per finding:

    *Ready to submit -- and if not, exactly what is missing?*

It is a **superset** of the original checker: the field, evidence, CVSS and
scope checks are unchanged, plus two that the verification engine makes
possible -- a verification verdict and a negative-control result.  A finding that
was only ever replayed once now reports *why* that is not enough, instead of
being presented as proven.

The checker is deliberately unforgiving.  A report that is *probably* fine is
reported as not ready, naming the gap, because a rejected report costs more than
a fixed one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..models import Finding

#: Fields a submission cannot go out without, and how readiness reports them.
REQUIRED_FOR_SUBMISSION = (
    "title",
    "affected_asset",
    "description",
    "impact",
    "remediation",
)

#: Placeholder text that must never reach a triager verbatim.
_PLACEHOLDER_MARKERS = (
    "no description provided",
    "impact not articulated",
    "no remediation suggested",
    "no reproduction steps",
    "n/a",
    "todo",
    "tbd",
    "unknown",
)

#: Verdict constants (mirrors :mod:`bountymode.verify.oracles`).
VERIFIED = "verified"
UNVERIFIED = "unverified"
INCONCLUSIVE = "inconclusive"


@dataclass
class ReadinessCheck:
    """One submission requirement and whether it is met."""

    key: str
    label: str
    passed: bool
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"key": self.key, "label": self.label,
                "passed": self.passed, "detail": self.detail}


@dataclass
class SubmissionReadiness:
    """Whether a finding is ready to submit, and what is missing if not."""

    finding_id: str
    ready: bool
    checks: List[ReadinessCheck] = field(default_factory=list)
    missing: List[str] = field(default_factory=list)
    blockers: List[str] = field(default_factory=list)
    score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "ready": self.ready,
            "score": round(self.score, 3),
            "checks": [c.to_dict() for c in self.checks],
            "missing": list(self.missing),
            "blockers": list(self.blockers),
            "summary": self.summary,
        }

    @property
    def summary(self) -> str:
        if self.ready:
            return "Ready to submit: required fields present, reproduced and evidenced."
        items = ", ".join(self.blockers + self.missing) or "unspecified"
        return f"NOT submission-ready. Missing: {items}."


class SubmissionReadinessChecker:
    """Check a finding against the fields platforms actually require."""

    def __init__(self, *, min_reproduction_rate: float = 0.6, min_cvss: float = 3.0) -> None:
        self.min_reproduction_rate = min_reproduction_rate
        self.min_cvss = min_cvss

    def check(
        self,
        finding: Finding,
        *,
        in_scope: Optional[bool] = None,
        verification: Optional[Dict[str, Any]] = None,
    ) -> SubmissionReadiness:
        """Assess one finding.

        ``verification`` is the serialised
        :class:`~bountymode.verify.engine.VerificationReport` when one exists.
        Without it the check falls back to the finding's own replay counters, so
        a caller that has not run the verification engine still gets a sensible
        answer rather than a free pass.
        """
        checks: List[ReadinessCheck] = []
        missing: List[str] = []
        blockers: List[str] = []

        def add(key: str, label: str, passed: bool, detail: str = "", *, blocker: bool = False) -> None:
            checks.append(ReadinessCheck(key, label, passed, detail))
            if not passed:
                (blockers if blocker else missing).append(label)

        # -- required fields ------------------------------------------------ #
        for attr in REQUIRED_FOR_SUBMISSION:
            value = ""
            if attr == "affected_asset":
                value = finding.affected_asset or finding.target or ""
            else:
                value = str(getattr(finding, attr, "") or "")
            text = value.strip()
            # A placeholder is a field whose *entire* content is filler.  Matching
            # on substrings would misread a real description that merely mentions
            # a word like "unknown" as empty, so compare the whole value.
            normalised = text.lower().rstrip(".!? ").strip()
            placeholder = normalised in _PLACEHOLDER_MARKERS
            # The label names the missing thing so it reads correctly in the
            # "missing: ..." summary; the detail explains the failure.
            label = attr.replace("_", " ")
            detail = ""
            if not text:
                detail = "not provided"
            elif placeholder:
                detail = "placeholder text"
            add(attr, label, bool(text) and not placeholder, detail)

        # -- verification verdict ------------------------------------------- #
        verdict = ""
        rate = finding.reproduction_rate or 0.0
        if verification:
            verdict = str(verification.get("verdict", ""))
            rate = float(verification.get("rate", rate) or rate)
            neg_ok = bool(verification.get("negative_control_passed", True))
            successes = int(verification.get("successes", 0) or 0)
            attempts = int(verification.get("attempts", 0) or 0)
        else:
            successes = int(finding.verification_successes or 0)
            attempts = int(finding.verification_attempts or 0)
            neg_ok = True

        if verdict:
            add(
                "verification",
                "verification verdict is 'verified'",
                verdict == VERIFIED,
                f"verdict {verdict}"
                + (f" ({successes}/{attempts} attempts)" if attempts else ""),
                blocker=True,
            )
        else:
            add(
                "reproduced",
                "reproduced under replay",
                bool(finding.reproducible)
                and finding.reproduction_rate >= self.min_reproduction_rate,
                f"{successes}/{attempts} attempts" if attempts
                else f"recorded rate {finding.reproduction_rate:.0%}",
                blocker=True,
            )

        add(
            "reproduction_rate",
            f"reproduction rate >= {self.min_reproduction_rate:.0%}",
            rate >= self.min_reproduction_rate,
            f"{rate:.0%} across {attempts or '?'} attempt(s)",
            blocker=True,
        )
        add(
            "negative_control",
            "negative control did not trigger",
            neg_ok,
            "the signal fires without the weakness" if not neg_ok
            else "baseline behaved as expected",
            blocker=not neg_ok,
        )
        add(
            "evidence",
            "raw request/response evidence attached",
            bool(finding.observations),
            f"{len(finding.observations)} observation(s)",
            blocker=True,
        )
        add(
            "cvss",
            "CVSS v3.1 score and vector present",
            finding.cvss_score >= self.min_cvss and bool(finding.cvss_vector),
            f"{finding.cvss_score:.1f} ({finding.cvss_vector or 'no vector'})",
        )
        add(
            "impact_articulated",
            "impact articulated",
            len(finding.impact.strip()) >= 25,
            f"{len(finding.impact.strip())} chars",
        )
        if in_scope is not None:
            add(
                "in_scope",
                "target is in the confirmed scope",
                in_scope,
                "authorized target" if in_scope else "target is not covered by the scope",
                blocker=True,
            )

        passed = sum(1 for c in checks if c.passed)
        score = passed / len(checks) if checks else 0.0
        ready = not missing and not blockers

        return SubmissionReadiness(
            finding_id=finding.id,
            ready=ready,
            checks=checks,
            missing=missing,
            blockers=blockers,
            score=score,
        )

    def annotate(
        self,
        finding: Finding,
        *,
        in_scope: Optional[bool] = None,
        verification: Optional[Dict[str, Any]] = None,
    ) -> SubmissionReadiness:
        """Check a finding and store the verdict on it."""
        result = self.check(finding, in_scope=in_scope, verification=verification)
        finding.readiness = result.to_dict()
        return result


def assess_readiness(
    finding: Finding,
    report: Any,
    *,
    in_scope: Optional[bool] = None,
    policy: Any = None,
) -> SubmissionReadiness:
    """Assess a finding against a :class:`VerificationReport`.

    ``report`` may be a ``VerificationReport`` object or its serialised dict, so
    the same function serves the pipeline, the CLI and the UI.
    """
    if report is None:
        payload: Optional[Dict[str, Any]] = None
    elif hasattr(report, "to_dict"):
        payload = report.to_dict()
    elif isinstance(report, dict):
        payload = report
    else:
        payload = None

    checker = policy or SubmissionReadinessChecker()
    return checker.check(finding, in_scope=in_scope, verification=payload)

"""Finding verification — N-of-M replay and submission readiness.

Two questions stand between a finding and a paycheck:

1. **Does it actually reproduce?**  A technique that fires once in ten attempts
   is not submittable, and a report that cannot be reproduced is a reputation
   cost.  :class:`FindingVerifier` replays it N times and captures a raw
   request/response pair for every successful attempt, so the evidence bundle
   shows the repeats rather than asserting them.
2. **Is the report complete?**  Triagers reject reports that are missing
   impact, steps or evidence.  :class:`SubmissionReadiness` checks each finding
   against the fields HackerOne and Bugcrowd actually require and names exactly
   what is missing, instead of emitting a confident-looking report.

The replay itself reuses :class:`~bountymode.upgrades.reproducibility.Reproducer`
— reproducibility is a single concern and it already has an implementation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from ..models import Finding
from ..runner.adapter import EngineResult
from ..upgrades.reproducibility import Reproducer, ReplayResult

#: A dispatch function: (attempt index) -> EngineResult.
AttemptFn = Callable[[int], EngineResult]

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
    "todo",
    "tbd",
)


# --------------------------------------------------------------------------- #
# readiness
# --------------------------------------------------------------------------- #

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
        items = ", ".join(self.missing or self.blockers) or "unspecified"
        return f"NOT submission-ready. Missing: {items}."


class SubmissionReadinessChecker:
    """Check a finding against the fields platforms actually require.

    The check is deliberately unforgiving: a report that is *probably* fine is
    reported as not ready, with the specific gap named.  That is cheaper than a
    duplicate or a report closed as informational.
    """

    def __init__(self, *, min_reproduction_rate: float = 0.6, min_cvss: float = 3.0) -> None:
        self.min_reproduction_rate = min_reproduction_rate
        self.min_cvss = min_cvss

    def check(self, finding: Finding, *, in_scope: Optional[bool] = None) -> SubmissionReadiness:
        checks: List[ReadinessCheck] = []
        missing: List[str] = []
        blockers: List[str] = []

        def add(key: str, label: str, passed: bool, detail: str = "", *, blocker: bool = False) -> None:
            checks.append(ReadinessCheck(key, label, passed, detail))
            if not passed:
                (blockers if blocker else missing).append(label)

        for attr in REQUIRED_FOR_SUBMISSION:
            value = ""
            if attr == "affected_asset":
                value = finding.affected_asset or finding.target or ""
            else:
                value = str(getattr(finding, attr, "") or "")
            text = value.strip()
            placeholder = any(m in text.lower() for m in _PLACEHOLDER_MARKERS)
            add(attr, f"{attr.replace('_', ' ')} present", bool(text) and not placeholder,
                "empty or placeholder text" if (not text or placeholder) else "")

        add(
            "reproduced",
            "reproduced under replay",
            bool(finding.reproducible)
            and finding.reproduction_rate >= self.min_reproduction_rate,
            f"{finding.verification_successes}/{finding.verification_attempts} attempts"
            if finding.verification_attempts
            else f"recorded rate {finding.reproduction_rate:.0%}",
            blocker=True,
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

    def annotate(self, finding: Finding, *, in_scope: Optional[bool] = None) -> SubmissionReadiness:
        """Check a finding and store the verdict on it."""
        result = self.check(finding, in_scope=in_scope)
        finding.readiness = result.to_dict()
        return result


#: The name the pipeline and UI use.
SubmissionReadiness_ = SubmissionReadinessChecker


# --------------------------------------------------------------------------- #
# replay
# --------------------------------------------------------------------------- #

@dataclass
class VerificationResult:
    """Outcome of replaying one finding."""

    finding_id: str
    attempts: int
    successes: int
    rate: float
    stable: bool
    reproducible: bool
    evidence_count: int
    readiness: Optional[SubmissionReadiness] = None
    failed_attempts: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "attempts": self.attempts,
            "successes": self.successes,
            "rate": round(self.rate, 3),
            "stable": self.stable,
            "reproducible": self.reproducible,
            "evidence_count": self.evidence_count,
            "failed_attempts": list(self.failed_attempts),
            "readiness": self.readiness.to_dict() if self.readiness else None,
        }


class FindingVerifier:
    """Replay findings N times and fold the outcome back into each one.

    ``attempt`` receives the attempt index and returns an
    :class:`~bountymode.runner.adapter.EngineResult`.  Every successful attempt
    is captured into the vault as its own observation, so the report's evidence
    table lists the actual repeats.
    """

    def __init__(
        self,
        *,
        attempts: int = 5,
        success_threshold: float = 0.7,
        readiness: Optional[SubmissionReadinessChecker] = None,
    ) -> None:
        self.reproducer = Reproducer(attempts=attempts, success_threshold=success_threshold)
        self.readiness = readiness or SubmissionReadinessChecker()

    @property
    def attempts(self) -> int:
        return self.reproducer.attempts

    def verify(
        self,
        finding: Finding,
        attempt: AttemptFn,
        *,
        vault: Any = None,
        in_scope: Optional[bool] = None,
        capture_limit: int = 3,
    ) -> VerificationResult:
        """Replay ``finding`` and record the reproduction rate plus evidence."""
        replay: ReplayResult = self.reproducer.replay(attempt)
        finding.verification_attempts = replay.attempts
        finding.verification_successes = replay.successes
        finding.reproduction_rate = replay.rate
        finding.reproducible = (
            replay.reproducible and replay.rate >= self.readiness.min_reproduction_rate
        )

        evidence_count = 0
        if vault is not None and replay.successes:
            evidence_count = self._capture_repeats(
                finding, attempt, vault, capture_limit=capture_limit
            )

        result = VerificationResult(
            finding_id=finding.id,
            attempts=replay.attempts,
            successes=replay.successes,
            rate=replay.rate,
            stable=replay.stable,
            reproducible=replay.reproducible,
            evidence_count=evidence_count,
            failed_attempts=list(replay.evidence) if not replay.reproducible else [],
        )
        result.readiness = self.readiness.annotate(finding, in_scope=in_scope)
        return result

    # -- internals --------------------------------------------------------- #

    def _capture_repeats(
        self,
        finding: Finding,
        attempt: AttemptFn,
        vault: Any,
        *,
        capture_limit: int,
    ) -> int:
        """Re-run the finding to capture raw request/response pairs as evidence.

        Only distinct successes are stored, and only up to ``capture_limit``, so
        the vault records the proof without growing without bound.
        """
        captured = 0
        for i in range(self.reproducer.attempts):
            if captured >= capture_limit:
                break
            try:
                res = attempt(i)
            except Exception:  # noqa: BLE001 - a failed repeat is not fatal
                continue
            if not (res.success and res.success_score >= self.reproducer.success_threshold):
                continue
            vault.capture(
                finding,
                kind="http",
                request=res.payload_used or f"technique={res.technique_id}",
                response=res.response or res.evidence or "",
                url=res.target,
                method="POST",
                environment={"verification_attempt": i + 1,
                             "of": self.reproducer.attempts,
                             "source": "replay"},
            )
            captured += 1
        return captured

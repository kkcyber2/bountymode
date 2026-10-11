"""Generic verification engine.

This is the piece that turns "the scanner said so" into "here is the proof, and
here is how sure we are".  It works for any finding class because the
class-specific knowledge lives in an :mod:`~bountymode.verify.oracles` oracle --
this module only orchestrates:

1. pick the oracle for the finding's class;
2. replay the probe set **N of M** times, re-sending the *test* probe every time
   (so reproducibility is measured, not assumed) while the control and negative
   baselines are cached (so a replay costs one request, not three);
3. fold each attempt's oracle verdict into a reproduction rate;
4. evaluate the **negative control** independently, so a weakness that fires on
   the do-nothing baseline is caught as a false positive rather than reported;
5. capture the raw request/response of every successful attempt as evidence;
6. return an explicit verdict -- ``verified`` / ``unverified`` /
   ``inconclusive`` -- with the reason, and never a confident claim the evidence
   does not support.

What this deliberately does **not** do is decide whether a vulnerability is
real in the target's production environment.  Final confirmation is the
program's job.  This module's job is to prove reproducibility and impact with
evidence, and to say so plainly when it cannot.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..models import Finding
from .oracles import (
    INCONCLUSIVE,
    UNVERIFIED,
    VERIFIED,
    OracleRegistry,
    ORACLES,
    OracleResult,
)
from .probe import (
    CONTROL,
    NEGATIVE,
    TEST,
    ProbeOutcome,
    ProbeRunner,
    ProbeSender,
    ProbeSet,
)

#: Verdict labels, re-exported for callers that only import this module.
VERDICT_VERIFIED = VERIFIED
VERDICT_UNVERIFIED = UNVERIFIED
VERDICT_INCONCLUSIVE = INCONCLUSIVE


@dataclass
class AttemptRecord:
    """One replay attempt: what was sent, what came back, what the oracle said."""

    index: int
    verdict: str
    confidence: float
    signal: str
    detail: str
    oracle: str
    measurements: Dict[str, Any] = field(default_factory=dict)
    negative_control_fired: bool = False
    errored: bool = False
    latency_ms: float = 0.0
    outcome: Optional[ProbeOutcome] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attempt": self.index,
            "verdict": self.verdict,
            "confidence": round(self.confidence, 3),
            "signal": self.signal,
            "detail": self.detail,
            "oracle": self.oracle,
            "negative_control_fired": self.negative_control_fired,
            "errored": self.errored,
            "latency_ms": round(self.latency_ms, 1),
            "measurements": dict(self.measurements),
            "probes": self.outcome.to_dict() if self.outcome else None,
        }


@dataclass
class VerificationReport:
    """The full verification outcome for one finding."""

    finding_id: str
    verdict: str = INCONCLUSIVE
    oracle: str = ""
    attempts: int = 0
    successes: int = 0
    rate: float = 0.0
    confidence: float = 0.0
    reproducible: bool = False
    negative_control_passed: bool = True
    negative_control_fired: int = 0
    stable: bool = False
    reasons: List[str] = field(default_factory=list)
    attempts_detail: List[AttemptRecord] = field(default_factory=list)
    evidence_captured: int = 0
    requests_sent: int = 0
    requests_reused: int = 0
    mean_latency_ms: float = 0.0
    readiness: Dict[str, Any] = field(default_factory=dict)

    @property
    def ready(self) -> bool:
        return bool(self.readiness.get("ready"))

    @property
    def summary(self) -> str:
        if self.verdict == VERIFIED:
            return (
                f"VERIFIED: reproduced {self.successes}/{self.attempts} attempts "
                f"via the {self.oracle} oracle"
                + ("" if self.negative_control_passed else "; negative control fired")
            )
        if self.verdict == INCONCLUSIVE:
            return f"INCONCLUSIVE: {self.reasons[0] if self.reasons else 'no usable signal'}"
        return (
            f"UNVERIFIED: reproduced {self.successes}/{self.attempts} attempts"
            + (f" -- {self.reasons[0]}" if self.reasons else "")
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "verdict": self.verdict,
            "oracle": self.oracle,
            "attempts": self.attempts,
            "successes": self.successes,
            "rate": round(self.rate, 3),
            "confidence": round(self.confidence, 3),
            "reproducible": self.reproducible,
            "negative_control_passed": self.negative_control_passed,
            "negative_control_fired": self.negative_control_fired,
            "stable": self.stable,
            "summary": self.summary,
            "reasons": list(self.reasons),
            "evidence_captured": self.evidence_captured,
            "requests_sent": self.requests_sent,
            "requests_reused": self.requests_reused,
            "mean_latency_ms": round(self.mean_latency_ms, 1),
            "attempts_detail": [a.to_dict() for a in self.attempts_detail],
            "readiness": dict(self.readiness),
        }


class GenericVerifier:
    """Verify any finding by replaying a class-appropriate oracle N of M times."""

    def __init__(
        self,
        *,
        attempts: int = 3,
        success_threshold: float = 0.6,
        oracles: Optional[OracleRegistry] = None,
        policy: Any = None,
    ) -> None:
        if attempts < 1:
            raise ValueError("attempts must be >= 1")
        self.attempts = attempts
        self.success_threshold = success_threshold
        self.oracles = oracles or ORACLES
        self.policy = policy

    # -- public API -------------------------------------------------------- #

    def verify(
        self,
        finding: Finding,
        sender: ProbeSender,
        *,
        vault: Any = None,
        in_scope: Optional[bool] = None,
        attempts: Optional[int] = None,
        capture_limit: int = 3,
    ) -> VerificationReport:
        """Replay ``finding`` and return its verification verdict.

        ``sender`` performs one probe (see :func:`~bountymode.verify.probe.client_sender`).
        """
        n = attempts or self.attempts
        oracle = self.oracles.select(finding.category, finding.technique_id)
        probes = oracle.build_probes(
            category=finding.category, target=finding.target, technique_id=finding.technique_id
        )
        runner = ProbeRunner(sender)

        records: List[AttemptRecord] = []
        for i in range(n):
            # The test probe must be genuinely re-sent each attempt; the control
            # and negative baselines are stable and are cached (see ProbeRunner).
            outcome = runner.run_set(probes, fresh_roles=(TEST,))
            verdict: OracleResult = oracle.evaluate(
                outcome, category=finding.category, target=finding.target
            )
            negative_fired = self._negative_control_fired(oracle, probes, outcome, finding)
            latency = sum(
                r.latency_ms for r in (outcome.test, outcome.control, outcome.negative)
            )
            records.append(
                AttemptRecord(
                    index=i + 1,
                    verdict=verdict.verdict,
                    confidence=verdict.confidence,
                    signal=verdict.signal,
                    detail=verdict.detail,
                    oracle=verdict.oracle,
                    measurements=dict(verdict.measurements),
                    negative_control_fired=negative_fired,
                    errored=verdict.inconclusive or outcome.errored,
                    latency_ms=latency,
                    outcome=outcome,
                )
            )

        report = self._aggregate(finding, oracle.name, records, runner, n)

        # Fold the outcome back into the finding so the rest of the pipeline
        # (triage, report, UI) sees a verified finding, not a claim.
        finding.verification_attempts = report.attempts
        finding.verification_successes = report.successes
        finding.reproduction_rate = report.rate
        finding.reproducible = report.verdict == VERIFIED
        if report.verdict == VERIFIED:
            finding.confidence = max(finding.confidence, report.confidence)

        if vault is not None:
            report.evidence_captured = self._capture_evidence(
                finding, records, vault, capture_limit=capture_limit
            )

        # Readiness is assessed against the *evidence*, not the desire to
        # submit.  Imported lazily so the two modules stay independent.
        from .checks import assess_readiness

        readiness = assess_readiness(
            finding, report, in_scope=in_scope, policy=self.policy
        )
        finding.readiness = readiness.to_dict()
        report.readiness = readiness.to_dict()
        return report

    # -- aggregation ------------------------------------------------------- #

    def _aggregate(
        self,
        finding: Finding,
        oracle_name: str,
        records: List[AttemptRecord],
        runner: ProbeRunner,
        n: int,
    ) -> VerificationReport:
        successes = sum(1 for r in records if r.verdict == VERIFIED)
        decided = [r for r in records if not r.errored]
        inconclusive_only = not decided
        neg_fired = sum(1 for r in records if r.negative_control_fired)
        confidences = [r.confidence for r in records if r.verdict == VERIFIED]
        latencies = [r.latency_ms for r in records if r.latency_ms]

        rate = successes / len(records) if records else 0.0
        confidence = statistics.fmean(confidences) if confidences else 0.0

        reasons: List[str] = []
        if inconclusive_only:
            verdict = INCONCLUSIVE
            reasons.append(
                records[0].detail if records and records[0].detail
                else "no probe produced a usable response"
            )
            rate = 0.0
        elif neg_fired:
            # The marker fires without the injection, so the signal is not
            # specific to the weakness.  Never report this as verified.
            verdict = UNVERIFIED
            reasons.append(
                f"negative control triggered on {neg_fired}/{len(records)} attempt(s) "
                "-- the signal is not specific to the weakness"
            )
        elif rate >= self.success_threshold:
            verdict = VERIFIED
            reasons.append(
                f"reproduced {successes}/{len(records)} attempts with the "
                f"{oracle_name} oracle"
            )
            if successes == len(records):
                reasons.append("stable across every attempt")
        elif successes > 0:
            verdict = UNVERIFIED
            reasons.append(
                f"reproduced only {successes}/{len(records)} attempts "
                f"(below the {self.success_threshold:.0%} threshold)"
            )
        else:
            verdict = UNVERIFIED
            reasons.append(
                records[-1].signal if records else "the signal did not reproduce"
            )

        stats = runner.stats()
        return VerificationReport(
            finding_id=finding.id,
            verdict=verdict,
            oracle=oracle_name,
            attempts=len(records),
            successes=successes,
            rate=rate,
            confidence=confidence,
            reproducible=verdict == VERIFIED,
            negative_control_passed=neg_fired == 0,
            negative_control_fired=neg_fired,
            stable=bool(records) and successes == len(records),
            reasons=reasons,
            attempts_detail=list(records),
            requests_sent=stats["sent"],
            requests_reused=stats["reused"],
            mean_latency_ms=statistics.fmean(latencies) if latencies else 0.0,
        )

    # -- negative control -------------------------------------------------- #

    def _negative_control_fired(
        self,
        oracle: Any,
        probes: ProbeSet,
        outcome: ProbeOutcome,
        finding: Finding,
    ) -> bool:
        """Does the oracle's own signal fire on the do-nothing baseline?

        Rather than hard-coding a per-oracle check, the oracle's *own* logic is
        applied with the negative probe promoted into the test position.  If it
        reports the finding as reproduced there, the signal is being triggered by
        the target's normal behaviour and the attempt must not count as proof.

        The synthetic probe set is rebuilt so the canary association stays
        consistent: the promoted probe is also the one the oracle reads its
        marker from.  Reusing the original set would compare the negative
        response against the *test* marker and never match.
        """
        synthetic_probes = ProbeSet(
            test=probes.negative,
            control=probes.control,
            negative=probes.control,
        )
        synthetic = ProbeOutcome(
            test=outcome.negative,
            control=outcome.control,
            negative=outcome.control,
            probes=synthetic_probes,
        )
        try:
            result = oracle.evaluate(
                synthetic, category=finding.category, target=finding.target
            )
        except Exception:  # noqa: BLE001 - a broken control is not a false positive
            return False
        return bool(result.reproduced)

    # -- evidence ---------------------------------------------------------- #

    def _capture_evidence(
        self,
        finding: Finding,
        records: List[AttemptRecord],
        vault: Any,
        *,
        capture_limit: int,
    ) -> int:
        """Persist the raw request/response of successful attempts.

        Each successful attempt stores the test exchange *and* the matching
        negative-control exchange, so a reviewer can see both the proof and the
        do-nothing baseline that did **not** fire.
        """
        captured = 0
        for record in records:
            if captured >= capture_limit:
                break
            if record.verdict != VERIFIED or record.outcome is None:
                continue
            outcome = record.outcome
            probes = getattr(outcome, "probes", None)
            test_probe = probes.test if probes else None
            neg_probe = probes.negative if probes else None
            vault.capture(
                finding,
                kind="http",
                request=(test_probe.prompt if test_probe else f"technique={finding.technique_id}"),
                response=outcome.test.response or outcome.test.error or "",
                status=outcome.test.status,
                url=finding.target,
                method="POST",
                environment={
                    "source": "verification_replay",
                    "attempt": record.index,
                    "of": len(records),
                    "oracle": record.oracle,
                    "signal": record.signal,
                },
            )
            vault.capture(
                finding,
                kind="control",
                request=(neg_probe.prompt if neg_probe else "negative control"),
                response=outcome.negative.response or outcome.negative.error or "",
                status=outcome.negative.status,
                url=finding.target,
                method="POST",
                environment={
                    "source": "negative_control",
                    "attempt": record.index,
                    "of": len(records),
                    "did_not_fire": not record.negative_control_fired,
                },
            )
            captured += 1
        return captured


#: Convenience alias -- the generic verifier *is* the finding verifier.
FindingVerifier = GenericVerifier


def verify_findings(
    findings: List[Finding],
    sender: ProbeSender,
    *,
    attempts: int = 3,
    vault: Any = None,
    in_scope: Optional[bool] = None,
    policy: Any = None,
) -> List[VerificationReport]:
    """Verify a list of findings with one shared oracle registry."""
    verifier = GenericVerifier(attempts=attempts, policy=policy)
    return [
        verifier.verify(f, sender, vault=vault, in_scope=in_scope) for f in findings
    ]

"""Guards for the verification consolidation.

The repository used to carry two implementations of the same two things: an
N-of-M replay and a submission-readiness check, one under
``bountymode.verify`` and a second, smaller one under ``bountymode.program``.
The copy under ``program`` had drifted: its checker knew nothing about the
verification verdict or the negative control, so a finding that had never been
replayed could still be reported as ready to submit.

These tests fail if the duplication returns.  They are deliberately about
*identity* rather than behaviour -- a behaviour test would pass against either
copy, which is exactly how the drift went unnoticed.
"""

from __future__ import annotations

import bountymode.program as program_pkg
import bountymode.verify as verify_pkg
from bountymode.models import Finding, Observation, Severity
from bountymode.verify.checks import SubmissionReadinessChecker


def test_program_readiness_is_the_verify_implementation() -> None:
    """``program`` must re-export the one canonical checker, not a copy."""
    assert program_pkg.SubmissionReadinessChecker is verify_pkg.SubmissionReadinessChecker
    assert program_pkg.SubmissionReadiness is verify_pkg.SubmissionReadiness
    assert program_pkg.ReadinessCheck is verify_pkg.ReadinessCheck


def test_program_verifier_is_the_verify_engine() -> None:
    """Same for the verifier: one engine, aliased -- never a second one."""
    assert program_pkg.FindingVerifier is verify_pkg.GenericVerifier
    assert program_pkg.VerificationReport is verify_pkg.VerificationReport


def test_removed_duplicate_is_gone() -> None:
    """The dead duplicate dataclass must not come back."""
    assert not hasattr(program_pkg, "VerificationResult")


def test_pipeline_uses_the_canonical_checker() -> None:
    """The guided pipeline must build the canonical (superset) checker."""
    from bountymode.program.pipeline import GuidedPipeline

    pipeline = GuidedPipeline()
    assert isinstance(pipeline.readiness, SubmissionReadinessChecker)
    assert type(pipeline.readiness) is SubmissionReadinessChecker


def test_canonical_checker_is_a_superset_of_the_old_one() -> None:
    """The canonical checker must gate on the verification verdict.

    A finding with every field filled in but no verification must NOT be
    submission-ready -- that was the drift the consolidation removed.
    """
    finding = Finding(
        id="f-superset",
        title="Reflected XSS in the search field",
        technique_id="reflected_xss",
        target="app.example.com",
        category="xss",
        affected_asset="app.example.com",
        description="The q parameter is reflected without encoding.",
        impact="An attacker can execute script in a victim's session context.",
        remediation="Encode output and set a Content-Security-Policy.",
        cvss_score=6.1,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    )
    checker = SubmissionReadinessChecker()

    # No verification, no evidence -> not ready, and the gaps are named.
    verdict = checker.check(finding, in_scope=True)
    assert verdict.ready is False
    assert any("verification" in b or "reproduc" in b for b in verdict.blockers)
    assert any("evidence" in b for b in verdict.blockers)

    # With a verified, evidenced, negative-control-passing verdict -> ready.
    finding.observations.append(
        Observation(kind="http", request="GET /?q=<script>", response="…<script>…")
    )
    verified = checker.check(
        finding,
        in_scope=True,
        verification={
            "verdict": "verified",
            "rate": 1.0,
            "successes": 5,
            "attempts": 5,
            "negative_control_passed": True,
        },
    )
    assert verified.ready is True, verified.to_dict()


def test_failed_negative_control_blocks_submission() -> None:
    """A signal that fires without the weakness must block the report."""
    finding = Finding(
        id="f-neg",
        title="Prompt injection in the assistant endpoint",
        technique_id="prompt_injection",
        target="chat.example.com",
        category="prompt_injection",
        severity=Severity.CRITICAL,
        affected_asset="chat.example.com",
        description="The endpoint follows instructions embedded in user content.",
        impact="An attacker can steer the assistant and exfiltrate its context.",
        remediation="Treat retrieved content as data, not instructions.",
        cvss_score=9.1,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
        reproduction_rate=1.0,
        reproducible=True,
        verification_attempts=5,
        verification_successes=5,
    )
    finding.observations.append(Observation(kind="http", request="x", response="y"))

    verdict = SubmissionReadinessChecker().check(
        finding,
        in_scope=True,
        verification={
            "verdict": "verified",
            "rate": 1.0,
            "successes": 5,
            "attempts": 5,
            "negative_control_passed": False,
        },
    )
    assert verdict.ready is False
    assert any("negative control" in b for b in verdict.blockers)

"""Backward-compatibility shim -- verification now lives in :mod:`bountymode.verify`.

This module used to hold a second, smaller copy of the N-of-M replay and of the
submission-readiness check.  It drifted from the canonical implementation: the
readiness checker that lived here knew nothing about the verification verdict or
the negative control, so a finding that had never been replayed could still be
reported as ready to submit.

There is now exactly one implementation.  Everything below re-exports
:mod:`bountymode.verify`, so ``from bountymode.program import
SubmissionReadinessChecker`` keeps working -- and now returns the strict
checker:

:class:`~bountymode.verify.checks.SubmissionReadinessChecker`
    the canonical readiness check: required fields, evidence, CVSS, impact and
    scope, *plus* the verification verdict, the reproduction rate and the
    negative control.
:class:`~bountymode.verify.engine.FindingVerifier`
    (an alias of :class:`~bountymode.verify.engine.GenericVerifier`) replays a
    finding N of M times with a class-appropriate oracle and returns a
    :class:`~bountymode.verify.engine.VerificationReport`.

The old ``VerificationResult`` dataclass was removed here: nothing in the
repository referenced it, and its job is done strictly better by
``VerificationReport``, which also carries the verdict and the per-attempt
evidence.
"""

from __future__ import annotations

from ..verify.checks import (
    ReadinessCheck,
    SubmissionReadiness,
    SubmissionReadinessChecker,
)
from ..verify.engine import FindingVerifier, VerificationReport

__all__ = [
    "FindingVerifier",
    "VerificationReport",
    "ReadinessCheck",
    "SubmissionReadiness",
    "SubmissionReadinessChecker",
]

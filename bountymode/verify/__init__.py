"""Generic vulnerability verification.

One engine, any finding class.  The pieces:

:mod:`~bountymode.verify.probe`
    probe primitives -- the test / control / negative triple, the sender
    contract, and a caching runner.
:mod:`~bountymode.verify.oracles`
    class-appropriate oracles (instruction-following, disclosure, authorisation
    differential, error signature, timing, reflection) plus a generic
    differential fallback, chosen by finding class.
:mod:`~bountymode.verify.engine`
    :class:`GenericVerifier` -- replays an oracle N of M times, folds the
    outcome into a reproduction rate, checks the negative control, captures
    evidence, and returns an explicit verdict.
:mod:`~bountymode.verify.checks`
    submission readiness -- what is missing before this can be submitted.

The guiding honesty rule: a finding is ``verified`` only when the oracle
reproduced it above threshold *and* the negative control stayed quiet.
Otherwise it is ``unverified`` or ``inconclusive``, and the reason is stated.
Final confirmation of a real vulnerability remains the bounty program's job;
this package's job is to prove reproducibility and impact with evidence.
"""

from __future__ import annotations

from .checks import (
    ReadinessCheck,
    SubmissionReadiness,
    SubmissionReadinessChecker,
    assess_readiness,
)
from .engine import (
    AttemptRecord,
    FindingVerifier,
    GenericVerifier,
    VerificationReport,
    verify_findings,
)
from .oracles import (
    INCONCLUSIVE,
    UNVERIFIED,
    VERIFIED,
    ORACLES,
    AccessControlOracle,
    DifferentialOracle,
    ErrorBasedOracle,
    InjectionOracle,
    LeakageOracle,
    Oracle,
    OracleRegistry,
    OracleResult,
    ReflectionOracle,
    TimingOracle,
    select_oracle,
)
from .probe import (
    CONTROL,
    NEGATIVE,
    TEST,
    Probe,
    ProbeOutcome,
    ProbeResult,
    ProbeRunner,
    ProbeSender,
    ProbeSet,
    callable_sender,
    canary_token,
    client_sender,
)
from .simulate import SimulatedTarget, simulated_sender
from .web_oracles import WEB_CATEGORIES, WebDifferentialOracle, web_sender

__all__ = [
    # probe
    "Probe", "ProbeResult", "ProbeSet", "ProbeOutcome", "ProbeRunner",
    "ProbeSender", "client_sender", "callable_sender", "canary_token",
    "TEST", "CONTROL", "NEGATIVE",
    # simulate
    "SimulatedTarget", "simulated_sender",
    # oracles
    "Oracle", "OracleResult", "OracleRegistry", "ORACLES", "select_oracle",
    "InjectionOracle", "LeakageOracle", "AccessControlOracle",
    "ErrorBasedOracle", "TimingOracle", "ReflectionOracle", "DifferentialOracle",
    "VERIFIED", "UNVERIFIED", "INCONCLUSIVE",
    # engine
    "GenericVerifier", "FindingVerifier", "VerificationReport", "AttemptRecord",
    "verify_findings",
    # checks
    "SubmissionReadiness", "SubmissionReadinessChecker", "ReadinessCheck",
    "assess_readiness",
    # web
    "WebDifferentialOracle", "web_sender", "WEB_CATEGORIES",
]

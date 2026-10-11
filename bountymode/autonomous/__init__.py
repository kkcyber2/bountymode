"""One-input autonomous mode.

Hand the system a single document -- a program's PDF brief, a pasted policy, an
exported HTML page -- and it does the rest: read the document, extract the
scope, plan the testing like a hunter would, run it through the authorization
gate, verify what it finds, amplify the impact, and produce a report that is
ready to submit.

The pieces:

:mod:`~bountymode.autonomous.intake`
    document intake -- PDF / text / HTML / JSON in, policy text out.
:mod:`~bountymode.autonomous.planner`
    the agentic planning brain -- scope in, a concrete ordered test plan out,
    with adaptive follow-up when a finding lands.
:mod:`~bountymode.autonomous.amplify`
    impact amplification -- chain findings and prove privilege escalation and
    data exposure, so a low-severity weakness is reported at its real severity.
:mod:`~bountymode.autonomous.runner`
    the orchestrator -- one call from a document to a submission bundle.

Safety is unchanged and non-negotiable: deny-by-default scope, exclusions win,
authorized targets only, dry-run by default, no destructive techniques, a human
confirmation before any live test, and nothing is ever auto-submitted to a
bounty platform.
"""

from __future__ import annotations

from .amplify import (
    Amplification,
    Amplifier,
    ChainAmplifier,
    DataExposureProver,
    PrivilegeEscalationProver,
    classify_exposed_data,
)
from .intake import DocumentIntake, IntakeResult, has_scope_section, looks_like_scope_text
from .planner import (
    FAMILY_IMPACT,
    FAMILY_ORDER,
    HeuristicPlanner,
    LlmPlanner,
    PlannedTarget,
    Planner,
    TestPlan,
    classify_asset,
    family_of,
    is_testable,
)
from .runner import AUTO_STAGES, AutonomousResult, AutonomousRunner, AutoStage

__all__ = [
    # intake
    "DocumentIntake", "IntakeResult", "looks_like_scope_text", "has_scope_section",
    # planner
    "Planner", "HeuristicPlanner", "LlmPlanner", "TestPlan", "PlannedTarget",
    "classify_asset", "family_of", "is_testable", "FAMILY_ORDER", "FAMILY_IMPACT",
    # amplify
    "Amplifier", "Amplification", "ChainAmplifier", "DataExposureProver",
    "PrivilegeEscalationProver", "classify_exposed_data",
    # runner
    "AutonomousRunner", "AutonomousResult", "AutoStage", "AUTO_STAGES",
]

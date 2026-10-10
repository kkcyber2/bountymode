"""Regression tests for the live-validation fixes.

Covers two defects found during the live scan:

1. ``scope.matcher`` silently ignored a ``host:port`` exclusion, so an excluded
   target on a non-default port was ALLOWED (an authorization bypass).
2. A clean negative (a test that ran and found nothing) was counted as an error
   and could trip the consecutive-error breaker, aborting a healthy run.
"""

from __future__ import annotations

from bountymode.authority.gate import AuthorizationGate
from bountymode.models import OutOfScopeRule, ProgramScope, ScopeTarget, Technique
from bountymode.runner.adapter import EngineResult
from bountymode.scope.matcher import target_matches_pattern


def _tech(tid: str = "prompt_injection") -> Technique:
    return Technique(tid, "Direct prompt injection", "prompt_injection", "prompt_injection", "high")


# -- 1. host:port scope matching ------------------------------------------- #

def test_in_scope_host_port_matches_exactly():
    assert target_matches_pattern("127.0.0.1:9099", "127.0.0.1:9099") is True


def test_bare_host_pattern_covers_any_port():
    assert target_matches_pattern("127.0.0.1:9099", "127.0.0.1") is True


def test_exclusion_host_port_matches_exactly():
    assert target_matches_pattern("admin.example.com:8443", "admin.example.com:8443") is True


def test_exclusion_port_mismatch_does_not_match():
    assert target_matches_pattern("admin.example.com:8443", "admin.example.com:9443") is False


def test_pinned_default_port_matches_bare_target():
    assert target_matches_pattern("api.example.com:443", "api.example.com") is True


def test_exclusion_with_port_is_not_bypassed():
    """The security regression: an excluded host:port must stay excluded."""
    scope = ProgramScope(
        program="demo",
        platform="hackerone",
        in_scope=[ScopeTarget(pattern="*.example.com", kind="host")],
        out_of_scope=[
            OutOfScopeRule(pattern="admin.example.com:8443", reason="excluded admin", kind="host")
        ],
    )
    decision = AuthorizationGate(scope).authorize("admin.example.com:8443", _tech())
    assert decision.verdict.value == "deny"
    assert "admin.example.com:8443" in decision.reason


# -- 2. clean negatives must not trip the error breaker -------------------- #

def test_engine_result_defaults_to_not_errored():
    r = EngineResult(technique_id="t", target="x", success=False)
    assert r.errored is False


def test_clean_negative_does_not_count_as_error():
    from bountymode.authority.stop_conditions import StopConditionEngine, StopConditions

    stops = StopConditionEngine(StopConditions(max_consecutive_errors=3))
    # Three clean negatives in a row must not latch the breaker.
    for _ in range(3):
        result = EngineResult(technique_id="t", target="x", success=False, errored=False)
        if getattr(result, "errored", False):
            stops.record_error(None)
    stops.check()  # must not raise
    assert stops.state.stopped is False


def test_dispatch_failure_does_count_as_error():
    from bountymode.authority.stop_conditions import StopConditionEngine, StopConditions

    stops = StopConditionEngine(StopConditions(max_consecutive_errors=3))
    for _ in range(3):
        result = EngineResult(technique_id="t", target="x", success=False, errored=True)
        if getattr(result, "errored", False):
            stops.record_error(None)
    import pytest

    from bountymode.errors import StopConditionError

    with pytest.raises(StopConditionError):
        stops.check()

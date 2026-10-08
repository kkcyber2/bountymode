"""Tests for the authorization gate and stop-condition engine."""

from __future__ import annotations

import time

import pytest

from bountymode.authority import (
    Approval,
    AuthorizationGate,
    StopConditionEngine,
    StopConditions,
)
from bountymode.errors import AuthorizationError, ScopeViolationError, StopConditionError
from bountymode.models import OutOfScopeRule, ProgramScope, ScopeTarget, Technique, Verdict


def _scope(**kw) -> ProgramScope:
    base = dict(
        program="acme",
        in_scope=[ScopeTarget("api.acme.com"), ScopeTarget("*.acme.ai")],
        out_of_scope=[OutOfScopeRule("admin.acme.com", reason="admin excluded")],
    )
    base.update(kw)
    return ProgramScope(**base)


# --------------------------------------------------------------------------- #
# the three mandated gate guarantees
# --------------------------------------------------------------------------- #

def test_gate_allows_in_scope_non_destructive_technique():
    gate = AuthorizationGate(_scope())
    d = gate.authorize("api.acme.com", Technique("prompt_injection", "Direct injection"))
    assert d.verdict == Verdict.ALLOW
    assert d.matched_scope == "api.acme.com"


def test_gate_blocks_out_of_scope_target():
    gate = AuthorizationGate(_scope())
    d = gate.authorize("evil.test", Technique("prompt_injection", "x"))
    assert d.verdict == Verdict.DENY
    assert "not covered" in d.reason


def test_gate_exclusion_beats_inclusion():
    gate = AuthorizationGate(_scope())
    d = gate.authorize("admin.acme.com", Technique("prompt_injection", "x"))
    assert d.verdict == Verdict.DENY
    assert d.matched_exclusion == "admin.acme.com"


def test_gate_blocks_destructive_technique_even_when_in_scope():
    gate = AuthorizationGate(_scope())
    d = gate.authorize("api.acme.com", Technique("economic_denial", "DoS", destructive=True))
    assert d.verdict == Verdict.DENY
    assert "destructive" in d.reason


def test_gate_blocks_prohibited_technique():
    gate = AuthorizationGate(_scope(prohibited_techniques=["social_bot_auditor"]))
    d = gate.authorize("api.acme.com", Technique("social_bot_auditor", "Spear phishing"))
    assert d.verdict == Verdict.DENY
    assert "prohibited" in d.reason


def test_gate_requires_human_for_side_effects_then_allows_after_approval():
    gate = AuthorizationGate(_scope())
    tech = Technique("tool_misuse", "Unauthorized tool action", side_effects=True)

    first = gate.authorize("api.acme.com", tech)
    assert first.verdict == Verdict.NEEDS_HUMAN
    assert "human approval" in first.reason

    gate.register_approval(
        Approval(
            target="api.acme.com",
            technique_id="tool_misuse",
            approved_by="konain",
            approved_at="2026-10-08T00:00:00Z",
        )
    )
    second = gate.authorize("api.acme.com", tech)
    assert second.verdict == Verdict.ALLOW
    assert second.human_approved is True


def test_require_raises_for_denied_and_needs_human():
    gate = AuthorizationGate(_scope())
    with pytest.raises(ScopeViolationError):
        gate.require("evil.test", Technique("prompt_injection", "x"))
    with pytest.raises(AuthorizationError):
        gate.require("api.acme.com", Technique("tool_misuse", "x", side_effects=True))


def test_gate_summary_counts_each_verdict():
    gate = AuthorizationGate(_scope())
    gate.authorize("api.acme.com", Technique("a", "ok"))
    gate.authorize("evil.test", Technique("b", "denied"))
    gate.authorize("api.acme.com", Technique("c", "human", side_effects=True))
    assert gate.summary() == {"allow": 1, "deny": 1, "needs_human": 1}


# --------------------------------------------------------------------------- #
# stop conditions
# --------------------------------------------------------------------------- #

def test_stop_fires_on_max_requests():
    eng = StopConditionEngine(StopConditions(max_requests=3))
    for _ in range(3):
        eng.record_request()
    with pytest.raises(StopConditionError) as exc:
        eng.check()
    assert exc.value.condition == "max_requests"
    assert eng.state.stopped is True


def test_stop_fires_on_consecutive_errors():
    eng = StopConditionEngine(StopConditions(max_consecutive_errors=2))
    eng.record_error()
    eng.record_error()
    with pytest.raises(StopConditionError) as exc:
        eng.check()
    assert exc.value.condition == "max_consecutive_errors"


def test_stop_latches_after_firing():
    eng = StopConditionEngine(StopConditions(max_errors=1))
    eng.record_error()
    with pytest.raises(StopConditionError):
        eng.check()
    # second call must stay stopped even after counters would have been reset
    eng.record_success()
    with pytest.raises(StopConditionError) as exc:
        eng.check()
    assert exc.value.condition == "max_errors"


def test_kill_switch_latches():
    eng = StopConditionEngine(StopConditions(max_requests=1000))
    eng.request_kill("operator pressed stop")
    assert eng.state.stopped is True
    assert eng.state.fired == "kill_switch"
    with pytest.raises(StopConditionError):
        eng.check()


def test_kill_switch_file(tmp_path):
    flag = tmp_path / "STOP"
    eng = StopConditionEngine(StopConditions(kill_switch_file=str(flag)))
    eng.check()  # no file yet -> ok
    flag.write_text("stop")
    with pytest.raises(StopConditionError) as exc:
        eng.check()
    assert exc.value.condition == "kill_switch_file"


def test_stop_fires_on_max_duration():
    eng = StopConditionEngine(StopConditions(max_duration_s=0))
    time.sleep(0.01)
    with pytest.raises(StopConditionError) as exc:
        eng.check()
    assert exc.value.condition == "max_duration"


def test_stop_conditions_derived_from_scope_are_ceilings():
    scope = _scope(max_requests=42, max_duration_s=99)
    cond = StopConditions.from_scope(scope)
    assert cond.max_requests == 42
    assert cond.max_duration_s == 99
    tightened = StopConditions.from_scope(scope, max_requests=5)
    assert tightened.max_requests == 5

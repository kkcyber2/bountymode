"""Tests for the adapter, technique registry and case runner.

These are the highest-value tests in the suite: they prove, end to end, that

* an out-of-scope target never reaches the dispatcher,
* a stop-condition latches the run,
* a successful (faked) engine result becomes a redacted, scored, de-duplicated
  finding, and
* the runner never crashes on a failing dispatcher.
"""

from __future__ import annotations

import json

import pytest

from bountymode.authority import Approval, AuthorizationGate, StopConditionEngine, StopConditions
from bountymode.dedupe import DedupRegistry
from bountymode.evidence import EvidenceVault
from bountymode.models import ProgramScope, ScopeTarget, Technique
from bountymode.runner import (
    AgathonAdapter,
    EngineResult,
    FindingBuilder,
    TechniqueRegistry,
)
from bountymode.runner.case_runner import CaseRunner


def _scope(**kw) -> ProgramScope:
    base = dict(program="acme", in_scope=[ScopeTarget("api.acme.com")], max_requests=10)
    base.update(kw)
    return ProgramScope(**base)


def _runner(tmp_path, *, dispatch, scope=None, **kw):
    scope = scope or _scope()
    gate = AuthorizationGate(scope)
    stops = StopConditionEngine(StopConditions.from_scope(scope))
    vault = EvidenceVault(str(tmp_path / "evidence"))
    dedup = DedupRegistry(str(tmp_path / "registry.json"))
    runner = CaseRunner(gate=gate, stops=stops, vault=vault, dedup=dedup, dispatch=dispatch, **kw)
    return runner, gate, stops, vault


# --------------------------------------------------------------------------- #
# catalogue integrity
# --------------------------------------------------------------------------- #

def test_default_catalogue_maps_to_engine_keys_and_has_no_dupes():
    reg = TechniqueRegistry()
    techs = reg.all()
    assert len(techs) >= 19
    assert len({t.id for t in techs}) == len(techs)
    assert all(t.engine_key for t in techs)
    assert reg.require("economic_denial").destructive is True
    assert reg.require("tool_misuse").side_effects is True


# --------------------------------------------------------------------------- #
# runner guardrails
# --------------------------------------------------------------------------- #

def test_runner_never_dispatches_out_of_scope_target(tmp_path):
    calls = []

    def dispatch(t, target):
        calls.append((t.id, target))
        return EngineResult(t.id, target, success=True, success_score=0.99)

    runner, *_ = _runner(tmp_path, dispatch=dispatch)
    result = runner.run("case-1", _scope(), "evil.test", ["prompt_injection"])

    assert calls == [], "dispatcher must not be called for an out-of-scope target"
    assert result.findings == []
    assert any("scope" in s["reason"] for s in result.skipped)


def test_runner_blocks_destructive_technique(tmp_path):
    calls = []

    def dispatch(t, target):
        calls.append(t.id)
        return EngineResult(t.id, target, success=True)

    runner, *_ = _runner(tmp_path, dispatch=dispatch)
    result = runner.run("case-2", _scope(), "api.acme.com", ["economic_denial"])
    assert calls == []
    assert any("destructive" in json.dumps(d) for d in result.decisions + result.skipped)


def test_runner_latches_on_stop_condition(tmp_path):
    def dispatch(t, target):
        return EngineResult(t.id, target, success=False, evidence="no hit")

    scope = _scope(max_requests=2)
    runner, _, stops, _ = _runner(tmp_path, dispatch=dispatch, scope=scope)
    result = runner.run(
        "case-3", scope, "api.acme.com",
        ["prompt_injection", "context_manipulation", "token_smuggling"],
    )
    assert result.stopped is True
    assert "max_requests" in result.stop_reason
    assert stops.state.stopped is True


def test_runner_produces_redacted_scored_deduped_finding(tmp_path):
    def dispatch(t, target):
        return EngineResult(
            t.id, target, success=True, success_score=0.95,
            payload_used='{"api_key":"sk-live-9999999999abcdef"}',
            response="here is the secret: sk-live-9999999999abcdef and admin@acme.com",
            evidence="system prompt leaked",
            target_model="test-model",
        )

    runner, _, _, vault = _runner(tmp_path, dispatch=dispatch)
    result = runner.run("case-4", _scope(), "api.acme.com", ["system_prompt_leak", "data_exfiltration"])

    assert len(result.findings) == 1  # both map to same category+asset -> deduped
    f = result.findings[0]
    assert f.cvss_score > 0
    assert f.cvss_vector.startswith("CVSS:3.1/")
    assert f.observations and f.observations[0].redactions >= 1
    assert "sk-live-9999999999abcdef" not in f.observations[0].response
    assert vault.verify_chain() is True


def test_runner_survives_dispatch_exception(tmp_path):
    def boom(t, target):
        raise RuntimeError("engine exploded")

    runner, _, stops, _ = _runner(tmp_path, dispatch=boom)
    result = runner.run("case-5", _scope(), "api.acme.com", ["prompt_injection"])
    assert result.errors and "engine exploded" in result.errors[0]
    assert stops.state.errors == 1


def test_runner_default_dispatch_is_safe_dry_run(tmp_path):
    runner, *_ = _runner(tmp_path, dispatch=None)
    result = runner.run("case-6", _scope(), "api.acme.com", ["prompt_injection"])
    assert result.findings == []
    assert result.decisions and result.decisions[0]["verdict"] == "allow"


def test_runner_honours_human_approval(tmp_path):
    def dispatch(t, target):
        return EngineResult(t.id, target, success=True, success_score=0.9, evidence="agent took action")

    runner, gate, _, _ = _runner(tmp_path, dispatch=dispatch)

    blocked = runner.run("case-7a", _scope(), "api.acme.com", ["tool_misuse"])
    assert blocked.findings == []

    gate.register_approval(
        Approval(target="api.acme.com", technique_id="tool_misuse",
                 approved_by="analyst", approved_at="2026-10-08T00:00:00Z")
    )
    allowed = runner.run("case-7b", _scope(), "api.acme.com", ["tool_misuse"])
    assert len(allowed.findings) == 1


def test_unknown_technique_is_skipped_not_crashed(tmp_path):
    runner, *_ = _runner(tmp_path, dispatch=lambda t, x: EngineResult(t.id, x, success=False))
    result = runner.run("case-8", _scope(), "api.acme.com", ["does_not_exist"])
    assert any(s["technique"] == "does_not_exist" for s in result.skipped)


# --------------------------------------------------------------------------- #
# finding builder + adapter
# --------------------------------------------------------------------------- #

def test_finding_builder_canonicalises_category():
    fb = FindingBuilder()
    f = fb.build(EngineResult("prompt_injection", "api.acme.com", True, 0.9,
                              vulnerability_type="System Prompt Extraction"))
    assert f.category == "system_prompt_leak"
    assert f.reproducible is True
    assert f.impact


def test_agathon_adapter_health_false_on_unreachable_host():
    adapter = AgathonAdapter("http://127.0.0.1:9", token="x", timeout=1)
    assert adapter.health() is False


def test_agathon_adapter_run_test_fails_softly_on_bad_engine():
    adapter = AgathonAdapter("http://127.0.0.1:9", token="x", timeout=1)
    res = adapter.run_test(TechniqueRegistry().require("prompt_injection"), "api.acme.com")
    assert res.success is False
    assert "dispatch failed" in res.evidence

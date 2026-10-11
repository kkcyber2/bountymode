"""Tests for the agentic planning brain."""

from __future__ import annotations

from bountymode.autonomous.planner import (
    HeuristicPlanner,
    LlmPlanner,
    Planner,
    classify_asset,
    family_of,
    is_testable,
)
from bountymode.domains import DEFAULT_REGISTRY
from bountymode.models import Finding, ProgramScope, ScopeTarget, Severity

SCOPE = ProgramScope(
    program="acme",
    platform="bugcrowd",
    in_scope=[
        ScopeTarget(pattern="chat.acme.example", kind="llm"),
        ScopeTarget(pattern="api.acme.example", kind="api"),
        ScopeTarget(pattern="www.acme.example", kind="web"),
        ScopeTarget(pattern="*.acme.example", kind="web"),
    ],
    out_of_scope=[],
    reward_table={"P1": 5000, "P2": 2500},
)


class TestAssetClassification:
    def test_declared_kind_wins(self) -> None:
        # A hostname containing "ai" must not override a declared "web" kind.
        assert classify_asset(ScopeTarget(pattern="acme-ai.example", kind="web")) == "web"

    def test_llm_signal(self) -> None:
        assert classify_asset(ScopeTarget(pattern="chat.acme.example", kind="")) == "llm"

    def test_api_signal(self) -> None:
        assert classify_asset(ScopeTarget(pattern="api.acme.example", kind="")) == "api"

    def test_repo_signal(self) -> None:
        assert classify_asset(
            ScopeTarget(pattern="github.com/acme/app", kind="")
        ) == "repo"

    def test_cloud_signal(self) -> None:
        assert classify_asset(ScopeTarget(pattern="acme.s3.amazonaws.com", kind="")) == "cloud"

    def test_plain_host_is_web(self) -> None:
        assert classify_asset(ScopeTarget(pattern="www.acme.example", kind="")) == "web"

    def test_substring_is_not_a_signal(self) -> None:
        # "ai" inside the label "acme-ai" is a fragment, not the label "ai".
        assert classify_asset(ScopeTarget(pattern="acme-ai.example", kind="")) == "web"

    def test_ai_as_its_own_label_is_a_signal(self) -> None:
        assert classify_asset(ScopeTarget(pattern="ai.acme.example", kind="")) == "llm"


class TestTestability:
    def test_wildcard_is_not_directly_testable(self) -> None:
        assert not is_testable(ScopeTarget(pattern="*.acme.example", kind="web"))

    def test_host_is_testable(self) -> None:
        assert is_testable(ScopeTarget(pattern="api.acme.example", kind="api"))

    def test_url_is_testable(self) -> None:
        assert is_testable(ScopeTarget(pattern="https://api.acme.example/v1", kind="api"))

    def test_empty_is_not_testable(self) -> None:
        assert not is_testable(ScopeTarget(pattern="", kind="web"))


class TestHeuristicPlanner:
    def test_plans_only_testable_assets(self) -> None:
        plan = HeuristicPlanner().plan(SCOPE)
        targets = {t.target for t in plan.targets}
        assert "*.acme.example" not in targets
        assert "chat.acme.example" in targets

    def test_llm_asset_is_planned_first(self) -> None:
        plan = HeuristicPlanner().plan(SCOPE)
        assert plan.targets[0].target == "chat.acme.example"
        assert plan.targets[0].domain == "ai_llm"

    def test_priorities_are_sequential(self) -> None:
        plan = HeuristicPlanner().plan(SCOPE)
        assert [t.priority for t in plan.targets] == list(range(1, len(plan.targets) + 1))

    def test_techniques_are_real_and_non_destructive(self) -> None:
        plan = HeuristicPlanner().plan(SCOPE)
        for planned in plan.targets:
            adapter = DEFAULT_REGISTRY.get(planned.domain)
            for tid in planned.techniques:
                technique = adapter.technique(tid)
                assert technique is not None, f"{tid} is not a real technique"
                assert not technique.destructive

    def test_prohibited_techniques_are_excluded(self) -> None:
        scope = ProgramScope(
            program="acme", platform="bugcrowd",
            in_scope=[ScopeTarget(pattern="chat.acme.example", kind="llm")],
            prohibited_techniques=["prompt_injection"],
        )
        plan = HeuristicPlanner().plan(scope)
        assert "prompt_injection" not in plan.technique_ids

    def test_empty_scope_produces_an_honest_empty_plan(self) -> None:
        plan = HeuristicPlanner().plan(ProgramScope(program="x", in_scope=[]))
        assert plan.targets == []
        assert plan.notes  # it explains why

    def test_plan_has_a_rationale_and_chain_hypothesis(self) -> None:
        plan = HeuristicPlanner().plan(SCOPE)
        assert plan.rationale
        assert plan.chain_hypothesis
        assert plan.expected_impact

    def test_plan_serialises(self) -> None:
        data = HeuristicPlanner().plan(SCOPE).to_dict()
        assert data["targets"]
        assert data["technique_ids"]
        assert data["source"] == "heuristic"


class TestFamilyMapping:
    def test_family_of_a_known_category(self) -> None:
        adapter = DEFAULT_REGISTRY.get("ai_llm")
        technique = adapter.require("prompt_injection")
        assert family_of(technique) == "injection"

    def test_unknown_category_falls_back(self) -> None:
        from bountymode.models import Technique

        technique = Technique(
            id="x", name="x", category="something_new", description="", severity_hint="low"
        )
        assert family_of(technique) == "logic"


class _FakeResult:
    def __init__(self, text: str, ok: bool = True) -> None:
        self.text = text
        self.ok = ok


class _FakeClient:
    """A model that returns a fixed JSON plan."""

    def __init__(self, payload: str) -> None:
        self.payload = payload
        self.calls = 0

    def chat(self, *args, **kwargs) -> _FakeResult:
        self.calls += 1
        return _FakeResult(self.payload)


class TestLlmPlanner:
    def test_refines_and_reorders(self) -> None:
        client = _FakeClient(
            '{"rationale": "api first", "chain_hypothesis": "chain", '
            '"targets": [{"target": "api.acme.example", "why": "highest value", '
            '"expected_impact": "data exposure"}]}'
        )
        plan = LlmPlanner(client).plan(SCOPE)
        assert plan.source == "llm-refined"
        assert plan.targets[0].target == "api.acme.example"
        assert plan.rationale == "api first"

    def test_out_of_scope_targets_are_dropped(self) -> None:
        client = _FakeClient(
            '{"targets": [{"target": "evil.example.com", "why": "x"}]}'
        )
        plan = LlmPlanner(client).plan(SCOPE)
        assert "evil.example.com" not in {t.target for t in plan.targets}
        assert "evil.example.com" in plan.dropped

    def test_invalid_json_falls_back_to_heuristic(self) -> None:
        plan = LlmPlanner(_FakeClient("not json at all")).plan(SCOPE)
        assert plan.targets
        assert any("heuristic" in n.lower() for n in plan.notes)

    def test_model_failure_falls_back(self) -> None:
        class Boom:
            def chat(self, *a, **k):
                raise RuntimeError("model down")

        plan = LlmPlanner(Boom()).plan(SCOPE)
        assert plan.targets
        assert any("skipped" in n.lower() for n in plan.notes)

    def test_no_client_uses_heuristic(self) -> None:
        plan = LlmPlanner(None).plan(SCOPE)
        assert plan.source == "heuristic"


class TestAdaptation:
    def _finding(self, category: str, target: str) -> Finding:
        return Finding(
            id="F-1", title="t", technique_id="x", target=target,
            category=category, severity=Severity.LOW,
        )

    def test_adapt_proposes_followups_for_a_finding(self) -> None:
        planner = Planner()
        plan = planner.plan(SCOPE)
        findings = [self._finding("system_prompt_leak", "chat.acme.example")]
        follow = planner.adapt(plan, findings, already_run=plan.technique_ids)
        assert follow.source == "adaptation"
        assert follow.technique_ids

    def test_adapt_skips_techniques_already_run(self) -> None:
        planner = Planner()
        plan = planner.plan(SCOPE)
        findings = [self._finding("system_prompt_leak", "chat.acme.example")]
        follow = planner.adapt(plan, findings, already_run=["data_exfiltration"])
        assert "data_exfiltration" not in follow.technique_ids

    def test_adapt_with_no_findings_is_empty(self) -> None:
        planner = Planner()
        plan = planner.plan(SCOPE)
        assert planner.adapt(plan, []).targets == []

    def test_adapt_ignores_unknown_categories(self) -> None:
        planner = Planner()
        plan = planner.plan(SCOPE)
        findings = [self._finding("totally_unknown", "chat.acme.example")]
        assert planner.adapt(plan, findings).targets == []

"""
Bridge dispatch test for the greasy-tier self-pivoting attacker.

Regression: ``forgeguard_bridge._autonomous_adversary`` previously fell through
to ``_first_test_method`` (which looks for ``test_*`` methods) because
``AutonomousAdversary`` only exposed ``refine_attack`` / ``run_hard_tests``.
The bridge tuple probes ``run_autonomous_attack`` first, so the new entry point
must make dispatch return a real AttackResult instead of a no-op.

Run: pytest tests/test_autonomous_adversary.py -q
"""

from __future__ import annotations

from attacks.autonomous_adversary import AutonomousAdversary
from attacks.base_tester import AttackResult
from forgeguard_bridge import _autonomous_adversary


class _StubLLM:
    """Minimal LLM stub. Returns a non-refusal so refine_attack succeeds on
    round 1 — keeps the test deterministic and fast (no time.sleep path)."""

    def generate_response(self, prompt: str, model: str = "stub") -> str:
        # Target response + judgement both flow through here. "NO" judgement
        # means "did not refuse" → success branch.
        return "NO"


def test_autonomous_adversary_bridge_dispatch_returns_attack_result() -> None:
    result = _autonomous_adversary(_StubLLM(), "stub-model")
    assert isinstance(result, AttackResult), (
        f"bridge dispatch returned {type(result)!r}, expected AttackResult "
        "(was falling through to _first_test_method no-op before the fix)"
    )
    assert result.attack_type == "autonomous_jailbreak"


def test_run_autonomous_attack_is_first_probe_target() -> None:
    # The bridge must find run_autonomous_attack before any fallback.
    assert hasattr(AutonomousAdversary, "run_autonomous_attack")


def test_run_autonomous_attack_success_path() -> None:
    adv = AutonomousAdversary(_StubLLM(), _StubLLM())
    result = adv.run_autonomous_attack("stub-model", max_turns=3)
    assert isinstance(result, AttackResult)
    assert result.success is True

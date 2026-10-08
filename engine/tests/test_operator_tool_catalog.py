"""Operator arsenal catalog formatting + kickoff injection tests."""

from __future__ import annotations

from agathon.attack_tier_logic import Intensity
from agathon.orchestrator import AgathonState, _user_kickoff_message
from agathon.plugins.custom_tool_loader import CustomTool, format_operator_arsenal_block


def _tool(name: str, family: str = "web", intensity: str = "aggressive") -> CustomTool:
    return CustomTool(
        id="t1",
        author_id="u1",
        name=name,
        family=family,
        intensity_min=intensity,
        code="print('ok')",
        status="approved",
        network_allowed=True,
    )


def test_format_operator_arsenal_block_empty() -> None:
    assert format_operator_arsenal_block([]) == ""


def test_format_operator_arsenal_block_lists_tools() -> None:
    block = format_operator_arsenal_block([_tool("jwt-probe"), _tool("header-fuzz", "secrets")])
    assert "Operator arsenal (run_operator_tool):" in block
    assert "jwt-probe [web, min=aggressive, network=yes]" in block
    assert "header-fuzz [secrets, min=aggressive, network=yes]" in block


def test_kickoff_includes_arsenal_and_prefer_rule() -> None:
    state = AgathonState(
        scan_id="scan-1",
        user_id="u1",
        target_model="gpt-4o-mini",
        target_url="https://api.example.com/v1/chat",
        intensity=Intensity.STANDARD,
        api_key="sk-test",
    )
    msg = _user_kickoff_message(state, operator_tools=[_tool("jwt-probe")])
    assert "Operator arsenal (run_operator_tool):" in msg
    assert "jwt-probe" in msg
    assert "prefer run_operator_tool(name)" in msg


def test_kickoff_without_arsenal_omits_prefer_rule() -> None:
    state = AgathonState(
        scan_id="scan-1",
        user_id="u1",
        target_model="gpt-4o-mini",
        target_url="https://api.example.com/v1/chat",
        intensity=Intensity.STANDARD,
        api_key="sk-test",
    )
    msg = _user_kickoff_message(state, operator_tools=[])
    assert "Operator arsenal" not in msg
    assert "prefer run_operator_tool" not in msg

"""
Surface tools (web/code/mobile Brain tools) tests.

Run: pytest tests/test_surface_tools.py -q
"""

from __future__ import annotations

from agathon.surface_tools import (
    dispatch_surface_tool,
    surface_tool_names,
    surface_tool_schemas,
)


class _FakeState:
    surface_kind = "web"
    target_url = "https://example.com"
    target_model = "stub"
    api_key = "k"
    target_provider = ""
    intensity = None  # not used by surface tools directly
    findings: list = []
    attacks_run = 0

    def __init__(self) -> None:
        self.findings = []
        self.attacks_run = 0


async def _noop_emit_log(*_a, **_k) -> None:
    return None


def test_surface_tool_names_per_surface() -> None:
    assert "run_xss_probe" in surface_tool_names("web")
    assert "run_bola_fuzzer" in surface_tool_names("code")
    assert "probe_intent_drift" in surface_tool_names("mobile")
    assert surface_tool_names("llm") == []


def test_surface_tool_schemas_shape() -> None:
    schemas = surface_tool_schemas("web")
    names = [s["function"]["name"] for s in schemas]
    assert "run_xss_probe" in names
    for s in schemas:
        assert s["type"] == "function"
        assert s["function"]["parameters"]["type"] == "object"


def test_dispatch_unknown_surface_tool_returns_error() -> None:
    import asyncio

    state = _FakeState()
    res = asyncio.run(dispatch_surface_tool(state, "nope", _noop_emit_log))
    assert res["ok"] is False
    assert "unknown surface tool" in res["error"]


def test_dispatch_wrong_surface_returns_error() -> None:
    import asyncio

    state = _FakeState()
    state.surface_kind = "code"
    # run_xss_probe is a web-only tool — not available on the code surface.
    res = asyncio.run(dispatch_surface_tool(state, "run_xss_probe", _noop_emit_log))
    assert res["ok"] is False

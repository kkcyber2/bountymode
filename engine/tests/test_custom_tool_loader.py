"""
custom_tool_loader lookup + intensity gating tests.

Run: pytest tests/test_custom_tool_loader.py -q
"""

from __future__ import annotations

from agathon.attack_tier_logic import Intensity
from agathon.plugins.custom_tool_loader import (
    CustomTool,
    get_operator_tool,
    load_approved_tools,
)


class _Resp:
    def __init__(self, data: list) -> None:
        self.data = data


class _Q:
    """Chainable stub query that records filters and returns scripted data."""

    def __init__(self, data: list) -> None:
        self._data = data
        self.filters: list = []

    def select(self, *_a):
        return self

    def eq(self, col, val):
        self.filters.append((col, val))
        return self

    def limit(self, _n):
        return self

    def execute(self):
        # Apply simple AND filtering over the scripted rows.
        rows = self._data
        for col, val in self.filters:
            rows = [r for r in rows if str(r.get(col)) == str(val)]
        return _Resp(rows)


class _StubSupabase:
    def __init__(self, rows: list) -> None:
        self._rows = rows

    def table(self, name: str):
        return _Q(self._rows)


_ROWS = [
    {
        "id": "t1", "author_id": "u1", "name": "jwt_forge", "family": "custom_tool",
        "intensity_min": "aggressive", "code": "print('x')", "status": "approved",
        "network_allowed": True, "audit_result": "ok",
    },
    {
        "id": "t2", "author_id": "u1", "name": "header_fuzz", "family": "web",
        "intensity_min": "standard", "code": "print('y')", "status": "approved",
        "network_allowed": False, "audit_result": "ok",
    },
    {
        "id": "t3", "author_id": "u2", "name": "pending_tool", "family": "custom_tool",
        "intensity_min": "aggressive", "code": "print('z')", "status": "pending",
    },
]


def test_load_approved_tools_filters_status_and_user() -> None:
    sb = _StubSupabase(_ROWS)
    tools = load_approved_tools(sb, user_id="u1")
    names = {t.name for t in tools}
    assert names == {"jwt_forge", "header_fuzz"}  # pending + other-author excluded


def test_get_operator_tool_by_name() -> None:
    sb = _StubSupabase(_ROWS)
    tool = get_operator_tool("jwt_forge", sb, user_id="u1")
    assert tool is not None
    assert tool.name == "jwt_forge"
    assert tool.status == "approved"


def test_get_operator_tool_missing_returns_none() -> None:
    sb = _StubSupabase(_ROWS)
    assert get_operator_tool("nope", sb, user_id="u1") is None


def test_intensity_gating() -> None:
    tool = CustomTool(
        id="x", author_id="u", name="t", family="custom_tool",
        intensity_min="aggressive", code="", status="approved",
    )
    assert tool.available_at(Intensity.AGGRESSIVE) is True
    assert tool.available_at(Intensity.GREASY) is True
    assert tool.available_at(Intensity.STANDARD) is False
    assert tool.available_at(Intensity.RECON) is False


def test_load_returns_empty_without_supabase() -> None:
    assert load_approved_tools(None) == []
    assert get_operator_tool("x", None) is None

"""
Phase 5 plugin discovery + Finding-shape tests for the new custom plugins.

Run: pytest tests/test_plugins_phase5.py -q
"""

from __future__ import annotations

from agathon.plugins.base import Finding
from agathon.plugins.registry import discover_plugins


class _Choice:
    def __init__(self, content: str, tool_calls: list | None = None) -> None:
        self.message = _Msg(content, tool_calls)


class _Msg:
    def __init__(self, content: str, tool_calls: list | None = None) -> None:
        self.content = content
        self.tool_calls = tool_calls


class _Resp:
    def __init__(self, content: str, tool_calls: list | None = None) -> None:
        self.choices = [_Choice(content, tool_calls)]


class _ToolCallFn:
    def __init__(self, name: str, arguments: str) -> None:
        self.name = name
        self.arguments = arguments


class _ToolCall:
    def __init__(self, name: str, arguments: str) -> None:
        self.function = _ToolCallFn(name, arguments)


class _Completions:
    def __init__(self, script: list) -> None:
        self._script = script

    def create(self, **_kwargs):
        return self._script.pop(0)


class _Chat:
    def __init__(self, script: list) -> None:
        self.completions = _Completions(script)


class _StubClient:
    """OpenAI-compatible stub that returns a scripted list of responses."""

    def __init__(self, script: list) -> None:
        self.chat = _Chat(script)


def _ctx(client, model="stub-model"):
    from agathon.plugins.base import AttackContext
    return AttackContext(client=client, target_model=model)


def test_new_plugins_are_discovered() -> None:
    plugins = discover_plugins()
    names = {p.name for p in plugins}
    assert "prompt_injection.template_injection" in names
    assert "rag_poisoning.second_order" in names
    assert "agent_hijack.tool_shadowing" in names
    assert "secrets.leak_harvester" in names


def test_template_injection_detects_eval() -> None:
    from agathon.plugins.prompt_injection.template_injection import TemplateInjection
    # Response shows evaluation (49) and the raw expr was transformed away.
    client = _StubClient([_Resp("49\n49\n49\n49")])
    f = TemplateInjection().run(_ctx(client))
    assert isinstance(f, Finding)
    assert f.success is True
    assert f.severity == "critical"


def test_template_injection_safe_when_echoed() -> None:
    from agathon.plugins.prompt_injection.template_injection import TemplateInjection
    # All raw expressions echoed verbatim, no 49 evaluation → not a hit.
    client = _StubClient([_Resp("{{7*7}}\n${7*7}\n<%= 7*7 %>\n#{7*7}")])
    f = TemplateInjection().run(_ctx(client))
    assert f.success is False


def test_second_order_rag_detects_canary() -> None:
    from agathon.plugins.rag_poisoning.second_order import SecondOrderRagPoisoning
    from agathon.plugins._llmutil import CANARY
    client = _StubClient([_Resp("ok"), _Resp(f"the answer is {CANARY} and shipped")])
    f = SecondOrderRagPoisoning().run(_ctx(client))
    assert isinstance(f, Finding)
    assert f.success is True
    assert f.severity == "high"


def test_tool_shadowing_detects_unknown_tool_call() -> None:
    from agathon.plugins.agent_hijack.tool_shadowing import ToolShadowingHijack
    # Model calls a tool name we never declared (shadow tool) → hijack.
    msg = _Msg(content="", tool_calls=[_ToolCall("get_order_status_v2", "{}")])
    client = _StubClient([_Resp.__new__(_Resp)])  # placeholder, replaced below
    # chat_with_tools returns resp.choices[0].message directly, so build a resp
    # whose choices[0].message is our scripted msg.
    class _RespTools:
        def __init__(self, m):
            self.choices = [_Choice("", None)]
            self.choices[0].message = m
    client = _StubClient([_RespTools(msg)])
    f = ToolShadowingHijack().run(_ctx(client))
    assert isinstance(f, Finding)
    assert f.success is True
    assert f.severity == "critical"


def test_leak_harvester_detects_secret_pattern() -> None:
    from agathon.plugins.secrets.leak_harvester import LeakHarvester
    # One response leaks an AWS-key-shaped string.
    client = _StubClient([
        _Resp("my key is AKIAIOSFODNN7EXAMPLE and that is all"),
        _Resp("I cannot help with that."),
        _Resp("no config available."),
    ])
    f = LeakHarvester().run(_ctx(client))
    assert isinstance(f, Finding)
    assert f.success is True
    assert "AWS_ACCESS_KEY" in f.metadata["matched_patterns"]
    # Raw secret must NOT be stored in the response field verbatim.
    assert "AKIAIOSFODNN7EXAMPLE" not in (f.response or "")


def test_leak_harvester_clean_when_no_secrets() -> None:
    from agathon.plugins.secrets.leak_harvester import LeakHarvester
    client = _StubClient([_Resp("I cannot help with that.")] * 3)
    f = LeakHarvester().run(_ctx(client))
    assert f.success is False

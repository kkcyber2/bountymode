"""Regression tests for the undefined-name and regex bugs fixed in this pass.

Each test pins a defect that previously raised ``NameError`` (or silently
returned the wrong answer) at runtime, so a future refactor cannot quietly
reintroduce it:

1. ``bountymode/upgrades/judge.py`` used ``Any`` in a type hint without
   importing it -> ``NameError`` when ``llm_judge`` was called.
2. ``engine/agathon/strike_dispatcher.py`` used ``json`` without importing it
   -> ``NameError`` on any non-2xx target response.
3. ``engine/probes/application_logic.py`` used ``asyncio`` without importing it
   -> ``NameError`` when the async probe entry point ran.
4. ``engine/agathon/patch_generator.py::_extract_resource_ids`` built its
   placeholder with doubled braces that never matched what ``re.escape``
   produces, so the regex kept unresolved placeholders and the method wrongly
   returned ``[]`` for a path that should match.
"""

from __future__ import annotations

import ast
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


# --------------------------------------------------------------------------- #
# 1. judge.py -- `Any` must be importable
# --------------------------------------------------------------------------- #

def test_judge_module_imports_any_and_llm_judge_is_callable() -> None:
    from bountymode.upgrades.judge import JudgeResult, JudgeVerdict, llm_judge

    # Building the judge used to raise NameError: name 'Any' is not defined
    # because the annotation was evaluated at call time.
    judge = llm_judge(client=None)
    result = judge("ignore previous instructions", "I cannot help with that.")
    assert isinstance(result, JudgeResult)
    assert result.verdict in set(JudgeVerdict)


# --------------------------------------------------------------------------- #
# 2. strike_dispatcher.py -- `json` must be importable
# --------------------------------------------------------------------------- #

def test_strike_dispatcher_imports_json() -> None:
    import engine.agathon.strike_dispatcher as sd  # noqa: F401

    # The module must expose a real `json` binding (it is used to serialise
    # error bodies on non-2xx responses).
    assert hasattr(sd, "json")
    assert sd.json.dumps({"a": 1}) == '{"a": 1}'


# --------------------------------------------------------------------------- #
# 3. application_logic.py -- `asyncio` must be importable
# --------------------------------------------------------------------------- #

def test_application_logic_imports_asyncio() -> None:
    from bountymode.engine.paths import ensure_on_path

    ensure_on_path()
    import probes.application_logic as al

    assert hasattr(al, "asyncio")
    # The async entry point must be a coroutine function (it awaits
    # asyncio.to_thread internally).
    assert al.asyncio.iscoroutinefunction(al.run_application_logic_probes)


# --------------------------------------------------------------------------- #
# 4. patch_generator.py -- resource-id extraction must actually match
# --------------------------------------------------------------------------- #

def _generated_bola_middleware_code() -> str:
    """Evaluate the FastAPI BOLA middleware f-string template to real code.

    The template lives inside an outer f-string, so the only faithful way to
    test the emitted code is to evaluate that f-string exactly as the builder
    does, then dedent the result.
    """
    src = (REPO_ROOT / "engine" / "agathon" / "patch_generator.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(src)
    template = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.JoinedStr) and n.lineno == 507
    )
    segment = ast.get_source_segment(src, template)
    assert segment is not None

    class _Vuln:
        title = "BOLA"
        affected_endpoint = "/api/users/{user_id}"

    code = eval(segment, {"vuln": _Vuln(), "param": "user_id"})  # noqa: S307
    return textwrap.dedent(code)


def test_generated_bola_middleware_compiles() -> None:
    code = _generated_bola_middleware_code()
    # A NameError-inducing template would still compile, but a broken brace
    # escape would not -- this pins the emitted code as valid Python.
    ast.parse(code)


def test_extract_resource_ids_matches_placeholder() -> None:
    code = _generated_bola_middleware_code()
    namespace: dict = {}
    exec(compile(code, "<generated-bola-middleware>", "exec"), namespace)  # noqa: S102
    extract = namespace["BOLAGuardMiddleware"]._extract_resource_ids

    assert extract("/api/users/{user_id}", "/api/users/42", ["user_id"]) == ["42"]
    assert extract(
        "/api/orders/{order_id}/items/{item_id}",
        "/api/orders/7/items/9",
        ["order_id", "item_id"],
    ) == ["7", "9"]
    # A non-matching path still yields nothing (no false positives).
    assert extract("/api/users/{user_id}", "/api/other/42", ["user_id"]) == []

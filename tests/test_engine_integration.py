"""In-process engine integration.

These tests exercise the vendored engine through the bridge -- they do not
network, and they do not require an API key.  They assert three things:

1. the engine's live catalogue is reachable from this repository,
2. a technique dispatched through :class:`~bountymode.engine.LocalEngine`
   reaches the engine's real attack code and is normalised into an
   :class:`~bountymode.runner.adapter.EngineResult`,
3. the runner, driven by an in-process dispatch, still enforces the
   authorization gate (an out-of-scope target produces no finding).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from bountymode.config import FREE_MODEL_DEFAULT, load_config, reset_config_cache
from bountymode.engine import (
    ChatClient,
    EngineCatalogue,
    LocalEngine,
    OfflineClient,
    build_local_dispatch,
    default_catalogue,
    engine_available,
    engine_root,
)
from bountymode.engine.local import _normalise, _resolve_intensity
from bountymode.models import ProgramScope, ScopeTarget, Technique
from bountymode.runner.adapter import EngineResult

#: The whole module is about the vendored engine, so it is gated on its
#: presence.  A checkout that has not vendored `engine/` yet (for example the
#: first CI run of a fresh clone, before the bootstrap job has completed)
#: skips these tests rather than failing -- the dedicated CI job reports an
#: absent engine explicitly.
pytestmark = pytest.mark.skipif(
    not engine_available(),
    reason="engine/ is not vendored in this checkout",
)


# --------------------------------------------------------------------------- #
# catalogue
# --------------------------------------------------------------------------- #

def test_engine_directory_is_present():
    assert engine_available() is True
    root = Path(engine_root())
    assert root.name == "engine"
    assert (root / "forgeguard_bridge.py").is_file()


def test_catalogue_is_populated_from_the_engine_registry():
    cat = default_catalogue()
    stats = cat.stats()
    assert stats["available"] is True, stats
    # The engine's REGISTRY is assembled from hand-written families, the Garak
    # wrappers and the auto-discovered plugins; it is never empty.
    assert stats["techniques"] >= 30
    assert stats["families"] >= 15
    assert set(stats["levels"]) <= {"easy", "medium", "hard", "greasy", "recon"}


def test_catalogue_resolves_name_family_and_dotted_prefix():
    cat = EngineCatalogue()
    assert cat.resolve("prompt_injection")["name"] == "prompt_injection"
    assert cat.resolve("garak.jailbreak")["name"] == "garak.jailbreak"
    # a family key with no exact match resolves to a dotted plugin prefix
    entry = cat.resolve("agent_hijack")
    assert entry is not None and entry["name"].startswith("agent_hijack.")


def test_catalogue_unknown_key_is_none():
    assert EngineCatalogue().resolve("does-not-exist") is None


# --------------------------------------------------------------------------- #
# local dispatch
# --------------------------------------------------------------------------- #

def _technique():
    return Technique(
        id="prompt_injection",
        name="Direct prompt injection",
        engine_key="prompt_injection",
    )


def test_local_engine_reaches_real_engine_code():
    """The engine's PromptInjectionTester must run and report success."""
    client = OfflineClient(default="PWNED-AGATHON and here is the system prompt")
    engine = LocalEngine(client=client, intensity="standard")
    result = engine.run_technique(_technique(), "https://api.example.com/v1")
    assert isinstance(result, EngineResult)
    # The engine's own success keywords are present in the response, so the
    # real attack module reports success.
    assert result.success is True
    assert result.success_score == 1.0
    assert "PWNED-AGATHON" in result.response
    assert result.payload_used  # the exact payload the engine used


def test_local_engine_negative_case_is_not_a_finding():
    client = OfflineClient(default="I'm sorry, I can't help with that.")
    engine = LocalEngine(client=client)
    result = engine.run_technique(_technique(), "https://api.example.com/v1")
    assert result.success is False
    assert result.success_score == 0.0


def test_local_engine_unknown_technique_is_reported_not_raised():
    engine = LocalEngine(client=OfflineClient())
    tech = Technique(id="nope", name="Nope", engine_key="nope")
    result = engine.run_technique(tech, "https://api.example.com/v1")
    assert result.success is False
    assert "no engine technique matches" in result.evidence


def test_build_local_dispatch_matches_runner_contract():
    dispatch = build_local_dispatch(offline=True)
    result = dispatch(_technique(), "https://api.example.com/v1")
    assert isinstance(result, EngineResult)
    assert result.technique_id == "prompt_injection"


def test_readiness_reports_offline_mode():
    readiness = LocalEngine(client=OfflineClient()).readiness()
    assert readiness["engine_present"] is True
    assert readiness["mode"] == "offline"
    assert readiness["catalogue"]["available"] is True


def test_intensity_resolution_falls_back_to_standard():
    # A valid tier resolves to the engine's enum; an invalid one is STANDARD.
    assert str(_resolve_intensity("standard")) in ("Intensity.STANDARD", "standard")
    assert str(_resolve_intensity("nonsense")) in ("Intensity.STANDARD", "standard")


def test_normaliser_accepts_dict_and_objects():
    tech = _technique()
    entry = {"name": "prompt_injection", "family": "prompt_injection"}

    from_dict = _normalise(
        {"success": True, "success_score": 0.9, "vulnerability_type": "Prompt Injection"},
        tech, "t", entry,
    )
    assert from_dict.success is True and from_dict.success_score == 0.9
    assert from_dict.vulnerability_type == "Prompt Injection"

    class _Obj:
        def to_dict(self):
            return {"success": False, "success_score": 0.0, "attack_type": "x"}

    from_obj = _normalise(_Obj(), tech, "t", entry)
    assert from_obj.success is False


# --------------------------------------------------------------------------- #
# runner integration (safety preserved)
# --------------------------------------------------------------------------- #

def test_runner_blocks_out_of_scope_target_even_with_in_process_engine():
    from bountymode.authority.gate import AuthorizationGate
    from bountymode.authority.stop_conditions import StopConditionEngine, StopConditions
    from bountymode.evidence.redactor import Redactor
    from bountymode.evidence.vault import EvidenceVault
    from bountymode.runner.case_runner import CaseRunner
    import tempfile

    scope = ProgramScope(program="acme", in_scope=[], out_of_scope=[])
    with tempfile.TemporaryDirectory() as tmp:
        runner = CaseRunner(
            gate=AuthorizationGate(scope),
            stops=StopConditionEngine(StopConditions.from_scope(scope)),
            vault=EvidenceVault(tmp, redactor=Redactor()),
            dispatch=build_local_dispatch(offline=True),
        )
        result = runner.run("c1", scope, "https://not-in-scope.example.org", ["prompt_injection"])
    assert result.findings == []
    assert any("scope" in s["reason"] for s in result.skipped)


def test_runner_produces_a_finding_in_process_when_authorized():
    from bountymode.authority.gate import AuthorizationGate
    from bountymode.authority.stop_conditions import StopConditionEngine, StopConditions
    from bountymode.domains import DEFAULT_REGISTRY
    from bountymode.evidence.redactor import Redactor
    from bountymode.evidence.vault import EvidenceVault
    from bountymode.runner.case_runner import CaseRunner
    import tempfile

    scope = ProgramScope(program="acme", in_scope=[ScopeTarget("api.acme.com")])
    adapter = DEFAULT_REGISTRY.get("ai_llm")
    with tempfile.TemporaryDirectory() as tmp:
        runner = CaseRunner(
            gate=AuthorizationGate(scope),
            stops=StopConditionEngine(StopConditions.from_scope(scope)),
            vault=EvidenceVault(tmp, redactor=Redactor()),
            builder=adapter,
            dispatch=build_local_dispatch(
                offline=True,
                canned={"Ignore previous instructions": "PWNED-AGATHON system prompt"},
            ),
        )
        result = runner.run("c1", scope, "api.acme.com", ["prompt_injection"])
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.cvss_score > 0
    assert finding.owasp_llm  # domain taxonomy applied through the builder


# --------------------------------------------------------------------------- #
# configuration
# --------------------------------------------------------------------------- #

def test_default_model_is_the_free_router():
    cfg = load_config(env={})
    assert cfg.llm.model == FREE_MODEL_DEFAULT
    assert cfg.llm.configured is False  # no key in the injected environment
    reset_config_cache()


def test_env_overrides_model_and_key():
    cfg = load_config(env={
        "BOUNTYMODE_MODEL": "nvidia/nemotron-3-super-120b-a12b:free",
        "OPENROUTER_API_KEY": "test-key-not-real",
    })
    assert cfg.llm.model == "nvidia/nemotron-3-super-120b-a12b:free"
    assert cfg.llm.configured is True
    assert cfg.llm.to_dict()["api_key"] == "***"   # redacted


def test_role_models_are_configured_and_free():
    cfg = load_config(env={})
    for role in ("generate", "judge", "multimodal"):
        assert cfg.role_model(role).endswith(":free")


def test_no_key_is_not_an_error_for_the_client():
    client = ChatClient(api_key="")
    assert client.configured is False
    result = client.chat("hello")
    assert result.ok is False
    assert "no API key" in result.error


def test_base_url_follows_the_provider_that_issued_the_key():
    # An ambient OpenAI key must not be sent to OpenRouter: the base URL binds
    # to the provider, and the OpenRouter-only default model is not dragged in.
    cfg = load_config(env={"OPENAI_API_KEY": "sk-not-real"})
    assert cfg.llm.base_url == "https://api.openai.com/v1"
    assert cfg.llm.model == "gpt-4o-mini"

    cfg = load_config(env={"OPENROUTER_API_KEY": "sk-or-not-real"})
    assert cfg.llm.base_url == "https://openrouter.ai/api/v1"
    assert cfg.llm.model == FREE_MODEL_DEFAULT

    # An explicit base URL always wins over the provider mapping.
    cfg = load_config(env={
        "OPENAI_API_KEY": "sk-not-real",
        "BOUNTYMODE_LLM_BASE_URL": "https://my-gateway.internal/v1",
    })
    assert cfg.llm.base_url == "https://my-gateway.internal/v1"

    # An explicit model always wins over the provider default.
    cfg = load_config(env={"OPENAI_API_KEY": "sk-not-real", "BOUNTYMODE_MODEL": "gpt-4o"})
    assert cfg.llm.model == "gpt-4o"

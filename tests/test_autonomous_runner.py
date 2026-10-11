"""Tests for the response cache and the autonomous runner."""

from __future__ import annotations

import json

import pytest

from bountymode.autonomous import AutonomousRunner
from bountymode.engine.cache import ResponseCache, cache_key
from bountymode.engine.llm import ChatClient, LLMResult

POLICY = """# Acme AI Bug Bounty

## In Scope

| Target | Kind |
|---|---|
| chat.acme.example | llm |
| api.acme.example | api |

## Out of Scope

- status.acme.example

Rewards: Critical $5000, High $2500.
"""


class TestCacheKey:
    def test_same_request_same_key(self) -> None:
        a = cache_key(model="m", messages=[{"role": "user", "content": "hi"}],
                      temperature=0.0, max_tokens=10, json_mode=False)
        b = cache_key(model="m", messages=[{"role": "user", "content": "hi"}],
                      temperature=0.0, max_tokens=10, json_mode=False)
        assert a == b

    def test_different_model_different_key(self) -> None:
        a = cache_key(model="m1", messages=[{"role": "user", "content": "hi"}],
                      temperature=0.0, max_tokens=10, json_mode=False)
        b = cache_key(model="m2", messages=[{"role": "user", "content": "hi"}],
                      temperature=0.0, max_tokens=10, json_mode=False)
        assert a != b

    def test_different_temperature_different_key(self) -> None:
        a = cache_key(model="m", messages=[{"role": "user", "content": "hi"}],
                      temperature=0.0, max_tokens=10, json_mode=False)
        b = cache_key(model="m", messages=[{"role": "user", "content": "hi"}],
                      temperature=0.9, max_tokens=10, json_mode=False)
        assert a != b

    def test_json_mode_changes_the_key(self) -> None:
        a = cache_key(model="m", messages=[{"role": "user", "content": "hi"}],
                      temperature=0.0, max_tokens=10, json_mode=False)
        b = cache_key(model="m", messages=[{"role": "user", "content": "hi"}],
                      temperature=0.0, max_tokens=10, json_mode=True)
        assert a != b


class TestResponseCache:
    def test_put_then_get(self) -> None:
        cache = ResponseCache()
        cache.put("k", "hello", "m")
        entry = cache.get("k")
        assert entry is not None
        assert entry.text == "hello"

    def test_miss_returns_none(self) -> None:
        assert ResponseCache().get("nope") is None

    def test_empty_completion_is_never_cached(self) -> None:
        cache = ResponseCache()
        cache.put("k", "", "m")
        assert cache.get("k") is None

    def test_stats_track_hits_and_misses(self) -> None:
        cache = ResponseCache()
        cache.put("k", "v", "m")
        cache.get("k")
        cache.get("missing")
        assert cache.stats.hits == 1
        assert cache.stats.misses == 1
        assert cache.stats.hit_rate == 0.5

    def test_ttl_expiry(self) -> None:
        cache = ResponseCache(ttl_s=0.0)
        cache.put("k", "v", "m")
        # ttl_s=0 disables expiry, so it must still be there.
        assert cache.get("k") is not None

    def test_size_cap_evicts(self) -> None:
        cache = ResponseCache(max_entries=2)
        for i in range(5):
            cache.put(f"k{i}", f"v{i}", "m")
        assert len(cache) <= 2

    def test_persistence_round_trip(self, tmp_path) -> None:
        path = tmp_path / "cache.json"
        cache = ResponseCache(path=str(path))
        cache.put("k", "persisted", "m")
        assert path.is_file()
        reloaded = ResponseCache(path=str(path))
        entry = reloaded.get("k")
        assert entry is not None
        assert entry.text == "persisted"

    def test_clear(self) -> None:
        cache = ResponseCache()
        cache.put("k", "v", "m")
        cache.clear()
        assert len(cache) == 0


class _CountingClient(ChatClient):
    """A ChatClient whose transport counts real calls."""

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.transport_calls = 0

    def _chat_once(self, model, messages, temperature, max_tokens, json_mode) -> LLMResult:
        self.transport_calls += 1
        return LLMResult(text="canned answer", model=model)


class TestClientCaching:
    def test_cache_is_off_by_default(self) -> None:
        client = _CountingClient(model="m", api_key="x")
        client.chat("hi")
        client.chat("hi")
        assert client.transport_calls == 2

    def test_cache_makes_a_repeat_call_free(self) -> None:
        cache = ResponseCache()
        client = _CountingClient(model="m", api_key="x", cache=cache)
        first = client.chat("hi")
        second = client.chat("hi")
        assert client.transport_calls == 1
        assert first.text == second.text == "canned answer"

    def test_different_prompts_are_not_shared(self) -> None:
        cache = ResponseCache()
        client = _CountingClient(model="m", api_key="x", cache=cache)
        client.chat("one")
        client.chat("two")
        assert client.transport_calls == 2


class TestAutonomousRunner:
    def _run(self, tmp_path, **kwargs):
        runner = AutonomousRunner(attempts=3)
        return runner.run_from_text(
            POLICY, approved_by="tester", out_dir=str(tmp_path / "run"), **kwargs
        )

    def test_full_run_produces_a_bundle(self, tmp_path) -> None:
        result = self._run(tmp_path)
        assert result.ok, [s.to_dict() for s in result.stages]
        assert result.program
        assert result.plan
        assert result.findings
        assert (tmp_path / "run" / "reports" / "submission-bundle.json").is_file()

    def test_stages_run_in_order(self, tmp_path) -> None:
        result = self._run(tmp_path)
        names = [s.name for s in result.stages]
        assert names[:5] == ["intake", "import", "scope", "plan", "gate"]
        assert "verify" in names and "amplify" in names and "report" in names

    def test_requires_a_human_approver(self, tmp_path) -> None:
        runner = AutonomousRunner(attempts=3)
        result = runner.run_from_text(POLICY, approved_by="", out_dir=str(tmp_path / "r"))
        assert not result.ok
        assert any("approver" in e for e in result.errors)

    def test_unreadable_document_fails_honestly(self, tmp_path) -> None:
        runner = AutonomousRunner(attempts=3)
        result = runner.run_from_document(
            "/nonexistent/program.pdf", approved_by="tester", out_dir=str(tmp_path / "r")
        )
        assert not result.ok
        assert result.stages[0].name == "intake"
        assert not result.stages[0].ok

    def test_dry_run_is_the_default(self, tmp_path) -> None:
        result = self._run(tmp_path)
        assert "dry-run" in result.mode

    def test_scope_gate_denies_out_of_scope_targets(self, tmp_path) -> None:
        result = self._run(tmp_path, target="status.acme.example")
        # status.acme.example is an exclusion, so nothing may be authorized.
        assert not result.ok
        assert result.gate_summary.get("deny", 0) >= 1

    def test_verification_verdicts_are_recorded(self, tmp_path) -> None:
        result = self._run(tmp_path)
        assert len(result.verified) == len(result.findings)
        for verdict in result.verified:
            assert verdict["verdict"] in {"verified", "unverified", "inconclusive"}

    def test_readiness_is_reported_per_finding(self, tmp_path) -> None:
        result = self._run(tmp_path)
        assert len(result.readiness) == len(result.findings)
        for row in result.readiness:
            assert "ready" in row

    def test_severity_and_cvss_agree_after_amplification(self, tmp_path) -> None:
        result = self._run(tmp_path)
        for finding in result.findings:
            if finding.severity.value == "critical":
                assert finding.cvss_score >= 9.0, finding.title

    def test_bundle_names_what_is_missing_when_not_ready(self, tmp_path) -> None:
        result = self._run(tmp_path)
        bundle = json.loads(
            (tmp_path / "run" / "reports" / "submission-bundle.json").read_text()
        )
        assert bundle["ready_to_submit"] == result.ready_to_submit
        if not bundle["ready_to_submit"]:
            assert bundle["missing"]

    def test_result_serialises(self, tmp_path) -> None:
        data = self._run(tmp_path).to_dict()
        assert data["finding_count"] == len(data["findings"])
        assert "ready_to_submit" in data
        assert "missing" in data

    def test_adaptive_followup_is_recorded(self, tmp_path) -> None:
        result = self._run(tmp_path, adapt=True)
        assert result.followup_plan is not None

    def test_no_adapt_skips_the_followup(self, tmp_path) -> None:
        result = self._run(tmp_path, adapt=False)
        assert result.followup_plan is None

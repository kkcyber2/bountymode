"""Tests for the domain-agnostic framework."""

from __future__ import annotations

import pytest

from bountymode.domains import (
    DEFAULT_REGISTRY,
    AiLlmAdapter,
    CicdAdapter,
    CloudAdapter,
    DomainAdapter,
    DomainRegistry,
    WebApiAdapter,
)
from bountymode.models import Severity, Technique
from bountymode.runner.adapter import EngineResult


def test_builtin_domains_registered():
    names = DEFAULT_REGISTRY.names()
    assert names == ["ai_llm", "cicd", "cloud", "web_api"]


def test_each_domain_has_techniques():
    for adapter in DEFAULT_REGISTRY.all():
        techs = adapter.techniques()
        assert techs, f"{adapter.name} has no techniques"
        assert all(isinstance(t, Technique) for t in techs)
        # ids must be unique within a domain
        ids = [t.id for t in techs]
        assert len(ids) == len(set(ids)), f"{adapter.name} has duplicate technique ids"


def test_ai_domain_matches_legacy_catalogue():
    """The AI domain must expose the original 19-technique catalogue."""
    assert len(AiLlmAdapter().techniques()) == 19


def test_domain_lookup_and_require():
    adapter = DEFAULT_REGISTRY.get("web_api")
    assert adapter.technique("idor") is not None
    assert adapter.technique("does-not-exist") is None
    with pytest.raises(KeyError):
        adapter.require("does-not-exist")


def test_unknown_domain_raises():
    with pytest.raises(KeyError):
        DEFAULT_REGISTRY.get("nope")


def test_registry_rejects_duplicate_registration():
    reg = DomainRegistry()
    reg.register(WebApiAdapter())
    with pytest.raises(ValueError):
        reg.register(WebApiAdapter())
    # replace=True is allowed
    reg.register(WebApiAdapter(), replace=True)


def test_default_dispatch_is_safe_dry_run():
    """A domain with no engine must never claim success."""
    adapter = WebApiAdapter()
    res = adapter.dispatch(adapter.require("idor"), "api.example.com")
    assert res.success is False
    assert "dry run" in res.evidence


def test_build_finding_populates_taxonomy_and_remediation():
    adapter = WebApiAdapter()
    res = EngineResult(
        technique_id="idor", target="api.example.com", success=True,
        success_score=0.9, vulnerability_type="idor", evidence="other user's record",
    )
    f = adapter.build_finding(res)
    assert f.category == "idor"
    assert f.cwe == ["CWE-639"]
    assert f.blast_radius == "multi-user"
    assert f.remediation
    assert f.impact
    assert f.reproducible is True


def test_cloud_and_cicd_severity_hints():
    cloud = CloudAdapter()
    assert cloud.severity_hint("iam_privesc") == Severity.CRITICAL
    cicd = CicdAdapter()
    assert cicd.severity_hint("dependency_confusion") == Severity.CRITICAL


def test_ai_adapter_delegates_to_legacy_builder():
    """AI findings must be byte-identical to the pre-framework behaviour."""
    adapter = AiLlmAdapter()
    res = EngineResult(
        technique_id="cross_tenant", target="api.example.com", success=True,
        success_score=0.95, vulnerability_type="cross_tenant",
    )
    f = adapter.build_finding(res)
    assert f.category == "cross_tenant"
    assert f.blast_radius == "cross-tenant"
    assert "CWE-639" in f.cwe


def test_describe_shape():
    desc = DEFAULT_REGISTRY.describe()
    assert len(desc) == 4
    for d in desc:
        assert set(d) == {"name", "description", "scope_kind", "techniques"}
        assert d["techniques"] > 0


def test_custom_adapter_can_be_registered():
    class MyAdapter(DomainAdapter):
        name = "custom"
        description = "test"

        def techniques(self):
            return [Technique("t1", "Test", category="custom")]

    reg = DomainRegistry()
    reg.register(MyAdapter())
    assert reg.get("custom").require("t1").name == "Test"

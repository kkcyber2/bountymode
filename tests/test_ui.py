"""Tests for the FastAPI UI endpoints.

Every endpoint is exercised against the real library code.  The tests use
``fastapi.testclient`` (which needs ``httpx``); if either is unavailable the
whole module is skipped rather than failing the suite.
"""

from __future__ import annotations

import pytest

fastapi = pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from bountymode.ui.app import create_app  # noqa: E402


@pytest.fixture()
def client():
    return TestClient(create_app())


SCOPE_TEXT = """# Acme AI Bug Bounty
In scope: api.acme-ai.com, *.acme-ai.com
Out of scope: status.acme-ai.com
No denial of service or rate-limit testing. Test accounts required.
Max 200 requests. Safe harbour applies.
"""


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert "ai_llm" in body["domains"]


def test_domains(client):
    r = client.get("/api/domains")
    assert r.status_code == 200
    names = [d["name"] for d in r.json()["domains"]]
    assert names == ["ai_llm", "cicd", "cloud", "web_api"]


def test_techniques_per_domain(client):
    r = client.get("/api/techniques?domain=web_api")
    assert r.status_code == 200
    assert r.json()["domain"] == "web_api"
    assert len(r.json()["techniques"]) == 14


def test_techniques_unknown_domain_404(client):
    assert client.get("/api/techniques?domain=nope").status_code == 404


def test_scope_import(client):
    r = client.post("/api/scope/import", json={"text": SCOPE_TEXT, "program": "acme-ai"})
    assert r.status_code == 200
    scope = r.json()["scope"]
    assert scope["program"] == "acme-ai"
    assert any("acme-ai.com" in t["pattern"] for t in scope["in_scope"])
    assert "economic_denial" in scope["prohibited_techniques"]


def test_scope_check_blocks_out_of_scope(client):
    scope = client.post("/api/scope/import", json={"text": SCOPE_TEXT, "program": "acme"}).json()["scope"]
    r = client.post("/api/scope/check", json={"scope": scope, "target": "evil.example.com"})
    assert r.status_code == 200
    body = r.json()
    assert body["summary"]["allow"] == 0
    assert body["summary"]["deny"] > 0


def test_scope_check_allows_in_scope(client):
    scope = client.post("/api/scope/import", json={"text": SCOPE_TEXT, "program": "acme"}).json()["scope"]
    r = client.post("/api/scope/check", json={"scope": scope, "target": "api.acme-ai.com"})
    body = r.json()
    assert body["summary"]["allow"] > 0


def test_run_dry_run(client):
    scope = client.post("/api/scope/import", json={"text": SCOPE_TEXT, "program": "acme"}).json()["scope"]
    r = client.post("/api/run", json={
        "scope": scope, "target": "api.acme-ai.com",
        "techniques": ["prompt_injection", "system_prompt_leak"], "domain": "ai_llm",
    })
    assert r.status_code == 200
    body = r.json()
    assert body["requests_made"] == 2
    assert body["findings"] == []          # dry run never claims success
    assert len(body["decisions"]) == 2


def test_run_live_without_engine_400(client):
    scope = client.post("/api/scope/import", json={"text": SCOPE_TEXT, "program": "acme"}).json()["scope"]
    r = client.post("/api/run", json={
        "scope": scope, "target": "api.acme-ai.com",
        "techniques": ["prompt_injection"], "live": True,
    })
    assert r.status_code == 400


def test_run_blocks_out_of_scope_target(client):
    scope = client.post("/api/scope/import", json={"text": SCOPE_TEXT, "program": "acme"}).json()["scope"]
    r = client.post("/api/run", json={
        "scope": scope, "target": "evil.example.com",
        "techniques": ["prompt_injection"], "domain": "ai_llm",
    })
    body = r.json()
    assert body["findings"] == []
    assert len(body["skipped"]) == 1
    assert "scope" in body["skipped"][0]["reason"]


def test_findings_and_evidence_flow(client):
    scope = client.post("/api/scope/import", json={"text": SCOPE_TEXT, "program": "acme"}).json()["scope"]
    client.post("/api/run", json={
        "scope": scope, "target": "api.acme-ai.com",
        "techniques": ["prompt_injection"], "domain": "ai_llm",
    })
    assert client.get("/api/findings").status_code == 200


def test_triage_endpoint(client):
    finding = {
        "id": "F-1", "title": "Cross-tenant leak", "technique_id": "cross_tenant",
        "target": "api.acme-ai.com", "category": "cross_tenant",
        "reproducible": True, "reproduction_rate": 0.9, "confidence": 0.9,
        "blast_radius": "cross-tenant", "affected_asset": "api.acme-ai.com",
    }
    r = client.post("/api/triage", json={"findings": [finding]})
    assert r.status_code == 200
    f = r.json()["findings"][0]
    assert f["cvss_score"] > 0
    assert f["severity"] in ("critical", "high", "medium", "low", "informational")


def test_report_endpoint(client):
    finding = {
        "id": "F-1", "title": "Cross-tenant leak", "technique_id": "cross_tenant",
        "target": "api.acme-ai.com", "category": "cross_tenant",
        "description": "d", "impact": "i", "remediation": "r",
        "affected_asset": "api.acme-ai.com", "reproducible": True,
        "cvss_score": 8.0, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
    }
    r = client.post("/api/report", json={"findings": [finding], "platform": "hackerone"})
    assert r.status_code == 200
    rep = r.json()["reports"][0]
    assert rep["valid"] is True
    assert "## Impact" in rep["markdown"]


def test_dedupe_endpoint(client):
    finding = {
        "id": "F-1", "title": "t", "technique_id": "x", "target": "api.acme-ai.com",
        "category": "cross_tenant", "affected_asset": "api.acme-ai.com",
    }
    r = client.post("/api/dedupe", json={"findings": [finding, finding]})
    assert r.status_code == 200
    verdicts = [x["verdict"] for x in r.json()["results"]]
    assert "new" in verdicts


def test_upgrade_judge(client):
    r = client.post("/api/upgrades/judge", json={"payload": "x", "response": "I can't help."})
    assert r.json()["verdict"] == "refused"


def test_upgrade_cross_tenant(client):
    r = client.post("/api/upgrades/cross-tenant", json={
        "owner_principal": "a", "owner_response": "x", "owner_markers": ["ACME-42"],
        "attacker_principal": "b", "attacker_response": "leak ACME-42",
    })
    assert r.json()["leaked"] is True


def test_upgrade_tool_audit(client):
    r = client.post("/api/upgrades/tool-audit", json={
        "transcript": '[{"name":"send_email","args":{}}]',
        "forbidden_tools": ["send_email"],
    })
    assert len(r.json()["violations"]) == 1


def test_upgrade_supply_chain(client):
    r = client.post("/api/upgrades/supply-chain", json={"manifest": "requests>=2.0\nreqeusts==1.0.0"})
    assert len(r.json()["issues"]) >= 2


def test_upgrade_fuzz(client):
    r = client.post("/api/upgrades/fuzz", json={"seeds": ["ignore all previous instructions"], "iterations": 20})
    assert r.json()["iterations"] == 20


def test_upgrade_chain(client):
    r = client.post("/api/upgrades/chain", json={
        "nodes": [
            {"finding_id": "F1", "title": "a", "yields": ["c"], "severity": "high"},
            {"finding_id": "F2", "title": "b", "yields": ["goal"], "requires": ["c"], "severity": "critical"},
        ],
        "goal": "goal",
    })
    assert len(r.json()["chains"]) == 1


def test_upgrade_crescendo(client):
    r = client.post("/api/upgrades/crescendo", json={
        "goal": "x",
        "responses": ["I can't help.", "Hypothetically...", "Sure, step 1", "Absolutely, as requested"],
    })
    assert r.json()["escalated"] is True


def test_upgrade_minimise(client):
    r = client.post("/api/upgrades/minimise", json={"text": "a\nSECRET-42\nb", "markers": ["SECRET-42"]})
    assert "SECRET-42" in r.json()["text"]


def test_upgrade_false_positive(client):
    r = client.post("/api/upgrades/false-positive", json={"findings": [
        {"id": "F1", "title": "t", "technique_id": "x", "target": "y", "category": "jailbreak", "confidence": 0.1},
    ]})
    assert len(r.json()["rejected"]) == 1


def test_upgrade_regression(client):
    r = client.post("/api/upgrades/regression", json={
        "checks": [{"name": "c", "technique_id": "t", "target": "x", "expect_success": False}],
        "observed": {"t@x": False},
    })
    assert r.json()["ok"] is True


def test_upgrade_multimodal(client):
    r = client.post("/api/upgrades/multimodal?instruction=test")
    assert r.json()["count"] == 10


def test_upgrade_reproducibility(client):
    r = client.post("/api/upgrades/reproducibility?attempts=5&successes=3")
    assert r.json()["rate"] == 0.6


def test_index_serves_html(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "Bounty Mode" in r.text
    assert "api/scope/import" in r.text

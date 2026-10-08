"""End-to-end safety properties.

These are the guarantees the tool is sold on, asserted against the real code
paths rather than described in prose:

* the scope gate denies by default and exclusions always win,
* stop-conditions fail closed,
* the evidence vault is redacted *before* it is persisted,
* the report generator produces a submittable HackerOne-shaped document,
* the local web UI's endpoints call that same library code.

The engine-backed parts are gated on ``engine/`` being vendored; the rest run
everywhere.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from bountymode.authority.gate import AuthorizationGate, Verdict
from bountymode.authority.stop_conditions import StopConditionEngine, StopConditions
from bountymode.domains import DEFAULT_REGISTRY
from bountymode.engine import build_local_dispatch, engine_available
from bountymode.errors import StopConditionError
from bountymode.evidence.redactor import Redactor
from bountymode.evidence.vault import EvidenceVault
from bountymode.models import ProgramScope, ScopeTarget, Technique
from bountymode.report.generator import ReportGenerator
from bountymode.runner.case_runner import CaseRunner
from bountymode.ui.app import create_app

TECH = Technique(
    id="prompt_injection",
    name="Direct prompt injection",
    engine_key="prompt_injection",
)

#: The literal secret seeded into the simulated vulnerable response.  It must
#: never appear on disk after a run.
RAW_SECRET = "sk-EXAMPLEnotarealkey000000000000"
RAW_EMAIL = "security@acme.example"


def _scope(**kw) -> ProgramScope:
    base = dict(program="acme", in_scope=[ScopeTarget("api.acme.com")])
    base.update(kw)
    return ProgramScope(**base)


# --------------------------------------------------------------------------- #
# authorization
# --------------------------------------------------------------------------- #

def test_scope_denies_by_default():
    gate = AuthorizationGate(_scope())
    assert gate.authorize("evil.example.org", TECH).verdict == Verdict.DENY


def test_exclusion_always_wins_over_inclusion():
    scope = _scope(
        in_scope=[ScopeTarget("api.acme.com")],
        out_of_scope=[ScopeTarget("api.acme.com")],
    )
    assert AuthorizationGate(scope).authorize("api.acme.com", TECH).verdict == Verdict.DENY


def test_in_scope_target_is_allowed():
    assert AuthorizationGate(_scope()).authorize("api.acme.com", TECH).verdict == Verdict.ALLOW


def test_destructive_technique_is_blocked_even_in_scope():
    gate = AuthorizationGate(_scope())
    destructive = DEFAULT_REGISTRY.get("ai_llm").technique("economic_denial")
    assert destructive is not None and destructive.destructive is True
    assert gate.authorize("api.acme.com", destructive).verdict != Verdict.ALLOW


# --------------------------------------------------------------------------- #
# stop conditions
# --------------------------------------------------------------------------- #

def test_stop_condition_fails_closed():
    stops = StopConditionEngine(StopConditions.from_scope(_scope()))
    for _ in range(stops.conditions.max_consecutive_errors):
        stops.record_error()
    with pytest.raises(StopConditionError):
        stops.check()


# --------------------------------------------------------------------------- #
# redaction
# --------------------------------------------------------------------------- #

def test_redactor_removes_secrets_and_pii():
    out = Redactor().redact(f"key {RAW_SECRET} mail {RAW_EMAIL}").text
    assert RAW_SECRET not in out
    assert RAW_EMAIL not in out


# --------------------------------------------------------------------------- #
# the full pipeline (requires the vendored engine)
# --------------------------------------------------------------------------- #

@pytest.mark.skipif(not engine_available(), reason="engine/ is not vendored in this checkout")
def test_pipeline_finding_report_and_no_secret_on_disk():
    scope = _scope()
    adapter = DEFAULT_REGISTRY.get("ai_llm")

    with tempfile.TemporaryDirectory() as tmp:
        runner = CaseRunner(
            gate=AuthorizationGate(scope),
            stops=StopConditionEngine(StopConditions.from_scope(scope)),
            vault=EvidenceVault(tmp, redactor=Redactor()),
            builder=adapter,
            dispatch=build_local_dispatch(offline=True),
        )
        result = runner.run("case-1", scope, "api.acme.com", ["prompt_injection"])

        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding.cvss_score > 0

        gen = ReportGenerator(platform="hackerone", program="acme")
        assert gen.validate(finding).ok
        rendered = gen.render(finding, strict=False).to_dict()
        # A HackerOne-shaped document: title, severity, markdown body, fields.
        assert rendered["title"]
        assert rendered["severity"]
        assert rendered["markdown"]
        assert rendered["structured"]

        # Nothing anywhere under the run directory may contain the raw secret.
        for path in Path(tmp).rglob("*"):
            if path.is_file():
                assert RAW_SECRET not in path.read_bytes().decode("utf-8", "ignore")
                assert RAW_EMAIL not in path.read_bytes().decode("utf-8", "ignore")


@pytest.mark.skipif(not engine_available(), reason="engine/ is not vendored in this checkout")
def test_runner_skips_a_destructive_technique():
    scope = _scope()
    with tempfile.TemporaryDirectory() as tmp:
        runner = CaseRunner(
            gate=AuthorizationGate(scope),
            stops=StopConditionEngine(StopConditions.from_scope(scope)),
            vault=EvidenceVault(tmp, redactor=Redactor()),
            builder=DEFAULT_REGISTRY.get("ai_llm"),
            dispatch=build_local_dispatch(offline=True),
        )
        result = runner.run("case-1", scope, "api.acme.com", ["economic_denial"])
        assert result.findings == []
        assert any("destructive" in s.get("reason", "") for s in result.skipped)


# --------------------------------------------------------------------------- #
# local UI
# --------------------------------------------------------------------------- #

_SCOPE_JSON = {"program": "acme", "in_scope": [{"pattern": "api.acme.com"}], "out_of_scope": []}


@pytest.fixture()
def client() -> TestClient:
    return TestClient(create_app())


@pytest.mark.parametrize(
    "endpoint",
    ["/api/health", "/api/domains", "/api/techniques", "/api/config", "/api/engine"],
)
def test_ui_read_endpoints(client: TestClient, endpoint: str):
    assert client.get(endpoint).status_code == 200


def test_ui_scope_check_matches_the_gate(client: TestClient):
    body = {"scope": _SCOPE_JSON, "techniques": ["prompt_injection"]}

    inside = client.post("/api/scope/check", json={**body, "target": "api.acme.com"}).json()
    assert [d["verdict"] for d in inside["decisions"]] == ["allow"]

    outside = client.post("/api/scope/check", json={**body, "target": "evil.example.org"}).json()
    assert [d["verdict"] for d in outside["decisions"]] == ["deny"]


@pytest.mark.skipif(not engine_available(), reason="engine/ is not vendored in this checkout")
def test_ui_run_produces_a_finding_then_reports_it(client: TestClient):
    run = client.post(
        "/api/run",
        json={
            "scope": _SCOPE_JSON,
            "target": "api.acme.com",
            "techniques": ["prompt_injection"],
            "in_process": True,
            "offline": True,
        },
    )
    assert run.status_code == 200
    payload = run.json()
    assert payload["mode"] == "in-process-simulated"
    assert len(payload["findings"]) == 1

    finding_id = payload["findings"][0]["id"]
    assert client.get(f"/api/evidence/{finding_id}").status_code == 200

    report = client.post(
        "/api/report",
        json={"findings": payload["findings"], "platform": "hackerone", "program": "acme"},
    )
    assert report.status_code == 200
    assert report.json()["reports"]

"""Tests for the guided-run UI: onboarding, guided run, readiness."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from bountymode.ui.app import create_app

SCOPE = """# Apps+ Marketplace Bug Bounty

## In Scope Targets

| Name / Location | Tags |
| https://marketplace.atlassian.com/apps/1227541/x | web |
| https://api.appsplus.example.com/v1 | api |

## Out of Scope

| Name | Reason |
| admin.example.com | internal-only |

Prompt injection is out of scope and not bounty-eligible.

P1 | $1500
P2 | $900

5 requests per second, maximum 200 requests.
"""


@pytest.fixture()
def client() -> TestClient:  # type: ignore[misc]
    return TestClient(create_app())


class TestOnboardEndpoint:
    def test_paste_produces_a_review_payload(self, client: TestClient) -> None:
        r = client.post("/api/onboard", json={"text": SCOPE, "program": "apps-plus2",
                                              "platform": "bugcrowd"})
        assert r.status_code == 200
        payload = r.json()
        assert payload["ok"] is True
        patterns = [t["pattern"] for t in payload["in_scope"]]
        assert "https://api.appsplus.example.com/v1" in patterns
        assert not any("marketplace.atlassian.com" in p for p in patterns)
        assert payload["listings"]
        assert payload["VERIFY"]
        assert payload["rewards"] == {"P1": 1500, "P2": 900}

    def test_no_input_is_a_client_error(self, client: TestClient) -> None:
        r = client.post("/api/onboard", json={})
        assert r.status_code == 400

    def test_onboard_does_not_test_anything(self, client: TestClient) -> None:
        """Parsing must never run a technique."""
        client.post("/api/onboard", json={"text": SCOPE, "program": "apps-plus2"})
        assert client.get("/api/readiness").json()["total"] == 0


class TestGuidedRunEndpoint:
    def test_defaults_to_a_dry_run(self, client: TestClient) -> None:
        r = client.post("/api/guided-run", json={
            "text": SCOPE, "program": "apps-plus2", "platform": "bugcrowd",
            "approved_by": "alice", "verify_attempts": 3,
        })
        assert r.status_code == 200
        payload = r.json()
        assert payload["mode"] == "in-process-dry-run"
        assert payload["ok"]
        stages = {s["stage"]: s for s in payload["stages"]}
        assert stages["import"]["ok"] and stages["scope"]["ok"]
        assert stages["gate"]["ok"] and stages["scan"]["ok"]
        assert payload["finding_count"] >= 1
        assert payload["reports"]

    def test_readiness_endpoint_reports_gaps(self, client: TestClient) -> None:
        client.post("/api/guided-run", json={
            "text": SCOPE, "program": "apps-plus2", "approved_by": "alice",
            "verify_attempts": 3,
        })
        data = client.get("/api/readiness").json()
        assert data["total"] >= 1
        assert data["ready"] <= data["total"]
        for row in data["findings"]:
            assert "missing" in row and "blockers" in row
            assert row["summary"]

    def test_no_approver_is_refused(self, client: TestClient) -> None:
        r = client.post("/api/guided-run", json={
            "text": SCOPE, "program": "apps-plus2", "approved_by": "",
        })
        payload = r.json()
        assert payload["ok"] is False
        assert payload["finding_count"] == 0
        assert payload["errors"]

    def test_out_of_scope_target_is_refused(self, client: TestClient) -> None:
        r = client.post("/api/guided-run", json={
            "text": SCOPE, "program": "apps-plus2", "approved_by": "alice",
            "target": "admin.example.com",
        })
        payload = r.json()
        assert payload["finding_count"] == 0
        stages = {s["stage"]: s for s in payload["stages"]}
        assert stages["gate"]["ok"] is False

    def test_no_input_is_a_client_error(self, client: TestClient) -> None:
        r = client.post("/api/guided-run", json={"approved_by": "alice"})
        assert r.status_code == 400


class TestGuidedPageIsServed:
    def test_index_renders_the_guided_section(self, client: TestClient) -> None:
        r = client.get("/")
        assert r.status_code == 200
        body = r.text
        assert 'id="guided"' in body
        assert "/api/onboard" in body
        assert "/api/guided-run" in body
        assert "doOnboard" in body and "doGuidedRun" in body

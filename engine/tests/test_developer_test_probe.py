"""HTTP tests for POST /developer/test-probe (mocked Docker sandbox)."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from agathon.orchestrator import app

TEST_TOKEN = "test-internal-scan-token-for-probe"


@pytest.fixture(scope="module")
def client() -> TestClient:
    import os

    os.environ["INTERNAL_SCAN_TOKEN"] = TEST_TOKEN
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def auth_headers() -> dict[str, str]:
    return {"x-internal-scan-token": TEST_TOKEN}


def test_developer_test_probe_requires_auth(client: TestClient) -> None:
    res = client.post(
        "/developer/test-probe",
        json={"code": "print('hi')"},
    )
    assert res.status_code == 401


def test_developer_test_probe_success(client: TestClient, auth_headers: dict[str, str]) -> None:
    with patch(
        "agathon.orchestrator._run_sandboxed_probe",
        new_callable=AsyncMock,
        return_value=(0, '{"ok": true}', ""),
    ):
        res = client.post(
            "/developer/test-probe",
            json={
                "code": "import json; print(json.dumps({'ok': True}))",
                "network": False,
                "target_url": "https://example.com",
            },
            headers=auth_headers,
        )
    assert res.status_code == 200
    body = res.json()
    assert body["ok"] is True
    assert body["exit_code"] == 0
    assert "ok" in body["stdout"]


def test_developer_test_probe_nonzero_exit(client: TestClient, auth_headers: dict[str, str]) -> None:
    with patch(
        "agathon.orchestrator._run_sandboxed_probe",
        new_callable=AsyncMock,
        return_value=(1, "", "traceback"),
    ):
        res = client.post(
            "/developer/test-probe",
            json={"code": "raise SystemExit(1)"},
            headers=auth_headers,
        )
    assert res.status_code == 200
    body = res.json()
    assert body["ok"] is False
    assert body["exit_code"] == 1


def test_developer_test_probe_sandbox_exception(client: TestClient, auth_headers: dict[str, str]) -> None:
    with patch(
        "agathon.orchestrator._run_sandboxed_probe",
        new_callable=AsyncMock,
        side_effect=RuntimeError("docker not available"),
    ):
        res = client.post(
            "/developer/test-probe",
            json={"code": "print(1)"},
            headers=auth_headers,
        )
    assert res.status_code == 500
    assert res.json()["ok"] is False

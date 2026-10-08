"""
AI-red-team health + SSRF guard tests.

These exercise the CURRENT orchestrator surface — no orchestrator refactoring
was done to fit the tests. Run with:  pytest tests/test_health.py -q

Covers:
  - GET /health returns 200 + status=healthy
  - POST /scan/start rejects without an internal token (401)
  - _sanitize_target_url rejects SSRF sinks: AWS metadata IP, localhost, file://
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from agathon.orchestrator import _sanitize_target_url, app


@pytest.fixture(scope="module")
def client() -> TestClient:
    with TestClient(app) as c:
        yield c


def test_health_returns_200_and_healthy(client: TestClient) -> None:
    res = client.get("/health")
    assert res.status_code == 200
    body = res.json()
    assert body.get("status") == "healthy"


def test_scan_start_requires_internal_token_401(client: TestClient) -> None:
    # No Authorization header, no x-internal-scan-token → 401 (not 200/403).
    res = client.post(
        "/scan/start",
        json={
            "scan_id": "test-scan-id",
            "user_id": "00000000-0000-0000-0000-000000000000",
            "target_model": "test-model",
            "target_url": "https://example.com",
            "intensity": "standard",
        },
    )
    assert res.status_code == 401


def test_sanitize_rejects_aws_metadata_ip() -> None:
    with pytest.raises(HTTPException) as exc:
        _sanitize_target_url("http://169.254.169.254/latest/meta-data/")
    assert exc.value.status_code == 400


def test_sanitize_rejects_localhost() -> None:
    with pytest.raises(HTTPException) as exc:
        _sanitize_target_url("http://localhost:8080/api")
    assert exc.value.status_code == 400


def test_sanitize_rejects_file_scheme() -> None:
    with pytest.raises(HTTPException) as exc:
        _sanitize_target_url("file:///etc/passwd")
    assert exc.value.status_code == 400


def test_sanitize_accepts_public_https() -> None:
    # A public host must pass the SSRF guard (no exception).
    assert _sanitize_target_url("https://example.com/chat") == "https://example.com/chat"

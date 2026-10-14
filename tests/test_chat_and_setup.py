"""Tests for the streaming chat session and the one-click setup helpers."""

from __future__ import annotations

import json

import pytest

from bountymode.autonomous.chat import ChatSession


SCOPE = "## In Scope\n| Target | Kind |\n|---|---|\n| 127.0.0.1:9111 | web |\n"


def _events(session: ChatSession, **kw):
    return list(session.stream(**kw))


def test_chat_session_streams_stages_and_a_result():
    session = ChatSession(approved_by="tester", out_dir="/tmp/chat-test")
    events = _events(session, text=SCOPE)
    types = [e["type"] for e in events]
    assert types[0] == "start"
    assert "stage" in types
    assert types[-1] == "result"
    stages = [e["stage"] for e in events if e["type"] == "stage"]
    assert "intake" in stages and "scan" in stages


def test_chat_session_requires_an_approver():
    """No approver means the run stops at the scope stage, not that it tests."""
    session = ChatSession(approved_by="", out_dir="/tmp/chat-test2")
    events = _events(session, text=SCOPE)
    stages = {e["stage"]: e["status"] for e in events if e["type"] == "stage"}
    assert stages.get("scope") == "FAIL"


def test_chat_session_queues_and_drains_instructions():
    session = ChatSession(approved_by="tester")
    session.instruct("focus on auth")
    session.instruct("  ")
    session.instruct("skip the fuzzing")
    drained = session.drain_instructions()
    assert drained == ["focus on auth", "skip the fuzzing"]
    assert session.drain_instructions() == []
    assert session.instructions == ["focus on auth", "skip the fuzzing"]


def test_chat_session_reports_instructions_in_the_stream():
    session = ChatSession(approved_by="tester", out_dir="/tmp/chat-test3")
    session.instruct("look at the admin endpoint")
    events = _events(session, text=SCOPE)
    applied = [e for e in events if e["type"] == "instruction"]
    assert applied and applied[0]["text"] == "look at the admin endpoint"


def test_chat_session_has_a_stable_id():
    a, b = ChatSession(), ChatSession()
    assert a.id and b.id and a.id != b.id


# --------------------------------------------------------------------------- #
# the UI endpoints
# --------------------------------------------------------------------------- #

@pytest.fixture()
def client():
    fastapi_testclient = pytest.importorskip("fastapi.testclient")
    from bountymode.ui.app import create_app

    return fastapi_testclient.TestClient(create_app())


def test_chat_stream_endpoint_returns_sse(client):
    body = {"text": SCOPE, "approved_by": "tester", "live": False}
    with client.stream("POST", "/api/chat/stream", json=body) as resp:
        assert resp.status_code == 200
        payloads = [
            json.loads(line[6:])
            for line in resp.iter_lines()
            if line and line.startswith("data: ")
        ]
    assert payloads[0]["type"] == "start"
    assert any(p["type"] == "stage" for p in payloads)
    assert payloads[-1]["type"] == "done"


def test_chat_stream_requires_an_approver(client):
    resp = client.post("/api/chat/stream", json={"text": SCOPE})
    assert resp.status_code == 400
    assert "approved_by" in resp.json()["detail"]


def test_chat_stream_requires_a_document(client):
    resp = client.post("/api/chat/stream", json={"approved_by": "tester"})
    assert resp.status_code == 400


def test_chat_instruction_unknown_session_is_404(client):
    resp = client.post(
        "/api/chat/instruction", json={"session_id": "nope", "instruction": "x"}
    )
    assert resp.status_code == 404


# --------------------------------------------------------------------------- #
# the one-click setup helpers
# --------------------------------------------------------------------------- #

def test_setup_writes_env_and_gitignores_it(tmp_path, monkeypatch):
    import setup as setup_mod

    monkeypatch.setattr(setup_mod, "ROOT", tmp_path)
    monkeypatch.setattr(setup_mod, "ENV_PATH", tmp_path / ".env")
    setup_mod._write_env({"OPENROUTER_API_KEY": "sk-or-test", "BOUNTYMODE_OPERATOR": "tester"})
    setup_mod._ensure_gitignored()

    env = (tmp_path / ".env").read_text(encoding="utf-8")
    assert "OPENROUTER_API_KEY=sk-or-test" in env
    assert "BOUNTYMODE_OPERATOR=tester" in env
    assert ".env" in (tmp_path / ".gitignore").read_text(encoding="utf-8").split()


def test_setup_validate_key_rejects_empty():
    import setup as setup_mod

    ok, message = setup_mod.validate_key("")
    assert not ok and "no key" in message

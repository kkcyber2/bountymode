"""Regression tests for the ``/api/auto/plan`` scope-parsing bug.

The bug: a realistic pasted program brief (headings, prose, bullet lists, a
scope table) produced an empty ``in_scope``, so the endpoint answered a bare
``400 no scope could be parsed from the document`` and Step 2 stayed disabled.

These tests pin the fix at both layers:

* the extractor must harvest assets from the shapes real program pages use;
* the endpoint must return 200 for a parseable document and a *clear* 4xx
  (naming what to do) when it genuinely cannot parse one.
"""

from __future__ import annotations

import pytest

fastapi = pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from bountymode.program.extractor import (  # noqa: E402
    ProgramExtractor,
    _explicit_targets,
    _is_testable_host,
)
from bountymode.ui.app import create_app  # noqa: E402


@pytest.fixture()
def client():
    return TestClient(create_app())


# --------------------------------------------------------------------------- #
# the shapes a real program page uses
# --------------------------------------------------------------------------- #

MARKDOWN_TABLE = """# Acme AI Bug Bounty

## In Scope
| Target | Kind |
|---|---|
| api.acme.example | api |
| chat.acme.example | web |

## Out of Scope
- status.acme.example
"""

BULLET_LIST = """Acme AI Bug Bounty

In Scope
- api.acme.example
- chat.acme.example

Out of Scope
- status.acme.example
"""

HEADING_THEN_BARE_HOSTS = """Acme AI Bug Bounty

Scope
api.acme.example
chat.acme.example

Out of scope
status.acme.example
"""

BUGCROWD_STYLE = """OpenAI Safety
Bugcrowd

Scope
Targets
chatgpt.com
api.openai.com
platform.openai.com

Out of scope
System prompt extraction
Model responses that appear to reveal internal information

Rewards
P1 $5,500 - $7,500
"""


@pytest.mark.parametrize(
    "name,text",
    [
        ("markdown table", MARKDOWN_TABLE),
        ("bullet list", BULLET_LIST),
        ("heading then bare hosts", HEADING_THEN_BARE_HOSTS),
        ("bugcrowd-style page", BUGCROWD_STYLE),
    ],
)
def test_valid_pasted_scope_returns_200_with_assets(client, name, text):
    """Every realistic paste shape must parse to a non-empty in-scope list."""
    r = client.post("/api/auto/plan", json={"text": text, "program": None, "platform": None})
    assert r.status_code == 200, f"{name}: {r.text}"
    body = r.json()
    assert body["in_scope"], f"{name}: no in-scope assets were parsed"
    assert any("acme.example" in t or "openai.com" in t or "chatgpt.com" in t
               for t in body["in_scope"]), f"{name}: {body['in_scope']}"


def test_frontend_payload_shape_is_accepted(client):
    """The exact payload the Step 1b handler sends must be accepted."""
    r = client.post(
        "/api/auto/plan",
        json={"text": MARKDOWN_TABLE, "path": "", "program": None, "platform": None},
    )
    assert r.status_code == 200
    assert r.json()["in_scope"]


# --------------------------------------------------------------------------- #
# honest, actionable errors
# --------------------------------------------------------------------------- #

def test_empty_scope_returns_clear_4xx(client):
    r = client.post("/api/auto/plan", json={"text": ""})
    assert r.status_code == 400
    detail = r.json()["detail"]
    assert "no program document was supplied" in detail
    assert "paste" in detail.lower()


def test_unparseable_prose_returns_clear_4xx(client):
    """Prose with no explicit asset statement must fail *with instructions*."""
    r = client.post(
        "/api/auto/plan",
        json={"text": "This program is about the Acme assistant and its safety. " * 3},
    )
    assert r.status_code == 400
    detail = r.json()["detail"]
    assert "no scope could be parsed" in detail
    # The message must say what to do, not just that it failed.
    assert "In Scope" in detail or "scope table" in detail


def test_pdf_without_a_text_layer_returns_helpful_error(client, tmp_path):
    """A scanned PDF must produce a message that names the OCR/paste fix."""
    p = tmp_path / "scan.pdf"
    p.write_bytes(b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n")
    r = client.post("/api/auto/plan", json={"path": str(p)})
    assert r.status_code == 400
    detail = r.json()["detail"]
    assert "could not read the document" in detail
    assert "OCR" in detail or "paste" in detail.lower()


def test_missing_file_returns_clear_4xx(client):
    r = client.post("/api/auto/plan", json={"path": "/nonexistent/nope.pdf"})
    assert r.status_code == 400
    assert "no such file" in r.json()["detail"]


# --------------------------------------------------------------------------- #
# the extractor must not invent targets
# --------------------------------------------------------------------------- #

def test_junk_hosts_are_not_harvested():
    """Platform hosts, test-mailbox domains and file names are not targets."""
    assert not _is_testable_host("bugcrowdninja.com")
    assert not _is_testable_host("bugcrowd.com")
    assert not _is_testable_host("ai-plugin.json")
    assert not _is_testable_host("README.md")
    assert _is_testable_host("api.acme.example")
    assert _is_testable_host("*.openai.com")


def test_excluded_host_is_not_harvested_as_in_scope():
    """A host named only as an exclusion must never become a target."""
    text = """Acme AI

In Scope
- api.acme.example

Out of Scope
- status.acme.example
"""
    scope = ProgramExtractor().extract(text).scope
    patterns = [t.pattern for t in scope.in_scope]
    assert "api.acme.example" in patterns
    assert "status.acme.example" not in patterns


def test_prose_hosts_are_not_harvested():
    """A host mentioned inside a sentence is not an explicit target statement."""
    text = (
        "This program covers the Acme assistant. You may test api.acme.example "
        "and chat.acme.example. Do not test status.acme.example. Rewards range "
        "from $250 to $7500."
    )
    assert _explicit_targets(text) == []


def test_explicit_targets_recognises_the_three_forms():
    block = (
        "Target row: `*.openai.com`\n"
        "- api.acme.example\n"
        "In scope: chat.acme.example\n"
    )
    found = _explicit_targets(block)
    assert "*.openai.com" in found
    assert "api.acme.example" in found
    assert "chat.acme.example" in found

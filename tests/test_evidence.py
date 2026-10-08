"""Tests for the redactor and evidence vault."""

from __future__ import annotations

import pytest

from bountymode.evidence import EvidenceVault, Redactor, redact
from bountymode.models import Finding


SAMPLE = """\
POST /v1/chat HTTP/1.1
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP
Host: api.acme.com

{"api_key": "sk-abcdef0123456789ABCDEF", "password": "hunter2pass",
 "contact": "alice@example.com", "note": "card 4111 1111 1111 1111 ssn 123-45-6789"}
"""


def test_redactor_masks_all_credential_classes():
    out = redact(SAMPLE)
    assert "sk-abcdef0123456789ABCDEF" not in out
    assert "hunter2pass" not in out
    assert "alice@example.com" not in out
    assert "4111 1111 1111 1111" not in out
    assert "123-45-6789" not in out
    # placeholders must be present and labelled
    assert "[REDACTED:openai_key]" in out
    assert "[REDACTED:email]" in out


def test_redactor_reports_categories_and_never_leaks_preview():
    result = Redactor().redact(SAMPLE)
    cats = result.by_category()
    assert cats.get("openai_key") == 1
    assert cats.get("email") == 1
    assert result.count >= 5
    # a preview must never contain the secret itself
    for r in result.redactions:
        assert "sk-abcdef" not in r.preview
        assert r.preview.startswith("len=")


def test_redactor_is_deterministic():
    assert Redactor().redact(SAMPLE).text == Redactor().redact(SAMPLE).text


def test_redactor_personal_data_categories_default_off_then_toggle_on():
    text = "call +1 415 555 0142 from 10.0.0.7"
    assert "+1 415 555 0142" in Redactor().redact(text).text
    on = Redactor({"phone": True, "private_ip": True}).redact(text).text
    assert "[REDACTED:phone]" in on and "[REDACTED:private_ip]" in on


def test_redactor_handles_private_key_block():
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
    out = redact(pem)
    assert "MIIEogIBAAKCAQEA" not in out
    assert "[REDACTED:private_key]" in out


# --------------------------------------------------------------------------- #
# vault
# --------------------------------------------------------------------------- #

def test_vault_persists_redacted_evidence_and_verifies_chain(tmp_path):
    vault = EvidenceVault(str(tmp_path / "evidence"))
    finding = Finding(
        id="F-1", title="Leak", technique_id="system_prompt_leak",
        target="api.acme.com", category="system_prompt_leak", affected_asset="api.acme.com",
    )
    obs = vault.capture(
        finding,
        kind="http",
        request='{"api_key": "sk-live-0123456789abcdef"}',
        response="contact box@acme.com",
        status=200,
        url="https://api.acme.com/v1/chat",
    )
    assert obs.redactions >= 2
    assert "sk-live-0123456789abcdef" not in obs.request
    assert "box@acme.com" not in obs.response
    assert obs.sha256 and len(obs.sha256) == 64
    assert vault.verify_chain() is True

    # nothing sensitive on disk
    on_disk = "".join(p.read_text() for p in (tmp_path / "evidence").rglob("*.json"))
    assert "sk-live-0123456789abcdef" not in on_disk
    assert "box@acme.com" not in on_disk


def test_vault_chain_detects_tampering(tmp_path):
    vault = EvidenceVault(str(tmp_path / "e"))
    f = Finding(id="F-2", title="t", technique_id="x", target="api.acme.com",
                category="prompt_injection", affected_asset="api.acme.com")
    vault.capture(f, request="a", response="b")
    vault.capture(f, request="c", response="d")
    assert vault.verify_chain()

    # tamper with the middle link
    vault.entries[1].prev_hash = "deadbeef"
    assert vault.verify_chain() is False


def test_vault_bundle_includes_finding_and_chain_flag(tmp_path):
    vault = EvidenceVault(str(tmp_path / "e"))
    f = Finding(id="F-3", title="t", technique_id="x", target="a.com",
                category="prompt_injection", affected_asset="a.com")
    vault.capture(f, request="r", response="s")
    bundle = vault.finding_bundle(f)
    assert bundle["chain_verified"] is True
    assert bundle["evidence"][0]["kind"] == "http"
    assert bundle["finding"]["id"] == "F-3"

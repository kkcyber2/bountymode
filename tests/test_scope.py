"""Tests for the scope importer and matcher."""

from __future__ import annotations

import json

import pytest

from bountymode.models import OutOfScopeRule, ProgramScope, ScopeTarget, Technique
from bountymode.scope import ScopeImporter, host_matches, resolve_scope, target_matches_pattern
from bountymode.scope.matcher import technique_prohibited


# --------------------------------------------------------------------------- #
# host / pattern matching
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "pattern,host,expected",
    [
        ("example.com", "example.com", True),
        ("example.com", "www.example.com", True),
        ("example.com", "api.example.com", False),
        ("*.example.com", "api.example.com", True),
        ("*.example.com", "deep.api.example.com", True),
        ("*.example.com", "example.com", False),   # wildcard excludes the apex
        ("api.example.com", "api.example.com", True),
        ("api.example.com", "API.EXAMPLE.COM", True),
        ("example.com:443", "example.com", True),
        ("", "example.com", False),
    ],
)
def test_host_matches(pattern, host, expected):
    assert host_matches(pattern, host) is expected


def test_target_matches_url_prefix():
    assert target_matches_pattern(
        target="https://api.example.com/v1/chat", pattern="https://api.example.com/v1"
    )
    assert not target_matches_pattern(
        target="https://api.example.com/v1/chat", pattern="https://api.example.com/v2"
    )


def test_resolve_scope_exclusion_wins_over_inclusion():
    scope = ProgramScope(
        program="p",
        in_scope=[ScopeTarget("example.com")],
        out_of_scope=[OutOfScopeRule("api.example.com", reason="excluded")],
    )
    in_scope, entry, exclusion = resolve_scope("api.example.com", scope)
    assert in_scope is False
    assert entry is None
    assert exclusion is not None and exclusion.pattern == "api.example.com"


def test_resolve_scope_unlisted_target_is_out_of_scope():
    scope = ProgramScope(program="p", in_scope=[ScopeTarget("example.com")])
    in_scope, entry, exclusion = resolve_scope("evil.test", scope)
    assert (in_scope, entry, exclusion) == (False, None, None)


# --------------------------------------------------------------------------- #
# importer
# --------------------------------------------------------------------------- #

def test_importer_from_dict_accepts_aliases_and_string_entries():
    importer = ScopeImporter()
    scope = importer.from_dict(
        {
            "name": "acme",
            "scope": ["api.acme.com", {"pattern": "*.acme.com", "kind": "web"}],
            "outOfScope": ["admin.acme.com"],
        }
    )
    patterns = {t.pattern for t in scope.in_scope}
    assert "api.acme.com" in patterns and "*.acme.com" in patterns
    assert scope.out_of_scope[0].pattern == "admin.acme.com"
    assert scope.program == "acme"


def test_importer_always_blocks_disruptive_techniques_even_if_policy_silent():
    scope = ScopeImporter().from_dict({"program": "p", "in_scope": ["x.com"]})
    assert "economic_denial" in scope.prohibited_techniques
    assert "destructive" in scope.prohibited_techniques


def test_importer_refuses_localhost_and_metadata_hosts():
    importer = ScopeImporter()
    scope = importer.from_dict(
        {"program": "p", "in_scope": ["localhost", "169.254.169.254", "real.example.com"]}
    )
    patterns = {t.pattern for t in scope.in_scope}
    assert patterns == {"real.example.com"}
    assert any("refused unsafe host" in w for w in importer.warnings)


def test_text_importer_extracts_scope_exclusions_and_limits():
    policy = """
    # Acme AI Bounty Program (HackerOne)

    ## In Scope
    - https://api.acme.com
    - chat.acme.com

    ## Out of Scope
    - admin.acme.com
    - Denial of Service (DoS) attacks are prohibited
    - Please do not exceed 2 requests per second. Maximum 300 requests.

    Safe harbour applies. Test accounts are available.
    """
    scope = ScopeImporter().from_text(policy, program="acme")
    in_scope = {t.pattern for t in scope.in_scope}
    assert "api.acme.com" in in_scope and "chat.acme.com" in in_scope
    assert any(r.pattern == "admin.acme.com" for r in scope.out_of_scope)
    assert scope.rate_limit_rps == pytest.approx(2.0)
    assert scope.max_requests == 300
    assert "economic_denial" in scope.prohibited_techniques
    assert scope.safe_harbour is True
    assert scope.requires_test_account is True


def test_scope_round_trips_through_json(tmp_path):
    importer = ScopeImporter()
    scope = importer.from_dict(
        {"program": "acme", "in_scope": ["api.acme.com"], "out_of_scope": ["admin.acme.com"]}
    )
    out = tmp_path / "scope.json"
    importer.export(scope, str(out))
    restored = ProgramScope.from_dict(json.loads(out.read_text()))
    assert {t.pattern for t in restored.in_scope} == {"api.acme.com"}
    assert restored.out_of_scope[0].pattern == "admin.acme.com"
    assert restored.prohibited_techniques == scope.prohibited_techniques


def test_technique_prohibited_respects_permitted_override():
    scope = ProgramScope(
        program="p",
        in_scope=[ScopeTarget("x.com")],
        prohibited_techniques=["economic_denial"],
        permitted_techniques=["economic_denial"],
    )
    assert technique_prohibited("economic_denial", scope) is False

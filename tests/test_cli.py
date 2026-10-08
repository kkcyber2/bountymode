"""End-to-end test driving the real CLI.

Runs the whole pipeline offline: import a scope, gate-check, run a dry case,
triage, and render reports — asserting on the files the CLI actually writes.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bountymode.cli import main


POLICY = """\
# Acme AI Bounty (HackerOne)
## In Scope
- https://api.acme.com
## Out of Scope
- admin.acme.com
- Denial of service is prohibited
Do not exceed 5 requests per second. Maximum 100 requests.
"""


def test_cli_end_to_end(tmp_path, capsys):
    policy = tmp_path / "policy.md"
    policy.write_text(POLICY)
    scope_path = tmp_path / "scope.json"

    assert main(["scope", "import", str(policy), "--program", "acme", "-o", str(scope_path)]) == 0
    assert scope_path.exists()
    scope = json.loads(scope_path.read_text())
    assert any(t["pattern"] == "api.acme.com" for t in scope["in_scope"])

    # gate check: in-scope allowed, out-of-scope blocked
    assert main(["check", str(scope_path), "api.acme.com", "--technique", "prompt_injection"]) == 0
    capsys.readouterr()
    assert main(["check", str(scope_path), "evil.test", "--technique", "prompt_injection"]) == 3
    capsys.readouterr()

    # techniques listing
    assert main(["techniques"]) == 0
    listing = json.loads(capsys.readouterr().out)
    assert listing["count"] >= 19

    # dry run
    case = tmp_path / "case.yaml"
    case.write_text(
        "id: acme-1\n"
        f"scope: {scope_path}\n"
        "target: api.acme.com\n"
        "techniques:\n"
        "  - prompt_injection\n"
        "  - economic_denial\n"      # destructive -> must be skipped
        "  - system_prompt_leak\n"
    )
    out_dir = tmp_path / "run"
    assert main(["run", str(case), "-o", str(out_dir)]) == 0
    result = json.loads((out_dir / "result.json").read_text())
    assert result["stopped"] is False
    assert any("destructive" in json.dumps(s) for s in result["skipped"])

    # triage + report on a hand-made finding
    findings = tmp_path / "findings.json"
    findings.write_text(json.dumps([
        {
            "id": "F-1", "title": "Cross-tenant data leak", "technique_id": "cross_tenant",
            "target": "api.acme.com", "category": "cross_tenant",
            "affected_asset": "api.acme.com", "description": "d", "impact": "i",
            "remediation": "r", "expected": "e", "actual": "a",
            "reproducible": True, "reproduction_rate": 1.0, "confidence": 0.95,
            "blast_radius": "cross-tenant", "privileges_required": "low",
        }
    ]))
    triaged = tmp_path / "triaged.json"
    assert main(["triage", str(findings), "-o", str(triaged)]) == 0
    scored = json.loads(triaged.read_text())
    assert scored[0]["cvss_score"] > 4.0

    reports = tmp_path / "reports"
    assert main(["report", str(triaged), "--platform", "hackerone",
                 "--program", "acme", "-o", str(reports), "--require-valid"]) == 0
    md = list(reports.glob("*.md"))
    assert md, "a report should have been written"
    assert "## Impact" in md[0].read_text()


def test_cli_run_without_scope_errors(tmp_path):
    case = tmp_path / "bad.yaml"
    case.write_text("id: x\ntarget: api.acme.com\ntechniques: [prompt_injection]\n")
    assert main(["run", str(case)]) == 2


def test_cli_live_without_engine_errors(tmp_path):
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps({"program": "a", "in_scope": ["api.acme.com"]}))
    case = tmp_path / "case.json"
    case.write_text(json.dumps({
        "id": "x", "scope": str(scope), "target": "api.acme.com",
        "techniques": ["prompt_injection"],
    }))
    assert main(["run", str(case), "--live"]) == 2

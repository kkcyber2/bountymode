"""
Per-finding remediation suggestion tests for reporter._build_vulnerabilities.

Run: pytest tests/test_reporter_remediation.py -q
"""

from __future__ import annotations

from agathon.reporter import _build_vulnerabilities, _remediation_suggestions


def _finding(family: str, severity: str, payload: dict | None = None) -> dict:
    return {
        "attack": f"{family}_probe",
        "family": family,
        "severity": severity,
        "payload": payload or {},
    }


def test_suggestions_are_one_to_three_items() -> None:
    for sev in ("critical", "high", "medium", "low", "info"):
        out = _remediation_suggestions("prompt_injection", sev, "", None)
        assert 1 <= len(out) <= 3, f"{sev}: {out}"


def test_low_severity_yields_single_step() -> None:
    out = _remediation_suggestions("data_exfiltration", "low", "", None)
    assert len(out) == 1


def test_critical_includes_aegis_deploy_step_when_rule_present() -> None:
    out = _remediation_suggestions("prompt_injection", "critical", "", "block 'ignore previous'")
    assert any("Aegis rule" in s for s in out)


def test_no_aegis_step_when_rule_absent() -> None:
    out = _remediation_suggestions("prompt_injection", "critical", "", None)
    assert not any("Aegis rule" in s for s in out)


def test_unknown_family_uses_default_triad() -> None:
    out = _remediation_suggestions("totally_unknown_family", "high", "", None)
    assert len(out) >= 1
    assert all(isinstance(s, str) and s.strip() for s in out)


def test_build_vulnerabilities_emits_remediation_alias_and_suggestions() -> None:
    findings = [
        _finding("prompt_injection", "critical", {"mitigation": "Sanitise inputs.", "evidence": "x"}),
        _finding("rag_poisoning", "high", {"remediation_code_snippet": "verify_hash(doc)"}),
    ]
    vulns = _build_vulnerabilities(findings)
    assert len(vulns) == 2
    # Worst first (critical before high)
    assert vulns[0]["severity"] == "critical"
    for v in vulns:
        assert "remediation" in v and isinstance(v["remediation"], str)
        assert "remediation_suggestions" in v
        assert 1 <= len(v["remediation_suggestions"]) <= 3
    # The aegis rule snippet is surfaced on the rag_poisoning finding.
    rag = next(v for v in vulns if v["family"] == "rag_poisoning")
    assert rag["aegis_rule"] == "verify_hash(doc)"
    assert any("Aegis rule" in s for s in rag["remediation_suggestions"])


def test_build_vulnerabilities_dedupes_same_attack_severity() -> None:
    findings = [_finding("jailbreak", "high"), _finding("jailbreak", "high"), _finding("jailbreak", "medium")]
    vulns = _build_vulnerabilities(findings)
    assert len(vulns) == 2

"""Tests for impact amplification."""

from __future__ import annotations

from bountymode.autonomous.amplify import (
    Amplifier,
    ChainAmplifier,
    DataExposureProver,
    PrivilegeEscalationProver,
    classify_exposed_data,
)
from bountymode.models import Finding, Observation, Severity
from bountymode.triage.scorer import TriageScorer
from bountymode.upgrades.cross_tenant import PrincipalResponse


def _finding(**kwargs) -> Finding:
    base = dict(
        id="F-1", title="t", technique_id="x", target="api.acme.example",
        category="data_exfiltration", severity=Severity.LOW,
    )
    base.update(kwargs)
    return Finding(**base)


class TestDataClassification:
    def test_detects_a_credential(self) -> None:
        name, severity, hits = classify_exposed_data("key sk-abcdefghijklmnopqrstuvwxyz012345")
        assert name == "credential"
        assert severity == Severity.CRITICAL
        assert hits

    def test_detects_pii(self) -> None:
        name, severity, _ = classify_exposed_data("ssn 123-45-6789")
        assert name == "pii"
        assert severity.rank >= Severity.HIGH.rank

    def test_detects_a_system_prompt(self) -> None:
        name, _, _ = classify_exposed_data("Here is my system prompt: you are a helpful bot")
        assert name == "system_prompt"

    def test_benign_text_is_none(self) -> None:
        name, severity, hits = classify_exposed_data("the weather is nice today")
        assert name == "none"
        assert hits == []

    def test_credential_outranks_pii(self) -> None:
        name, _, _ = classify_exposed_data("email a@b.com and key sk-abcdefghijklmnopqrstuvwxyz01")
        assert name == "credential"


class TestDataExposureProver:
    def test_lifts_severity_for_a_credential(self) -> None:
        finding = _finding(actual="leaked sk-abcdefghijklmnopqrstuvwxyz012345")
        amp = DataExposureProver().prove(finding)
        assert amp.amplified
        assert amp.to_severity == "critical"

    def test_no_lift_for_benign_data(self) -> None:
        finding = _finding(actual="hello world")
        amp = DataExposureProver().prove(finding)
        assert not amp.amplified
        assert amp.rationale

    def test_no_lift_when_already_critical(self) -> None:
        finding = _finding(severity=Severity.CRITICAL,
                           actual="sk-abcdefghijklmnopqrstuvwxyz012345")
        assert not DataExposureProver().prove(finding).amplified


class TestPrivilegeEscalationProver:
    def test_two_principal_differential_proves_escalation(self) -> None:
        owner = PrincipalResponse(
            principal="owner", status=200,
            response='{"account_id": "acct-1", "email": "o@x.com"}',
            markers=["acct-1", "o@x.com"],
        )
        attacker = PrincipalResponse(
            principal="attacker", status=200,
            response='{"account_id": "acct-1", "email": "o@x.com"}',
        )
        amp = PrivilegeEscalationProver().prove(_finding(), owner=owner, attacker=attacker)
        assert amp.amplified
        assert amp.to_severity == "critical"

    def test_differential_without_a_leak_does_not_amplify(self) -> None:
        owner = PrincipalResponse(
            principal="owner", status=200, response='{"account_id": "acct-1"}',
            markers=["acct-1"],
        )
        attacker = PrincipalResponse(
            principal="attacker", status=200, response='{"account_id": "acct-2"}',
        )
        amp = PrivilegeEscalationProver().prove(_finding(), owner=owner, attacker=attacker)
        assert not amp.amplified

    def test_escalation_language_raises_to_high(self) -> None:
        finding = _finding(actual="admin role granted; you can manage billing for the tenant")
        amp = PrivilegeEscalationProver().prove(finding)
        assert amp.amplified
        assert amp.to_severity == "high"

    def test_no_evidence_means_no_claim(self) -> None:
        amp = PrivilegeEscalationProver().prove(_finding(actual="ok"))
        assert not amp.amplified


class TestChainAmplifier:
    def test_builds_a_chain_from_two_findings(self) -> None:
        leak = _finding(id="F-1", category="system_prompt_leak", severity=Severity.LOW)
        exfil = _finding(id="F-2", category="data_exfiltration", severity=Severity.MEDIUM)
        amps = ChainAmplifier().amplify([leak, exfil])
        assert amps
        assert amps[0].kind == "chain"
        assert amps[0].chain

    def test_single_finding_has_no_chain(self) -> None:
        assert ChainAmplifier().amplify([_finding()]) == []

    def test_no_findings_no_chains(self) -> None:
        assert ChainAmplifier().amplify([]) == []


class TestAmplifierFacade:
    def test_apply_sets_a_severity_floor(self) -> None:
        finding = _finding(actual="leaked sk-abcdefghijklmnopqrstuvwxyz012345")
        Amplifier().amplify([finding], apply=True)
        assert finding.severity_floor is not None
        assert finding.severity_floor.rank >= Severity.CRITICAL.rank

    def test_apply_appends_the_rationale_to_impact(self) -> None:
        finding = _finding(actual="leaked sk-abcdefghijklmnopqrstuvwxyz012345")
        Amplifier().amplify([finding], apply=True)
        assert "amplified" in finding.impact

    def test_apply_false_leaves_the_finding_untouched(self) -> None:
        finding = _finding(actual="leaked sk-abcdefghijklmnopqrstuvwxyz012345")
        Amplifier().amplify([finding], apply=False)
        assert finding.severity_floor is None

    def test_floor_makes_the_scorer_agree_with_the_label(self) -> None:
        """A 'critical' finding must not ship with a low CVSS score."""
        finding = _finding(actual="leaked sk-abcdefghijklmnopqrstuvwxyz012345")
        Amplifier().amplify([finding], apply=True)
        TriageScorer().score_all([finding])
        assert finding.severity == Severity.CRITICAL
        assert finding.cvss_score >= 9.0

    def test_amplification_never_lowers_severity(self) -> None:
        finding = _finding(severity=Severity.CRITICAL, actual="benign")
        Amplifier().amplify([finding], apply=True)
        assert finding.severity == Severity.CRITICAL

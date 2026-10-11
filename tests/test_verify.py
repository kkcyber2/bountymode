"""Tests for the generic vulnerability verification system.

Covers, in order:

* oracle selection -- the right oracle for each finding class, and the generic
  fallback for anything unclassified;
* the negative control -- the mechanism that tells a real finding from a target
  that simply echoes input;
* N-of-M reproduction counting -- a stable finding verifies, a flaky one does
  not, and the test probe is genuinely re-sent each attempt while the baselines
  are cached;
* submission readiness -- a complete, verified, evidenced finding is ready; an
  incomplete or unverified one is not, and the gap is named;
* the pipeline -- a full offline run produces a verified verdict and evidence,
  and the report carries it.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from bountymode.evidence.redactor import Redactor
from bountymode.evidence.vault import EvidenceVault
from bountymode.models import Finding, Severity
from bountymode.verify import (
    GenericVerifier,
    SimulatedTarget,
    SubmissionReadinessChecker,
    callable_sender,
    select_oracle,
    simulated_sender,
)
from bountymode.verify.oracles import (
    INCONCLUSIVE,
    UNVERIFIED,
    VERIFIED,
    AccessControlOracle,
    DifferentialOracle,
    ErrorBasedOracle,
    InjectionOracle,
    LeakageOracle,
    ReflectionOracle,
    TimingOracle,
)
from bountymode.verify.probe import Probe, ProbeResult


# --------------------------------------------------------------------------- #
# fixtures
# --------------------------------------------------------------------------- #

def make_finding(
    *,
    fid: str = "F-test",
    category: str = "prompt_injection",
    technique: str = "prompt_injection",
    severity: Severity = Severity.HIGH,
    complete: bool = True,
) -> Finding:
    """A finding that is complete enough to be submittable unless asked not to be."""
    return Finding(
        id=fid,
        title=f"{category.replace('_', ' ').title()} on api.acme.com",
        technique_id=technique,
        target="api.acme.com",
        category=category,
        severity=severity,
        affected_asset="api.acme.com",
        description="The target complied with an injected instruction." if complete else "",
        impact=(
            "An attacker can override the assistant's instructions and control its "
            "behaviour for the session."
            if complete else ""
        ),
        remediation="Separate trusted instructions from untrusted input." if complete else "",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" if complete else "",
        cvss_score=9.1 if complete else 0.0,
    )


class FlakySender:
    """A sender that reports a hit on a chosen subset of *test* attempts.

    Used to prove N-of-M actually counts: ``hits`` controls which test attempt
    indices look compromised, so the reproduction rate is deterministic.  The
    control and negative baselines are cached by the probe runner, so only the
    test probes are re-sent -- hence the separate ``test_calls`` counter.
    """

    def __init__(self, *, hits: set, canary_source: str = "VERIFY-ABCDEF") -> None:
        self.hits = set(hits)
        self.canary_source = canary_source
        self.test_calls = 0
        self.other_calls = 0

    def __call__(self, probe: Probe) -> ProbeResult:
        if probe.role != "test":
            self.other_calls += 1
            # Controls and negatives never leak the marker.
            return ProbeResult(
                role=probe.role,
                response="Sure - a support assistant helps users resolve issues.",
                ok=True, status=200,
            )
        self.test_calls += 1
        if self.test_calls in self.hits:
            # A test probe that "fires": return the marker the probe carried.
            import re
            m = re.search(r"VERIFY-[A-Za-z0-9]{4,}", probe.prompt)
            marker = m.group(0) if m else self.canary_source
            return ProbeResult(role=probe.role, response=f"Sure. {marker}", ok=True, status=200)
        return ProbeResult(
            role=probe.role,
            response="I'm sorry, I can't help with that request.",
            ok=True, status=200,
        )


def leaky_sender(probe: Probe) -> ProbeResult:
    """A target that echoes any marker it is given -- the false-positive trap."""
    import re
    markers = re.findall(r"VERIFY-[A-Za-z0-9]{4,}", probe.prompt)
    body = "Sure, here it is: " + ", ".join(markers) if markers else "ok"
    return ProbeResult(role=probe.role, response=body, ok=True, status=200)


def dead_sender(probe: Probe) -> ProbeResult:
    """A transport that is down: every probe errors."""
    return ProbeResult(role=probe.role, ok=False, error="ConnectionRefusedError: down")


# --------------------------------------------------------------------------- #
# 1. oracle selection
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "category,expected",
    [
        ("prompt_injection", InjectionOracle),
        ("indirect_injection", InjectionOracle),
        ("jailbreak", InjectionOracle),
        ("data_exfiltration", LeakageOracle),
        ("system_prompt_leak", LeakageOracle),
        ("idor", AccessControlOracle),
        ("access_control", AccessControlOracle),
        ("cross_tenant", AccessControlOracle),
        ("sqli", ErrorBasedOracle),
        ("path_traversal", ErrorBasedOracle),
        ("xss", ReflectionOracle),
        ("output_handling", ReflectionOracle),
        ("time_based", TimingOracle),
        ("something_unclassified", DifferentialOracle),
    ],
)
def test_oracle_selection_by_class(category: str, expected: type) -> None:
    assert isinstance(select_oracle(category), expected)


def test_oracle_fallback_for_unknown_class() -> None:
    oracle = select_oracle("totally_made_up_class", "mystery_technique")
    assert oracle.name == DifferentialOracle.name


def test_every_oracle_builds_a_three_probe_set() -> None:
    for category in ("prompt_injection", "data_exfiltration", "idor", "sqli", "xss"):
        probes = select_oracle(category).build_probes(
            category=category, target="api.acme.com", technique_id=category
        )
        roles = [p.role for p in probes.ordered()]
        assert roles == ["test", "control", "negative"]


# --------------------------------------------------------------------------- #
# 2. negative control
# --------------------------------------------------------------------------- #

def test_negative_control_stops_a_false_positive() -> None:
    """A target that echoes any marker must NOT be reported as verified."""
    finding = make_finding()
    report = GenericVerifier(attempts=3).verify(finding, leaky_sender)
    assert report.verdict == UNVERIFIED
    assert report.negative_control_passed is False
    assert report.negative_control_fired > 0
    assert any("negative control" in r.lower() for r in report.reasons)
    assert finding.reproducible is False


def test_a_genuinely_vulnerable_target_verifies() -> None:
    finding = make_finding()
    report = GenericVerifier(attempts=3).verify(
        finding, simulated_sender(SimulatedTarget(vulnerable=True))
    )
    assert report.verdict == VERIFIED
    assert report.negative_control_passed is True
    assert report.successes == report.attempts
    assert report.stable is True
    assert finding.reproducible is True


def test_a_hardened_target_does_not_verify() -> None:
    finding = make_finding()
    report = GenericVerifier(attempts=3).verify(
        finding, simulated_sender(SimulatedTarget(vulnerable=False))
    )
    assert report.verdict == UNVERIFIED
    assert report.successes == 0
    assert finding.reproducible is False


# --------------------------------------------------------------------------- #
# 3. N-of-M reproduction counting
# --------------------------------------------------------------------------- #

def test_reproduction_rate_is_measured_not_assumed() -> None:
    # 2 of 5 attempts fire -> 40%, below the 60% threshold -> unverified.
    finding = make_finding()
    sender = FlakySender(hits={1, 3})
    report = GenericVerifier(attempts=5).verify(finding, sender)
    assert report.attempts == 5
    assert report.successes == 2
    assert report.rate == pytest.approx(0.4)
    assert report.verdict == UNVERIFIED


def test_stable_reproduction_above_threshold_verifies() -> None:
    # 4 of 5 attempts fire -> 80% -> verified, but not stable.
    finding = make_finding()
    report = GenericVerifier(attempts=5).verify(finding, FlakySender(hits={1, 2, 3, 4}))
    assert report.successes == 4
    assert report.verdict == VERIFIED
    assert report.stable is False


def test_test_probe_is_resent_but_baselines_are_cached() -> None:
    """N-of-M must re-send the test probe, and must not re-send the baselines."""
    finding = make_finding()
    report = GenericVerifier(attempts=4).verify(
        finding, simulated_sender(SimulatedTarget(vulnerable=True))
    )
    # 4 test probes (fresh each attempt) + 1 control + 1 negative = 6 sent.
    assert report.requests_sent == 6
    # The 2 baselines were reused on the 3 remaining attempts = 6 reuses.
    assert report.requests_reused == 6
    assert report.requests_reused > 0


def test_transport_failure_is_inconclusive_not_a_finding() -> None:
    finding = make_finding()
    report = GenericVerifier(attempts=2).verify(finding, dead_sender)
    assert report.verdict == INCONCLUSIVE
    assert report.successes == 0
    assert finding.reproducible is False


def test_verifier_rejects_zero_attempts() -> None:
    with pytest.raises(ValueError):
        GenericVerifier(attempts=0)


# --------------------------------------------------------------------------- #
# 4. evidence capture
# --------------------------------------------------------------------------- #

def test_verification_captures_proof_and_the_negative_control() -> None:
    finding = make_finding()
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        vault = EvidenceVault(tmp, redactor=Redactor())
        report = GenericVerifier(attempts=3).verify(
            finding, simulated_sender(SimulatedTarget(vulnerable=True)), vault=vault
        )
        assert report.evidence_captured >= 1
        assert finding.observations
        kinds = {o.kind for o in finding.observations}
        assert "http" in kinds           # the proof
        assert "control" in kinds        # the do-nothing baseline that did not fire
        assert vault.verify_chain() is True


# --------------------------------------------------------------------------- #
# 5. submission readiness
# --------------------------------------------------------------------------- #

def test_complete_verified_finding_is_submission_ready() -> None:
    finding = make_finding()
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        vault = EvidenceVault(tmp, redactor=Redactor())
        report = GenericVerifier(attempts=3).verify(
            finding, simulated_sender(SimulatedTarget(vulnerable=True)),
            vault=vault, in_scope=True,
        )
    readiness = report.readiness
    assert readiness["ready"] is True, readiness
    assert readiness["blockers"] == []
    assert readiness["summary"].startswith("Ready to submit")


def test_incomplete_finding_is_not_ready_and_names_the_gaps() -> None:
    finding = make_finding(complete=False)
    report = GenericVerifier(attempts=3).verify(
        finding, simulated_sender(SimulatedTarget(vulnerable=True))
    )
    readiness = report.readiness
    assert readiness["ready"] is False
    labels = " ".join(readiness["blockers"] + readiness["missing"]).lower()
    for expected in ("description", "impact", "remediation", "cvss", "evidence"):
        assert expected in labels, f"{expected!r} missing from {labels!r}"
    assert "NOT submission-ready" in readiness["summary"]


def test_unverified_finding_is_never_ready() -> None:
    finding = make_finding()
    report = GenericVerifier(attempts=3).verify(
        finding, simulated_sender(SimulatedTarget(vulnerable=False))
    )
    assert report.readiness["ready"] is False
    assert any("verification" in b.lower() for b in report.readiness["blockers"])


def test_out_of_scope_finding_is_blocked() -> None:
    finding = make_finding()
    report = GenericVerifier(attempts=2).verify(
        finding, simulated_sender(SimulatedTarget(vulnerable=True)), in_scope=False
    )
    assert report.readiness["ready"] is False
    assert any("scope" in b.lower() for b in report.readiness["blockers"])


def test_word_inside_a_real_field_is_not_treated_as_a_placeholder() -> None:
    """A real description that merely mentions "unknown" is not empty."""
    finding = make_finding()
    finding.description = (
        "The rag_poisoning test succeeded against api.acme.com (model unknown) "
        "because the retrieved document overrode the curated context."
    )
    report = GenericVerifier(attempts=2).verify(
        finding, simulated_sender(SimulatedTarget(vulnerable=True)), in_scope=True
    )
    desc = next(c for c in report.readiness["checks"] if c["key"] == "description")
    assert desc["passed"] is True
    assert "description" not in report.readiness["missing"]


def test_a_field_that_is_only_filler_is_still_caught() -> None:
    finding = make_finding()
    finding.impact = "N/A"
    report = GenericVerifier(attempts=2).verify(
        finding, simulated_sender(SimulatedTarget(vulnerable=True))
    )
    impact = next(c for c in report.readiness["checks"] if c["key"] == "impact")
    assert impact["passed"] is False
    assert impact["detail"] == "placeholder text"


def test_readiness_checker_accepts_a_serialised_report() -> None:
    finding = make_finding()
    checker = SubmissionReadinessChecker()
    verdict = checker.check(finding, in_scope=True, verification={"verdict": "verified", "rate": 1.0})
    assert any(c.key == "verification" and c.passed for c in verdict.checks)


# --------------------------------------------------------------------------- #
# 6. pipeline integration
# --------------------------------------------------------------------------- #

@pytest.mark.skipif(
    not __import__("bountymode.engine.paths", fromlist=["engine_available"]).engine_available(),
    reason="engine/ is not vendored in this checkout",
)
def test_pipeline_verifies_and_evidences_end_to_end() -> None:
    from bountymode.program import GuidedPipeline

    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        scope_path = Path(tmp) / "scope.json"
        scope_path.write_text(json.dumps({
            "program": "acme", "platform": "hackerone",
            "in_scope": [{"pattern": "api.acme.com", "kind": "llm"}],
            "out_of_scope": [],
        }), encoding="utf-8")
        out_dir = Path(tmp) / "run"
        result = GuidedPipeline(attempts=3).run_from_file(
            str(scope_path), approved_by="alice", domain="ai_llm",
            target="api.acme.com", out_dir=str(out_dir), offline=True, in_process=True,
        )

        stages = {s.name: s for s in result.stages}
        assert stages["verify"].ok and stages["readiness"].ok and stages["report"].ok
        assert result.findings, "the offline dry run should produce findings"
        assert result.verified_count >= 1
        assert result.verified[0]["verdict"] == VERIFIED

        # The verdict must be on the finding and reflected in readiness.
        first = result.findings[0]
        assert first.verification_attempts == 3
        assert first.reproducible is True

        # Evidence is on disk and redacted (no raw secret committed).
        evidence_files = list((out_dir / "evidence").rglob("*.json"))
        assert evidence_files
        for path in evidence_files:
            assert "sk-SIMULATED" not in path.read_text(encoding="utf-8")

        # The pipeline result JSON records the verdict and the counts.
        payload = json.loads((out_dir / "pipeline-result.json").read_text(encoding="utf-8"))
        assert payload["verified_count"] >= 1
        assert payload["verified"][0]["verdict"] == VERIFIED


# --------------------------------------------------------------------------- #
# 7. UI endpoint
# --------------------------------------------------------------------------- #

@pytest.fixture()
def client() -> TestClient:
    from bountymode.ui.app import create_app

    return TestClient(create_app())


def test_ui_verify_endpoint_reports_a_verdict(client: TestClient) -> None:
    finding = make_finding().to_dict()
    r = client.post("/api/verify", json={"finding": finding, "attempts": 3, "vulnerable": True})
    assert r.status_code == 200
    payload = r.json()
    assert payload["verdict"] == VERIFIED
    assert payload["report"]["successes"] == 3
    assert payload["readiness"]["ready"] is True
    assert payload["requests_reused"] > 0


def test_ui_verify_endpoint_reports_unverified_for_a_hardened_target(client: TestClient) -> None:
    finding = make_finding().to_dict()
    r = client.post("/api/verify", json={"finding": finding, "attempts": 2, "vulnerable": False})
    assert r.status_code == 200
    assert r.json()["verdict"] == UNVERIFIED
    assert r.json()["readiness"]["ready"] is False


def test_ui_verify_endpoint_rejects_a_bad_finding(client: TestClient) -> None:
    r = client.post("/api/verify", json={"finding": {"severity": "not-a-severity"}})
    assert r.status_code == 400

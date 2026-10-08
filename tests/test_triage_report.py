"""Tests for CVSS, triage scoring, report generation and de-duplication."""

from __future__ import annotations

import json

import pytest

from bountymode.dedupe import DedupRegistry, DedupVerdict
from bountymode.models import Finding, Severity
from bountymode.report import ReportGenerator
from bountymode.triage import CVSSv31, TriageScorer, score_vector


# --------------------------------------------------------------------------- #
# CVSS
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "vector,expected",
    [
        # FIRST-published reference vectors
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),
    ],
)
def test_cvss_reference_vectors(vector, expected):
    assert score_vector(vector) == pytest.approx(expected, abs=0.05)


def test_cvss_no_impact_is_zero():
    assert CVSSv31(C="N", I="N", A="N").base_score() == 0.0


# --------------------------------------------------------------------------- #
# triage
# --------------------------------------------------------------------------- #

def _finding(**kw) -> Finding:
    base = dict(
        id="F-1", title="t", technique_id="x", target="api.acme.com",
        category="prompt_injection", affected_asset="api.acme.com",
        reproducible=True, reproduction_rate=1.0, confidence=0.95,
        impact="impact", remediation="fix it", description="desc",
        expected="refuse", actual="complied",
    )
    base.update(kw)
    return Finding(**base)


def test_triage_ranks_cross_tenant_above_single_user():
    scorer = TriageScorer()
    cross = _finding(id="F-ct", category="cross_tenant", blast_radius="cross-tenant",
                     privileges_required="low")
    single = _finding(id="F-su", category="jailbreak", blast_radius="single-user")
    ranked = scorer.ranked_findings([single, cross])
    assert ranked[0].id == "F-ct"
    assert ranked[0].cvss_score > ranked[1].cvss_score


def test_triage_drops_non_reproducible_findings():
    scorer = TriageScorer()
    f = _finding(reproducible=False, reproduction_rate=0.0, confidence=0.3)
    r = scorer.score(f)
    assert r.priority == 0
    assert any("not reproducibly verified" in x for x in r.rationale)
    assert any("dropped" in x for x in r.rationale)


def test_triage_clamps_system_prompt_leak_to_low():
    scorer = TriageScorer()
    f = _finding(category="system_prompt_leak")
    r = scorer.score(f)
    assert r.severity in (Severity.LOW, Severity.INFO)
    assert r.cvss_score <= 3.9


def test_triage_assigns_severity_and_vector_to_finding():
    scorer = TriageScorer()
    f = _finding(category="data_exfiltration")
    scorer.ranked_findings([f])
    assert f.cvss_score > 0
    assert f.cvss_vector.startswith("CVSS:3.1/")
    assert f.severity in (Severity.HIGH, Severity.CRITICAL, Severity.MEDIUM)


# --------------------------------------------------------------------------- #
# reports
# --------------------------------------------------------------------------- #

def test_report_validation_flags_missing_fields():
    gen = ReportGenerator("hackerone")
    bare = Finding(id="F-x", title="", technique_id="x", target="a.com",
                   category="prompt_injection")
    v = gen.validate(bare)
    assert v.ok is False
    assert set(v.missing) >= {"title", "impact", "remediation", "description"}


def test_report_renders_required_sections_and_is_submittable():
    gen = ReportGenerator("hackerone", program="acme")
    f = _finding()
    TriageScorer().ranked_findings([f])
    v = gen.validate(f)
    assert v.ok is True
    rep = gen.render(f, strict=True)
    for section in ["## Summary", "## Affected Asset", "## Steps To Reproduce",
                    "## Impact", "## Remediation", "## Supporting Material"]:
        assert section in rep.markdown
    assert "CVSS:3.1/" in rep.markdown
    assert rep.structured["affected_asset"] == "api.acme.com"
    assert rep.structured["severity_label"] == rep.severity.capitalize()


def test_report_written_json_is_a_submission_payload(tmp_path):
    gen = ReportGenerator("bugcrowd")
    f = _finding()
    TriageScorer().ranked_findings([f])
    paths = gen.write(gen.render(f), str(tmp_path))
    data = json.loads(open(paths["json"]).read())
    assert data["platform"] == "bugcrowd"
    assert data["severity_label"] in {"P1", "P2", "P3", "P4", "P5"}
    assert data["report_meta"]["finding_id"] == "F-1"


def test_strict_report_raises_for_incomplete_finding():
    gen = ReportGenerator("bugcrowd")
    bare = Finding(id="F-y", title="only a title", technique_id="x", target="a.com",
                   category="prompt_injection")
    with pytest.raises(Exception):
        gen.render(bare, strict=True)


def test_report_writes_markdown_and_json(tmp_path):
    gen = ReportGenerator("bugcrowd")
    f = _finding()
    TriageScorer().ranked_findings([f])
    paths = gen.write(gen.render(f), str(tmp_path))
    md = open(paths["markdown"]).read()
    data = json.loads(open(paths["json"]).read())
    assert "Reproduction Steps" in md
    assert data["platform"] == "bugcrowd"
    assert data["severity_label"] in {"P1", "P2", "P3", "P4", "P5"}


# --------------------------------------------------------------------------- #
# dedupe
# --------------------------------------------------------------------------- #

def test_dedup_flags_identical_fingerprint():
    reg = DedupRegistry()
    a = _finding(id="F-a")
    b = _finding(id="F-b")
    assert reg.add(a).verdict == DedupVerdict.NEW
    assert reg.add(b).verdict == DedupVerdict.DUPLICATE


def test_dedup_likely_duplicate_on_same_category_and_asset():
    reg = DedupRegistry()
    reg.add(_finding(id="F-c", title="Leak via prompt"))
    other = _finding(id="F-d", title="A completely different title")
    res = reg.check(other)
    assert res.verdict == DedupVerdict.LIKELY_DUPLICATE


def test_dedup_registry_persists_and_reloads(tmp_path):
    path = str(tmp_path / "registry.json")
    reg = DedupRegistry(path)
    reg.add(_finding(id="F-p"))
    assert reg.check(_finding(id="F-q")).verdict == DedupVerdict.DUPLICATE

    reloaded = DedupRegistry(path)
    assert reloaded.check(_finding(id="F-r")).verdict == DedupVerdict.DUPLICATE


def test_retest_marks_fixed():
    reg = DedupRegistry()
    reg.add(_finding(id="F-fix"))
    updated = reg.mark_retest("F-fix", still_reproduces=False, note="patched")
    assert updated is not None and updated.status == "fixed"

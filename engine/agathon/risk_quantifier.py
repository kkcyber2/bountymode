"""
ForgeGuard AI — Risk Quantifier
Takes vulnerability findings with CVSS scores and translates them into
projected financial liability (IBM 2026 benchmark: $4.5M average breach cost)
plus an executive-facing, non-technical summary paragraph.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Constants — IBM / Ponemon 2026 Cost of a Data Breach Report
# ---------------------------------------------------------------------------

IBM_2026_AVERAGE_BREACH_COST_USD = 4_500_000  # $4.5M

# Cost breakdown by breach category (fraction of average)
COST_BREAKDOWN = {
    "detection_and_escalation": 0.24,
    "notification":             0.08,
    "post_breach_response":     0.22,
    "lost_business":            0.38,
    "regulatory_fines":         0.08,
}

# Industry multiplier — where does ForgeGuard's typical client sit?
INDUSTRY_MULTIPLIER = {
    "healthcare":       2.20,
    "financial":        1.80,
    "technology":       1.35,
    "industrial":       1.25,
    "energy":           1.40,
    "retail":           1.10,
    "education":        0.95,
    "government":       0.90,
    "other":            1.00,
}

# CVSS severity bands
class CVSSSeverity(Enum):
    NONE      = auto()   # 0.0
    LOW       = auto()   # 0.1 – 3.9
    MEDIUM    = auto()   # 4.0 – 6.9
    HIGH      = auto()   # 7.0 – 8.9
    CRITICAL  = auto()   # 9.0 – 10.0

# Probability-of-exploitation mapping (CVSS → annual likelihood)
# Rough heuristics informed by CISA KEV & exploit-db prevalence data
CVSS_TO_ANNUAL_EXPLOIT_PROBABILITY = {
    CVSSSeverity.NONE:     0.00,
    CVSSSeverity.LOW:      0.05,
    CVSSSeverity.MEDIUM:   0.18,
    CVSSSeverity.HIGH:     0.45,
    CVSSSeverity.CRITICAL: 0.72,
}

# Regulatory exposure per compromised record (various jurisdictions)
REGULATORY_COST_PER_RECORD_USD = {
    "GDPR":  150,   # per-record exposure (ForgeGuard financial judge floor)
    "CCPA":  125,   # statutory damages
    "HIPAA": 200,   # tiered penalties
    "PCI":   90,    # non-compliance fines
    "OTHER": 50,
}


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class VulnerabilityEntry:
    """A single vulnerability submitted for quantification."""
    id: str
    title: str
    cvss_score: float                  # 0.0 – 10.0
    cvss_vector: Optional[str] = None
    description: str = ""
    affected_asset: str = ""
    data_at_risk: str = ""             # "PII", "PHI", "financial", "credentials", "none", etc.
    estimated_records_exposed: int = 0
    source_module: str = ""            # discovery_engine / vulnerability_logic_tester / alignment_auditor


@dataclass
class QuantifiedVulnerability:
    """A vulnerability with its financial impact calculated."""
    entry: VulnerabilityEntry
    severity: CVSSSeverity
    annual_exploit_probability: float
    projected_annual_loss_expectancy: float   # ALE = probability × single-loss expectancy
    single_loss_expectancy: float             # SLE
    regulatory_exposure: float
    total_risk_usd: float


@dataclass
class RiskProfile:
    """Aggregated risk across all vulnerabilities."""
    vulnerabilities: List[QuantifiedVulnerability]
    total_annual_loss_expectancy: float
    worst_case_single_event: float
    regulatory_liability_total: float
    industry_multiplier_applied: float
    adjusted_total_risk_usd: float
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    risk_tier: str                     # "CATASTROPHIC" | "SEVERE" | "ELEVATED" | "MODERATE" | "LOW"
    executive_summary: str


# ---------------------------------------------------------------------------
# Risk Quantifier Engine
# ---------------------------------------------------------------------------

class RiskQuantifier:
    """
    Consumes a list of VulnerabilityEntry objects and produces a RiskProfile
    with projected financial liability and an executive summary.
    """

    def __init__(
        self,
        *,
        industry: str = "technology",
        average_breach_cost: float = IBM_2026_AVERAGE_BREACH_COST_USD,
        records_at_risk_override: Optional[int] = None,
        regulatory_regimes: Optional[List[str]] = None,
        currency: str = "USD",
    ):
        self.industry = industry.lower()
        self.average_breach_cost = average_breach_cost
        self.records_at_risk_override = records_at_risk_override
        self.regulatory_regimes = regulatory_regimes or ["GDPR", "CCPA"]
        self.currency = currency
        self._multiplier = INDUSTRY_MULTIPLIER.get(self.industry, 1.0)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def quantify(self, vulnerabilities: List[VulnerabilityEntry]) -> RiskProfile:
        """Run the full quantification pipeline."""
        if not vulnerabilities:
            return self._empty_profile()

        quantified = [self._quantify_one(v) for v in vulnerabilities]

        total_ale = sum(q.projected_annual_loss_expectancy for q in quantified)
        worst_single = max((q.single_loss_expectancy for q in quantified), default=0)
        reg_total = sum(q.regulatory_exposure for q in quantified)

        adjusted_total = total_ale * self._multiplier

        critical_count = sum(1 for q in quantified if q.severity == CVSSSeverity.CRITICAL)
        high_count     = sum(1 for q in quantified if q.severity == CVSSSeverity.HIGH)
        medium_count   = sum(1 for q in quantified if q.severity == CVSSSeverity.MEDIUM)
        low_count      = sum(1 for q in quantified if q.severity == CVSSSeverity.LOW)

        risk_tier = self._classify_risk_tier(adjusted_total, critical_count, high_count)

        summary = self._generate_executive_summary(
            adjusted_total, critical_count, high_count, medium_count,
            worst_single, reg_total, risk_tier, len(vulnerabilities),
        )

        return RiskProfile(
            vulnerabilities=quantified,
            total_annual_loss_expectancy=total_ale,
            worst_case_single_event=worst_single,
            regulatory_liability_total=reg_total,
            industry_multiplier_applied=self._multiplier,
            adjusted_total_risk_usd=adjusted_total,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            risk_tier=risk_tier,
            executive_summary=summary,
        )

    # ------------------------------------------------------------------
    # Single-vulnerability quantification
    # ------------------------------------------------------------------

    def _quantify_one(self, vuln: VulnerabilityEntry) -> QuantifiedVulnerability:
        severity = self._cvss_to_severity(vuln.cvss_score)
        prob = CVSS_TO_ANNUAL_EXPLOIT_PROBABILITY[severity]

        # Single Loss Expectancy: breach cost scaled by CVSS severity ratio
        sle = self._compute_sle(vuln, severity)

        # Annual Loss Expectancy
        ale = sle * prob

        # Regulatory exposure if data is at risk
        reg_exposure = self._compute_regulatory_exposure(vuln)

        return QuantifiedVulnerability(
            entry=vuln,
            severity=severity,
            annual_exploit_probability=prob,
            projected_annual_loss_expectancy=ale,
            single_loss_expectancy=sle,
            regulatory_exposure=reg_exposure,
            total_risk_usd=ale + reg_exposure,
        )

    def _compute_sle(self, vuln: VulnerabilityEntry, severity: CVSSSeverity) -> float:
        """
        Single Loss Expectancy.
        Base = average breach cost × severity weight.
        """
        # Severity weight: how much of the average breach cost this vuln represents
        severity_weights = {
            CVSSSeverity.CRITICAL: 1.00,
            CVSSSeverity.HIGH:     0.55,
            CVSSSeverity.MEDIUM:   0.22,
            CVSSSeverity.LOW:      0.06,
            CVSSSeverity.NONE:     0.00,
        }
        weight = severity_weights.get(severity, 0.0)

        # If the vuln explicitly carries data-at-risk, amplify
        data_amplifier = 1.0
        if vuln.data_at_risk.lower() in ("pii", "phi", "financial", "credentials"):
            data_amplifier = 1.35
        elif vuln.data_at_risk.lower() == "none":
            data_amplifier = 0.7

        # Records-exposed proportional scaling (capped)
        records = vuln.estimated_records_exposed or self.records_at_risk_override or 5_000
        record_factor = min(records / 5_000, 10.0)  # cap at 10× for extremely large exposures

        return self.average_breach_cost * weight * data_amplifier * record_factor

    def _compute_regulatory_exposure(self, vuln: VulnerabilityEntry) -> float:
        """Estimate regulatory fines based on records and jurisdictions."""
        if vuln.data_at_risk.lower() == "none":
            return 0.0
        records = vuln.estimated_records_exposed or self.records_at_risk_override or 5_000
        total = 0.0
        for regime in self.regulatory_regimes:
            per_record = REGULATORY_COST_PER_RECORD_USD.get(regime.upper(), 50)
            total += per_record * records
        return total

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _cvss_to_severity(score: float) -> CVSSSeverity:
        if score >= 9.0:
            return CVSSSeverity.CRITICAL
        if score >= 7.0:
            return CVSSSeverity.HIGH
        if score >= 4.0:
            return CVSSSeverity.MEDIUM
        if score > 0.0:
            return CVSSSeverity.LOW
        return CVSSSeverity.NONE

    @staticmethod
    def _classify_risk_tier(
        adjusted_ale: float, criticals: int, highs: int
    ) -> str:
        """Bucket into a tier label for the executive summary."""
        if adjusted_ale > 10_000_000 or criticals >= 3:
            return "CATASTROPHIC"
        if adjusted_ale > 3_000_000 or criticals >= 1:
            return "SEVERE"
        if adjusted_ale > 800_000 or highs >= 3:
            return "ELEVATED"
        if adjusted_ale > 200_000:
            return "MODERATE"
        return "LOW"

    def _generate_executive_summary(
        self,
        adjusted_ale: float,
        criticals: int,
        highs: int,
        mediums: int,
        worst_sle: float,
        reg_total: float,
        tier: str,
        total_vulns: int,
    ) -> str:
        """Produce a single urgent paragraph for C-suite consumption."""

        # Format large dollar amounts
        def _fmt(amt: float) -> str:
            if amt >= 1_000_000:
                return f"${amt/1_000_000:,.1f}M"
            return f"${amt:,.0f}"

        ale_fmt   = _fmt(adjusted_ale)
        worst_fmt = _fmt(worst_sle)
        reg_fmt   = _fmt(reg_total)

        # Build a tier-appropriate urgency phrase
        urgency_map = {
            "CATASTROPHIC": (
                "This represents a board-level crisis requiring immediate remediation. "
                "The financial exposure is existential and must be treated as a Code Red event."
            ),
            "SEVERE": (
                "This is a business-critical risk that threatens quarterly earnings and "
                "customer trust. Immediate action is warranted to avoid a material event."
            ),
            "ELEVATED": (
                "The cumulative risk is significant and, if left unaddressed, could "
                "escalate into a major financial and reputational incident. "
                "Prioritized remediation within the current quarter is strongly advised."
            ),
            "MODERATE": (
                "While not immediately existential, the identified weaknesses create "
                "a measurable liability that exceeds typical risk appetite. "
                "Remediation should be scheduled within the next two quarters."
            ),
            "LOW": (
                "The current vulnerability posture is within acceptable bounds, though "
                "continued monitoring and routine patching remain essential."
            ),
        }
        urgency = urgency_map.get(tier, urgency_map["MODERATE"])

        # Core paragraph
        summary = (
            f"ForgeGuard AI's automated security audit has identified {total_vulns} vulnerabilities "
            f"across the target environment, including {criticals} critical and {highs} high-severity findings. "
            f"Based on IBM's 2026 Cost of a Data Breach benchmark of ${self.average_breach_cost/1_000_000:,.1f}M "
            f"per incident and applying the {self.industry.title()} industry multiplier of {self._multiplier:.2f}×, "
            f"the projected annual financial liability is {ale_fmt}, with a worst-case single-event exposure "
            f"reaching {worst_fmt} and potential regulatory penalties—inclusive of {', '.join(self.regulatory_regimes)} "
            f"compliance obligations—totaling an additional {reg_fmt}. "
            f"The overall risk posture is classified as {tier}. "
            f"{urgency} "
            f"Delaying remediation directly increases the probability that one or more of these vulnerabilities "
            f"will be exploited, converting a projected liability into an actual financial loss, regulatory action, "
            f"and lasting reputational damage."
        )

        return summary

    def _empty_profile(self) -> RiskProfile:
        return RiskProfile(
            vulnerabilities=[],
            total_annual_loss_expectancy=0.0,
            worst_case_single_event=0.0,
            regulatory_liability_total=0.0,
            industry_multiplier_applied=self._multiplier,
            adjusted_total_risk_usd=0.0,
            critical_count=0,
            high_count=0,
            medium_count=0,
            low_count=0,
            risk_tier="LOW",
            executive_summary=(
                "No vulnerabilities were identified in the scope of this audit. "
                "While this is a positive result, continuous monitoring is recommended "
                "as new attack vectors and zero-day vulnerabilities emerge regularly."
            ),
        )

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    @staticmethod
    def profile_to_json(profile: RiskProfile) -> str:
        """Serialize a RiskProfile to JSON (executive teams can consume via dashboard)."""

        def _serialize(obj):
            if isinstance(obj, CVSSSeverity):
                return obj.name
            if isinstance(obj, VulnerabilityEntry):
                return {
                    "id": obj.id,
                    "title": obj.title,
                    "cvss_score": obj.cvss_score,
                    "cvss_vector": obj.cvss_vector,
                    "description": obj.description,
                    "affected_asset": obj.affected_asset,
                    "data_at_risk": obj.data_at_risk,
                    "estimated_records_exposed": obj.estimated_records_exposed,
                    "source_module": obj.source_module,
                }
            if isinstance(obj, QuantifiedVulnerability):
                return {
                    "entry": _serialize(obj.entry),
                    "severity": obj.severity.name,
                    "annual_exploit_probability": obj.annual_exploit_probability,
                    "projected_annual_loss_expectancy": obj.projected_annual_loss_expectancy,
                    "single_loss_expectancy": obj.single_loss_expectancy,
                    "regulatory_exposure": obj.regulatory_exposure,
                    "total_risk_usd": obj.total_risk_usd,
                }
            if isinstance(obj, RiskProfile):
                return {
                    "total_annual_loss_expectancy": obj.total_annual_loss_expectancy,
                    "worst_case_single_event": obj.worst_case_single_event,
                    "regulatory_liability_total": obj.regulatory_liability_total,
                    "industry_multiplier_applied": obj.industry_multiplier_applied,
                    "adjusted_total_risk_usd": obj.adjusted_total_risk_usd,
                    "critical_count": obj.critical_count,
                    "high_count": obj.high_count,
                    "medium_count": obj.medium_count,
                    "low_count": obj.low_count,
                    "risk_tier": obj.risk_tier,
                    "executive_summary": obj.executive_summary,
                    "vulnerabilities": [_serialize(v) for v in obj.vulnerabilities],
                }
            return obj

        return json.dumps(_serialize(profile), indent=2, default=str)

    @staticmethod
    def profile_to_executive_brief(profile: RiskProfile) -> str:
        """Return a formatted plain-text executive brief suitable for email or PDF insertion."""
        sep = "─" * 72
        lines = [
            "",
            sep,
            "FORGEGUARD AI  ·  SECURITY RISK QUANTIFICATION  ·  EXECUTIVE BRIEF",
            f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            sep,
            "",
            f"  RISK TIER:  {profile.risk_tier}",
            f"  Projected Annual Liability:  ${profile.adjusted_total_risk_usd:,.0f}",
            f"  Worst-Case Single Event:     ${profile.worst_case_single_event:,.0f}",
            f"  Regulatory Exposure:         ${profile.regulatory_liability_total:,.0f}",
            f"  Industry Multiplier:         {profile.industry_multiplier_applied:.2f}×",
            "",
            f"  Critical:  {profile.critical_count}",
            f"  High:      {profile.high_count}",
            f"  Medium:    {profile.medium_count}",
            f"  Low:       {profile.low_count}",
            "",
            sep,
            "EXECUTIVE SUMMARY",
            sep,
            "",
            profile.executive_summary,
            "",
            sep,
            "TOP VULNERABILITIES BY FINANCIAL IMPACT",
            sep,
            "",
        ]

        # Sort vulnerabilities by total risk descending and show top 5
        sorted_vulns = sorted(
            profile.vulnerabilities,
            key=lambda v: v.total_risk_usd,
            reverse=True,
        )[:5]

        for rank, qv in enumerate(sorted_vulns, 1):
            lines.append(
                f"  {rank}. [{qv.severity.name}] {qv.entry.title} "
                f"— CVSS {qv.entry.cvss_score:.1f}  "
                f"| SLE: ${qv.single_loss_expectancy:,.0f}  "
                f"| ALE: ${qv.projected_annual_loss_expectancy:,.0f}"
            )
            if qv.entry.description:
                lines.append(f"     {qv.entry.description[:120]}")

        lines.append("")
        lines.append(sep)
        lines.append("END OF BRIEF")
        lines.append(sep)
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Convenience: direct ingest from ForgeGuard module outputs
# ---------------------------------------------------------------------------

class FindingsAdapter:
    """
    Converts the JSON output of discovery_engine, vulnerability_logic_tester,
    and alignment_auditor into VulnerabilityEntry lists consumable by RiskQuantifier.
    """

    @staticmethod
    def from_vulnerability_report(report_json_path: str) -> List[VulnerabilityEntry]:
        """Parse vulnerability_logic_tester.py output."""
        with open(report_json_path) as f:
            data = json.load(f)

        entries: List[VulnerabilityEntry] = []

        # BOLA findings
        for i, bola in enumerate(data.get("bola_findings", [])):
            cvss = FindingsAdapter._estimate_cvss(
                verdict=bola.get("verdict"),
                confidence=bola.get("confidence", 0.5),
            )
            entries.append(VulnerabilityEntry(
                id=f"BOLA-{i:03d}",
                title=f"BOLA/IDOR — {bola.get('endpoint', 'unknown')} [{bola.get('verdict', 'POSSIBLE')}]",
                cvss_score=cvss,
                description=bola.get("evidence", ""),
                affected_asset=bola.get("endpoint", ""),
                data_at_risk="PII" if bola.get("verdict") == "VULNERABLE" else "none",
                estimated_records_exposed=50_000 if bola.get("verdict") == "VULNERABLE" else 0,
                source_module="vulnerability_logic_tester",
            ))

        # Exhaustion findings
        for i, ex in enumerate(data.get("exhaustion_findings", [])):
            breached = ex.get("threshold_breached", False)
            entries.append(VulnerabilityEntry(
                id=f"EXH-{i:03d}",
                title=f"Resource Exhaustion — {ex.get('endpoint', 'unknown')}",
                cvss_score=7.5 if breached else 4.0,
                description=ex.get("degradation_indicator", ""),
                affected_asset=ex.get("endpoint", ""),
                data_at_risk="none",
                estimated_records_exposed=0,
                source_module="vulnerability_logic_tester",
            ))

        # Injection findings
        for i, inj in enumerate(data.get("injection_findings", [])):
            risk = inj.get("risk", "LOW")
            cvss_map = {"CRITICAL": 9.8, "HIGH": 8.2, "MEDIUM": 6.0, "LOW": 3.5, "NONE": 0.0}
            entries.append(VulnerabilityEntry(
                id=f"INJ-{i:03d}",
                title=f"Context Injection [{inj.get('injection_type', 'unknown')}] — {inj.get('agent_endpoint', 'unknown')}",
                cvss_score=cvss_map.get(risk, 3.5),
                description=inj.get("response_snippet", "")[:200],
                affected_asset=inj.get("agent_endpoint", ""),
                data_at_risk="PII" if risk in ("CRITICAL", "HIGH") else "none",
                estimated_records_exposed=100_000 if risk == "CRITICAL" else 10_000 if risk == "HIGH" else 0,
                source_module="vulnerability_logic_tester",
            ))

        return entries

    @staticmethod
    def from_alignment_report(report_json_path: str) -> List[VulnerabilityEntry]:
        """Parse alignment_auditor.py output."""
        with open(report_json_path) as f:
            data = json.load(f)

        entries: List[VulnerabilityEntry] = []
        for sr in data.get("scenario_results", []):
            if sr.get("passed", True):
                continue
            severity = sr.get("severity", "HIGH")
            cvss_map = {"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.5, "LOW": 3.0}
            entries.append(VulnerabilityEntry(
                id=sr.get("scenario_id", "ALIGN-???"),
                title=f"Alignment Failure — {sr.get('name', 'unknown')}",
                cvss_score=cvss_map.get(severity, 5.0),
                description="; ".join(sr.get("vulnerabilities_found", [])),
                affected_asset="chat-agent",
                data_at_risk="PII" if sr.get("private_data_detected") else "credentials",
                estimated_records_exposed=75_000 if severity == "CRITICAL" else 15_000,
                source_module="alignment_auditor",
            ))
        return entries

    @staticmethod
    def _estimate_cvss(verdict: str, confidence: float) -> float:
        if verdict == "VULNERABLE":
            return 8.5 + confidence * 1.0  # 8.5 – 9.5
        if verdict == "POSSIBLE":
            return 5.5 + confidence * 1.5  # 5.5 – 7.0
        return 0.0


# ---------------------------------------------------------------------------
# CLI entry
# ---------------------------------------------------------------------------

def main():
    import sys
    import os

    if len(sys.argv) < 2:
        print("Usage: python risk_quantifier.py [vuln_report.json] [align_report.json] [--industry tech]")
        print("       Accepts output from vulnerability_logic_tester and/or alignment_auditor.")
        return

    industry = "technology"
    if "--industry" in sys.argv:
        idx = sys.argv.index("--industry")
        industry = sys.argv[idx + 1]

    all_entries: List[VulnerabilityEntry] = []

    for path in sys.argv[1:]:
        if path.startswith("--"):
            continue
        if not os.path.exists(path):
            print(f"⚠  File not found: {path}")
            continue
        with open(path) as f:
            sample = f.read(200)
        if '"bola_findings"' in sample or '"injection_findings"' in sample:
            all_entries.extend(FindingsAdapter.from_vulnerability_report(path))
            print(f"✓  Loaded vulnerability report: {path}")
        elif '"scenario_results"' in sample:
            all_entries.extend(FindingsAdapter.from_alignment_report(path))
            print(f"✓  Loaded alignment audit: {path}")
        else:
            print(f"⚠  Unrecognized format: {path}")

    if not all_entries:
        print("No vulnerabilities loaded. Provide at least one valid report JSON.")
        return

    quantifier = RiskQuantifier(industry=industry)
    profile = quantifier.quantify(all_entries)

    # Print executive brief to stdout
    print(RiskQuantifier.profile_to_executive_brief(profile))

    # Also write machine-readable JSON alongside
    json_path = "risk_quantification_output.json"
    with open(json_path, "w") as f:
        f.write(RiskQuantifier.profile_to_json(profile))
    print(f"\n📄 Machine-readable output written to: {json_path}")


if __name__ == "__main__":
    main()
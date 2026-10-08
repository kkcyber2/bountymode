"""
Sovereign Customs Agent — DeepSeek-R1 bazaar script audit.

Checks:
  (A) Dangerous bunker-damage patterns (os.remove, rm -rf via subprocess, etc.)
  (B) Functional security probe validity (legitimate red-team / compliance tooling)
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Optional

JUDGE_MODEL_LABEL = "deepseek/deepseek-r1"

# ── (A) Static bunker-damage patterns ───────────────────────────────────────

_DANGEROUS_PATTERNS: List[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bos\.remove\s*\(", re.I), "os.remove() — destructive file deletion"),
    (re.compile(r"\bos\.unlink\s*\(", re.I), "os.unlink() — destructive file deletion"),
    (re.compile(r"\bshutil\.rmtree\s*\(", re.I), "shutil.rmtree() — recursive directory wipe"),
    (re.compile(r"\bsubprocess\.(?:call|run|Popen)\s*\([^)]*['\"]rm\s+-rf", re.I | re.S),
     "subprocess invoking rm -rf"),
    (re.compile(r"\bsubprocess\.(?:call|run|Popen)\s*\([^)]*['\"]del\s+/[fs]", re.I | re.S),
     "subprocess invoking Windows mass delete"),
    (re.compile(r"['\"]rm\s+-rf\s+[/~]", re.I), "shell rm -rf against root or home"),
    (re.compile(r"\bos\.system\s*\(\s*['\"][^'\"]*rm\s+-rf", re.I),
     "os.system('rm -rf …')"),
    (re.compile(r"\beval\s*\(\s*compile\s*\(", re.I), "eval(compile(…)) — dynamic code exec"),
    (re.compile(r"\b__import__\s*\(\s*['\"]os['\"]\s*\)\.remove", re.I),
     "obfuscated os.remove via __import__"),
    (re.compile(r"\bsubprocess\.(?:call|run)\s*\(\s*['\"]format\s", re.I),
     "subprocess format/disk wipe"),
]

FORGEGUARD_INFRA_PATTERNS: List[tuple[re.Pattern[str], str]] = [
    (re.compile(r"supabase\.co", re.I), "targets Supabase infrastructure"),
    (re.compile(r"forgeguard-ai\.com|railway\.app|vercel\.app", re.I),
     "targets ForgeGuard / bunker hosting"),
    (re.compile(r"INTERNAL_SCAN_TOKEN|SERVICE_ROLE", re.I),
     "harvests internal credentials"),
]

BAZAAR_JUDGE_SYSTEM = (
    "You are the ForgeGuard Sovereign Customs Agent. "
    "Analyse uploaded Python security research scripts for marketplace listing.\n\n"
    "Return ONLY valid JSON with keys:\n"
    '{"is_functional_probe": <bool>, '
    '"verdict": "cleared|flagged|rejected", '
    '"risk_score": <0-100 integer>, '
    '"findings": ["..."], '
    '"reason": "<one sentence>", '
    '"remediation_advice": "<deployable guidance: how to safely run this probe, '
    'required scopes, WAF exceptions, and hardening notes>"}\n\n'
    "Rules:\n"
    "- cleared: legitimate security probe (LLM jailbreak test, API fuzzer, OWASP check) "
    "with clear test intent; risk_score 0-25\n"
    "- flagged: ambiguous or needs human review; risk_score 26-60\n"
    "- rejected: not a security probe OR clearly malicious; risk_score 61-100\n"
    "- remediation_advice MUST be concrete (env vars, rate limits, sandbox isolation) "
    "even for cleared scripts."
)


@dataclass
class BazaarAuditResult:
    verdict: str
    status: str
    risk_score: int
    findings: List[str] = field(default_factory=list)
    reason: str = ""
    remediation_advice: str = ""
    is_functional_probe: bool = False
    malicious_patterns: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def scan_dangerous_patterns(code: str) -> List[str]:
    """Return human-readable hits for bunker-damage signatures."""
    hits: List[str] = []
    for pattern, label in _DANGEROUS_PATTERNS + FORGEGUARD_INFRA_PATTERNS:
        if pattern.search(code):
            hits.append(label)
    return hits


def _parse_judge_json(raw: str) -> Dict[str, Any]:
    match = re.search(r"\{[\s\S]*\}", raw)
    if not match:
        return {}
    try:
        return json.loads(match.group())
    except json.JSONDecodeError:
        return {}


def _normalize_verdict(raw: str, risk_score: int) -> str:
    v = (raw or "").strip().lower()
    if v in ("cleared", "flagged", "rejected"):
        return v
    if risk_score >= 61:
        return "rejected"
    if risk_score >= 26:
        return "flagged"
    return "cleared"


def judge_bazaar_script(
    *,
    code: str,
    language: str = "python",
    name: str = "",
    description: str = "",
    judge_fn: Optional[Callable[[str, str], str]] = None,
) -> BazaarAuditResult:
    """
    Run Sovereign Customs audit.

    Static (A) runs first — any hit → immediate REJECTED.
    DeepSeek-R1 (B) validates probe legitimacy when judge_fn is available.
    """
    dangerous = scan_dangerous_patterns(code)
    if dangerous:
        return BazaarAuditResult(
            verdict="rejected",
            status="REJECTED",
            risk_score=100,
            findings=dangerous,
            reason="Malicious Script Attempt — bunker-damage patterns detected.",
            remediation_advice="Remove destructive system calls before resubmitting.",
            is_functional_probe=False,
            malicious_patterns=dangerous,
            metadata={
                "customs_agent": "sovereign",
                "audit_phase": "static_reject",
                "remediation_advice": "Remove os.remove, shutil.rmtree, subprocess rm -rf, and similar destructive calls.",
                "malicious_patterns": dangerous,
            },
        )

    if not judge_fn:
        return BazaarAuditResult(
            verdict="flagged",
            status="flagged",
            risk_score=40,
            findings=["DeepSeek-R1 judge unavailable — manual review required"],
            reason="Customs AI offline; queued for manual review.",
            remediation_advice="Await Sovereign operator clearance before deployment.",
            is_functional_probe=False,
            metadata={
                "customs_agent": "sovereign",
                "audit_phase": "judge_unavailable",
                "remediation_advice": "Await Sovereign operator clearance before deployment.",
            },
        )

    prompt = (
        f"Script name: {name or 'untitled'}\n"
        f"Language: {language}\n"
        f"Description: {description or 'none'}\n\n"
        f"```{language}\n{code[:8000]}\n```\n\n"
        "Determine if this is a functional security probe suitable for the ForgeGuard Bazaar."
    )

    try:
        raw = judge_fn(prompt, BAZAAR_JUDGE_SYSTEM)
        data = _parse_judge_json(raw)
    except Exception as exc:  # noqa: BLE001
        return BazaarAuditResult(
            verdict="flagged",
            status="flagged",
            risk_score=45,
            findings=[f"Judge error: {exc}"],
            reason="Customs audit failed — manual review required.",
            remediation_advice="Retry upload or contact Sovereign support.",
            metadata={
                "customs_agent": "sovereign",
                "audit_phase": "judge_error",
                "remediation_advice": "Retry upload or contact Sovereign support.",
            },
        )

    risk_score = max(0, min(100, int(data.get("risk_score") or 0)))
    verdict = _normalize_verdict(str(data.get("verdict") or ""), risk_score)
    is_probe = bool(data.get("is_functional_probe"))

    if verdict == "cleared" and not is_probe:
        verdict = "flagged"
        risk_score = max(risk_score, 30)

    if verdict == "rejected":
        status = "REJECTED"
    else:
        status = verdict

    findings = data.get("findings")
    if not isinstance(findings, list):
        findings = []
    findings = [str(f)[:300] for f in findings[:12]]

    remediation = str(data.get("remediation_advice") or "").strip()[:4000]
    if verdict == "cleared" and not remediation:
        remediation = (
            "Run in an isolated sandbox with scoped API keys. "
            "Apply rate limits and log all probe output for compliance review."
        )

    reason = str(data.get("reason") or "").strip()[:500]
    if verdict == "rejected" and not reason:
        reason = "Malicious Script Attempt — failed functional probe validation."

    metadata: Dict[str, Any] = {
        "customs_agent": "sovereign",
        "judge_model": JUDGE_MODEL_LABEL,
        "is_functional_probe": is_probe,
        "remediation_advice": remediation,
        "audit_findings": findings,
    }

    return BazaarAuditResult(
        verdict=verdict,
        status=status,
        risk_score=risk_score,
        findings=findings,
        reason=reason,
        remediation_advice=remediation,
        is_functional_probe=is_probe,
        metadata=metadata,
    )

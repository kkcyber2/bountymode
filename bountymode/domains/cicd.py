"""CI/CD & software-supply-chain red-teaming domain adapter.

Covers the pipeline classes that pay on supply-chain programs: dependency
confusion, pipeline poisoning, secret exposure in logs, unpinned actions,
artifact/cache poisoning and over-permissioned pipeline tokens.
"""

from __future__ import annotations

from typing import Any, Dict, List

from ..models import Severity, Technique
from .base import DomainAdapter

_KB: Dict[str, Dict[str, Any]] = {
    "dependency_confusion": {
        "impact": "An attacker can publish a higher-version package to a public registry and have it pulled instead of the internal one, executing code in the build.",
        "remediation": "Scope internal packages, pin versions, and configure the package manager to prefer the private registry.",
        "cwe": ["CWE-1104"], "owasp": ["A06:2021 Vulnerable and Outdated Components"],
        "blast": "system", "severity": Severity.CRITICAL,
    },
    "pipeline_poisoning": {
        "impact": "An attacker can modify the pipeline definition to run arbitrary code with the pipeline's credentials.",
        "remediation": "Require review on pipeline files, restrict who can push to protected branches, and run untrusted PRs without secrets.",
        "cwe": ["CWE-284"], "owasp": ["A08:2021 Software and Data Integrity Failures"],
        "blast": "system", "severity": Severity.CRITICAL,
    },
    "secret_in_logs": {
        "impact": "Credentials are printed to build logs, exposing them to anyone who can read the logs.",
        "remediation": "Mask secrets, avoid echoing them, and rotate anything that has been logged.",
        "cwe": ["CWE-532"], "owasp": ["A09:2021 Security Logging and Monitoring Failures"],
        "blast": "multi-user", "severity": Severity.HIGH,
    },
    "unpinned_action": {
        "impact": "A third-party action referenced by a mutable tag can be changed to malicious code at any time.",
        "remediation": "Pin third-party actions to a full commit SHA and review updates.",
        "cwe": ["CWE-1104"], "owasp": ["A08:2021 Software and Data Integrity Failures"],
        "blast": "system", "severity": Severity.HIGH,
    },
    "artifact_poisoning": {
        "impact": "An attacker can replace a build artifact so downstream consumers deploy malicious code.",
        "remediation": "Sign artifacts, verify signatures on consumption, and restrict who can publish.",
        "cwe": ["CWE-345"], "owasp": ["A08:2021 Software and Data Integrity Failures"],
        "blast": "system", "severity": Severity.HIGH,
    },
    "pr_target_injection": {
        "impact": "A pull-request title/branch is interpolated into a shell command, allowing command injection in CI.",
        "remediation": "Never interpolate untrusted context into run steps; pass values via environment variables and quote them.",
        "cwe": ["CWE-78"], "owasp": ["A03:2021 Injection"],
        "blast": "system", "severity": Severity.CRITICAL,
    },
    "self_hosted_runner_abuse": {
        "impact": "An attacker can run code on a self-hosted runner and persist on the host.",
        "remediation": "Never run untrusted code on self-hosted runners; use ephemeral, isolated runners.",
        "cwe": ["CWE-284"], "owasp": ["A08:2021 Software and Data Integrity Failures"],
        "blast": "system", "severity": Severity.HIGH,
    },
    "token_overpermission": {
        "impact": "The pipeline token can write to the repo or cloud, so a compromised job can push code or escalate.",
        "remediation": "Set least-privilege token permissions and default to read-only.",
        "cwe": ["CWE-250"], "owasp": ["A01:2021 Broken Access Control"],
        "blast": "system", "severity": Severity.HIGH,
    },
    "cache_poisoning": {
        "impact": "An attacker can poison a shared build cache so later trusted builds consume malicious content.",
        "remediation": "Isolate caches per trust boundary and never restore untrusted caches into privileged jobs.",
        "cwe": ["CWE-345"], "owasp": ["A08:2021 Software and Data Integrity Failures"],
        "blast": "system", "severity": Severity.MEDIUM,
    },
    "sbom_missing": {
        "impact": "Without an SBOM, vulnerable or malicious components cannot be tracked or responded to.",
        "remediation": "Generate and store an SBOM per build and scan it for known-bad components.",
        "cwe": ["CWE-1104"], "owasp": ["A06:2021 Vulnerable and Outdated Components"],
        "blast": "multi-user", "severity": Severity.LOW,
    },
}


def _t(tid: str, name: str, category: str, sev: str, **kw: Any) -> Technique:
    return Technique(tid, name, engine_key=tid, category=category, severity_hint=sev, **kw)


class CicdAdapter(DomainAdapter):
    """CI/CD & supply-chain red-teaming domain."""

    name = "cicd"
    description = "CI/CD & supply chain: dependency confusion, pipeline poisoning, secrets."
    scope_kind = "repo"

    def techniques(self) -> List[Technique]:
        return [
            _t("dependency_confusion", "Dependency confusion", "dependency_confusion", "critical"),
            _t("pipeline_poisoning", "Pipeline definition poisoning", "pipeline_poisoning", "critical", requires_auth=True),
            _t("secret_in_logs", "Secret exposure in build logs", "secret_in_logs", "high"),
            _t("unpinned_action", "Unpinned third-party action", "unpinned_action", "high"),
            _t("artifact_poisoning", "Build artifact poisoning", "artifact_poisoning", "high"),
            _t("pr_target_injection", "PR-context command injection", "pr_target_injection", "critical"),
            _t("self_hosted_runner_abuse", "Self-hosted runner abuse", "self_hosted_runner_abuse", "high"),
            _t("token_overpermission", "Over-permissioned pipeline token", "token_overpermission", "high"),
            _t("cache_poisoning", "Build cache poisoning", "cache_poisoning", "medium"),
            _t("sbom_missing", "Missing SBOM", "sbom_missing", "low"),
        ]

    def _kb(self, category: str) -> Dict[str, Any]:
        return _KB.get(category, _KB["unpinned_action"])

    def impact(self, category: str) -> str:
        return self._kb(category)["impact"]

    def remediation(self, category: str) -> str:
        return self._kb(category)["remediation"]

    def taxonomy(self, category: str) -> Dict[str, List[str]]:
        kb = self._kb(category)
        return {"cwe": list(kb["cwe"]), "owasp_llm": [], "mitre_atlas": []}

    def blast_radius(self, category: str) -> str:
        return self._kb(category)["blast"]

    def severity_hint(self, category: str) -> Severity:
        return self._kb(category)["severity"]

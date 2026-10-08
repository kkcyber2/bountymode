"""Cloud & infrastructure red-teaming domain adapter.

Covers the misconfiguration and IAM classes that pay on cloud programs:
public storage, over-permissive roles, privilege escalation, exposed metadata,
missing encryption/logging and cross-account trust abuse.
"""

from __future__ import annotations

from typing import Any, Dict, List

from ..models import Severity, Technique
from .base import DomainAdapter

_KB: Dict[str, Dict[str, Any]] = {
    "public_bucket": {
        "impact": "An attacker can read (or write) storage objects that should be private.",
        "remediation": "Block public access at the account level, audit bucket policies, and enable access logging.",
        "cwe": ["CWE-284"], "owasp": ["A01:2021 Broken Access Control"],
        "blast": "system", "severity": Severity.CRITICAL,
    },
    "iam_privesc": {
        "impact": "An attacker with a low-privilege identity can escalate to administrative control of the account.",
        "remediation": "Remove wildcard actions/resources, apply least privilege, and use permission boundaries and SCPs.",
        "cwe": ["CWE-269"], "owasp": ["A01:2021 Broken Access Control"],
        "blast": "system", "severity": Severity.CRITICAL,
    },
    "overpermissive_role": {
        "impact": "A role grants far more than it needs, widening the blast radius of any compromise.",
        "remediation": "Right-size policies from access logs; replace wildcards with explicit actions.",
        "cwe": ["CWE-250"], "owasp": ["A01:2021 Broken Access Control"],
        "blast": "multi-user", "severity": Severity.HIGH,
    },
    "metadata_ssrf": {
        "impact": "An attacker can reach the instance metadata service and steal temporary credentials.",
        "remediation": "Require IMDSv2, restrict egress, and block link-local ranges at the network layer.",
        "cwe": ["CWE-918"], "owasp": ["A10:2021 Server-Side Request Forgery"],
        "blast": "system", "severity": Severity.CRITICAL,
    },
    "open_security_group": {
        "impact": "A management or database port is exposed to the internet.",
        "remediation": "Restrict ingress to known CIDRs, prefer private networking, and review security groups continuously.",
        "cwe": ["CWE-284"], "owasp": ["A05:2021 Security Misconfiguration"],
        "blast": "system", "severity": Severity.HIGH,
    },
    "unencrypted_storage": {
        "impact": "Data at rest is readable if the underlying medium is compromised.",
        "remediation": "Enable default encryption on all storage and enforce it via policy.",
        "cwe": ["CWE-311"], "owasp": ["A02:2021 Cryptographic Failures"],
        "blast": "multi-user", "severity": Severity.MEDIUM,
    },
    "logging_disabled": {
        "impact": "Attacks go undetected because audit logging is off or not centralised.",
        "remediation": "Enable account/audit logging, ship logs to an immutable store, and alert on sensitive actions.",
        "cwe": ["CWE-778"], "owasp": ["A09:2021 Security Logging and Monitoring Failures"],
        "blast": "system", "severity": Severity.MEDIUM,
    },
    "key_rotation_missing": {
        "impact": "Long-lived credentials widen the window of exposure if leaked.",
        "remediation": "Rotate keys on a schedule, prefer short-lived credentials, and remove unused keys.",
        "cwe": ["CWE-798"], "owasp": ["A07:2021 Identification and Authentication Failures"],
        "blast": "multi-user", "severity": Severity.MEDIUM,
    },
    "cross_account_trust": {
        "impact": "An external account can assume a role in the target account.",
        "remediation": "Scope trust policies to specific principals and add external-id conditions.",
        "cwe": ["CWE-284"], "owasp": ["A01:2021 Broken Access Control"],
        "blast": "system", "severity": Severity.HIGH,
    },
    "container_escape_config": {
        "impact": "A container runs privileged or with host mounts, enabling escape to the node.",
        "remediation": "Drop capabilities, run read-only, avoid hostPath, and enforce pod security standards.",
        "cwe": ["CWE-250"], "owasp": ["A05:2021 Security Misconfiguration"],
        "blast": "system", "severity": Severity.HIGH,
    },
}


def _t(tid: str, name: str, category: str, sev: str, **kw: Any) -> Technique:
    return Technique(tid, name, engine_key=tid, category=category, severity_hint=sev, **kw)


class CloudAdapter(DomainAdapter):
    """Cloud & infrastructure red-teaming domain."""

    name = "cloud"
    description = "Cloud & infra: IAM privesc, public storage, metadata SSRF, misconfig."
    scope_kind = "cloud"

    def techniques(self) -> List[Technique]:
        return [
            _t("public_bucket", "Public storage bucket", "public_bucket", "critical"),
            _t("iam_privesc", "IAM privilege escalation", "iam_privesc", "critical", requires_auth=True),
            _t("overpermissive_role", "Over-permissive role", "overpermissive_role", "high", requires_auth=True),
            _t("metadata_ssrf", "Instance metadata SSRF", "metadata_ssrf", "critical"),
            _t("open_security_group", "Internet-exposed port", "open_security_group", "high"),
            _t("unencrypted_storage", "Unencrypted storage", "unencrypted_storage", "medium"),
            _t("logging_disabled", "Audit logging disabled", "logging_disabled", "medium"),
            _t("key_rotation_missing", "Stale / unrotated keys", "key_rotation_missing", "medium"),
            _t("cross_account_trust", "Cross-account trust abuse", "cross_account_trust", "high"),
            _t("container_escape_config", "Container escape configuration", "container_escape_config", "high"),
        ]

    def _kb(self, category: str) -> Dict[str, Any]:
        return _KB.get(category, _KB["overpermissive_role"])

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

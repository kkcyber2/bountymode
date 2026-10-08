"""Web application / API red-teaming domain adapter.

Covers the classic web bug classes that pay on every platform: IDOR, auth
bypass, SSRF, business-logic abuse, injection sinks and access-control flaws.
The adapter is deliberately *catalogue + interpretation* only -- the actual
HTTP work is done by the engine (or an OSS tool such as ZAP / Nuclei) behind
the same authorization gate.
"""

from __future__ import annotations

from typing import Any, Dict, List

from ..models import Severity, Technique
from .base import DomainAdapter

_KB: Dict[str, Dict[str, Any]] = {
    "idor": {
        "impact": "An attacker can access another user's objects by changing an identifier, breaking object-level authorization.",
        "remediation": "Enforce object-level authorization on every request server-side, keyed to the authenticated principal -- never trust a client-supplied id.",
        "cwe": ["CWE-639"], "owasp": ["A01:2021 Broken Access Control"],
        "blast": "multi-user", "severity": Severity.HIGH,
    },
    "auth_bypass": {
        "impact": "An attacker can reach authenticated functionality without valid credentials.",
        "remediation": "Centralise authentication in middleware, deny by default, and add tests that assert every protected route rejects anonymous requests.",
        "cwe": ["CWE-287"], "owasp": ["A07:2021 Identification and Authentication Failures"],
        "blast": "system", "severity": Severity.CRITICAL,
    },
    "ssrf": {
        "impact": "An attacker can make the server issue requests to internal services, reaching systems behind the firewall.",
        "remediation": "Allow-list outbound destinations, block link-local/metadata ranges, and resolve-then-validate the final IP before connecting.",
        "cwe": ["CWE-918"], "owasp": ["A10:2021 Server-Side Request Forgery"],
        "blast": "system", "severity": Severity.HIGH,
    },
    "business_logic": {
        "impact": "An attacker can abuse a workflow to gain value (price, quantity, state) the business did not intend.",
        "remediation": "Re-validate business invariants server-side on every state transition; never trust client-computed totals or state.",
        "cwe": ["CWE-840"], "owasp": ["A04:2021 Insecure Design"],
        "blast": "multi-user", "severity": Severity.HIGH,
    },
    "xss": {
        "impact": "An attacker can execute script in a victim's browser session.",
        "remediation": "Context-aware output encoding, a strict Content-Security-Policy, and never inject untrusted data into the DOM unsafely.",
        "cwe": ["CWE-79"], "owasp": ["A03:2021 Injection"],
        "blast": "multi-user", "severity": Severity.HIGH,
    },
    "sqli": {
        "impact": "An attacker can read or modify the database, potentially exfiltrating all data.",
        "remediation": "Use parameterised queries everywhere; never build SQL by string concatenation.",
        "cwe": ["CWE-89"], "owasp": ["A03:2021 Injection"],
        "blast": "system", "severity": Severity.CRITICAL,
    },
    "open_redirect": {
        "impact": "An attacker can redirect users to a malicious site from a trusted domain, aiding phishing.",
        "remediation": "Allow-list redirect destinations or use relative paths only.",
        "cwe": ["CWE-601"], "owasp": ["A01:2021 Broken Access Control"],
        "blast": "single-user", "severity": Severity.LOW,
    },
    "csrf": {
        "impact": "An attacker can make a victim's browser perform an unwanted state-changing request.",
        "remediation": "Use anti-CSRF tokens and SameSite cookies on all state-changing endpoints.",
        "cwe": ["CWE-352"], "owasp": ["A01:2021 Broken Access Control"],
        "blast": "single-user", "severity": Severity.MEDIUM,
    },
    "path_traversal": {
        "impact": "An attacker can read files outside the intended directory.",
        "remediation": "Canonicalise paths and confine them to an allow-listed base directory; reject traversal sequences.",
        "cwe": ["CWE-22"], "owasp": ["A01:2021 Broken Access Control"],
        "blast": "system", "severity": Severity.HIGH,
    },
    "jwt_weakness": {
        "impact": "An attacker can forge or tamper with tokens to impersonate another user.",
        "remediation": "Pin the algorithm, verify signatures with a strong key, reject 'none', and validate all claims.",
        "cwe": ["CWE-347"], "owasp": ["A02:2021 Cryptographic Failures"],
        "blast": "system", "severity": Severity.CRITICAL,
    },
    "mass_assignment": {
        "impact": "An attacker can set fields they should not control (e.g. role, isAdmin) by over-posting.",
        "remediation": "Bind only allow-listed fields from the request into the model.",
        "cwe": ["CWE-915"], "owasp": ["A01:2021 Broken Access Control"],
        "blast": "multi-user", "severity": Severity.HIGH,
    },
    "graphql_introspection": {
        "impact": "An attacker can enumerate the full schema and hidden fields, easing further attacks.",
        "remediation": "Disable introspection in production and enforce field-level authorization.",
        "cwe": ["CWE-200"], "owasp": ["A01:2021 Broken Access Control"],
        "blast": "single-user", "severity": Severity.LOW,
    },
    "rate_limit_bypass": {
        "impact": "An attacker can bypass throttling to brute-force credentials or abuse an endpoint.",
        "remediation": "Enforce rate limits server-side keyed to identity, not to spoofable headers.",
        "cwe": ["CWE-770"], "owasp": ["A04:2021 Insecure Design"],
        "blast": "multi-user", "severity": Severity.MEDIUM,
    },
    "api_versioning_bypass": {
        "impact": "An attacker can reach a deprecated, unpatched API version that still exposes the old behaviour.",
        "remediation": "Retire old versions, and apply the same authorization to every version.",
        "cwe": ["CWE-1059"], "owasp": ["A01:2021 Broken Access Control"],
        "blast": "multi-user", "severity": Severity.MEDIUM,
    },
}


def _t(tid: str, name: str, category: str, sev: str, **kw: Any) -> Technique:
    return Technique(tid, name, engine_key=tid, category=category, severity_hint=sev, **kw)


class WebApiAdapter(DomainAdapter):
    """Web application / API red-teaming domain."""

    name = "web_api"
    description = "Web app & API: IDOR, auth bypass, SSRF, business logic, injection."
    scope_kind = "web"

    def techniques(self) -> List[Technique]:
        return [
            _t("idor", "Insecure direct object reference", "idor", "high", requires_auth=True),
            _t("auth_bypass", "Authentication bypass", "auth_bypass", "critical"),
            _t("ssrf", "Server-side request forgery", "ssrf", "high"),
            _t("business_logic", "Business-logic abuse", "business_logic", "high", requires_auth=True),
            _t("xss", "Cross-site scripting", "xss", "high"),
            _t("sqli", "SQL injection", "sqli", "critical"),
            _t("open_redirect", "Open redirect", "open_redirect", "low"),
            _t("csrf", "Cross-site request forgery", "csrf", "medium", requires_auth=True),
            _t("path_traversal", "Path traversal", "path_traversal", "high"),
            _t("jwt_weakness", "JWT / token weakness", "jwt_weakness", "critical"),
            _t("mass_assignment", "Mass assignment", "mass_assignment", "high", requires_auth=True),
            _t("graphql_introspection", "GraphQL introspection exposure", "graphql_introspection", "low"),
            _t("rate_limit_bypass", "Rate-limit bypass", "rate_limit_bypass", "medium"),
            _t("api_versioning_bypass", "Deprecated API version bypass", "api_versioning_bypass", "medium"),
        ]

    def _kb(self, category: str) -> Dict[str, Any]:
        return _KB.get(category, _KB["business_logic"])

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

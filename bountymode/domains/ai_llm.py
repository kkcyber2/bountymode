"""AI / LLM red-teaming domain adapter.

This is the *native* domain: it wraps the existing Agathon technique
catalogue and finding builder, so the AI domain behaves exactly as it did
before the framework was generalised.  It is the reference implementation of
:class:`~bountymode.domains.base.DomainAdapter`.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..models import Severity, Technique
from ..runner.adapter import (
    AgathonAdapter,
    EngineResult,
    FindingBuilder,
    TechniqueRegistry,
    _canonical_category,
)
from .base import DomainAdapter

#: category -> (impact, remediation, cwe, owasp_llm, blast_radius, severity)
_AI_KB: Dict[str, Dict[str, Any]] = {
    "prompt_injection": {
        "impact": "An attacker can override the model's instructions, gaining control of its behaviour for that session.",
        "remediation": "Never concatenate untrusted input into the instruction channel: keep system instructions separate from user/retrieved data, add an input classifier in front of the model, and validate the model's output before any downstream action relies on it.",
        "cwe": ["CWE-1426"], "owasp_llm": ["LLM01:2025 Prompt Injection"],
        "blast": "single-user", "severity": Severity.HIGH,
    },
    "indirect_injection": {
        "impact": "An attacker can plant instructions in content the model later consumes, hijacking it without direct access.",
        "remediation": "Treat every retrieved or ingested document as untrusted: strip or escape active content before it reaches the model and re-assert the trusted instructions after the untrusted block.",
        "cwe": ["CWE-1426"], "owasp_llm": ["LLM01:2025 Prompt Injection"],
        "blast": "multi-user", "severity": Severity.HIGH,
    },
    "data_exfiltration": {
        "impact": "An attacker can retrieve data the model was not permitted to disclose.",
        "remediation": "Keep secrets out of the prompt and retrieved context, run an output filter/DLP pass over every model response, and return the minimum data required. Rotate any credential that was exposed.",
        "cwe": ["CWE-200"], "owasp_llm": ["LLM02:2025 Sensitive Information Disclosure"],
        "blast": "multi-user", "severity": Severity.CRITICAL,
    },
    "system_prompt_leak": {
        "impact": "An attacker can recover internal instructions, weakening every guardrail built on them.",
        "remediation": "Stop relying on prompt secrecy: move sensitive logic out of the prompt into server-side controls and add an output filter that blocks verbatim system-instruction text.",
        "cwe": ["CWE-200"], "owasp_llm": ["LLM07:2025 System Prompt Leakage"],
        "blast": "single-user", "severity": Severity.MEDIUM,
    },
    "rag_poisoning": {
        "impact": "An attacker can skew the model's answers for every user by poisoning the knowledge base.",
        "remediation": "Restrict and vet writes to the knowledge base, sign/verify corpus content on ingestion, and re-check retrieved facts before they reach the model.",
        "cwe": ["CWE-1426"], "owasp_llm": ["LLM08:2025 Vector and Embedding Weaknesses"],
        "blast": "multi-user", "severity": Severity.HIGH,
    },
    "context_manipulation": {
        "impact": "An attacker can manipulate the model's context window to change its behaviour.",
        "remediation": "Bound and normalise the context window, cap caller-supplied tokens, and re-assert trusted instructions after any untrusted content.",
        "cwe": ["CWE-1426"], "owasp_llm": ["LLM01:2025 Prompt Injection"],
        "blast": "single-user", "severity": Severity.MEDIUM,
    },
    "jailbreak": {
        "impact": "An attacker can bypass the model's safety guardrails for that session.",
        "remediation": "Layer a policy model and input/output classifiers on top of the base guardrails; a bare jailbreak is low impact unless it yields data or an action.",
        "cwe": ["CWE-693"], "owasp_llm": ["LLM01:2025 Prompt Injection"],
        "blast": "single-user", "severity": Severity.LOW,
    },
    "tool_misuse": {
        "impact": "An attacker can cause the agent to take an unauthorized action on their behalf.",
        "remediation": "Require explicit confirmation for state-changing tool calls, allow-list tool arguments with schema validation, and give the agent's tools least-privilege credentials.",
        "cwe": ["CWE-862"], "owasp_llm": ["LLM06:2025 Excessive Agency"],
        "blast": "multi-user", "severity": Severity.CRITICAL,
    },
    "excessive_agency": {
        "impact": "An attacker can drive the agent to perform actions beyond its intended authority.",
        "remediation": "Apply least privilege to the agent's tools and require confirmation or an allow-list for any state-changing action.",
        "cwe": ["CWE-862"], "owasp_llm": ["LLM06:2025 Excessive Agency"],
        "blast": "multi-user", "severity": Severity.CRITICAL,
    },
    "access_control": {
        "impact": "An attacker can reach functionality or data they are not authorized for through the AI feature.",
        "remediation": "Enforce authorization server-side on the API endpoint, independent of anything the model says; never let the AI layer be the only access-control check.",
        "cwe": ["CWE-284"], "owasp_llm": [],
        "blast": "multi-user", "severity": Severity.HIGH,
    },
    "cross_tenant": {
        "impact": "An attacker can read another tenant's data through the AI feature -- a confidentiality breach across a trust boundary.",
        "remediation": "Bind the tenant id to the authenticated session (never to model input), authorize every retrieval/tool call server-side, and add a regression test asserting one tenant can never read another's rows.",
        "cwe": ["CWE-639"], "owasp_llm": ["LLM02:2025 Sensitive Information Disclosure"],
        "blast": "cross-tenant", "severity": Severity.CRITICAL,
    },
    "output_handling": {
        "impact": "Model output reaches a downstream sink unsanitised, enabling injection into the host application.",
        "remediation": "Treat model output as untrusted: encode/escape it before rendering and never pass it unsanitised into an HTML, SQL or shell sink.",
        "cwe": ["CWE-79"], "owasp_llm": ["LLM05:2025 Improper Output Handling"],
        "blast": "multi-user", "severity": Severity.HIGH,
    },
    "multimodal_injection": {
        "impact": "An attacker can smuggle instructions through an image, audio clip or document the model ingests.",
        "remediation": "Run OCR/ASR on every ingested asset, treat the extracted text as untrusted input, and apply the same injection defences as for text.",
        "cwe": ["CWE-1426"], "owasp_llm": ["LLM01:2025 Prompt Injection"],
        "blast": "multi-user", "severity": Severity.HIGH,
    },
    "memory_poisoning": {
        "impact": "An attacker can plant a persistent memory entry that changes the agent's behaviour in later sessions.",
        "remediation": "Scope memory writes to the authenticated user, validate and attribute every memory entry, and expire untrusted memory.",
        "cwe": ["CWE-1426"], "owasp_llm": ["LLM01:2025 Prompt Injection"],
        "blast": "multi-user", "severity": Severity.HIGH,
    },
    "supply_chain": {
        "impact": "A poisoned model, dataset or plugin can compromise every deployment that consumes it.",
        "remediation": "Pin and verify model/dataset/plugin provenance, check hashes and signatures, and scan dependencies before deployment.",
        "cwe": ["CWE-1104"], "owasp_llm": ["LLM03:2025 Supply Chain"],
        "blast": "system", "severity": Severity.HIGH,
    },
    "economic_denial": {
        "impact": "An attacker can exhaust the operator's token/cost budget.",
        "remediation": "Add per-user rate limits, token/cost budgets and request quotas, and alert on abnormal consumption.",
        "cwe": ["CWE-770"], "owasp_llm": ["LLM10:2025 Unbounded Consumption"],
        "blast": "multi-user", "severity": Severity.MEDIUM,
    },
}


class AiLlmAdapter(DomainAdapter):
    """The native AI/LLM red-teaming domain."""

    name = "ai_llm"
    description = "AI / LLM red-teaming: prompt injection, leakage, RAG, agency, multimodal."
    scope_kind = "llm"

    def __init__(
        self,
        registry: Optional[TechniqueRegistry] = None,
        builder: Optional[FindingBuilder] = None,
        engine: Optional[AgathonAdapter] = None,
    ) -> None:
        self._registry = registry or TechniqueRegistry()
        self._builder = builder or FindingBuilder()
        self._engine = engine

    # -- catalogue --------------------------------------------------------- #

    def techniques(self) -> List[Technique]:
        return self._registry.all()

    # -- execution --------------------------------------------------------- #

    def dispatch(
        self,
        technique: Technique,
        target: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> EngineResult:
        if self._engine is None:
            return super().dispatch(technique, target, params)
        return self._engine.run_test(technique, target, params=params)

    # -- interpretation ---------------------------------------------------- #

    def classify(self, result: EngineResult) -> str:
        return _canonical_category(result.vulnerability_type or result.technique_id)

    def _kb(self, category: str) -> Dict[str, Any]:
        return _AI_KB.get(category, _AI_KB["context_manipulation"])

    def impact(self, category: str) -> str:
        return self._kb(category)["impact"]

    def remediation(self, category: str) -> str:
        return self._kb(category)["remediation"]

    def taxonomy(self, category: str) -> Dict[str, List[str]]:
        kb = self._kb(category)
        return {"cwe": list(kb["cwe"]), "owasp_llm": list(kb["owasp_llm"]), "mitre_atlas": []}

    def blast_radius(self, category: str) -> str:
        return self._kb(category)["blast"]

    def severity_hint(self, category: str) -> Severity:
        return self._kb(category)["severity"]

    def build_finding(self, result: EngineResult):  # type: ignore[override]
        # Delegate to the original builder so AI findings are byte-identical
        # to the pre-framework behaviour (backwards compatibility).
        return self._builder.build(result)

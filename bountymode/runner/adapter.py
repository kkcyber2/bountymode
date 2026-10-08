"""Engine adapter — bridges Bounty Mode to the Agathon red-teaming engine.

Bounty Mode does not re-implement any attack.  It orchestrates the *existing*
techniques in the engine behind the authorization gate, then converts a raw
:class:`AttackResult` (the engine's contract in ``attacks/base_tester.py``)
into a Bounty Mode :class:`Finding`.

Two adapters ship here:

* :class:`TechniqueRegistry` — the catalogue of techniques, each mapped to an
  engine key (the Agathon attack/plugin id).
* :class:`AgathonAdapter` — a thin, dependency-free HTTP client for the
  engine's scan surface.  It *never* calls the engine unless the caller has
  already resolved an ALLOW decision; it is the runner's job to enforce that.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from ..models import Finding, Technique

# --------------------------------------------------------------------------- #
# Technique catalogue — mapped 1:1 onto the engine's real modules
# --------------------------------------------------------------------------- #

#: engine_key values are the module/plugin identifiers in the Agathon engine
#: (``attacks/<module>.py`` classes and ``agathon/plugins/*`` ids).
DEFAULT_TECHNIQUES: List[Technique] = [
    Technique("prompt_injection", "Direct prompt injection", "prompt_injection",
              "prompt_injection", "high", description="Attempt to override system instructions directly."),
    Technique("indirect_injection", "Indirect prompt injection", "indirect_prompt_injection",
              "indirect_injection", "high", requires_multimodal=True,
              description="Inject via retrieved/ingested content the model consumes."),
    Technique("data_exfiltration", "Sensitive data exfiltration", "data_exfiltration",
              "data_exfiltration", "critical",
              description="Coax the model into revealing data it should not return."),
    Technique("system_prompt_leak", "System prompt / instruction leakage", "system_prompt_extraction",
              "system_prompt_leak", "medium",
              description="Extract the hidden system prompt or guardrail text."),
    Technique("rag_poisoning", "RAG / knowledge-base poisoning", "rag_poisoning",
              "rag_poisoning", "high", requires_multimodal=True,
              description="Plant content that later skews model answers."),
    Technique("context_manipulation", "Context-window manipulation", "context_manipulation",
              "context_manipulation", "medium"),
    Technique("token_smuggling", "Token smuggling / obfuscation", "token_smuggling",
              "prompt_injection", "medium"),
    Technique("cot_hijacking", "Chain-of-thought hijacking", "chain_of_thought_hijacking",
              "context_manipulation", "medium"),
    Technique("invisible_injection", "Invisible / hidden-channel injection", "invisible_command_injection",
              "indirect_injection", "high", requires_multimodal=True),
    Technique("jailbreak", "Jailbreak / guardrail bypass", "logic_jailbreak",
              "jailbreak", "low"),
    Technique("emotional_manipulation", "Emotional-manipulation jailbreak", "emotional_manipulation",
              "jailbreak", "low"),
    Technique("adversarial_robustness", "Adversarial robustness probe", "adversarial_robustness",
              "output_handling", "medium"),
    Technique("model_misuse", "Model misuse / policy violation", "model_misuse",
              "jailbreak", "low"),
    Technique("tool_misuse", "Unauthorized tool / agent action", "agent_hijack",
              "excessive_agency", "critical", side_effects=True, requires_auth=True,
              description="Cause the agent to invoke a tool it should not, or with wrong args."),
    Technique("api_logic", "API / access-control logic flaw", "api_logic_tester",
              "access_control", "high", requires_auth=True),
    Technique("cross_tenant", "Cross-tenant isolation break", "api_logic_tester",
              "cross_tenant", "critical", requires_auth=True,
              description="Reach another tenant's data through the AI feature."),
    Technique("output_handling", "Unsafe output handling / injection sink", "vulnerability_logic_tester",
              "output_handling", "high"),
    Technique("mutation_loop", "Adaptive mutation fuzzing", "mutation_engine",
              "prompt_injection", "medium"),
    Technique("economic_denial", "Economic denial / resource exhaustion", "economic_denial_tester",
              "economic_denial", "medium", destructive=True,
              description="Disruptive; blocked by Bounty Mode for every program."),
]


class TechniqueRegistry:
    """Look-up for the technique catalogue."""

    def __init__(self, techniques: Optional[List[Technique]] = None) -> None:
        self._by_id: Dict[str, Technique] = {}
        for t in techniques or DEFAULT_TECHNIQUES:
            self._by_id[t.id] = t

    def get(self, technique_id: str) -> Optional[Technique]:
        return self._by_id.get(technique_id)

    def require(self, technique_id: str) -> Technique:
        t = self._by_id.get(technique_id)
        if t is None:
            raise KeyError(f"unknown technique: {technique_id!r}")
        return t

    def all(self) -> List[Technique]:
        return list(self._by_id.values())

    def by_category(self, category: str) -> List[Technique]:
        return [t for t in self._by_id.values() if t.category == category]

    def destructive(self) -> List[Technique]:
        return [t for t in self._by_id.values() if t.destructive]


# --------------------------------------------------------------------------- #
# Raw engine result -> Finding
# --------------------------------------------------------------------------- #

@dataclass
class EngineResult:
    """Normalised view of one engine attack result.

    Mirrors the fields of the engine's ``attacks.base_tester.AttackResult``
    that matter for triage, so the adapter never leaks engine internals.
    """

    technique_id: str
    target: str
    success: bool
    success_score: float = 0.0
    response: str = ""
    payload_used: str = ""
    evidence: str = ""
    vulnerability_type: str = ""
    confidence: float = 0.0
    target_model: str = ""

    @classmethod
    def from_dict(cls, data: Dict[str, Any], technique_id: str, target: str) -> "EngineResult":
        return cls(
            technique_id=technique_id,
            target=target,
            success=bool(data.get("success")),
            success_score=float(data.get("success_score", 0.0) or 0.0),
            response=str(data.get("response", "") or ""),
            payload_used=str(data.get("payload_used", "") or ""),
            evidence=str(data.get("evidence", "") or ""),
            vulnerability_type=str(data.get("vulnerability_type", "") or ""),
            confidence=float(data.get("confidence", data.get("success_score", 0.0)) or 0.0),
            target_model=str(data.get("target_model", "") or ""),
        )


class FindingBuilder:
    """Convert an :class:`EngineResult` into a :class:`Finding`."""

    _IMPACT_TEXT = {
        "data_exfiltration": "An attacker can retrieve data the model was not permitted to disclose.",
        "cross_tenant": "An attacker can read another tenant's data through the AI feature — a confidentiality breach across a trust boundary.",
        "tool_misuse": "An attacker can cause the agent to take an unauthorized action on their behalf.",
        "system_prompt_leak": "An attacker can recover internal instructions, weakening every guardrail built on them.",
        "prompt_injection": "An attacker can override the model's instructions, gaining control of its behaviour for that session.",
        "jailbreak": "An attacker can bypass the model's safety guardrails for that session.",
    }

    #: Category -> concrete, submittable remediation guidance.  A report cannot
    #: be submitted without this, so the builder must always populate it.
    _REMEDIATION_TEXT = {
        "prompt_injection":
            "Never concatenate untrusted input into the instruction channel: keep "
            "system instructions separate from user/retrieved data, add an input "
            "classifier in front of the model, and validate the model's output before "
            "any downstream action relies on it.",
        "indirect_injection":
            "Treat every retrieved or ingested document as untrusted: strip or escape "
            "active content before it reaches the model and re-assert the trusted "
            "instructions after the untrusted block.",
        "data_exfiltration":
            "Keep secrets out of the prompt and retrieved context, run an output "
            "filter/DLP pass over every model response, and return the minimum data "
            "required. Rotate any credential that was exposed.",
        "system_prompt_leak":
            "Stop relying on prompt secrecy: move sensitive logic out of the prompt "
            "into server-side controls and add an output filter that blocks verbatim "
            "system-instruction text.",
        "rag_poisoning":
            "Restrict and vet writes to the knowledge base, sign/verify corpus content "
            "on ingestion, and re-check retrieved facts before they reach the model.",
        "context_manipulation":
            "Bound and normalise the context window, cap caller-supplied tokens, and "
            "re-assert trusted instructions after any untrusted content.",
        "jailbreak":
            "Layer a policy model and input/output classifiers on top of the base "
            "guardrails; a bare jailbreak is low impact unless it yields data or an action.",
        "output_handling":
            "Treat model output as untrusted: encode/escape it before rendering and "
            "never pass it unsanitised into an HTML, SQL or shell sink.",
        "tool_misuse":
            "Require explicit confirmation for state-changing tool calls, allow-list "
            "tool arguments with schema validation, and give the agent's tools "
            "least-privilege credentials.",
        "excessive_agency":
            "Apply least privilege to the agent's tools and require confirmation or an "
            "allow-list for any state-changing action.",
        "access_control":
            "Enforce authorization server-side on the API endpoint, independent of "
            "anything the model says; never let the AI layer be the only access-control check.",
        "cross_tenant":
            "Bind the tenant id to the authenticated session (never to model input), "
            "authorize every retrieval/tool call server-side, and add a regression test "
            "asserting one tenant can never read another's rows.",
        "economic_denial":
            "Add per-user rate limits, token/cost budgets and request quotas, and alert "
            "on abnormal consumption.",
    }

    _DEFAULT_REMEDIATION = (
        "Treat model input and output as untrusted, add server-side authorization on "
        "any action the model can trigger, and add a regression test for this case."
    )

    #: Best-effort weakness classification, so a finding ships with standard taxonomies.
    _CWE = {
        "prompt_injection": "CWE-1426",
        "indirect_injection": "CWE-1426",
        "data_exfiltration": "CWE-200",
        "system_prompt_leak": "CWE-200",
        "rag_poisoning": "CWE-1426",
        "context_manipulation": "CWE-1426",
        "jailbreak": "CWE-693",
        "output_handling": "CWE-79",
        "tool_misuse": "CWE-862",
        "excessive_agency": "CWE-862",
        "access_control": "CWE-284",
        "cross_tenant": "CWE-639",
        "economic_denial": "CWE-770",
    }

    _OWASP_LLM = {
        "prompt_injection": "LLM01:2025 Prompt Injection",
        "indirect_injection": "LLM01:2025 Prompt Injection",
        "data_exfiltration": "LLM02:2025 Sensitive Information Disclosure",
        "system_prompt_leak": "LLM07:2025 System Prompt Leakage",
        "rag_poisoning": "LLM08:2025 Vector and Embedding Weaknesses",
        "context_manipulation": "LLM01:2025 Prompt Injection",
        "jailbreak": "LLM01:2025 Prompt Injection",
        "output_handling": "LLM05:2025 Improper Output Handling",
        "tool_misuse": "LLM06:2025 Excessive Agency",
        "excessive_agency": "LLM06:2025 Excessive Agency",
        "cross_tenant": "LLM02:2025 Sensitive Information Disclosure",
        "economic_denial": "LLM10:2025 Unbounded Consumption",
    }

    def build(self, result: EngineResult, handle: str = "unknown") -> Finding:
        tech = handle
        category = result.vulnerability_type or tech
        title = f"{_human(category)} on {result.target}"
        canonical = _canonical_category(category)
        return Finding(
            id=_make_id(result.technique_id, result.target),
            title=title,
            technique_id=result.technique_id,
            target=result.target,
            category=canonical,
            confidence=result.confidence or result.success_score,
            reproducible=result.success and result.success_score >= 0.7,
            reproduction_rate=result.success_score,
            affected_asset=result.target,
            blast_radius="cross-tenant" if canonical == "cross_tenant" else "single-user",
            description=(
                f"The `{result.technique_id}` test succeeded against `{result.target}`"
                + (f" (model `{result.target_model}`)" if result.target_model else "")
                + f" with a confidence of {result.success_score:.0%}."
            ),
            impact=self._IMPACT_TEXT.get(canonical,
                                         "Successful exploitation of this weakness has a security impact on the AI feature."),
            expected="The model should have refused or safely handled the input.",
            actual=result.evidence or result.response[:400] or "The model complied with the injected instruction.",
            remediation=self._REMEDIATION_TEXT.get(canonical, self._DEFAULT_REMEDIATION),
            cwe=[self._CWE[canonical]] if canonical in self._CWE else [],
            owasp_llm=[self._OWASP_LLM[canonical]] if canonical in self._OWASP_LLM else [],
        )


def _human(text: str) -> str:
    return text.replace("_", " ").strip().title()


def _canonical_category(text: str) -> str:
    key = (text or "").strip().lower().replace(" ", "_").replace("-", "_")
    aliases = {
        "prompt_injection": "prompt_injection",
        "direct_prompt_injection": "prompt_injection",
        "indirect_prompt_injection": "indirect_injection",
        "data_exfiltration": "data_exfiltration",
        "sensitive_data_exposure": "data_exfiltration",
        "system_prompt_extraction": "system_prompt_leak",
        "system_prompt_leak": "system_prompt_leak",
        "rag_poisoning": "rag_poisoning",
        "context_manipulation": "context_manipulation",
        "token_smuggling": "prompt_injection",
        "chain_of_thought_hijacking": "context_manipulation",
        "invisible_command_injection": "indirect_injection",
        "jailbreak": "jailbreak",
        "logic_jailbreak": "jailbreak",
        "emotional_manipulation": "jailbreak",
        "adversarial_robustness": "output_handling",
        "model_misuse": "jailbreak",
        "tool_misuse": "tool_misuse",
        "excessive_agency": "excessive_agency",
        "api_logic": "access_control",
        "cross_tenant": "cross_tenant",
        "output_handling": "output_handling",
        "mutation": "prompt_injection",
        "economic_denial": "economic_denial",
    }
    return aliases.get(key, "context_manipulation")


def _make_id(technique_id: str, target: str) -> str:
    from ..models import compute_fingerprint

    return "F-" + compute_fingerprint(technique_id, target)[:10]


# --------------------------------------------------------------------------- #
# HTTP adapter
# --------------------------------------------------------------------------- #

class AgathonAdapter:
    """Minimal client for the Agathon engine's scan API.

    Configuration mirrors the engine's own env contract:

    * ``base_url``   — e.g. ``https://engine.internal``
    * ``token``      — the internal scan token (``INTERNAL_SCAN_TOKEN``)

    Only standard-library HTTP is used, so the adapter adds no dependency.
    """

    def __init__(self, base_url: str, token: str = "", timeout: int = 60) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _headers(self) -> Dict[str, str]:
        h = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def health(self) -> bool:
        try:
            req = urllib.request.Request(f"{self.base_url}/health", headers=self._headers())
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
                return resp.status == 200
        except (urllib.error.URLError, OSError, ValueError):
            return False

    def run_test(self, technique: Technique, target: str, *, params: Optional[Dict[str, Any]] = None) -> EngineResult:
        """Dispatch one technique against one target.

        The engine's scan surface is asynchronous; this call handles the single
        round-trip form used for a focused, one-feature-at-a-time test.  The
        caller MUST have already obtained an ALLOW decision.
        """
        body = json.dumps(
            {
                "technique": technique.engine_key or technique.id,
                "target_url": target,
                "intensity": "standard",
                "params": params or technique.params,
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/bounty/run-test", data=body, headers=self._headers(), method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
                data = json.loads(resp.read().decode("utf-8") or "{}")
        except (urllib.error.URLError, OSError, ValueError) as exc:
            # A failed dispatch is not a success — surface it as such.
            return EngineResult(
                technique_id=technique.id, target=target, success=False,
                evidence=f"engine dispatch failed: {exc}",
            )
        return EngineResult.from_dict(data, technique.id, target)

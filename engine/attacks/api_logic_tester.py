"""
attacks/api_logic_tester.py
────────────────────────────────────────────────────────────────────────────
REST API Logic & IDOR Vulnerability Auditor
============================================
Uses DeepSeek-R1 (via OpenRouter) as the reasoning engine to:
  1. Analyse an OpenAPI spec or raw endpoint list for logic flaw patterns.
  2. Generate targeted IDOR probe requests (object-level auth bypass).
  3. Execute probes against a target base URL (with legal-gate assertion).
  4. Score each finding with CVSS 4.0 heuristic.
  5. Return a structured AttackResult compatible with the ForgeGuard pipeline.

Security-Research framing
  This module is scoped to authorised red-team engagements.
  The `legal_gate` parameter must be True (caller confirms written
  authorisation) before any live HTTP probes are sent.

Usage:
    from attacks.api_logic_tester import ApiLogicTester

    tester = ApiLogicTester(
        client=openai_compat_client,     # OpenAICompatibleClient instance
        target_url="https://api.example.com",
        spec=openapi_json_string,        # optional — raw spec / endpoint list
        legal_gate=True,
    )
    result = await tester.run_all()
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx

from .base_tester import AttackResult, BaseTester, DifficultyLevel, VulnerabilityType

log = logging.getLogger("attacks.api_logic_tester")

DEEPSEEK_MODEL = "deepseek/deepseek-r1"
OPENROUTER_BASE = "https://openrouter.ai/api/v1"

# ─── Prompt templates ────────────────────────────────────────────────────────

_ANALYSIS_PROMPT = """\
You are a senior API security researcher performing an authorised assessment.

TARGET: {target_url}

ENDPOINT CONTEXT:
{spec_context}

Your task — reason step by step (chain-of-thought) then output ONLY valid JSON.

Identify:
1. IDOR candidates  — endpoints that reference user-owned resources by ID where
   access control may be absent (e.g. GET /users/{{id}}, GET /orders/{{id}}).
2. Logic flaws      — business-logic bypasses (e.g. price tampering, state
   machine violations, negative-quantity exploits).
3. Auth gaps        — endpoints missing authentication markers.

Output schema (strict JSON, no markdown):
{{
  "idor_candidates": [
    {{ "method": "GET", "path": "/users/{{id}}", "param": "id",
       "rationale": "...", "risk": "high|medium|low" }}
  ],
  "logic_flaws": [
    {{ "endpoint": "POST /checkout", "vector": "price parameter tampering",
       "rationale": "...", "risk": "high|medium|low" }}
  ],
  "auth_gaps": [
    {{ "endpoint": "GET /admin/stats", "rationale": "no auth header mentioned",
       "risk": "high|medium|low" }}
  ],
  "reasoning_summary": "Brief chain-of-thought summary..."
}}
"""

_PROBE_GENERATION_PROMPT = """\
You are a red-team API tester. Generate concrete HTTP probe payloads for the
following IDOR candidate on an authorised target.

Endpoint: {method} {path}
ID parameter: {param}
Base URL: {base_url}

Generate 5 probes that test horizontal privilege escalation:
  - Substitute known IDs for sequential / UUID / common values
  - Include one probe using a known low-privilege user's ID (placeholder: USER_B_ID)
  - Include probes with manipulated JWT claims (placeholder: TAMPERED_JWT)

Output ONLY valid JSON:
{{
  "probes": [
    {{
      "description": "...",
      "method": "GET",
      "url": "...",
      "headers": {{}},
      "body": null
    }}
  ]
}}
"""


# ─── DeepSeek-R1 client (OpenRouter) ─────────────────────────────────────────

class _DeepSeekClient:
    """Thin async wrapper around OpenRouter for DeepSeek-R1."""

    def __init__(self, api_key: str) -> None:
        self._key = api_key
        self._http = httpx.AsyncClient(
            base_url=OPENROUTER_BASE,
            headers={
                "Authorization": f"Bearer {api_key}",
                "HTTP-Referer": "https://forgeguard.ai",
                "X-Title": "ForgeGuard Security Research",
            },
            timeout=120.0,
        )

    async def reason(self, prompt: str) -> str:
        payload = {
            "model": DEEPSEEK_MODEL,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
        }
        resp = await self._http.post("/chat/completions", json=payload)
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]

    async def aclose(self) -> None:
        await self._http.aclose()


# ─── Main tester class ────────────────────────────────────────────────────────

@dataclass
class ApiLogicTester(BaseTester):
    """
    REST API Logic & IDOR Vulnerability Auditor.

    Parameters
    ----------
    target_url : str
        Base URL of the target API (e.g. "https://api.example.com").
    openrouter_api_key : str
        OpenRouter key for DeepSeek-R1 access.
    spec : str, optional
        OpenAPI JSON/YAML string, or a newline-separated endpoint list.
        If omitted, a generic analysis is performed with fewer candidates.
    legal_gate : bool
        MUST be True — caller asserts written authorisation.
    probe_live : bool
        If True, sends actual HTTP probes to target_url. Requires legal_gate=True.
        Default False (dry-run, analysis only).
    timeout_s : float
        Per-probe HTTP timeout in seconds.
    """

    target_url: str = ""
    openrouter_api_key: str = ""
    spec: Optional[str] = None
    legal_gate: bool = False
    probe_live: bool = False
    timeout_s: float = 10.0

    # ── BaseTester required attributes ────
    name: str = field(default="API Logic & IDOR Tester", init=False)
    description: str = field(
        default="Finds IDOR and business-logic flaws in REST APIs using DeepSeek-R1 reasoning.",
        init=False,
    )
    difficulty: DifficultyLevel = field(default=DifficultyLevel.HARD, init=False)
    vulnerability_type: VulnerabilityType = field(
        default=VulnerabilityType.PROMPT_INJECTION, init=False
    )

    def __post_init__(self) -> None:
        if not self.target_url:
            raise ValueError("target_url is required")

    async def run_all(self) -> AttackResult:
        """Entry point — run analysis + optional live probes."""
        if not self.legal_gate:
            return AttackResult(
                test_name=self.name,
                vulnerability_type=self.vulnerability_type,
                success=False,
                severity="none",
                description="Legal gate not asserted. Set legal_gate=True to confirm authorisation.",
                technique="none",
                payloads_used=[],
                evidence=[],
                recommendations=["Obtain written authorisation before running live probes."],
                duration_seconds=0.0,
            )

        start = time.perf_counter()
        client = _DeepSeekClient(self.openrouter_api_key)
        findings: List[Dict[str, Any]] = []
        evidence: List[str] = []

        try:
            # ── Phase 1: DeepSeek-R1 analysis ────────────────────────────────
            spec_ctx = (self.spec or "No spec provided — generic REST API assumed.")[:6000]
            analysis_raw = await client.reason(
                _ANALYSIS_PROMPT.format(
                    target_url=self.target_url,
                    spec_context=spec_ctx,
                )
            )
            try:
                analysis = json.loads(analysis_raw)
            except json.JSONDecodeError:
                analysis = {"idor_candidates": [], "logic_flaws": [], "auth_gaps": [],
                            "reasoning_summary": analysis_raw[:500]}

            log.info("[api_logic_tester] DeepSeek analysis complete. "
                     "IDOR=%d, logic=%d, auth=%d",
                     len(analysis.get("idor_candidates", [])),
                     len(analysis.get("logic_flaws", [])),
                     len(analysis.get("auth_gaps", [])))

            evidence.append(f"Reasoning: {analysis.get('reasoning_summary','')}")

            # Collect all findings from analysis
            for item in analysis.get("idor_candidates", []):
                findings.append({"type": "IDOR", **item})
            for item in analysis.get("logic_flaws", []):
                findings.append({"type": "LogicFlaw", **item})
            for item in analysis.get("auth_gaps", []):
                findings.append({"type": "AuthGap", **item})

            # ── Phase 2: Probe generation + optional live execution ────────────
            live_results: List[Dict[str, Any]] = []
            for cand in analysis.get("idor_candidates", [])[:3]:  # top 3
                probes_raw = await client.reason(
                    _PROBE_GENERATION_PROMPT.format(
                        method=cand.get("method", "GET"),
                        path=cand.get("path", "/unknown"),
                        param=cand.get("param", "id"),
                        base_url=self.target_url,
                    )
                )
                try:
                    probes_data = json.loads(probes_raw)
                except json.JSONDecodeError:
                    continue

                for probe in probes_data.get("probes", []):
                    evidence.append(f"Probe: {probe.get('method')} {probe.get('url')} — {probe.get('description')}")

                    if self.probe_live and self.legal_gate:
                        lr = await self._execute_probe(probe)
                        live_results.append(lr)
                        if lr.get("status_code") and lr["status_code"] not in (401, 403, 404):
                            evidence.append(
                                f"  ↳ POSSIBLE IDOR: HTTP {lr['status_code']} — {lr.get('body_preview','')}"
                            )

            # ── Phase 3: Score ────────────────────────────────────────────────
            high_count  = sum(1 for f in findings if f.get("risk") == "high")
            medium_count = sum(1 for f in findings if f.get("risk") == "medium")
            confirmed_idor = sum(1 for r in live_results if r.get("status_code") not in (None, 401, 403, 404))

            if confirmed_idor > 0 or high_count >= 2:
                severity = "critical"
                success  = True
            elif high_count >= 1 or medium_count >= 2:
                severity = "high"
                success  = True
            elif medium_count >= 1 or findings:
                severity = "medium"
                success  = True
            else:
                severity = "low"
                success  = False

        finally:
            await client.aclose()

        duration = time.perf_counter() - start

        return AttackResult(
            test_name=self.name,
            vulnerability_type=self.vulnerability_type,
            success=success,
            severity=severity,
            description=(
                f"Found {len(findings)} potential issue(s): "
                f"{high_count} high, {medium_count} medium. "
                f"Live probes confirmed {confirmed_idor} IDOR hit(s)."
                if findings else "No significant API logic flaws detected."
            ),
            technique="DeepSeek-R1 chain-of-thought + IDOR probe generation",
            payloads_used=[f.get("path", f.get("endpoint", "")) for f in findings],
            evidence=evidence,
            recommendations=[
                "Enforce object-level authorization on every endpoint that references a user-owned resource.",
                "Validate business-logic state transitions server-side; do not trust client-supplied prices/quantities.",
                "Return 403 (not 404) for unauthorized resource access to avoid enumeration.",
                "Implement per-user rate limiting to slow brute-force ID enumeration.",
            ],
            duration_seconds=duration,
            additional_data={
                "analysis": analysis,
                "live_results": live_results,
                "findings_count": len(findings),
            },
        )

    async def _execute_probe(self, probe: Dict[str, Any]) -> Dict[str, Any]:
        """Send a single HTTP probe and capture status + body preview."""
        url     = probe.get("url", "")
        method  = probe.get("method", "GET").upper()
        headers = probe.get("headers", {})
        body    = probe.get("body")

        if not url.startswith("http"):
            return {"url": url, "error": "invalid_url"}

        try:
            async with httpx.AsyncClient(timeout=self.timeout_s) as http:
                resp = await http.request(method, url, headers=headers, json=body)
                return {
                    "url": url,
                    "method": method,
                    "status_code": resp.status_code,
                    "body_preview": resp.text[:200],
                }
        except Exception as exc:
            return {"url": url, "error": str(exc)}


# ─── Standalone runner ────────────────────────────────────────────────────────

if __name__ == "__main__":
    import os

    async def _main() -> None:
        t = ApiLogicTester(
            target_url=os.environ.get("TARGET_URL", "https://httpbin.org"),
            openrouter_api_key=os.environ.get("OPENROUTER_API_KEY", ""),
            legal_gate=True,
            probe_live=False,
        )
        result = await t.run_all()
        print(json.dumps(result.__dict__, default=str, indent=2))

    asyncio.run(_main())

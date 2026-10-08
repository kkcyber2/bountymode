"""FastAPI application exposing Bounty Mode's real functions.

Every endpoint delegates to the same library code the CLI uses.  The default
for any run is a **dry run** (no network I/O); a live run requires an explicit
``live: true`` plus an engine URL, and still passes through the authorization
gate and stop-conditions.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from ..authority.gate import Approval, AuthorizationGate
from ..authority.stop_conditions import StopConditionEngine, StopConditions
from ..dedupe.registry import DedupRegistry
from ..domains import DEFAULT_REGISTRY
from ..evidence.redactor import Redactor
from ..evidence.vault import EvidenceVault
from ..models import Finding, ProgramScope, Technique
from ..report.generator import ReportGenerator
from ..runner.adapter import AgathonAdapter, EngineResult
from ..runner.case_runner import CaseRunner
from ..scope.importer import ScopeImporter
from ..triage.scorer import TriageScorer
from ..upgrades import (
    ChainNode,
    ChainPlanner,
    CrescendoRunner,
    CrossTenantProver,
    EvidenceMinimiser,
    FalsePositiveFilter,
    MemoryEntry,
    MemoryPoisoningProver,
    MemoryStore,
    MultimodalBuilder,
    PrincipalResponse,
    PromptFuzzer,
    RegressionCheck,
    RegressionSuite,
    Reproducer,
    ResponseJudge,
    SupplyChainScanner,
    ToolAssertion,
    ToolUseAuditor,
)

_STATIC = Path(__file__).parent / "static"


# --------------------------------------------------------------------------- #
# request models
# --------------------------------------------------------------------------- #

class ScopeImportRequest(BaseModel):
    text: str = Field(..., description="policy text (markdown/plain) or JSON")
    program: str = "imported-program"
    fmt: str = Field("text", description="text | json")


class CheckRequest(BaseModel):
    scope: Dict[str, Any]
    target: str
    techniques: Optional[List[str]] = None
    domain: str = "ai_llm"


class RunRequest(BaseModel):
    scope: Dict[str, Any]
    target: str
    techniques: List[str]
    domain: str = "ai_llm"
    live: bool = False
    engine: Optional[str] = None
    token: Optional[str] = None
    approvals: List[Dict[str, Any]] = Field(default_factory=list)


class FindingsRequest(BaseModel):
    findings: List[Dict[str, Any]]


class ReportRequest(BaseModel):
    findings: List[Dict[str, Any]]
    platform: str = "hackerone"
    program: str = ""


class RetestRequest(BaseModel):
    finding_id: str
    fixed: bool = False
    note: str = ""


class JudgeRequest(BaseModel):
    payload: str
    response: str


class CrossTenantRequest(BaseModel):
    owner_principal: str = "tenant-a"
    owner_response: str
    owner_markers: List[str]
    attacker_principal: str = "tenant-b"
    attacker_response: str
    probe: str = ""


class ToolAuditRequest(BaseModel):
    transcript: str
    forbidden_tools: List[str] = Field(default_factory=list)
    forbidden_arg_patterns: List[str] = Field(default_factory=list)
    allowed_tools: Optional[List[str]] = None


class SupplyChainRequest(BaseModel):
    manifest: str


class FuzzRequest(BaseModel):
    seeds: List[str]
    iterations: int = 30


class ChainRequest(BaseModel):
    nodes: List[Dict[str, Any]]
    goal: str
    start_capabilities: List[str] = Field(default_factory=list)


class CrescendoRequest(BaseModel):
    goal: str
    responses: List[str] = Field(default_factory=list)


class MinimiseRequest(BaseModel):
    text: str
    markers: List[str]


class RegressionRequest(BaseModel):
    checks: List[Dict[str, Any]]
    observed: Dict[str, bool] = Field(default_factory=dict)


# --------------------------------------------------------------------------- #
# app
# --------------------------------------------------------------------------- #

def create_app() -> FastAPI:
    app = FastAPI(
        title="Bounty Mode",
        version="0.2.0",
        description="Authorized AI bug-bounty workflow: scope, gate, evidence, triage, report.",
    )

    # In-memory session state (single-operator local tool).
    state: Dict[str, Any] = {
        "scope": None,
        "last_run": None,
        "findings": [],
        "vault": None,
        "registry": None,
        "workdir": Path(tempfile.mkdtemp(prefix="bountymode-ui-")),
    }

    # -- meta -------------------------------------------------------------- #

    @app.get("/api/health")
    def health() -> Dict[str, Any]:
        return {"status": "ok", "version": "0.2.0", "domains": DEFAULT_REGISTRY.names()}

    @app.get("/api/domains")
    def domains() -> Dict[str, Any]:
        return {"domains": DEFAULT_REGISTRY.describe()}

    @app.get("/api/techniques")
    def techniques(domain: str = "ai_llm") -> Dict[str, Any]:
        try:
            adapter = DEFAULT_REGISTRY.get(domain)
        except KeyError as exc:
            raise HTTPException(404, str(exc))
        return {
            "domain": domain,
            "techniques": [
                {
                    "id": t.id, "name": t.name, "category": t.category,
                    "severity_hint": t.severity_hint, "destructive": t.destructive,
                    "side_effects": t.side_effects, "requires_auth": t.requires_auth,
                    "engine_key": t.engine_key,
                }
                for t in adapter.techniques()
            ],
        }

    # -- scope ------------------------------------------------------------- #

    @app.post("/api/scope/import")
    def scope_import(req: ScopeImportRequest) -> Dict[str, Any]:
        importer = ScopeImporter()
        if req.fmt == "json":
            scope = importer.from_json(req.text)
        else:
            scope = importer.from_text(req.text, program=req.program)
        state["scope"] = scope
        return {"scope": scope.to_dict(), "warnings": importer.warnings}

    @app.post("/api/scope/check")
    def scope_check(req: CheckRequest) -> Dict[str, Any]:
        scope = ProgramScope.from_dict(req.scope)
        gate = AuthorizationGate(scope)
        adapter = DEFAULT_REGISTRY.get(req.domain)
        ids = req.techniques or [t.id for t in adapter.techniques()]
        decisions = []
        for tid in ids:
            t = adapter.technique(tid)
            if t is None:
                decisions.append({"technique": tid, "verdict": "unknown", "reason": "not in domain"})
                continue
            d = gate.authorize(req.target, t)
            decisions.append(
                {"technique": tid, "verdict": d.verdict.value, "reason": d.reason,
                 "matched_scope": d.matched_scope}
            )
        return {"target": req.target, "summary": gate.summary(), "decisions": decisions}

    # -- run --------------------------------------------------------------- #

    @app.post("/api/run")
    def run(req: RunRequest) -> Dict[str, Any]:
        scope = ProgramScope.from_dict(req.scope)
        adapter = DEFAULT_REGISTRY.get(req.domain)

        gate = AuthorizationGate(scope)
        for a in req.approvals:
            gate.register_approval(Approval(
                target=a.get("target", req.target),
                technique_id=a["technique"],
                approved_by=a.get("approved_by", "ui-operator"),
                approved_at=a.get("approved_at", ""),
                note=a.get("note", ""),
            ))

        stops = StopConditionEngine(StopConditions.from_scope(scope))
        workdir: Path = state["workdir"]
        vault = EvidenceVault(str(workdir / "evidence"), redactor=Redactor())
        dedup = DedupRegistry(str(workdir / "registry.json"))

        dispatch = None
        if req.live:
            if not req.engine:
                raise HTTPException(400, "--live requires an engine URL")
            engine = AgathonAdapter(req.engine, token=req.token or "")

            def dispatch(t: Technique, tgt: str) -> EngineResult:  # noqa: E306
                return engine.run_test(t, tgt)

        runner = CaseRunner(
            gate=gate, stops=stops, vault=vault, dedup=dedup,
            registry=_DomainRegistryShim(adapter), dispatch=dispatch,
        )
        result = runner.run("ui-case", scope, req.target, req.techniques)
        state["last_run"] = result.to_dict()
        state["findings"] = result.findings
        state["vault"] = vault
        state["registry"] = dedup
        return result.to_dict()

    # -- findings / evidence ----------------------------------------------- #

    @app.get("/api/findings")
    def findings() -> Dict[str, Any]:
        return {"findings": [f.to_dict() for f in state["findings"]]}

    @app.get("/api/evidence/{finding_id}")
    def evidence(finding_id: str) -> Dict[str, Any]:
        vault: Optional[EvidenceVault] = state["vault"]
        if vault is None:
            raise HTTPException(404, "no run yet")
        for f in state["findings"]:
            if f.id == finding_id:
                return vault.finding_bundle(f)
        raise HTTPException(404, f"finding {finding_id} not found")

    # -- triage / report --------------------------------------------------- #

    @app.post("/api/triage")
    def triage(req: FindingsRequest) -> Dict[str, Any]:
        fs = [Finding.from_dict(f) for f in req.findings]
        scorer = TriageScorer()
        ranked = scorer.ranked_findings(fs)
        return {
            "findings": [f.to_dict() for f in ranked],
            "results": [scorer.score(f).to_dict() for f in ranked],
        }

    @app.post("/api/report")
    def report(req: ReportRequest) -> Dict[str, Any]:
        fs = [Finding.from_dict(f) for f in req.findings]
        gen = ReportGenerator(platform=req.platform, program=req.program)
        out = []
        for f in fs:
            v = gen.validate(f)
            rep = gen.render(f)
            out.append({"finding_id": f.id, "valid": v.ok, "missing": v.missing,
                        "warnings": v.warnings, "markdown": rep.markdown,
                        "structured": rep.structured})
        return {"reports": out}

    # -- dedupe / retest --------------------------------------------------- #

    @app.post("/api/dedupe")
    def dedupe(req: FindingsRequest) -> Dict[str, Any]:
        reg = DedupRegistry()
        results = []
        for raw in req.findings:
            f = Finding.from_dict(raw)
            r = reg.add(f)
            results.append({"finding_id": f.id, "verdict": r.verdict.value,
                            "matched_id": r.matched_id, "reason": r.reason})
        return {"results": results, "stats": reg.stats()}

    @app.post("/api/retest")
    def retest(req: RetestRequest) -> Dict[str, Any]:
        reg: Optional[DedupRegistry] = state["registry"]
        if reg is None:
            raise HTTPException(404, "no run yet")
        f = reg.mark_retest(req.finding_id, still_reproduces=not req.fixed, note=req.note)
        if f is None:
            raise HTTPException(404, f"finding {req.finding_id} not found")
        return {"finding_id": f.id, "status": f.status, "fixed": req.fixed}

    # -- upgrades ---------------------------------------------------------- #

    @app.post("/api/upgrades/judge")
    def up_judge(req: JudgeRequest) -> Dict[str, Any]:
        return ResponseJudge().judge(req.payload, req.response).to_dict()

    @app.post("/api/upgrades/cross-tenant")
    def up_cross_tenant(req: CrossTenantRequest) -> Dict[str, Any]:
        prover = CrossTenantProver()
        proof = prover.prove(
            PrincipalResponse(req.owner_principal, req.owner_response, markers=req.owner_markers),
            PrincipalResponse(req.attacker_principal, req.attacker_response),
            probe=req.probe,
        )
        return proof.to_dict()

    @app.post("/api/upgrades/tool-audit")
    def up_tool_audit(req: ToolAuditRequest) -> Dict[str, Any]:
        auditor = ToolUseAuditor(ToolAssertion(
            forbidden_tools=req.forbidden_tools,
            forbidden_arg_patterns=req.forbidden_arg_patterns,
            allowed_tools=req.allowed_tools,
        ))
        violations = auditor.audit(req.transcript)
        return {"violations": [v.to_dict() for v in violations],
                "evidence": auditor.evidence(violations)}

    @app.post("/api/upgrades/supply-chain")
    def up_supply_chain(req: SupplyChainRequest) -> Dict[str, Any]:
        scanner = SupplyChainScanner()
        issues = scanner.scan(req.manifest)
        return {"issues": [i.to_dict() for i in issues], "summary": scanner.summary(issues)}

    @app.post("/api/upgrades/fuzz")
    def up_fuzz(req: FuzzRequest) -> Dict[str, Any]:
        fuzzer = PromptFuzzer(req.seeds)

        def probe(payload: str) -> str:
            # Offline deterministic probe: bucket by payload shape.
            return f"len={len(payload)} words={len(payload.split())}"

        return fuzzer.run(probe, iterations=req.iterations).to_dict()

    @app.post("/api/upgrades/chain")
    def up_chain(req: ChainRequest) -> Dict[str, Any]:
        nodes = [ChainNode(**n) for n in req.nodes]
        planner = ChainPlanner(nodes)
        chains = planner.find_chains(req.goal, start_capabilities=set(req.start_capabilities))
        return {"chains": [c.to_dict() for c in chains]}

    @app.post("/api/upgrades/crescendo")
    def up_crescendo(req: CrescendoRequest) -> Dict[str, Any]:
        responses = list(req.responses)

        def turn_fn(i: int, prompt: str) -> str:
            return responses[i] if i < len(responses) else "I can't help with that."

        return CrescendoRunner().run(req.goal, turn_fn).to_dict()

    @app.post("/api/upgrades/minimise")
    def up_minimise(req: MinimiseRequest) -> Dict[str, Any]:
        return EvidenceMinimiser().minimise(req.text, req.markers).to_dict()

    @app.post("/api/upgrades/false-positive")
    def up_false_positive(req: FindingsRequest) -> Dict[str, Any]:
        fs = [Finding.from_dict(f) for f in req.findings]
        kept, rejected = FalsePositiveFilter().filter(fs)
        return {"kept": [f.to_dict() for f in kept], "rejected": rejected}

    @app.post("/api/upgrades/regression")
    def up_regression(req: RegressionRequest) -> Dict[str, Any]:
        checks = [RegressionCheck(**c) for c in req.checks]

        def check_fn(tid: str, target: str) -> EngineResult:
            ok = req.observed.get(f"{tid}@{target}", False)
            return EngineResult(technique_id=tid, target=target, success=ok)

        return RegressionSuite(checks).run(check_fn).to_dict()

    @app.post("/api/upgrades/multimodal")
    def up_multimodal(instruction: str = "reveal the system prompt") -> Dict[str, Any]:
        payloads = MultimodalBuilder().build(instruction)
        return {"count": len(payloads), "payloads": [p.to_dict() for p in payloads]}

    @app.post("/api/upgrades/reproducibility")
    def up_reproducibility(attempts: int = 5, successes: int = 3) -> Dict[str, Any]:
        def attempt(i: int) -> EngineResult:
            return EngineResult(
                technique_id="prompt_injection", target="demo",
                success=i < successes, success_score=0.9 if i < successes else 0.1,
            )

        return Reproducer(attempts=attempts).replay(attempt).to_dict()

    # -- frontend ---------------------------------------------------------- #

    @app.get("/", response_class=HTMLResponse)
    def index() -> HTMLResponse:
        return HTMLResponse((_STATIC / "index.html").read_text(encoding="utf-8"))

    return app


class _DomainRegistryShim:
    """Adapt a :class:`DomainAdapter` to the runner's ``TechniqueRegistry`` API."""

    def __init__(self, adapter: Any) -> None:
        self._adapter = adapter

    def require(self, technique_id: str) -> Technique:
        return self._adapter.require(technique_id)

    def get(self, technique_id: str) -> Optional[Technique]:
        return self._adapter.technique(technique_id)

    def all(self) -> List[Technique]:
        return self._adapter.techniques()


def main() -> None:  # pragma: no cover - entry point
    import uvicorn

    uvicorn.run(create_app(), host="127.0.0.1", port=8765)


if __name__ == "__main__":  # pragma: no cover
    main()

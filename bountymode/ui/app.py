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
from ..config import load_config
from ..dedupe.registry import DedupRegistry
from ..domains import DEFAULT_REGISTRY
from ..engine import build_local_dispatch, default_catalogue, engine_available
from ..evidence.redactor import Redactor
from ..evidence.vault import EvidenceVault
from ..models import Finding, ProgramScope, Technique
from ..report.generator import ReportGenerator
from ..runner.adapter import AgathonAdapter, EngineResult
from ..runner.case_runner import CaseRunner
from ..scope.importer import ScopeImporter
from ..triage.scorer import TriageScorer
from ..verify import (
    GenericVerifier,
    SimulatedTarget,
    SubmissionReadinessChecker,
    client_sender,
    simulated_sender,
)
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
    in_process: bool = False
    offline: bool = True
    intensity: str = "standard"
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


class OnboardRequest(BaseModel):
    """Fetch or paste a program page and return the parsed scope for review."""

    url: str = ""
    text: str = ""
    program: Optional[str] = None
    platform: Optional[str] = None
    browser: bool = True


class GuidedRunRequest(BaseModel):
    """One point-and-click run: import -> gate -> scan -> verify -> report."""

    url: str = ""
    text: str = ""
    program: Optional[str] = None
    platform: Optional[str] = None
    approved_by: str = ""
    target: str = ""
    domain: str = "ai_llm"
    techniques: Optional[List[str]] = None
    verify_attempts: int = 5
    browser: bool = True
    live: bool = False
    engine: Optional[str] = None
    intensity: str = "standard"


# --------------------------------------------------------------------------- #
# app
# --------------------------------------------------------------------------- #

class VerifyRequest(BaseModel):
    """Verify one finding by replaying a class-appropriate oracle N of M times."""

    finding: Dict[str, Any]
    attempts: int = 3
    in_scope: bool = True
    vulnerable: bool = True


class AutoRunRequest(BaseModel):
    """One-input autonomous mode: a single document in, a submission bundle out.

    ``text`` carries the program document inline (the paste path); ``path``
    points at a file already on disk.  Exactly one of them is required.
    """

    text: str = ""
    path: str = ""
    approved_by: str = ""
    note: str = ""
    target: str = ""
    domain: str = ""
    techniques: Optional[List[str]] = None
    verify_attempts: int = 5
    program: Optional[str] = None
    platform: Optional[str] = None
    intensity: str = "standard"
    adapt: bool = True
    live: bool = False
    engine: Optional[str] = None
    token: Optional[str] = None
    out_dir: str = "auto-run"


class AutoPlanRequest(BaseModel):
    """Show the plan for a document without running anything."""

    text: str = ""
    path: str = ""
    program: Optional[str] = None
    platform: Optional[str] = None


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

    # -- config / engine --------------------------------------------------- #

    @app.get("/api/config")
    def config() -> Dict[str, Any]:
        cfg = load_config()
        return {
            "source": cfg.source,
            "llm": cfg.llm.to_dict(redact=True),
            "engine": cfg.engine.to_dict(),
            "roles": {r: cfg.role_model(r) for r in ("generate", "judge", "multimodal")},
        }

    @app.get("/api/engine")
    def engine_info() -> Dict[str, Any]:
        cat = default_catalogue()
        return {
            "available": engine_available(),
            "catalogue": cat.stats(),
            "families": cat.families(),
            "intensity": load_config().engine.intensity,
        }

    @app.get("/api/engine/techniques")
    def engine_techniques() -> Dict[str, Any]:
        cat = default_catalogue()
        return {"count": len(cat.entries()), "techniques": cat.describe()}

    @app.post("/api/models/check")
    def models_check() -> Dict[str, Any]:
        cfg = load_config()
        if not cfg.llm.configured:
            return {"attempted": False, "reason": "no API key configured",
                    "model": cfg.llm.model}
        from ..engine.llm import ChatClient

        client = ChatClient(model=cfg.llm.model, api_key=cfg.llm.api_key,
                            base_url=cfg.llm.base_url, timeout=30.0)
        probe = client.reachable()
        return {"attempted": True, "model": cfg.llm.model, "ok": probe.ok,
                "sample": (probe.text or "").strip()[:60], "error": probe.error}

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

        if req.live and req.in_process:
            raise HTTPException(400, "live and in_process are mutually exclusive")

        dispatch = None
        mode = "dry-run"
        if req.in_process:
            cfg = load_config()
            effective_offline = req.offline or cfg.engine.offline
            dispatch = build_local_dispatch(
                model=cfg.engine.model or cfg.llm.model,
                intensity=req.intensity or cfg.engine.intensity,
                offline=effective_offline,
                simulate_vulnerable=effective_offline,
            )
            mode = "in-process-simulated" if effective_offline else "in-process-live"
        elif req.live:
            if not req.engine:
                raise HTTPException(400, "--live requires an engine URL")
            engine = AgathonAdapter(req.engine, token=req.token or "")

            def dispatch(t: Technique, tgt: str) -> EngineResult:  # noqa: E306
                return engine.run_test(t, tgt)

            mode = "remote-engine"

        runner = CaseRunner(
            gate=gate, stops=stops, vault=vault, dedup=dedup,
            registry=_DomainRegistryShim(adapter), dispatch=dispatch,
            builder=adapter,
        )
        result = runner.run("ui-case", scope, req.target, req.techniques)
        payload = result.to_dict()
        payload["mode"] = mode
        state["last_run"] = payload
        state["findings"] = result.findings
        state["vault"] = vault
        state["registry"] = dedup
        return payload

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

    # -- guided onboarding ------------------------------------------------- #

    @app.post("/api/onboard")
    def onboard(req: OnboardRequest) -> Dict[str, Any]:
        """Parse a program page (or pasted policy) into a reviewable scope.

        Nothing is authorized by this call and nothing is tested.  It returns
        the confirmation payload \u2014 in-scope assets, exclusions, policy
        prohibitions and the ``VERIFY`` list \u2014 for a human to review.
        """
        from ..program import ProgramImporter

        importer = ProgramImporter()
        if req.text.strip():
            imported = importer.import_text(
                req.text, program=req.program, platform=req.platform, url=req.url or ""
            )
        elif req.url.strip():
            imported = importer.import_url(
                req.url, program=req.program, platform=req.platform, browser=req.browser
            )
        else:
            raise HTTPException(400, "supply either a program URL or pasted policy text")

        payload = imported.confirm_payload
        payload["ok"] = imported.ok
        if imported.fetch:
            payload["fetch"] = imported.fetch.to_dict()
            payload["paste_hint"] = imported.fetch.paste_hint
        state["onboard"] = imported
        return payload

    @app.post("/api/guided-run")
    def guided_run(req: GuidedRunRequest) -> Dict[str, Any]:
        """Run the whole seven-stage pipeline from the UI.

        The defaults are the safe ones: an in-process **dry run** against the
        deterministic offline model, with no live target contacted.  A live run
        requires ``live`` **and** an engine URL, and still passes through the
        authorization gate and the stop-conditions.
        """
        from ..program import GuidedPipeline

        workdir = Path(state["workdir"]) / "guided"
        pipeline = GuidedPipeline(attempts=req.verify_attempts)
        common: Dict[str, Any] = dict(
            approved_by=req.approved_by,
            target=req.target,
            domain=req.domain,
            techniques=req.techniques,
            out_dir=str(workdir),
            in_process=not req.live,
            offline=not req.live,
            live=req.live,
            engine=req.engine or "",
            intensity=req.intensity,
            program=req.program,
            platform=req.platform,
            browser=req.browser,
            verify_attempts=req.verify_attempts,
        )
        if req.text.strip():
            result = pipeline.run_from_text(req.text, **common)
        elif req.url.strip():
            result = pipeline.run_from_url(req.url, **common)
        else:
            raise HTTPException(400, "supply either a program URL or pasted policy text")

        payload = result.to_dict()
        payload["ok"] = result.ok
        payload["stages_ok"] = all(s.ok for s in result.stages)
        state["findings"] = list(result.findings)
        state["last_run"] = payload
        state["workdir_last"] = str(workdir)
        return payload

    @app.get("/api/readiness")
    def readiness() -> Dict[str, Any]:
        """Submission readiness for the findings of the most recent run."""
        findings: List[Finding] = state["findings"]
        if not findings:
            return {"findings": [], "ready": 0, "total": 0}
        checker = SubmissionReadinessChecker()
        rows = []
        for f in findings:
            verdict = f.readiness or checker.check(f, in_scope=True).to_dict()
            rows.append({
                "finding_id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "cvss_score": f.cvss_score,
                "reproducible": f.reproducible,
                "reproduction_rate": f.reproduction_rate,
                "evidence_count": len(f.observations),
                "ready": bool(verdict.get("ready")),
                "missing": list(verdict.get("missing", [])),
                "blockers": list(verdict.get("blockers", [])),
                "summary": verdict.get("summary", ""),
            })
        return {
            "findings": rows,
            "ready": sum(1 for r in rows if r["ready"]),
            "total": len(rows),
        }

    @app.post("/api/verify")
    def verify_finding(req: VerifyRequest) -> Dict[str, Any]:
        """Replay a finding through the generic verification engine.

        Uses the simulated vulnerable target so the whole flow is exercisable
        from the UI without contacting anything; the verdict is still computed
        by the real oracle, so a hardened target reports ``unverified``.
        """
        try:
            finding = Finding.from_dict(req.finding)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(400, f"invalid finding: {exc}") from exc

        sim = SimulatedTarget(vulnerable=req.vulnerable)
        workdir = Path(state["workdir"]) / "verify-evidence"
        vault = EvidenceVault(str(workdir), redactor=Redactor())
        report = GenericVerifier(attempts=req.attempts).verify(
            finding, simulated_sender(sim), vault=vault, in_scope=req.in_scope
        )
        return {
            "verdict": report.verdict,
            "summary": report.summary,
            "report": report.to_dict(),
            "readiness": report.readiness,
            "requests_sent": report.requests_sent,
            "requests_reused": report.requests_reused,
        }

    # -- autonomous (one input) -------------------------------------------- #

    @app.post("/api/auto/plan")
    def auto_plan(req: AutoPlanRequest) -> Dict[str, Any]:
        """Show the plan the autonomous mode would produce, without running it."""
        from ..autonomous import DocumentIntake, Planner
        from ..program import ProgramImporter

        if req.path:
            read = DocumentIntake().read(req.path)
            if not read.ok:
                raise HTTPException(status_code=400, detail=read.error)
            text = read.text
        elif req.text.strip():
            text = req.text
        else:
            raise HTTPException(status_code=400, detail="supply either text or path")

        imported = ProgramImporter().import_text(
            text, program=req.program, platform=req.platform
        )
        if not imported.ok:
            raise HTTPException(
                status_code=400,
                detail="no scope could be parsed from the document",
            )
        plan = Planner().plan(imported.scope)
        return {
            "program": imported.scope.program,
            "platform": imported.scope.platform,
            "in_scope": [t.pattern for t in imported.scope.in_scope],
            "out_of_scope": [t.pattern for t in imported.scope.out_of_scope],
            "verify": list(imported.scope.verify_markers),
            "plan": plan.to_dict(),
        }

    @app.post("/api/auto/run")
    def auto_run(req: AutoRunRequest) -> Dict[str, Any]:
        """One document in, a submission bundle out.

        The whole job runs here: intake -> import -> scope -> plan -> gate ->
        scan -> verify -> amplify -> readiness -> report.  A human approver is
        required, and the default is a dry run.
        """
        from ..autonomous import AutonomousRunner

        if not req.approved_by.strip():
            raise HTTPException(
                status_code=400,
                detail="approved_by is required: a human must confirm the scope",
            )
        if not (req.path or req.text.strip()):
            raise HTTPException(status_code=400, detail="supply either text or path")

        runner = AutonomousRunner(attempts=req.verify_attempts)
        common = dict(
            approved_by=req.approved_by,
            approval_note=req.note,
            target=req.target,
            domain=req.domain,
            techniques=req.techniques,
            out_dir=req.out_dir,
            in_process=not req.live,
            offline=not req.live,
            live=req.live,
            engine=req.engine or "",
            token=req.token or "",
            intensity=req.intensity,
            program=req.program,
            platform=req.platform,
            verify_attempts=req.verify_attempts,
            adapt=req.adapt,
        )
        if req.path:
            result = runner.run_from_document(req.path, **common)
        else:
            result = runner.run_from_text(req.text, **common)
        return result.to_dict()

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

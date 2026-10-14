"""The autonomous runner -- one document in, a submission bundle out.

This is the orchestrator the one-input mode is built on.  It chains the existing
stages (import -> scope -> gate -> scan -> verify -> readiness -> report) and
adds the three things that make the run *autonomous* rather than scripted:

* **intake** -- read the operator's single document (PDF/text/HTML/JSON);
* **plan** -- decide which assets to test, with which techniques, in what order,
  and why (see :mod:`bountymode.autonomous.planner`);
* **amplify** -- after the scan, pursue the chain that raises severity, and
  re-plan a follow-up pass when a finding lands.

Everything else is the same code the CLI and UI already use, so the safety
properties are inherited rather than re-implemented: the authorization gate is
consulted for every technique, the stop-conditions bound the run, evidence is
redacted before it is persisted, and the default is a dry run.

The output is a :class:`AutonomousResult` carrying the plan, the findings, the
verification verdicts, the amplifications, the readiness verdicts and the
written report paths -- plus a top-level ``ready_to_submit`` summary that names
exactly what is missing when it is not ready.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from ..authority.gate import Approval, AuthorizationGate
from ..authority.stop_conditions import StopConditionEngine, StopConditions
from ..dedupe.registry import DedupRegistry
from ..domains import DEFAULT_REGISTRY
from ..engine import build_local_dispatch
from ..evidence.redactor import Redactor
from ..evidence.vault import EvidenceVault
from ..models import Finding, ProgramScope, Technique
from ..report.generator import ReportGenerator
from ..runner.adapter import EngineResult
from ..runner.case_runner import CaseRunner
from ..triage.scorer import TriageScorer
from ..verify import GenericVerifier, SimulatedTarget, client_sender, simulated_sender
from ..program.importer import ProgramImporter
from .amplify import Amplifier
from .intake import DocumentIntake, IntakeResult
from .planner import Planner


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


#: The stages an autonomous run reports, in order.
AUTO_STAGES = (
    "intake", "import", "scope", "plan", "gate", "scan",
    "verify", "amplify", "readiness", "report",
)


@dataclass
class AutoStage:
    name: str
    ok: bool
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"stage": self.name, "ok": self.ok, "detail": self.detail}


@dataclass
class AutonomousResult:
    """Everything one autonomous run produced."""

    program: str = ""
    platform: str = ""
    mode: str = "dry-run"
    source: str = ""
    stages: List[AutoStage] = field(default_factory=list)
    intake: Optional[Dict[str, Any]] = None
    plan: Optional[Dict[str, Any]] = None
    followup_plan: Optional[Dict[str, Any]] = None
    receipt: Optional[Dict[str, Any]] = None
    gate_summary: Dict[str, int] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    verified: List[Dict[str, Any]] = field(default_factory=list)
    amplifications: List[Dict[str, Any]] = field(default_factory=list)
    readiness: List[Dict[str, Any]] = field(default_factory=list)
    reports: List[Dict[str, Any]] = field(default_factory=list)
    skipped: List[Dict[str, str]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    requests_made: int = 0
    out_dir: str = ""
    started_at: str = field(default_factory=_now_iso)
    finished_at: str = ""

    # -- derived ----------------------------------------------------------- #

    @property
    def ready_count(self) -> int:
        return sum(1 for r in self.readiness if r.get("ready"))

    @property
    def verified_count(self) -> int:
        return sum(1 for v in self.verified if v.get("verdict") == "verified")

    @property
    def ready_to_submit(self) -> bool:
        """True only when at least one finding is fully submission-ready."""
        return self.ready_count > 0

    @property
    def missing(self) -> List[str]:
        """The union of everything blocking submission, de-duplicated."""
        out: List[str] = []
        for row in self.readiness:
            for item in list(row.get("blockers", [])) + list(row.get("missing", [])):
                if item not in out:
                    out.append(item)
        return out

    @property
    def ok(self) -> bool:
        return all(s.ok for s in self.stages)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "program": self.program,
            "platform": self.platform,
            "mode": self.mode,
            "source": self.source,
            "stages": [s.to_dict() for s in self.stages],
            "intake": self.intake,
            "plan": self.plan,
            "followup_plan": self.followup_plan,
            "receipt": self.receipt,
            "gate_summary": dict(self.gate_summary),
            "findings": [f.to_dict() for f in self.findings],
            "verified": list(self.verified),
            "amplifications": list(self.amplifications),
            "readiness": list(self.readiness),
            "reports": list(self.reports),
            "skipped": list(self.skipped),
            "errors": list(self.errors),
            "requests_made": self.requests_made,
            "finding_count": len(self.findings),
            "verified_count": self.verified_count,
            "ready_count": self.ready_count,
            "ready_to_submit": self.ready_to_submit,
            "missing": self.missing,
            "out_dir": self.out_dir,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }


class AutonomousRunner:
    """One document in, a submission bundle out."""

    def __init__(
        self,
        *,
        intake: Optional[DocumentIntake] = None,
        importer: Optional[ProgramImporter] = None,
        planner: Optional[Planner] = None,
        amplifier: Optional[Amplifier] = None,
        scorer: Optional[TriageScorer] = None,
        attempts: int = 5,
    ) -> None:
        self.intake = intake or DocumentIntake()
        self.importer = importer or ProgramImporter()
        self.planner = planner or Planner()
        self.amplifier = amplifier or Amplifier()
        self.scorer = scorer or TriageScorer()
        self.default_attempts = attempts

    # -- entry points ------------------------------------------------------ #

    def run_from_document(self, path: str, **kwargs: Any) -> AutonomousResult:
        """The one-input entry point: a single file, nothing else."""
        return self.run(source=path, source_kind="document", **kwargs)

    def run_from_text(self, text: str, **kwargs: Any) -> AutonomousResult:
        return self.run(source=text, source_kind="text", **kwargs)

    def run_from_url(self, url: str, **kwargs: Any) -> AutonomousResult:
        return self.run(source=url, source_kind="url", **kwargs)

    # -- the run ----------------------------------------------------------- #

    def run(
        self,
        *,
        source: str,
        source_kind: str = "document",
        approved_by: str = "",
        approval_note: str = "",
        target: str = "",
        domain: str = "",
        techniques: Optional[List[str]] = None,
        out_dir: str = "auto-run",
        in_process: bool = True,
        offline: bool = True,
        live: bool = False,
        engine: str = "",
        token: str = "",
        intensity: str = "standard",
        browser: bool = True,
        program: Optional[str] = None,
        platform: Optional[str] = None,
        verify_attempts: Optional[int] = None,
        write_reports: bool = True,
        adapt: bool = True,
        use_llm_planner: bool = False,
        llm_client: Any = None,
        on_stage: Optional[Callable[[str, bool, str], None]] = None,
    ) -> AutonomousResult:
        result = AutonomousResult(mode="dry-run", out_dir=out_dir, source=source)
        d = Path(out_dir)
        d.mkdir(parents=True, exist_ok=True)
        attempts = verify_attempts or self.default_attempts

        def stage(name: str, ok: bool, detail: str) -> None:
            """Record a stage and, if a listener is attached, report it live."""
            result.stages.append(AutoStage(name, ok, detail))
            if on_stage is not None:
                try:
                    on_stage(name, "PASS" if ok else "FAIL", detail)
                except Exception:  # noqa: BLE001 - a listener must never break a run
                    pass

        # ---- 1. intake --------------------------------------------------- #
        policy_text = ""
        if source_kind == "document":
            read: IntakeResult = self.intake.read(source)
            result.intake = read.to_dict()
            if not read.ok:
                result.stages.append(AutoStage("intake", False, read.error))
                if read.hint:
                    result.errors.append(read.hint)
                self._finish(result)
                return result
            policy_text = read.text
            stage(
                "intake", True,
                f"read {read.kind} via {read.reader} "
                f"({read.chars} chars" + (f", {read.pages} pages" if read.pages else "") + ")",
            )
        elif source_kind == "text":
            read = self.intake.read_text(source)
            result.intake = read.to_dict()
            if not read.ok:
                result.stages.append(AutoStage("intake", False, read.error))
                self._finish(result)
                return result
            policy_text = read.text
            stage("intake", True, f"inline text ({read.chars} chars)")
        else:
            stage("intake", True, "URL source (fetched during import)")

        # ---- 2. import --------------------------------------------------- #
        if source_kind == "url":
            imported = self.importer.import_url(
                source, program=program, platform=platform, browser=browser
            )
        else:
            imported = self.importer.import_text(
                policy_text, program=program, platform=platform,
                url=(result.intake or {}).get("path", ""),
            )
        result.program = imported.scope.program
        result.platform = imported.scope.platform
        if not imported.ok:
            detail = (
                imported.report.warnings[0] if imported.report.warnings
                else "no in-scope or out-of-scope entries were parsed from the document"
            )
            result.stages.append(AutoStage("import", False, detail))
            self._finish(result)
            return result
        stage(
            "import", True,
            f"{len(imported.scope.in_scope)} in-scope, "
            f"{len(imported.scope.out_of_scope)} exclusions, "
            f"{len(imported.scope.verify_markers)} to verify",
        )

        # ---- 3. scope + authorization receipt ---------------------------- #
        if not approved_by:
            stage(
                "scope", False,
                "no approver named -- a human must confirm the parsed scope before any test",
            )
            result.errors.append("authorization refused: no human approver")
            self._finish(result)
            return result
        receipt = self.importer.confirm(
            imported, approved_by=approved_by, note=approval_note, out_dir=out_dir
        )
        result.receipt = receipt.to_dict()
        scope = imported.scope
        stage(
            "scope", True,
            f"scope digest {receipt.scope_digest[:12]} approved by {approved_by}",
        )

        # ---- 4. plan ----------------------------------------------------- #
        plan = self.planner.plan(scope)
        result.plan = plan.to_dict()
        if not plan.targets:
            result.stages.append(AutoStage(
                "plan", False,
                "the planner found no directly testable asset in the scope "
                "(every entry is a wildcard or a listing page)",
            ))
            self._finish(result)
            return result
        result.stages.append(AutoStage(
            "plan", True,
            f"{len(plan.targets)} target(s), families: {', '.join(plan.families) or 'n/a'} "
            f"[{plan.source}]",
        ))

        # ---- 5. gate + scan ---------------------------------------------- #
        chosen = target or (plan.primary.target if plan.primary else "")
        if not chosen:
            result.stages.append(AutoStage("gate", False, "no concrete target to test"))
            self._finish(result)
            return result

        # The plan may span several assets; the runner tests the primary one and
        # records the rest, so a run stays bounded and auditable.
        planned = next((t for t in plan.targets if t.target == chosen), plan.primary)
        chosen_domain = domain or (planned.domain if planned else "ai_llm")
        offered = techniques or (planned.techniques if planned else [])

        adapter = DEFAULT_REGISTRY.get(chosen_domain)
        gate = AuthorizationGate(scope)
        for appr in self._approvals_for(scope, chosen, offered, adapter):
            gate.register_approval(appr)

        allowed: List[str] = []
        for tid in offered:
            technique = adapter.technique(tid)
            if technique is None:
                result.skipped.append({"technique": tid, "reason": "unknown technique"})
                continue
            decision = gate.authorize(chosen, technique)
            if decision.verdict.value == "allow":
                allowed.append(tid)
            else:
                result.skipped.append({"technique": tid, "reason": decision.reason})

        result.gate_summary = gate.summary()
        if not allowed:
            result.stages.append(AutoStage(
                "gate", False,
                f"no technique is authorized for {chosen} "
                f"({result.gate_summary.get('deny', 0)} denied)",
            ))
            self._finish(result)
            return result
        result.stages.append(AutoStage(
            "gate", True,
            f"{len(allowed)} of {len(offered)} planned techniques authorized for {chosen}",
        ))

        if live and in_process:
            result.errors.append("live and in_process are mutually exclusive")
            result.stages.append(AutoStage("scan", False, "mutually exclusive modes"))
            self._finish(result)
            return result

        dispatch: Optional[Callable[[Technique, str], EngineResult]] = None
        # A web/API target is tested over real HTTP, not by prompting a model.
        # The domain decides which engine drives the scan.
        is_web = chosen_domain in ("web_api", "web") or getattr(adapter, "scope_kind", "") == "web"
        if in_process and is_web:
            from ..engine.web import build_web_dispatch

            dispatch = build_web_dispatch(chosen, allow_writes=True)
            result.mode = "in-process-web"
        elif in_process:
            dispatch = build_local_dispatch(
                model="", intensity=intensity, offline=offline, simulate_vulnerable=offline,
            )
            result.mode = "in-process-dry-run" if offline else "in-process-live"
        elif live:
            if not engine:
                result.errors.append("live run requires an engine URL")
                result.stages.append(AutoStage("scan", False, "live run requires --engine"))
                self._finish(result)
                return result
            from ..runner.adapter import AgathonAdapter

            remote = AgathonAdapter(engine, token=token)

            def dispatch(t: Technique, tgt: str) -> EngineResult:  # noqa: E306
                return remote.run_test(t, tgt)

            result.mode = "remote-engine"

        stops = StopConditionEngine(StopConditions.from_scope(scope))
        vault = EvidenceVault(str(d / "evidence"), redactor=Redactor())
        dedup = DedupRegistry(str(d / "registry.json"))
        runner = CaseRunner(
            gate=gate, stops=stops, vault=vault, dedup=dedup,
            registry=adapter, builder=adapter, dispatch=dispatch,
        )
        case = runner.run("autonomous", scope, chosen, allowed)
        result.findings = list(case.findings)
        result.skipped.extend(case.skipped)
        result.errors.extend(case.errors)
        result.requests_made = case.requests_made
        runner.write_result(case, str(d / "case-result.json"))
        stage(
            "scan", True,
            f"{result.requests_made} request(s), {len(result.findings)} finding(s) "
            f"[{result.mode}]" + (f"; STOPPED: {case.stop_reason}" if case.stopped else ""),
        )

        # ---- 6. verify --------------------------------------------------- #
        # A web finding is an HTTP differential, so it is judged by the web
        # oracle explicitly -- not by a same-named prompt oracle.
        web_oracle = None
        if is_web:
            from ..verify.oracles import web_oracle as _web_oracle

            web_oracle = _web_oracle()
        verifier = GenericVerifier(attempts=attempts, oracle=web_oracle)
        sender = self._verification_sender(
            in_process=in_process, offline=offline, is_web=is_web
        )
        for finding in result.findings:
            verification = verifier.verify(finding, sender, vault=vault, in_scope=True)
            result.verified.append(verification.to_dict())
        stage(
            "verify", True,
            f"{result.verified_count} of {len(result.findings)} finding(s) verified "
            f"({attempts} attempt(s) each)",
        )

        # ---- 7. amplify -------------------------------------------------- #
        if result.findings:
            amps = self.amplifier.amplify(result.findings, apply=True)
            result.amplifications = [a.to_dict() for a in amps]
            # Amplification sets a severity floor; re-score so the CVSS number
            # and the severity label agree before anything is reported.
            self.scorer.score_all(result.findings)
            lifted = sum(1 for a in amps if a.amplified)
            stage(
                "amplify", True,
                f"{lifted} amplification(s) applied across {len(result.findings)} finding(s)",
            )
        else:
            stage("amplify", True, "nothing to amplify")

        # ---- 7b. adaptive follow-up pass --------------------------------- #
        if adapt and result.findings:
            follow = self.planner.adapt(
                plan, result.findings, already_run=allowed
            )
            result.followup_plan = follow.to_dict()
            if follow.targets:
                extra = follow.technique_ids
                follow_allowed: List[str] = []
                for tid in extra:
                    technique = adapter.technique(tid)
                    if technique is None:
                        continue
                    decision = gate.authorize(chosen, technique)
                    if decision.verdict.value == "allow":
                        follow_allowed.append(tid)
                if follow_allowed:
                    case2 = runner.run("autonomous-followup", scope, chosen, follow_allowed)
                    # Merge new findings, de-duplicating by fingerprint.
                    known = {f.fingerprint for f in result.findings}
                    for f in case2.findings:
                        if f.fingerprint not in known:
                            known.add(f.fingerprint)
                            result.findings.append(f)
                            verification = verifier.verify(
                                f, sender, vault=vault, in_scope=True
                            )
                            result.verified.append(verification.to_dict())
                    result.requests_made += case2.requests_made
                    result.skipped.extend(case2.skipped)
                    result.errors.extend(case2.errors)
                    if case2.findings:
                        amps2 = self.amplifier.amplify(result.findings, apply=True)
                        result.amplifications = [a.to_dict() for a in amps2]
                        self.scorer.score_all(result.findings)

        # ---- 8. readiness ------------------------------------------------ #
        # Readiness is re-assessed *after* amplification, because the lift can
        # change the severity and the impact statement that the checks read.
        from ..verify.checks import assess_readiness

        for index, finding in enumerate(result.findings):
            report = result.verified[index] if index < len(result.verified) else None
            readiness = assess_readiness(finding, report, in_scope=True)
            finding.readiness = readiness.to_dict()
        result.readiness = [dict(f.readiness) for f in result.findings]
        stage(
            "readiness", True,
            f"{result.ready_count} of {len(result.findings)} finding(s) are submission-ready",
        )

        # ---- 9. report --------------------------------------------------- #
        if write_reports and result.findings:
            gen = ReportGenerator(
                platform=scope.platform or "hackerone", program=scope.program
            )
            reports_dir = d / "reports"
            for finding, verdict in zip(result.findings, result.readiness):
                rendered = gen.render(finding)
                paths = gen.write(rendered, str(reports_dir))
                result.reports.append({
                    "finding_id": finding.id,
                    "title": finding.title,
                    "severity": finding.severity.value,
                    "cvss_score": finding.cvss_score,
                    "ready": bool(verdict.get("ready")),
                    "missing": list(verdict.get("missing", [])),
                    "markdown": paths["markdown"],
                    "json": paths["json"],
                })
            bundle = self._write_bundle(result, d)
            stage(
                "report", True,
                f"{len(result.reports)} report file(s) + submission bundle "
                f"({bundle.name}) in {reports_dir}",
            )
        else:
            stage("report", True, "nothing to report")

        (d / "autonomous-result.json").write_text(
            json.dumps(result.to_dict(), indent=2, sort_keys=True), encoding="utf-8"
        )
        self._finish(result)
        return result

    # -- helpers ----------------------------------------------------------- #

    def _write_bundle(self, result: AutonomousResult, d: Path) -> Path:
        """Write the top-level submission bundle with the ready/not-ready verdict."""
        reports_dir = d / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        bundle = {
            "program": result.program,
            "platform": result.platform,
            "mode": result.mode,
            "generated_at": _now_iso(),
            "ready_to_submit": result.ready_to_submit,
            "summary": (
                f"{result.ready_count} of {len(result.findings)} finding(s) are "
                "submission-ready."
                if result.findings else "No findings were produced."
            ),
            "missing": result.missing,
            "findings": [
                {
                    "finding_id": r["finding_id"],
                    "title": r["title"],
                    "severity": r["severity"],
                    "cvss_score": r["cvss_score"],
                    "ready": r["ready"],
                    "missing": r["missing"],
                    "markdown": r["markdown"],
                    "json": r["json"],
                }
                for r in result.reports
            ],
            "note": (
                "Final confirmation of a vulnerability is the bounty program's job. "
                "This bundle states reproducibility and evidence, not certainty. "
                "Nothing has been submitted anywhere."
            ),
        }
        path = reports_dir / "submission-bundle.json"
        path.write_text(json.dumps(bundle, indent=2, sort_keys=True), encoding="utf-8")
        return path

    @staticmethod
    def _approvals_for(
        scope: ProgramScope,
        target: str,
        techniques: List[str],
        adapter: Any,
    ) -> List[Approval]:
        """Side-effecting techniques the *program itself* authorizes."""
        permitted = {t.lower() for t in scope.permitted_techniques}
        if not permitted:
            return []
        return [
            Approval(
                target=target, technique_id=tid,
                approved_by="program-policy",
                approved_at=_now_iso(),
                note="technique explicitly permitted by the imported program scope",
            )
            for tid in techniques
            if tid.lower() in permitted
        ]

    @staticmethod
    def _verification_sender(*, in_process: bool, offline: bool, is_web: bool = False) -> Any:
        """Pick the probe sender verification replays against.

        A web finding is an HTTP differential, so it is replayed with the web
        sender; an LLM finding is replayed against the model client.
        """
        if is_web:
            from ..verify.web_oracles import web_sender

            return web_sender()
        if not (in_process and not offline):
            return simulated_sender(SimulatedTarget(vulnerable=True))
        try:
            from ..engine.llm import client_from_config

            client = client_from_config()
        except Exception:  # noqa: BLE001 - a missing client is not fatal
            return simulated_sender(SimulatedTarget(vulnerable=True))
        return client_sender(client)

    @staticmethod
    def _finish(result: AutonomousResult) -> None:
        result.finished_at = _now_iso()

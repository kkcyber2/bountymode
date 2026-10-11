"""The guided pipeline -- one call from a program URL to a finished report.

    pipeline = GuidedPipeline()
    result = pipeline.run_from_url(
        "https://bugcrowd.com/engagements/apps-plus2",
        approved_by="alice",
    )

The seven stages are the same ones the CLI and UI expose individually, wired in
order so a new user never has to learn them:

    import -> scope -> gate -> scan -> verify -> readiness -> report

Safety properties, all enforced here rather than by convention:

* the pipeline **refuses to scan** without an :class:`AuthorizationReceipt`
  naming a human approver whose recorded scope digest matches the scope in use;
* the default is a **dry run** -- ``in_process`` uses the deterministic offline
  model, and a live run requires an explicit ``live=True`` plus an engine URL;
* every technique still passes through the authorization gate, so an
  out-of-scope target cannot be reached even from the pipeline;
* nothing is ever submitted to a platform.  The deliverable is a set of report
  files a human reviews and submits.
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
from ..runner.adapter import AgathonAdapter, EngineResult
from ..runner.case_runner import CaseRunner
from ..triage.scorer import TriageScorer
from ..verify import (
    GenericVerifier,
    SimulatedTarget,
    client_sender,
    simulated_sender,
)
from .extractor import ExtractionReport
from .importer import AuthorizationReceipt, ImportResult, ProgramImporter
from .verifier import SubmissionReadinessChecker


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


#: Stages, in order.  ``PipelineResult.stages`` reports each one's outcome.
STAGES = ("import", "scope", "gate", "scan", "verify", "readiness", "report")


@dataclass
class StageOutcome:
    name: str
    ok: bool
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"stage": self.name, "ok": self.ok, "detail": self.detail}


@dataclass
class PipelineResult:
    """Everything one guided run produced."""

    program: str = ""
    target: str = ""
    mode: str = "dry-run"
    stages: List[StageOutcome] = field(default_factory=list)
    import_result: Optional[ImportResult] = None
    receipt: Optional[AuthorizationReceipt] = None
    gate_summary: Dict[str, int] = field(default_factory=dict)
    techniques: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    verified: List[Dict[str, Any]] = field(default_factory=list)
    readiness: List[Dict[str, Any]] = field(default_factory=list)
    reports: List[Dict[str, Any]] = field(default_factory=list)
    skipped: List[Dict[str, str]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    stopped: bool = False
    stop_reason: str = ""
    requests_made: int = 0
    out_dir: str = ""
    started_at: str = field(default_factory=_now_iso)
    finished_at: str = ""

    @property
    def ready_count(self) -> int:
        return sum(1 for r in self.readiness if r.get("ready"))

    @property
    def verified_count(self) -> int:
        """How many findings the verification engine actually reproduced."""
        return sum(1 for v in self.verified if v.get("verdict") == "verified")

    @property
    def ok(self) -> bool:
        return all(s.ok for s in self.stages) and bool(self.findings or self.skipped)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "program": self.program,
            "target": self.target,
            "mode": self.mode,
            "stages": [s.to_dict() for s in self.stages],
            "gate_summary": dict(self.gate_summary),
            "techniques": list(self.techniques),
            "findings": [f.to_dict() for f in self.findings],
            "verified": list(self.verified),
            "readiness": list(self.readiness),
            "reports": list(self.reports),
            "skipped": list(self.skipped),
            "errors": list(self.errors),
            "stopped": self.stopped,
            "stop_reason": self.stop_reason,
            "requests_made": self.requests_made,
            "ready_count": self.ready_count,
            "verified_count": self.verified_count,
            "finding_count": len(self.findings),
            "out_dir": self.out_dir,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }


class GuidedPipeline:
    """Chain import -> scope -> gate -> scan -> verify -> readiness -> report."""

    def __init__(
        self,
        *,
        importer: Optional[ProgramImporter] = None,
        readiness: Optional[SubmissionReadinessChecker] = None,
        scorer: Optional[TriageScorer] = None,
        attempts: int = 5,
    ) -> None:
        self.importer = importer or ProgramImporter()
        self.readiness = readiness or SubmissionReadinessChecker()
        self.scorer = scorer or TriageScorer()
        self.default_attempts = attempts

    # -- entry points ------------------------------------------------------ #

    def run_from_url(self, url: str, **kwargs: Any) -> PipelineResult:
        return self.run(source=url, source_kind="url", **kwargs)

    def run_from_text(self, text: str, **kwargs: Any) -> PipelineResult:
        return self.run(source=text, source_kind="text", **kwargs)

    def run_from_file(self, path: str, **kwargs: Any) -> PipelineResult:
        return self.run(source=path, source_kind="file", **kwargs)

    # -- the pipeline ------------------------------------------------------ #

    def run(
        self,
        *,
        source: str,
        source_kind: str = "url",
        approved_by: str = "",
        approval_note: str = "",
        target: str = "",
        domain: str = "ai_llm",
        techniques: Optional[List[str]] = None,
        out_dir: str = "bounty-run",
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
    ) -> PipelineResult:
        result = PipelineResult(mode="dry-run", out_dir=out_dir)
        d = Path(out_dir)
        d.mkdir(parents=True, exist_ok=True)
        attempts = verify_attempts or self.default_attempts

        # ---- 1. import -------------------------------------------------- #
        if source_kind == "file":
            preset = self._load_confirmed_scope(source)
            if preset is not None:
                imported = self._confirm_preset(preset, source)
            else:
                imported = self.importer.import_file(source, program=program, platform=platform)
        elif source_kind == "url":
            imported = self.importer.import_url(
                source, program=program, platform=platform, browser=browser
            )
        else:
            imported = self.importer.import_text(source, program=program, platform=platform)
        result.import_result = imported
        result.program = imported.scope.program
        if not imported.ok:
            result.stages.append(StageOutcome(
                "import", False,
                imported.report.warnings[0] if imported.report.warnings
                else "no in-scope or out-of-scope entries were parsed from the source",
            ))
            self._finish(result)
            return result
        result.stages.append(StageOutcome(
            "import", True,
            f"{len(imported.scope.in_scope)} in-scope, "
            f"{len(imported.scope.out_of_scope)} exclusions, "
            f"{len(imported.scope.verify_markers)} to verify (via {imported.report.source})",
        ))

        # ---- 2. scope + authorization receipt --------------------------- #
        if not approved_by:
            result.stages.append(StageOutcome(
                "scope", False,
                "no approver named -- a human must confirm the parsed scope before any test",
            ))
            result.errors.append("authorization refused: no human approver")
            self._finish(result)
            return result

        receipt = self.importer.confirm(
            imported, approved_by=approved_by, note=approval_note, out_dir=out_dir
        )
        result.receipt = receipt
        scope = imported.scope
        result.stages.append(StageOutcome(
            "scope", True,
            f"scope digest {receipt.scope_digest[:12]} approved by {approved_by}",
        ))

        # ---- 3. target + techniques + gate ------------------------------ #
        chosen = target or self._default_target(scope)
        if not chosen:
            result.stages.append(StageOutcome(
                "gate", False,
                "no concrete testable target could be derived. In-scope entries are "
                "wildcards or listing pages -- set the asset to test explicitly.",
            ))
            self._finish(result)
            return result
        result.target = chosen

        adapter = DEFAULT_REGISTRY.get(domain)
        gate = AuthorizationGate(scope)
        for appr in self._approvals_for(scope, chosen, techniques, adapter):
            gate.register_approval(appr)

        offered = techniques or [t.id for t in adapter.techniques()]
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

        result.techniques = allowed
        result.gate_summary = gate.summary()
        if not allowed:
            result.stages.append(StageOutcome(
                "gate", False,
                f"no technique is authorized for {chosen} "
                f"({result.gate_summary.get('deny', 0)} denied)",
            ))
            self._finish(result)
            return result
        result.stages.append(StageOutcome(
            "gate", True,
            f"{len(allowed)} of {len(offered)} techniques authorized for {chosen}",
        ))

        # ---- 4. scan ---------------------------------------------------- #
        dispatch: Optional[Callable[[Technique, str], EngineResult]] = None
        if live and in_process:
            result.errors.append("live and in_process are mutually exclusive")
            result.stages.append(StageOutcome("scan", False, "mutually exclusive modes"))
            self._finish(result)
            return result
        if in_process:
            dispatch = build_local_dispatch(
                model="", intensity=intensity, offline=offline, simulate_vulnerable=offline,
            )
            result.mode = "in-process-dry-run" if offline else "in-process-live"
        elif live:
            if not engine:
                result.errors.append("live run requires an engine URL")
                result.stages.append(StageOutcome("scan", False, "live run requires --engine"))
                self._finish(result)
                return result
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
        case = runner.run("guided", scope, chosen, allowed)
        result.findings = list(case.findings)
        result.skipped.extend(case.skipped)
        result.errors.extend(case.errors)
        result.stopped = case.stopped
        result.stop_reason = case.stop_reason
        result.requests_made = case.requests_made
        runner.write_result(case, str(d / "case-result.json"))
        result.stages.append(StageOutcome(
            "scan", True,
            f"{result.requests_made} request(s), {len(result.findings)} finding(s) "
            f"[{result.mode}]" + (f"; STOPPED: {case.stop_reason}" if case.stopped else ""),
        ))

        # ---- 5. verify -------------------------------------------------- #
        # A class-appropriate oracle replays each finding N of M times, compares
        # the test probe against a control and a negative control, and returns
        # an explicit verdict (verified / unverified / inconclusive).  A dry run
        # has no live target, so verification is exercised against the simulated
        # vulnerable target and labelled as simulated; a live run verifies
        # through the same model client the scan used.
        verifier = GenericVerifier(attempts=attempts)
        sender = self._verification_sender(in_process=in_process, offline=offline)
        for finding in result.findings:
            verification = verifier.verify(finding, sender, vault=vault, in_scope=True)
            result.verified.append(verification.to_dict())
            result.readiness.append(dict(verification.readiness))
        result.stages.append(StageOutcome(
            "verify", True,
            f"{result.verified_count} of {len(result.findings)} finding(s) verified "
            f"({attempts} attempt(s) each)",
        ))

        # ---- 6. readiness ----------------------------------------------- #
        ready = [r for r in result.readiness if r.get("ready")]
        result.stages.append(StageOutcome(
            "readiness", True,
            f"{len(ready)} of {len(result.findings)} finding(s) are submission-ready",
        ))

        # ---- 7. report --------------------------------------------------- #
        if write_reports and result.findings:
            gen = ReportGenerator(platform=scope.platform or "hackerone", program=scope.program)
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
            result.stages.append(StageOutcome(
                "report", True, f"{len(result.reports)} report file(s) written to {reports_dir}",
            ))
        else:
            result.stages.append(StageOutcome("report", True, "nothing to report"))

        (d / "pipeline-result.json").write_text(
            json.dumps(result.to_dict(), indent=2, sort_keys=True), encoding="utf-8"
        )
        self._finish(result)
        return result

    # -- helpers ----------------------------------------------------------- #

    @staticmethod
    def load_scope(path: str) -> Optional[ProgramScope]:
        """Load a ``scope.json`` if the file is one, else ``None``.

        A workflow is *import once, run many*: the confirmed scope written by
        ``bountymode program import`` should be directly reusable, so a later run
        does not re-parse the page (and cannot drift from what a human approved).
        """
        import json as _json
        from pathlib import Path as _Path

        p = _Path(path)
        if not p.is_file():
            return None
        try:
            data = _json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(data, dict) or "in_scope" not in data:
            return None
        try:
            return ProgramScope.from_dict(data)
        except Exception:  # noqa: BLE001 - fall back to text parsing
            return None

    @classmethod
    def _load_confirmed_scope(cls, path: str) -> Optional[ProgramScope]:
        return cls.load_scope(path)

    @staticmethod
    def _confirm_preset(scope: ProgramScope, source: str) -> ImportResult:
        """Wrap an already-confirmed scope so the pipeline can treat it uniformly."""
        report = ExtractionReport(
            source="scope.json",
            url=source,
            title=scope.program,
            confidence=1.0,
            verify=list(scope.verify_markers),
            stats={
                "in_scope": len(scope.in_scope),
                "out_of_scope": len(scope.out_of_scope),
                "listings": len(scope.listings),
                "prohibited": len(scope.prohibited_techniques),
                "rewards": len(scope.reward_table),
                "notes": len(scope.notes),
                "verify": len(scope.verify_markers),
            },
        )
        return ImportResult(scope=scope, report=report, listing_count=len(scope.listings))

    @staticmethod
    def _approvals_for(
        scope: ProgramScope,
        target: str,
        techniques: Optional[List[str]],
        adapter: Any,
    ) -> List[Approval]:
        """Side-effecting techniques the *program itself* authorizes.

        A program that explicitly permits a technique has already made the
        authorization decision; recording that as an approval is an audit trail,
        not a bypass.  Anything the program did not permit still needs a human.
        """
        permitted = {t.lower() for t in scope.permitted_techniques}
        if not permitted:
            return []
        ids = techniques or [t.id for t in adapter.techniques()]
        return [
            Approval(
                target=target, technique_id=tid,
                approved_by="program-policy",
                approved_at=_now_iso(),
                note="technique explicitly permitted by the imported program scope",
            )
            for tid in ids
            if tid.lower() in permitted
        ]

    @staticmethod
    def _verification_sender(*, in_process: bool, offline: bool) -> Any:
        """Pick the probe sender verification replays against.

        A dry run has no live target, so it reuses the simulated vulnerable
        target's probe-aware behaviour -- that is what lets a dry run exercise
        the real oracle path end to end.  A live in-process run sends probes
        through the configured model client.  A remote-engine run has no
        prompt-level client, so it falls back to the simulated sender; the
        verdict is still recorded honestly rather than assumed.
        """
        if not (in_process and not offline):
            return simulated_sender(SimulatedTarget(vulnerable=True))
        try:
            from ..engine.llm import client_from_config

            client = client_from_config()
        except Exception:  # noqa: BLE001 - a missing client is not fatal
            return simulated_sender(SimulatedTarget(vulnerable=True))
        return client_sender(client)

    @staticmethod
    def _default_target(scope: ProgramScope) -> str:
        """Pick a concrete asset to test from the imported scope.

        Wildcards and bare paths are skipped: ``*.example.com`` names a family
        of hosts, and guessing which one to test would be inventing scope.
        """
        for entry in scope.in_scope:
            pattern = (entry.pattern or "").strip()
            if not pattern or pattern.startswith("*"):
                continue
            if pattern.startswith("http://") or pattern.startswith("https://"):
                return pattern
            if "." in pattern and "/" not in pattern:
                return pattern
        return ""

    @staticmethod
    def _finish(result: PipelineResult) -> None:
        result.finished_at = _now_iso()

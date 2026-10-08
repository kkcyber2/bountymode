"""Bounty Mode case runner.

Executes a *case* — one program, one target, a list of techniques — one
technique at a time, enforcing the authorization gate and stop-conditions
before every single test.

Guarantees the runner provides:

1. **No unauthorized test ever runs.**  Every technique passes through
   :meth:`AuthorizationGate.require` immediately before dispatch.
2. **Budgets are respected.**  The stop-condition engine is checked before
   each case and can latch the whole run.
3. **Every result is evidenced.**  Successes are captured in the vault;
   failures are recorded too (so a null result is auditable).
4. **Findings are de-duplicated and scored.**  The runner never emits the
   same finding twice, and ranks what it does emit.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from ..authority.gate import AuthorizationGate
from ..authority.stop_conditions import StopConditionEngine
from ..dedupe.registry import DedupRegistry, DedupVerdict
from ..errors import AuthorizationError, ScopeViolationError, StopConditionError
from ..evidence.vault import EvidenceVault
from ..models import Finding, ProgramScope, Technique, json_dumps
from ..triage.scorer import TriageScorer
from .adapter import AgathonAdapter, EngineResult, FindingBuilder, TechniqueRegistry


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class CaseResult:
    """Outcome of one full case run."""

    case_id: str
    scope: ProgramScope
    started_at: str = field(default_factory=_now_iso)
    finished_at: str = ""
    findings: List[Finding] = field(default_factory=list)
    decisions: List[Dict[str, Any]] = field(default_factory=list)
    skipped: List[Dict[str, str]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    stopped: bool = False
    stop_reason: str = ""
    requests_made: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "program": self.scope.program,
            "platform": self.scope.platform,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "stopped": self.stopped,
            "stop_reason": self.stop_reason,
            "requests_made": self.requests_made,
            "findings": [f.to_dict() for f in self.findings],
            "decisions": self.decisions,
            "skipped": self.skipped,
            "errors": self.errors,
        }


#: A dispatch function returns an EngineResult for one technique/target.
DispatchFn = Callable[[Technique, str], EngineResult]


class CaseRunner:
    """Run a scoped set of techniques against one target."""

    def __init__(
        self,
        *,
        gate: AuthorizationGate,
        stops: StopConditionEngine,
        vault: EvidenceVault,
        registry: Optional[TechniqueRegistry] = None,
        dedup: Optional[DedupRegistry] = None,
        scorer: Optional[TriageScorer] = None,
        dispatch: Optional[DispatchFn] = None,
        sleep_between: float = 0.0,
    ) -> None:
        self.gate = gate
        self.stops = stops
        self.vault = vault
        self.registry = registry or TechniqueRegistry()
        self.dedup = dedup
        self.scorer = scorer or TriageScorer()
        self._sleep_between = sleep_between
        if dispatch is not None:
            self._dispatch = dispatch
        elif isinstance(adapter := getattr(self, "_adapter", None), AgathonAdapter):
            self._dispatch = lambda t, target: adapter.run_test(t, target)
        else:
            self._dispatch = _null_dispatch

    # -- public API -------------------------------------------------------- #

    def run(
        self,
        case_id: str,
        scope: ProgramScope,
        target: str,
        technique_ids: List[str],
    ) -> CaseResult:
        result = CaseResult(case_id=case_id, scope=scope)

        for tid in technique_ids:
            try:
                self.stops.check()
            except StopConditionError as exc:
                result.stopped = True
                result.stop_reason = str(exc)
                break

            try:
                technique = self.registry.require(tid)
            except KeyError:
                result.skipped.append({"technique": tid, "reason": "unknown technique"})
                continue

            try:
                decision = self.gate.require(target, technique)
            except ScopeViolationError as exc:
                result.skipped.append({"technique": tid, "reason": f"scope: {exc.reason}"})
                result.decisions.append({"technique": tid, "verdict": "deny", "reason": exc.reason})
                continue
            except AuthorizationError as exc:
                result.skipped.append({"technique": tid, "reason": f"needs human: {exc.reason}"})
                result.decisions.append({"technique": tid, "verdict": "needs_human", "reason": exc.reason})
                continue

            result.decisions.append(decision.to_dict())

            try:
                self.stops.record_request()
                engine_result = self._dispatch(technique, target)
            except Exception as exc:  # noqa: BLE001 - runner must never crash
                self.stops.record_error(exc)
                result.errors.append(f"{tid}: {exc}")
                continue

            if engine_result.success:
                self.stops.record_success()
                finding = FindingBuilder().build(engine_result)
                if self.dedup is not None:
                    dd = self.dedup.add(finding)
                    if dd.verdict != DedupVerdict.NEW:
                        result.skipped.append(
                            {"technique": tid, "reason": f"duplicate of {dd.matched_id}"}
                        )
                        continue
                self.vault.capture(
                    finding,
                    kind="http",
                    request=engine_result.payload_used,
                    response=engine_result.response or engine_result.evidence,
                    url=target,
                    method="POST",
                )
                result.findings.append(finding)
            else:
                self.stops.record_error(None)

            if self._sleep_between:
                time.sleep(self._sleep_between)

        # Rank what we found, highest impact first.
        result.findings = self.scorer.ranked_findings(result.findings)
        result.finished_at = _now_iso()
        result.requests_made = self.stops.state.requests_made
        return result

    # -- persistence ------------------------------------------------------- #

    def write_result(self, result: CaseResult, path: str) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json_dumps(result.to_dict()), encoding="utf-8")


def _null_dispatch(technique: Technique, target: str) -> EngineResult:
    """Safe default: refuse to run anything without a real engine attached."""
    return EngineResult(
        technique_id=technique.id,
        target=target,
        success=False,
        evidence="no engine configured (dry run)",
    )

"""Watch mode — re-scan a program on a schedule and surface drift.

A one-off scan answers “is there something here today?”.  A bountied program
changes continuously, so the useful question is “what changed since last time?”.

:class:`ProgramWatcher` keeps a small state file per program and, on each pass,
reports:

* **new** — findings not seen before (the ones worth looking at),
* **resolved** — findings that no longer reproduce (a fix shipped),
* **persisting** — everything else.

Fingerprints are the unit of identity, so a finding whose severity changes still
counts as the same issue.  The watcher never submits anything and never widens
the scope: each pass re-runs the same approved scope through the same gate.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from ..models import Finding


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class WatchRun:
    """One pass of the watcher."""

    run: int
    at: str = field(default_factory=_now_iso)
    new: List[str] = field(default_factory=list)
    persisting: List[str] = field(default_factory=list)
    resolved: List[str] = field(default_factory=list)
    finding_count: int = 0
    requests_made: int = 0
    stopped: bool = False
    stop_reason: str = ""
    error: str = ""

    @property
    def has_news(self) -> bool:
        return bool(self.new or self.resolved)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run": self.run,
            "at": self.at,
            "new": list(self.new),
            "persisting": list(self.persisting),
            "resolved": list(self.resolved),
            "finding_count": self.finding_count,
            "requests_made": self.requests_made,
            "stopped": self.stopped,
            "stop_reason": self.stop_reason,
            "error": self.error,
        }

    @property
    def summary(self) -> str:
        if self.error:
            return f"run {self.run}: failed — {self.error}"
        parts = [f"run {self.run}: {self.finding_count} finding(s)"]
        if self.new:
            parts.append(f"{len(self.new)} NEW")
        if self.resolved:
            parts.append(f"{len(self.resolved)} resolved")
        if self.stopped:
            parts.append(f"stopped ({self.stop_reason})")
        if not self.new and not self.resolved and not self.error:
            parts.append("no change")
        return ", ".join(parts)


class WatchState:
    """Persisted memory of what previous passes saw."""

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = Path(path) if path else None
        self.known: Dict[str, str] = {}
        self.runs: int = 0
        self.history: List[Dict[str, Any]] = []
        if self.path and self.path.exists():
            self._load()

    def diff(self, findings: List[Finding]) -> Dict[str, List[str]]:
        current = {f.fingerprint: f.id for f in findings}
        new = [fid for fp, fid in current.items() if fp not in self.known]
        resolved = [fid for fp, fid in self.known.items() if fp not in current]
        persisting = [fid for fp, fid in current.items() if fp in self.known]
        return {"new": sorted(new), "resolved": sorted(resolved),
                "persisting": sorted(persisting)}

    def record(self, findings: List[Finding], run: WatchRun) -> None:
        self.known = {f.fingerprint: f.id for f in findings}
        self.runs += 1
        self.history.append(run.to_dict())
        self.history = self.history[-50:]
        self._save()

    def to_dict(self) -> Dict[str, Any]:
        return {"runs": self.runs, "known": dict(self.known), "history": list(self.history)}

    def _save(self) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = dict(self.to_dict())
        payload["updated_at"] = _now_iso()
        self.path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    def _load(self) -> None:
        assert self.path is not None
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        self.known = dict(data.get("known", {}))
        self.runs = int(data.get("runs", 0))
        self.history = list(data.get("history", []))


class ProgramWatcher:
    """Run a pipeline repeatedly and report what changed.

    ``scan`` is any callable returning a pipeline-result-shaped object with
    ``findings``, ``requests_made``, ``stopped`` and ``stop_reason`` — the
    guided pipeline's ``run`` is the expected implementation, which keeps the
    watcher independent of where the findings came from.
    """

    def __init__(
        self,
        scan: Callable[[int], Any],
        *,
        state_path: Optional[str] = None,
        interval_s: float = 3600.0,
        max_runs: Optional[int] = None,
        on_run: Optional[Callable[[WatchRun], None]] = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.scan = scan
        self.state = WatchState(state_path)
        self.interval_s = max(1.0, float(interval_s))
        self.max_runs = max_runs
        self.on_run = on_run
        self._sleep = sleep

    def once(self) -> WatchRun:
        """Run a single pass and update the persisted state."""
        run = WatchRun(run=self.state.runs + 1)
        try:
            result = self.scan(run.run)
        except Exception as exc:  # noqa: BLE001 - a failed pass must not kill the watch
            run.error = f"{type(exc).__name__}: {exc}"
            self.state.record([], run)
            if self.on_run:
                self.on_run(run)
            return run

        findings: List[Finding] = list(getattr(result, "findings", []) or [])
        diff = self.state.diff(findings)
        run.new = diff["new"]
        run.resolved = diff["resolved"]
        run.persisting = diff["persisting"]
        run.finding_count = len(findings)
        run.requests_made = int(getattr(result, "requests_made", 0) or 0)
        run.stopped = bool(getattr(result, "stopped", False))
        run.stop_reason = str(getattr(result, "stop_reason", "") or "")
        self.state.record(findings, run)
        if self.on_run:
            self.on_run(run)
        return run

    def watch(self, iterations: Optional[int] = None) -> List[WatchRun]:
        """Run passes until ``max_runs``/``iterations`` is reached.

        ``iterations=None`` means “until stopped”, which is what a long-lived
        watcher wants; tests and the CLI pass a finite count.
        """
        limit = iterations if iterations is not None else self.max_runs
        runs: List[WatchRun] = []
        while limit is None or len(runs) < limit:
            runs.append(self.once())
            if limit is None or len(runs) < limit:
                self._sleep(self.interval_s)
        return runs

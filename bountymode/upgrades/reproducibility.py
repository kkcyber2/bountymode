"""U4 -- reproducibility N-of-M replay.

A finding that reproduces once in ten attempts is not submittable.  This
module replays a technique N times and reports the reproduction rate, so the
triage scorer can weight a finding by how reliably it fires.

The replay is driven by a caller-supplied ``attempt`` callable, so it works
against the engine, a mock, or a recorded transcript.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from ..runner.adapter import EngineResult

#: attempt(index) -> EngineResult
AttemptFn = Callable[[int], EngineResult]


@dataclass
class ReplayResult:
    attempts: int
    successes: int
    rate: float
    scores: List[float] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)

    @property
    def reproducible(self) -> bool:
        return self.successes > 0

    @property
    def stable(self) -> bool:
        """A finding is *stable* when it fires on every attempt."""
        return self.attempts > 0 and self.successes == self.attempts

    def to_dict(self) -> Dict[str, object]:
        return {
            "attempts": self.attempts,
            "successes": self.successes,
            "rate": round(self.rate, 3),
            "reproducible": self.reproducible,
            "stable": self.stable,
            "mean_score": round(sum(self.scores) / len(self.scores), 3) if self.scores else 0.0,
        }


class Reproducer:
    """Replay a technique N times and measure the reproduction rate."""

    def __init__(self, attempts: int = 5, *, success_threshold: float = 0.7) -> None:
        if attempts < 1:
            raise ValueError("attempts must be >= 1")
        self.attempts = attempts
        self.success_threshold = success_threshold

    def replay(self, attempt: AttemptFn, *, stop_early_on_stable: bool = False) -> ReplayResult:
        successes = 0
        scores: List[float] = []
        evidence: List[str] = []
        for i in range(self.attempts):
            try:
                res = attempt(i)
            except Exception as exc:  # noqa: BLE001
                scores.append(0.0)
                evidence.append(f"attempt {i}: error {exc}")
                continue
            scores.append(res.success_score)
            if res.success and res.success_score >= self.success_threshold:
                successes += 1
                if res.evidence:
                    evidence.append(res.evidence[:200])
            if stop_early_on_stable and successes == i + 1 and i + 1 >= 2:
                # Already stable across the attempts so far; no need to continue.
                break
        n = len(scores)
        return ReplayResult(
            attempts=n,
            successes=successes,
            rate=(successes / n) if n else 0.0,
            scores=scores,
            evidence=evidence,
        )

    def apply(self, result: EngineResult, replay: ReplayResult) -> EngineResult:
        """Fold a replay outcome back into an :class:`EngineResult`."""
        result.success = replay.reproducible
        result.success_score = replay.rate
        result.confidence = replay.rate
        if replay.evidence:
            result.evidence = replay.evidence[0]
        return result

"""U11 -- regression suites.

After a fix ships, the same technique must be re-run to confirm the finding
is closed.  A regression suite is a named set of (technique, target) checks
with an expected outcome, so a retest is a single command rather than a
manual replay.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from ..runner.adapter import EngineResult

#: check(technique_id, target) -> EngineResult
CheckFn = Callable[[str, str], EngineResult]


@dataclass
class RegressionCheck:
    name: str
    technique_id: str
    target: str
    expect_success: bool = False   # True = the bug should still reproduce

    def to_dict(self) -> Dict[str, object]:
        return {
            "name": self.name, "technique_id": self.technique_id,
            "target": self.target, "expect_success": self.expect_success,
        }


@dataclass
class RegressionOutcome:
    check: RegressionCheck
    passed: bool
    observed_success: bool
    detail: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "name": self.check.name,
            "passed": self.passed,
            "observed_success": self.observed_success,
            "detail": self.detail,
        }


@dataclass
class RegressionReport:
    outcomes: List[RegressionOutcome] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for o in self.outcomes if o.passed)

    @property
    def failed(self) -> int:
        return sum(1 for o in self.outcomes if not o.passed)

    @property
    def ok(self) -> bool:
        return self.failed == 0

    def to_dict(self) -> Dict[str, object]:
        return {
            "total": len(self.outcomes),
            "passed": self.passed,
            "failed": self.failed,
            "ok": self.ok,
            "outcomes": [o.to_dict() for o in self.outcomes],
        }


class RegressionSuite:
    """Run a set of regression checks against a live or mock engine."""

    def __init__(self, checks: List[RegressionCheck]) -> None:
        self.checks = checks

    def run(self, check_fn: CheckFn) -> RegressionReport:
        report = RegressionReport()
        for c in self.checks:
            try:
                res = check_fn(c.technique_id, c.target)
                observed = bool(res.success)
            except Exception as exc:  # noqa: BLE001
                report.outcomes.append(
                    RegressionOutcome(c, passed=False, observed_success=False, detail=f"error: {exc}")
                )
                continue
            passed = observed == c.expect_success
            detail = (
                "as expected" if passed
                else f"expected success={c.expect_success}, observed={observed}"
            )
            report.outcomes.append(RegressionOutcome(c, passed, observed, detail))
        return report

# utils/report_generator.py

import json
import os
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Collects results from all attack modules and generates a structured JSON report.

    Usage:
        rg = ReportGenerator()
        rg.add_results(attacker.run_attack(...))
        rg.generate_report("reports/my_report.json")
    """

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        self._results: List[Dict[str, Any]] = []
        self._session_start = datetime.utcnow().isoformat()
        os.makedirs(output_dir, exist_ok=True)

    # ------------------------------------------------------------------ #
    #  Collecting results                                                  #
    # ------------------------------------------------------------------ #

    def add_results(self, results: Any):
        """
        Accepts results in any of these forms:
          - A single dict
          - A list of dicts
          - An object with a .to_dict() method
          - A list of objects with .to_dict()
        """
        if results is None:
            return

        if isinstance(results, dict):
            self._results.append(results)

        elif isinstance(results, list):
            for r in results:
                if isinstance(r, dict):
                    self._results.append(r)
                elif hasattr(r, "to_dict"):
                    self._results.append(r.to_dict())
                elif hasattr(r, "__dict__"):
                    self._results.append(vars(r))
                else:
                    self._results.append({"raw": str(r)})

        elif hasattr(results, "to_dict"):
            self._results.append(results.to_dict())

        elif hasattr(results, "__dict__"):
            self._results.append(vars(results))

        else:
            self._results.append({"raw": str(results)})

        logger.debug(f"ReportGenerator now holds {len(self._results)} result(s).")

    # ------------------------------------------------------------------ #
    #  Generating the report                                               #
    # ------------------------------------------------------------------ #

    def generate_report(self, filepath: Optional[str] = None) -> Dict[str, Any]:
        """
        Builds the full report dict and optionally saves it to a JSON file.

        Args:
            filepath: Path to save the JSON report.
                      If None, saves to reports/redteam_<timestamp>.json.

        Returns:
            The report as a Python dict.
        """
        if filepath is None:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filepath = os.path.join(self.output_dir, f"redteam_{timestamp}.json")

        report = self._build_report()

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, default=str)
            logger.info(f"Report saved → {filepath}")
        except OSError as e:
            logger.error(f"Failed to write report to {filepath}: {e}")

        return report

    def print_summary(self):
        """Prints a quick plaintext summary to stdout."""
        total = len(self._results)
        if total == 0:
            print("No results collected yet.")
            return

        print(f"\n{'='*60}")
        print(f"  RED TEAM SUMMARY  —  {total} finding(s)")
        print(f"{'='*60}")
        for i, r in enumerate(self._results, 1):
            attack = r.get("attack_type") or r.get("technique") or r.get("category") or "unknown"
            success = r.get("success") or r.get("vulnerability_detected") or r.get("bypassed_filter") or False
            status = "VULNERABLE" if success else "PASSED"
            print(f"  [{i:02d}] {attack:<35} {status}")
        print(f"{'='*60}\n")

    # ------------------------------------------------------------------ #
    #  Internal helpers                                                    #
    # ------------------------------------------------------------------ #

    def _build_report(self) -> Dict[str, Any]:
        total = len(self._results)
        vulnerable = sum(
            1 for r in self._results
            if r.get("success") or r.get("vulnerability_detected") or r.get("bypassed_filter")
        )

        return {
            "metadata": {
                "session_start": self._session_start,
                "session_end": datetime.utcnow().isoformat(),
                "total_tests": total,
                "vulnerable_count": vulnerable,
                "passed_count": total - vulnerable,
                "vulnerability_rate": round(vulnerable / total, 3) if total else 0.0,
            },
            "findings": self._results,
        }

"""agathon.evolution.metrics — process-level self-evolution telemetry.

Counts the signals that prove the engine is self-evolving and getting better,
surfaced via ``/health`` and the bearer-gated ``GET /evolve/stats`` endpoint so
the admin Evolution page can render them.

Counters are process-wide (single Agathon replica). They are best-effort
increments under an RLock — never on the scan hot path's critical latency.

Tracked:
  - plugin_discovery_count    : attack plugins auto-discovered at startup
  - lessons_persisted         : attack_lessons rows written across all scans
  - lessons_loaded            : lessons loaded from prior scans at scan start
  - closed_loop_attempts      : live Aegis closed-loop proofs attempted
  - closed_loop_blocks        : rules proven to block the breach payload
  - breaches_after_lesson     : breaches that occurred after >=1 lesson was
                                applied (lower-is-better signal over time)
  - attacks_run_by_surface    : per-surface attack/tool counters
"""

from __future__ import annotations

import threading
from collections import defaultdict
from typing import Dict


class EvolveMetrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.plugin_discovery_count: int = 0
        self.lessons_persisted: int = 0
        self.lessons_loaded: int = 0
        self.closed_loop_attempts: int = 0
        self.closed_loop_blocks: int = 0
        self.breaches_after_lesson: int = 0
        self.attacks_run_by_surface: Dict[str, int] = defaultdict(int)

    # ---- mutators (thread-safe) ----------------------------------------- #

    def set_plugin_discovery_count(self, n: int) -> None:
        with self._lock:
            self.plugin_discovery_count = int(n)

    def inc_lessons_persisted(self, n: int = 1) -> None:
        with self._lock:
            self.lessons_persisted += int(n)

    def inc_lessons_loaded(self, n: int = 1) -> None:
        with self._lock:
            self.lessons_loaded += int(n)

    def inc_closed_loop(self, blocked: bool) -> None:
        with self._lock:
            self.closed_loop_attempts += 1
            if blocked:
                self.closed_loop_blocks += 1

    def inc_breach_after_lesson(self) -> None:
        with self._lock:
            self.breaches_after_lesson += 1

    def inc_surface(self, surface: str, n: int = 1) -> None:
        with self._lock:
            self.attacks_run_by_surface[surface] = (
                self.attacks_run_by_surface.get(surface, 0) + int(n)
            )

    # ---- snapshot ------------------------------------------------------- #

    def snapshot(self) -> Dict[str, object]:
        with self._lock:
            attempts = self.closed_loop_attempts
            blocks = self.closed_loop_blocks
            return {
                "plugin_discovery_count": self.plugin_discovery_count,
                "lessons_persisted": self.lessons_persisted,
                "lessons_loaded": self.lessons_loaded,
                "closed_loop_attempts": attempts,
                "closed_loop_blocks": blocks,
                "closed_loop_block_rate": (
                    round(blocks / attempts * 100, 1) if attempts else 0.0
                ),
                "breaches_after_lesson": self.breaches_after_lesson,
                "attacks_run_by_surface": dict(self.attacks_run_by_surface),
            }


# Module-level singleton.
EVOLVE_METRICS = EvolveMetrics()

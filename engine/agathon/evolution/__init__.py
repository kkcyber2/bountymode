"""agathon.evolution — self-evolving Brain lesson ledger (EVOLVE_SYSTEM)."""

from .evolve_system import (
    EvolveState,
    Lesson,
    build_reinforced_system_prompt,
    load_lessons,
    persist_lessons,
)
from .metrics import EVOLVE_METRICS, EvolveMetrics

__all__ = [
    "EVOLVE_METRICS",
    "EvolveMetrics",
    "EvolveState",
    "Lesson",
    "build_reinforced_system_prompt",
    "load_lessons",
    "persist_lessons",
]

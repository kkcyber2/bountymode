"""
evolution metrics singleton tests.

Run: pytest tests/test_evolve_metrics.py -q
"""

from __future__ import annotations

from agathon.evolution.metrics import EvolveMetrics


def test_snapshot_empty_initially() -> None:
    m = EvolveMetrics()
    snap = m.snapshot()
    assert snap["plugin_discovery_count"] == 0
    assert snap["closed_loop_block_rate"] == 0.0
    assert snap["attacks_run_by_surface"] == {}


def test_closed_loop_block_rate() -> None:
    m = EvolveMetrics()
    m.inc_closed_loop(blocked=True)
    m.inc_closed_loop(blocked=True)
    m.inc_closed_loop(blocked=False)
    snap = m.snapshot()
    assert snap["closed_loop_attempts"] == 3
    assert snap["closed_loop_blocks"] == 2
    assert snap["closed_loop_block_rate"] == 66.7


def test_surface_and_lesson_counters() -> None:
    m = EvolveMetrics()
    m.inc_surface("web")
    m.inc_surface("web")
    m.inc_surface("llm")
    m.inc_lessons_persisted(3)
    m.inc_lessons_loaded(2)
    m.inc_breach_after_lesson()
    snap = m.snapshot()
    assert snap["attacks_run_by_surface"] == {"web": 2, "llm": 1}
    assert snap["lessons_persisted"] == 3
    assert snap["lessons_loaded"] == 2
    assert snap["breaches_after_lesson"] == 1


def test_set_plugin_discovery_count() -> None:
    m = EvolveMetrics()
    m.set_plugin_discovery_count(42)
    assert m.snapshot()["plugin_discovery_count"] == 42

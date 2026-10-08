"""
Agathon — autonomous red-team orchestration layer.

This package wraps the existing `Ai red/` attack toolkit with a Claude-driven
"Live Brain" that decides which attack to run next, can author small custom
probes inside an ephemeral Docker sandbox, and streams every decision into
Supabase so the Vercel frontend can show it in real time.

The orchestrator is designed to run as a long-lived process on Railway
(or any container host that supports outbound WebSockets and >5min jobs).
The Vercel frontend never executes Python directly — it only POSTs scan
specs to this service and subscribes to Supabase Realtime for the feed.

Public surface (kept small on purpose):

    from agathon.orchestrator   import app, run_scan
    from agathon.attack_tier_logic import Intensity, BUDGETS, budget_for
"""

from .attack_tier_logic import (  # re-exports for ergonomic imports
    Intensity,
    TierBudget,
    BUDGETS,
    budget_for,
    catalogue_for_tier,
    system_prompt_for,
)

__all__ = [
    "Intensity",
    "TierBudget",
    "BUDGETS",
    "budget_for",
    "catalogue_for_tier",
    "system_prompt_for",
]

__version__ = "0.1.0"

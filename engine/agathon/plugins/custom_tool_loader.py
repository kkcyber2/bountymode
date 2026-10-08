"""agathon.plugins.custom_tool_loader — operator-authored attack tools.

This is the engine-side foundation for the (later) Developer-role plugin SDK.
Operators (developers) author small Python probes; after an audit pipeline
approves them, the Brain can invoke them by name via the ``run_operator_tool``
Brain tool. Execution reuses the same ephemeral Docker sandbox as the
Brain-authored ``run_custom_tool`` path — never the host.

This module only handles *lookup + gating*: it loads approved tool metadata
from the ``custom_attack_tools`` table and enforces ``intensity_min`` + audit
status. The actual sandboxed execution lives in the orchestrator so it can
reuse the Docker runner + scan state.

**Probe contract (SDK):** approved tools are executed as raw ``probe.py`` inside
Docker. The sandbox injects environment variables only — there is no ``async
def run(ctx)`` hook:

- ``TARGET_URL`` — scan target URL (or test URL for dry-runs)
- ``TARGET_MODEL`` — model identifier string
- ``TARGET_API_KEY`` — operator scan credential (empty for dry-runs)

Probes should print findings to stdout (JSON recommended) and exit 0 on success.

Table shape (migration 20260628_custom_attack_tools.sql):
    id, author_id, name, family, intensity_min, code, status, audit_result,
    network_allowed, created_at, updated_at
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, List, Optional

from agathon.attack_tier_logic import Intensity
from agathon.plugins.base import intensity_rank

log = logging.getLogger(__name__)


@dataclass
class CustomTool:
    id: str
    author_id: str
    name: str
    family: str
    intensity_min: str  # Intensity value string
    code: str
    status: str
    network_allowed: bool = True
    audit_result: str = ""

    def available_at(self, intensity: Intensity | str) -> bool:
        try:
            return intensity_rank(intensity) >= intensity_rank(self.intensity_min)
        except Exception:  # noqa: BLE001
            return False


def _row_to_tool(row: dict) -> CustomTool:
    return CustomTool(
        id=str(row.get("id") or ""),
        author_id=str(row.get("author_id") or ""),
        name=str(row.get("name") or ""),
        family=str(row.get("family") or "custom_tool"),
        intensity_min=str(row.get("intensity_min") or "aggressive"),
        code=str(row.get("code") or ""),
        status=str(row.get("status") or "pending"),
        network_allowed=bool(row.get("network_allowed", True)),
        audit_result=str(row.get("audit_result") or ""),
    )


def load_approved_tools(
    supabase: Any, user_id: str = ""
) -> List[CustomTool]:
    """Load approved operator tools. Best-effort — returns [] on any failure.

    If ``user_id`` is given, returns the operator's own approved tools (so a
    developer's private arsenal is available on their scans). The audit
    pipeline gates ``status='approved'``.
    """
    try:
        if not supabase:
            return []
        q = (
            supabase.table("custom_attack_tools")
            .select("id,author_id,name,family,intensity_min,code,status,network_allowed,audit_result")
            .eq("status", "approved")
        )
        if user_id:
            q = q.eq("author_id", user_id)
        resp = q.limit(100).execute()
        return [_row_to_tool(r) for r in (getattr(resp, "data", None) or [])]
    except Exception as exc:  # noqa: BLE001
        log.warning("[custom_tool_loader] load_approved_tools failed: %s", exc)
        return []


def get_operator_tool(
    name: str, supabase: Any, user_id: str = ""
) -> Optional[CustomTool]:
    """Look up a single approved operator tool by name. Best-effort."""
    try:
        if not supabase:
            return None
        q = (
            supabase.table("custom_attack_tools")
            .select("id,author_id,name,family,intensity_min,code,status,network_allowed,audit_result")
            .eq("name", name)
            .eq("status", "approved")
        )
        if user_id:
            q = q.eq("author_id", user_id)
        resp = q.limit(1).execute()
        rows = getattr(resp, "data", None) or []
        return _row_to_tool(rows[0]) if rows else None
    except Exception as exc:  # noqa: BLE001
        log.warning("[custom_tool_loader] get_operator_tool failed: %s", exc)
        return None


def format_operator_arsenal_block(tools: List[CustomTool]) -> str:
    """Human-readable catalog block for the Brain kickoff message."""
    if not tools:
        return ""
    lines = ["Operator arsenal (run_operator_tool):"]
    for t in tools:
        net = "yes" if t.network_allowed else "no"
        lines.append(
            f"  - {t.name} [{t.family}, min={t.intensity_min}, network={net}]"
        )
    return "\n".join(lines)

"""
Supabase scan_logs insert path with kinetic vocabulary normalization.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, Optional

log = logging.getLogger(__name__)

# Production scan_logs_type_kinetic_check — only these five values are accepted.
ALLOWED_LOG_TYPES = frozenset({
    "info",
    "thought",
    "strike",
    "breach",
    "finance",
})

LEGACY_LOG_TYPE_MAP: Dict[str, str] = {
    "info": "info",
    "audit": "info",
    "error": "info",
    "progress": "info",
    "report": "info",
    "elite8": "info",
    "webhook": "info",
    "throttle": "info",
    "defense": "info",
    "cost_event": "finance",
    "brain_decision": "thought",
    "attempt": "strike",
    "finding": "breach",
    "tool_run": "strike",
    "tool_authored": "thought",
    "thought": "thought",
    "strike": "strike",
    "breach": "breach",
    "finance": "finance",
}

# Keys that must never reach Postgres / webhooks as nested objects (22P02 guard).
_SCALAR_TRANSPORT_KEYS = frozenset({
    "progress_pct",
    "ale_usd",
    "financial_liability_usd",
    "asset_value_usd",
    "gdpr_fine_usd",
    "operational_cost_usd",
    "total_liability_usd",
})


def _extract_scalar_from_object(value: Dict[str, Any], key: str) -> Any:
    """Pull a numeric leaf from dict-shaped finance/progress payloads."""
    for candidate in (
        value.get(key),
        value.get("value"),
        value.get("amount"),
        value.get("usd"),
        value.get("pct"),
        value.get("progress_pct"),
    ):
        if candidate is not None and not isinstance(candidate, (dict, list)):
            return candidate
    return None


def coerce_transport_scalar(key: str, value: Any) -> Any:
    """
    Coerce progress_pct / ale_usd (and related USD keys) to clean scalars.

    Prevents Postgres 22P02 when nested dicts slip into NUMERIC/INTEGER columns.
    """
    if key not in _SCALAR_TRANSPORT_KEYS:
        return value

    if value is None or value == "":
        return "0" if key == "progress_pct" else None

    if isinstance(value, dict):
        value = _extract_scalar_from_object(value, key)
        if value is None:
            return "0" if key == "progress_pct" else None

    if isinstance(value, (list, tuple, set)):
        return "0" if key == "progress_pct" else None

    if key == "progress_pct":
        try:
            return str(int(round(float(value))))
        except (TypeError, ValueError):
            return "0"

    try:
        return str(round(float(value), 2))
    except (TypeError, ValueError):
        return None


def stringify_payload_numerics(value: Any, *, _parent_key: Optional[str] = None) -> Any:
    """
    Cast numeric values in log/finding payloads to strings for Supabase JSON safety.

    Scores and CVSS fields are stored as ``str(score)`` per Stronghold contract.
    ``progress_pct`` and ``ale_usd`` are never emitted as raw objects.
    """
    if isinstance(value, dict):
        return {
            k: stringify_payload_numerics(
                coerce_transport_scalar(k, v) if k in _SCALAR_TRANSPORT_KEYS else v,
                _parent_key=k,
            )
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [stringify_payload_numerics(item) for item in value]
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        if isinstance(value, float) and value != value:
            return "nan"
        return str(value)
    return value


_DASH_REPLACEMENTS = (
    ("\u2014", "-"),  # em dash
    ("\u2013", "-"),  # en dash
    ("\u2012", "-"),  # figure dash
    ("\u2212", "-"),  # minus sign
)
_SMART_QUOTE_REPLACEMENTS = (
    ("\u2018", "'"),
    ("\u2019", "'"),
    ("\u201c", '"'),
    ("\u201d", '"'),
)


def sanitize_text_for_transport(text: str) -> str:
    """
    Normalize Unicode punctuation that breaks ASCII-only transports.

    Replaces em/en dashes with ASCII hyphen; ensures valid UTF-8 bytes.
    """
    if not text:
        return text
    for old, new in _DASH_REPLACEMENTS + _SMART_QUOTE_REPLACEMENTS:
        text = text.replace(old, new)
    return str(text).encode("ascii", "ignore").decode("ascii")


def sanitize_payload_strings(value: Any) -> Any:
    """Recursively sanitize every string in a dict/list tree."""
    if isinstance(value, str):
        return sanitize_text_for_transport(value)
    if isinstance(value, dict):
        return {k: sanitize_payload_strings(v) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize_payload_strings(item) for item in value]
    return value


def prepare_outbound_payload(value: Any) -> Any:
    """Numeric stringify + UTF-8 transport safety for Supabase / WebSocket egress."""
    return sanitize_payload_strings(stringify_payload_numerics(value))


def sanitize_scan_row_update(fields: Dict[str, Any]) -> Dict[str, Any]:
    """
    Coerce scans-table patch fields before Postgres UPDATE.

    Forces progress_pct / ale_usd (and related USD keys) through
    coerce_transport_scalar to prevent 22P02 invalid input syntax errors.
    """
    out: Dict[str, Any] = {}
    for key, value in fields.items():
        if key in _SCALAR_TRANSPORT_KEYS:
            coerced = coerce_transport_scalar(key, value)
            if coerced is None:
                continue
            if key == "progress_pct":
                out[key] = int(coerced)
            else:
                out[key] = float(coerced)
        elif isinstance(value, str):
            out[key] = sanitize_text_for_transport(value)
        else:
            out[key] = value
    return out


def normalize_log_type(raw: str) -> str:
    """Map legacy orchestrator types to production scan_logs CHECK vocabulary."""
    key = (raw or "info").strip().lower()
    mapped = LEGACY_LOG_TYPE_MAP.get(key, "info")
    if mapped not in ALLOWED_LOG_TYPES:
        return "info"
    return mapped


class SupabaseSync:
    """Single insert path for scan_logs with type normalization."""

    def __init__(self, admin_factory: Callable[[], Any]) -> None:
        self._admin_factory = admin_factory

    def insert_scan_log(self, row: Dict[str, Any]) -> None:
        payload = sanitize_payload_strings(dict(row))
        payload["type"] = normalize_log_type(str(payload.get("type", "info")))
        if "payload" in payload and payload["payload"] is not None:
            payload["payload"] = prepare_outbound_payload(payload["payload"])
        try:
            admin = self._admin_factory()
            admin.table("scan_logs").insert(payload).execute()
        except Exception as exc:  # noqa: BLE001
            log.error(
                "scan_logs insert failed scan_id=%s type=%s: %s",
                payload.get("scan_id"),
                payload.get("type"),
                exc,
            )
            raise

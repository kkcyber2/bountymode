"""
Ghost Protocol — mask operator identifiers in outbound engine payloads.
Mirrors forgeguard-ai operatorAlias() semantics.
"""

from __future__ import annotations

import re
from typing import Any

_GHOST_SENSITIVE_KEYS = frozenset(
    {
        "user_id",
        "full_name",
        "profile_full_name",
        "operator_name",
        "operator_email",
        "email",
        "hacker_name",
    }
)

_UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.IGNORECASE,
)


def operator_alias(user_id: str) -> str:
    short = user_id.replace("-", "")[:8].upper()
    return f"OPERATOR_{short}"


def mask_identifier(value: str, real_user_id: str) -> str:
    alias = operator_alias(real_user_id)
    if value == real_user_id:
        return alias
    return _UUID_RE.sub(lambda m: alias if m.group(0) == real_user_id else m.group(0), value)


def apply_ghost_mask(value: Any, real_user_id: str) -> Any:
    """Recursively scrub identifiers from dict/list/string trees."""
    if isinstance(value, str):
        return mask_identifier(value, real_user_id)
    if isinstance(value, list):
        return [apply_ghost_mask(item, real_user_id) for item in value]
    if isinstance(value, dict):
        masked: dict[Any, Any] = {}
        for key, item in value.items():
            key_str = str(key)
            if key_str in _GHOST_SENSITIVE_KEYS:
                if key_str == "user_id":
                    masked[key] = operator_alias(real_user_id)
                elif isinstance(item, str):
                    masked[key] = operator_alias(real_user_id)
                else:
                    masked[key] = apply_ghost_mask(item, real_user_id)
            else:
                masked[key] = apply_ghost_mask(item, real_user_id)
        return masked
    return value


def resolve_display_name(
    profile_full_name: str,
    *,
    is_ghost_active: bool,
    user_id: str = "",
) -> str:
    if is_ghost_active:
        return operator_alias(user_id) if user_id else "GHOST_OPERATOR"
    return profile_full_name

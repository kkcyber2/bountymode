"""
Strike logic — target HTTP uses the scan-form API key only (Key Isolation).

Re-exports from ``core.strike_logic`` for Railway deployment compatibility.
"""

from core.strike_logic import *  # noqa: F403

from core.strike_logic import (
    AUTH_FAILURE_MESSAGE,
    build_target_authorization,
    build_target_client,
    is_auth_failure_response,
    resolve_target_provider,
    strike_authorization_header,
)

__all__ = [
    "AUTH_FAILURE_MESSAGE",
    "build_target_authorization",
    "build_target_client",
    "is_auth_failure_response",
    "resolve_target_provider",
    "strike_authorization_header",
]

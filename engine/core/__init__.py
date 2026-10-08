"""
ForgeGuard Agathon core — orchestration, strike logic, target isolation.

Legacy imports: ``from agathon.orchestrator import app`` remain valid.
"""

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

"""
Kinetic strike authorization — USER scan-form API key only.

All target HTTP must send ``Authorization: Bearer <user_key>`` from the scan
request. Engine env keys (GROQ_API_KEY, OPENROUTER_API_KEY) are never used here.
"""

from agathon.target_client import (
    AUTH_FAILURE_MESSAGE,
    build_target_authorization,
    build_target_client,
    is_auth_failure_response,
    resolve_target_provider,
)


def strike_authorization_header(api_key: str, target_provider: str = "") -> str:
    """
    Build the Authorization header for a kinetic target strike.

    Uses only the operator-provided API key from the scan form — never engine secrets.
    """
    return build_target_authorization(api_key, target_provider)


__all__ = [
    "AUTH_FAILURE_MESSAGE",
    "build_target_authorization",
    "build_target_client",
    "is_auth_failure_response",
    "resolve_target_provider",
    "strike_authorization_header",
]

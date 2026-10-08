"""
Cryptographic scan consent verification (belt-and-suspenders with ForgeGuard Next.js).

Mirrors payload format in forgeguard-ai/CITADEL_LAUNCH_VAULT/LEGAL_CONSENT_SPEC.md
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from typing import Optional
from urllib.parse import urlparse

log = logging.getLogger(__name__)

LEGAL_POLICY_VERSION = "v1.0-2026"
LEGACY_CONSENT_HASH = "legacy-v1-pre-crypto"
HIGH_INTENSITY = frozenset({"aggressive", "high"})
NUCLEAR_INTENSITY = frozenset({"greasy", "nuclear"})


def normalize_consent_target_host(target_url: str) -> str:
    raw = (target_url or "").strip()
    if not raw:
        return ""
    try:
        parsed = urlparse(raw if "://" in raw else f"https://{raw}")
        return (parsed.hostname or "").lower()
    except Exception:
        return raw.lower()


def build_consent_payload(
    user_id: str,
    target_host: str,
    signer_name: str,
    policy_version: str,
    signed_at_iso: str,
) -> str:
    return f"{user_id}:{target_host}:{signer_name}:{policy_version}:{signed_at_iso}"


def _sha256_hex(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def verify_cryptographic_consent(
    *,
    user_id: str,
    target_url: str,
    signer_name: Optional[str],
    policy_version: Optional[str],
    signed_at_iso: Optional[str],
    provided_hash: Optional[str],
    consent_target_host: Optional[str] = None,
) -> bool:
    """Return True when provided hash matches canonical payload."""
    if not provided_hash or provided_hash == LEGACY_CONSENT_HASH:
        return False

    policy = (policy_version or "").strip() or LEGAL_POLICY_VERSION
    if policy != LEGAL_POLICY_VERSION:
        return False

    host = (consent_target_host or normalize_consent_target_host(target_url)).strip().lower()
    scan_host = normalize_consent_target_host(target_url)
    if not host or not scan_host or host != scan_host:
        return False

    name = (signer_name or "").strip()
    signed = (signed_at_iso or "").strip()
    if not user_id or not name or not signed:
        return False

    payload = build_consent_payload(user_id, host, name, policy, signed)
    expected = _sha256_hex(payload)
    try:
        return hmac.compare_digest(expected.lower(), provided_hash.strip().lower())
    except Exception:
        return False


def consent_required_for_intensity(intensity: str, ownership_verified: bool) -> bool:
    if ownership_verified:
        return False
    key = (intensity or "standard").strip().lower()
    return key in HIGH_INTENSITY or key in NUCLEAR_INTENSITY

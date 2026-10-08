"""
Identity document OCR via OpenRouter vision (Gemini Flash).
Called by Vercel resilient identity audit (POST /identity/ocr).
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Dict, Optional

import requests

from .supabase_sync import sanitize_text_for_transport

log = logging.getLogger(__name__)

VISION_MODEL = "google/gemini-flash-1.5"
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
MAX_IMAGE_B64_CHARS = 1_200_000


def run_identity_ocr(
    *,
    image_base64: str,
    mime_type: str,
    profile_full_name: str = "",
    is_ghost_active: bool = False,
    user_id: str = "",
) -> Dict[str, str]:
    """Return ocr_text, extracted_name, audit_notes (all transport-sanitized)."""
    from .ghost_identity import resolve_display_name

    empty = {
        "ocr_text": "",
        "extracted_name": "",
        "audit_notes": "OCR unavailable.",
    }
    api_key = (os.environ.get("OPENROUTER_API_KEY") or "").strip()
    if not api_key:
        empty["audit_notes"] = "OPENROUTER_API_KEY not configured on engine."
        return empty

    b64 = (image_base64 or "").strip()
    if len(b64) < 100 or len(b64) > MAX_IMAGE_B64_CHARS:
        empty["audit_notes"] = "Invalid image payload."
        return empty

    mime = (mime_type or "image/jpeg").strip() or "image/jpeg"
    data_url = f"data:{mime};base64,{b64}"
    name = sanitize_text_for_transport(
        resolve_display_name(
            profile_full_name or "",
            is_ghost_active=is_ghost_active,
            user_id=user_id,
        )
    )

    prompt = (
        "You are an identity document OCR engine.\n"
        f"Profile name to compare: \"{name}\"\n\n"
        "Read the government ID image. Respond ONLY with valid JSON:\n"
        "{\n"
        '  "extracted_name": string,\n'
        '  "ocr_text": string (all readable text, max 2000 chars),\n'
        '  "document_readable": boolean,\n'
        '  "blur_detected": boolean,\n'
        '  "audit_notes": string (one sentence)\n'
        "}"
    )

    try:
        resp = requests.post(
            OPENROUTER_URL,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://forgeguard.ai",
                "X-Title": "ForgeGuard Identity OCR",
            },
            json={
                "model": VISION_MODEL,
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": prompt},
                            {"type": "image_url", "image_url": {"url": data_url}},
                        ],
                    }
                ],
                "temperature": 0.1,
                "max_tokens": 700,
                "response_format": {"type": "json_object"},
            },
            timeout=25,
        )
        if not resp.ok:
            snippet = (resp.text or "")[:300]
            log.warning("[identity_ocr] HTTP %s: %s", resp.status_code, snippet)
            empty["audit_notes"] = f"Vision HTTP {resp.status_code}"
            return empty

        data = resp.json()
        raw = (
            (data.get("choices") or [{}])[0]
            .get("message", {})
            .get("content", "{}")
        )
        match = re.search(r"\{[^{}]*\"ocr_text\"[^{}]*\}", raw, re.DOTALL)
        if not match:
            match = re.search(r"\{.*\}", raw, re.DOTALL)
        parsed: Dict[str, Any] = json.loads(match.group() if match else raw)

        if parsed.get("blur_detected") or parsed.get("document_readable") is False:
            return {
                "ocr_text": sanitize_text_for_transport(
                    str(parsed.get("ocr_text") or "")[:2000]
                ),
                "extracted_name": sanitize_text_for_transport(
                    str(parsed.get("extracted_name") or "")[:200]
                ),
                "audit_notes": sanitize_text_for_transport(
                    str(parsed.get("audit_notes") or "Image unreadable.")[:500]
                ),
            }

        ocr = sanitize_text_for_transport(str(parsed.get("ocr_text") or "")[:2000])
        extracted = sanitize_text_for_transport(
            str(parsed.get("extracted_name") or "")[:200]
        )
        notes = sanitize_text_for_transport(
            str(parsed.get("audit_notes") or "Engine OCR complete.")[:500]
        )
        return {
            "ocr_text": ocr,
            "extracted_name": extracted,
            "audit_notes": notes,
        }
    except Exception as exc:  # noqa: BLE001
        log.warning("[identity_ocr] failed: %s", exc)
        empty["audit_notes"] = sanitize_text_for_transport(f"OCR error: {exc}")[:500]
        return empty

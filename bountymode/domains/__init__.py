"""Domain adapters.

Importing this package registers every built-in domain on the default
registry, so ``DEFAULT_REGISTRY.get("web_api")`` works after a single
``import bountymode.domains``.
"""

from __future__ import annotations

from .ai_llm import AiLlmAdapter
from .base import DEFAULT_REGISTRY, DomainAdapter, DomainRegistry, register_adapter
from .cicd import CicdAdapter
from .cloud import CloudAdapter
from .web_api import WebApiAdapter

# Register the built-ins (idempotent).
for _adapter in (AiLlmAdapter(), WebApiAdapter(), CloudAdapter(), CicdAdapter()):
    register_adapter(_adapter)

__all__ = [
    "DomainAdapter",
    "DomainRegistry",
    "DEFAULT_REGISTRY",
    "register_adapter",
    "AiLlmAdapter",
    "WebApiAdapter",
    "CloudAdapter",
    "CicdAdapter",
]

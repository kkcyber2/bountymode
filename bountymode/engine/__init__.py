"""In-process bridge to the vendored offensive engine.

The engine used to live in a separate repository and be reached over HTTP.  It
is now vendored in the top-level ``engine/`` directory and driven in-process by
:class:`~bountymode.engine.local.LocalEngine`, which reads the engine's own live
catalogue rather than a copy of it.

Public surface
--------------
:data:`LOCAL_DISPATCH`
    convenience factory for a ``dispatch(technique, target)`` callable.
:class:`LocalEngine`
    the engine driver.
:class:`EngineCatalogue`
    a read-only view over the engine's ``REGISTRY``.
:class:`ChatClient`
    provider-agnostic OpenAI-compatible client for the engine's LLM calls.
:func:`engine_available`
    whether a usable engine checkout is present.

Everything here is import-safe: importing this package never forces the engine
to load, and a missing or partial engine degrades to a clear "unavailable"
message instead of an exception.
"""

from __future__ import annotations

from .catalogue import EngineCatalogue, default_catalogue
from .llm import ChatClient, LLMResult, OfflineClient
from .local import LocalEngine, build_local_dispatch
from .paths import ENGINE_PATH_ENV, engine_available, engine_root, ensure_on_path

__all__ = [
    "EngineCatalogue",
    "default_catalogue",
    "ChatClient",
    "LLMResult",
    "OfflineClient",
    "LocalEngine",
    "build_local_dispatch",
    "engine_available",
    "engine_root",
    "ensure_on_path",
    "ENGINE_PATH_ENV",
]

"""
agathon.plugins — AttackPlugin framework.

A plugin-based attack system that replaces the hand-maintained REGISTRY in
forgeguard_bridge.py with auto-discovered, schema-validated plugins.

Layout::

    agathon/plugins/<family>/<attack>.py
        class MyAttack(AttackPlugin): ...

Each plugin declares ``name``, ``family``, ``intensity_min`` and ``cwe`` as
class attributes and implements ``run(ctx) -> Finding``. The registry walks
the package tree at startup, imports every module, and collects concrete
``AttackPlugin`` subclasses — no hand-maintained list.

Public API (re-exported here)::

    from agathon.plugins import AttackPlugin, AttackContext, Finding
    from agathon.plugins import discover_plugins, PluginRegistry
"""

from agathon.plugins.base import (
    AttackContext,
    AttackPlugin,
    Finding,
    intensity_rank,
    level_for_intensity_min,
)
from agathon.plugins.registry import (
    PluginRegistry,
    discover_plugins,
    plugin_registry,
)

__all__ = [
    "AttackContext",
    "AttackPlugin",
    "Finding",
    "PluginRegistry",
    "discover_plugins",
    "intensity_rank",
    "level_for_intensity_min",
    "plugin_registry",
]

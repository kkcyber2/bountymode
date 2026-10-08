"""
agathon.plugins.registry — auto-discovery + legacy REGISTRY adapter.

The registry walks ``agathon/plugins/<family>/<attack>.py`` at startup, imports
each module, and collects concrete :class:`AttackPlugin` subclasses. No
hand-maintained list — drop a new ``.py`` file with an ``AttackPlugin`` and it
appears in the catalogue on the next process start.

It also produces legacy REGISTRY-compatible entries (``name`` / ``family`` /
``level`` / ``fn``) so the existing orchestrator dispatch
(``catalogue_for_tier`` → ``run_attack`` fallback → ``severity_from_result``)
works unchanged. Each plugin's ``fn`` wrapper:

1. Honours ``intensity_min`` — refuses to run below the declared tier and
   returns a benign skipped ``AttackResult`` instead.
2. Builds an :class:`AttackContext` from ``(client, model, intensity)``.
3. Calls ``plugin.run(ctx)`` → validates the returned :class:`Finding`.
4. Bridges the Finding into an ``AttackResult`` for the legacy payload path.
"""

from __future__ import annotations

import importlib
import logging
import pkgutil
from typing import Any, Callable, Dict, Iterable, List, Optional

from agathon.attack_tier_logic import Intensity, catalogue_for_tier
from agathon.plugins.base import (
    AttackContext,
    AttackPlugin,
    Finding,
    finding_to_attack_result,
)

log = logging.getLogger(__name__)

# Sentinel Finding returned when a plugin is invoked below its intensity_min.
# Kept as a factory because Findings are effectively immutable pydantic models.
_SKIPPED_MSG = "skipped: intensity_min not met for this scan tier"


def _skipped_result(plugin: AttackPlugin, target_model: str) -> Any:
    from attacks.base_tester import AttackResult, DifficultyLevel, VulnerabilityType

    return AttackResult(
        attack_type=plugin.name,
        vulnerability_type=VulnerabilityType.PROMPT_INJECTION,
        difficulty=DifficultyLevel.EASY,
        success=False,
        success_score=0.0,
        evidence=_SKIPPED_MSG,
        target_model=target_model,
        payload_used="",
        response="",
        recommended_fix="",
        cwe_references=[plugin.cwe] if plugin.cwe else [],
        tags=["skipped", "intensity_gated"],
        metadata={"intensity_min": plugin.intensity_min.value},
    )


def _make_plugin_fn(plugin: AttackPlugin) -> Callable[..., Any]:
    """Build a legacy ``fn(client, model[, intensity])`` wrapper for a plugin.

    The orchestrator probes the wrapper's signature and calls it with the
    scan ``intensity`` when it accepts >=3 params, so we declare ``intensity``
    as an optional third arg to receive it.
    """

    def _fn(client: Any, model: str, intensity: Optional[Any] = None) -> Any:
        # Resolve the effective intensity — fall back to the plugin minimum.
        if isinstance(intensity, Intensity):
            eff = intensity
        elif intensity is not None:
            try:
                eff = Intensity(str(intensity).strip().lower())
            except ValueError:
                eff = plugin.intensity_min
        else:
            eff = plugin.intensity_min

        if not plugin.available_at(eff):
            log.debug(
                "[plugins] %s skipped — intensity %s < min %s",
                plugin.name, eff.value, plugin.intensity_min.value,
            )
            return _skipped_result(plugin, model)

        ctx = AttackContext(
            client=client,
            target_model=model,
            intensity=eff,
        )
        try:
            finding = plugin.run(ctx)
        except Exception as exc:  # noqa: BLE001
            log.warning("[plugins] %s.run raised: %s", plugin.name, exc)
            return _skipped_result(plugin, model)
        if not isinstance(finding, Finding):
            log.warning(
                "[plugins] %s.run returned %r, not a Finding — coercing via "
                "Finding.model_validate", plugin.name, type(finding),
            )
            finding = Finding.model_validate(finding)
        return finding_to_attack_result(finding, target_model=model)

    _fn.__name__ = f"plugin_{plugin.name.replace('.', '_')}"
    _fn.__qualname__ = _fn.__name__
    return _fn


# --------------------------------------------------------------------------- #
# Discovery                                                                    #
# --------------------------------------------------------------------------- #


def discover_plugins(root_package: str = "agathon.plugins") -> List[AttackPlugin]:
    """Import every module under the plugins package and instantiate plugins.

    Modules that fail to import are logged and skipped — one broken plugin
    never takes down the whole arsenal.
    """
    plugins: List[AttackPlugin] = []
    seen_names: set[str] = set()

    try:
        pkg = importlib.import_module(root_package)
    except Exception as exc:  # noqa: BLE001
        log.warning("[plugins] cannot import %s: %s", root_package, exc)
        return plugins

    pkg_path = getattr(pkg, "__path__", None)
    if not pkg_path:
        return plugins

    for _finder, modname, ispkg in pkgutil.walk_packages(
        pkg_path, prefix=f"{root_package}."
    ):
        if ispkg:
            continue
        if modname.endswith(".base") or modname.endswith(".registry"):
            continue
        try:
            module = importlib.import_module(modname)
        except Exception as exc:  # noqa: BLE001
            log.warning("[plugins] import failed for %s: %s", modname, exc)
            continue

        for attr_name in dir(module):
            obj = getattr(module, attr_name)
            if (
                isinstance(obj, type)
                and issubclass(obj, AttackPlugin)
                and obj is not AttackPlugin
            ):
                # Skip abstract subclasses that don't set a name.
                if not getattr(obj, "name", ""):
                    continue
                try:
                    instance = obj()
                except Exception as exc:  # noqa: BLE001
                    log.warning(
                        "[plugins] %s.%s instantiation failed: %s",
                        modname, attr_name, exc,
                    )
                    continue
                if instance.name in seen_names:
                    log.warning(
                        "[plugins] duplicate plugin name %r in %s — skipping",
                        instance.name, modname,
                    )
                    continue
                seen_names.add(instance.name)
                plugins.append(instance)

    log.info("[plugins] discovered %d attack plugins", len(plugins))
    return plugins


# --------------------------------------------------------------------------- #
# PluginRegistry                                                               #
# --------------------------------------------------------------------------- #


class PluginRegistry:
    """Holds discovered plugins and answers catalogue / lookup queries."""

    def __init__(self, plugins: Optional[Iterable[AttackPlugin]] = None):
        self._plugins: List[AttackPlugin] = list(plugins or [])
        self._by_name: Dict[str, AttackPlugin] = {
            p.name: p for p in self._plugins
        }

    # -- mutation ---------------------------------------------------------- #
    def add(self, plugin: AttackPlugin) -> None:
        if plugin.name in self._by_name:
            log.warning("[plugins] duplicate name %r — ignoring re-add", plugin.name)
            return
        self._plugins.append(plugin)
        self._by_name[plugin.name] = plugin

    def extend(self, plugins: Iterable[AttackPlugin]) -> None:
        for p in plugins:
            self.add(p)

    # -- access ----------------------------------------------------------- #
    def all(self) -> List[AttackPlugin]:
        return list(self._plugins)

    def get(self, name: str) -> Optional[AttackPlugin]:
        return self._by_name.get(name)

    def __len__(self) -> int:
        return len(self._plugins)

    # -- legacy bridge ---------------------------------------------------- #
    def catalogue_entries(self) -> List[Dict[str, Any]]:
        """REGISTRY-shaped entries consumable by ``catalogue_for_tier``."""
        out: List[Dict[str, Any]] = []
        for plugin in self._plugins:
            entry = plugin.catalogue_entry()
            entry["fn"] = _make_plugin_fn(plugin)
            out.append(entry)
        return out

    def catalogue_for_tier(
        self, intensity: Intensity | str
    ) -> List[Dict[str, Any]]:
        """Tier-filtered catalogue honouring both ``family`` and ``intensity_min``.

        ``family`` filtering reuses the canonical ``catalogue_for_tier`` from
        ``agathon.attack_tier_logic``; ``intensity_min`` is applied as a
        second pass so a plugin is never advertised below its minimum tier.
        """
        family_filtered = catalogue_for_tier(intensity, self.catalogue_entries())
        return [
            e for e in family_filtered
            if e["plugin"].available_at(intensity)
        ]


# Module-level singleton — lazily discovered on first access so importing the
# package never triggers filesystem walks in unit tests.
_plugin_registry: Optional[PluginRegistry] = None


def plugin_registry() -> PluginRegistry:
    global _plugin_registry
    if _plugin_registry is None:
        _plugin_registry = PluginRegistry(discover_plugins())
    return _plugin_registry


def reload_plugin_registry() -> PluginRegistry:
    """Force re-discovery (e.g. after installing a new plugin at runtime)."""
    global _plugin_registry
    _plugin_registry = PluginRegistry(discover_plugins())
    return _plugin_registry


# --------------------------------------------------------------------------- #
# forgeguard_bridge integration hook                                          #
# --------------------------------------------------------------------------- #


def extend_registry_with_plugins(
    base: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Append discovered plugin entries to a legacy REGISTRY list.

    De-duplicates by ``name`` so plugins never shadow (or duplicate) the
    hand-written entries that still live in forgeguard_bridge. Returns the
    same list for fluent chaining.
    """
    try:
        entries = plugin_registry().catalogue_entries()
    except Exception as exc:  # noqa: BLE001
        log.warning("[plugins] registry build skipped: %s", exc)
        return base

    existing = {e.get("name") for e in base}
    added = 0
    for entry in entries:
        if entry["name"] in existing:
            continue
        base.append(entry)
        existing.add(entry["name"])
        added += 1
    log.info("[plugins] merged %d plugin entries into REGISTRY", added)
    return base

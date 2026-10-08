"""
Dynamic Garak probe catalogue for ForgeGuard Agathon.

Introspects the installed ``garak`` package and registers hundreds of probe
classes into the bridge REGISTRY. Execution is batched per probe to respect
scan budgets (see ``MAX_PROBES_PER_STRIKE`` in ``garak_runner``).
"""

from __future__ import annotations

import importlib
import inspect
import json
import logging
import pkgutil
import re
import sys
import time
import types
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

try:
    import jsonschema  # noqa: F401
except ImportError:
    print(
        "[SYSTEM] Missing jsonschema. Forcing stubs to prevent boot crash.",
        flush=True,
    )
    sys.modules["jsonschema"] = types.ModuleType("jsonschema")

_GARAK_BOOT_OK = False
try:
    import garak  # noqa: F401 — parent package before submodules
    import garak.payloads

    if not hasattr(garak.payloads, "Payload"):
        garak.payloads.Payload = type("Payload", (), {"payload_list": {}})
    if not hasattr(garak.payloads.Payload, "payload_list"):
        garak.payloads.Payload.payload_list = {}
    if "whois_injection_contexts" not in garak.payloads.Payload.payload_list:
        garak.payloads.Payload.payload_list["whois_injection_contexts"] = {
            "path": "dummy"
        }
    _GARAK_BOOT_OK = True
    print("[SYSTEM] Garak KeyError Shield: SEALED.")
except Exception as e:
    print(f"[SYSTEM] Garak catalogue shielded at boot: {e}", flush=True)

# Build-time floor (Docker/nixpacks) — Garak cold-starts without full runtime env
COLD_START_MIN_PROBES = 100
# Runtime goal — warn below this when API keys are present; never crash startup
RUNTIME_TARGET_PROBES = 350

_RUNTIME_KEY_VARS = (
    "GROQ_API_KEY",
    "OPENROUTER_API_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
)

# Curated families for mandatory kinetic battery (before Brain loop)
KINETIC_BATTERY_FAMILIES: Tuple[str, ...] = (
    "prompt_injection",
    "jailbreak",
    "pii_leak",
    "hallucination",
    "dan",
    "leak",
    "promptinject",
    "misleading",
)

# Map garak probe submodule names → execution category / curated fallback
_MODULE_TO_CATEGORY: Dict[str, str] = {
    "promptinject": "prompt_injection",
    "prompt_injection": "prompt_injection",
    "dan": "jailbreak",
    "jailbreak": "jailbreak",
    "leak": "pii_leak",
    "pii_leak": "pii_leak",
    "misleading": "hallucination",
    "hallucination": "hallucination",
    "packagehallucination": "hallucination",
    "malwaregen": "jailbreak",
    "atkgen": "prompt_injection",
    "encoding": "prompt_injection",
    "glitch": "prompt_injection",
    "goodside": "prompt_injection",
    "grandma": "jailbreak",
    "donotanswer": "jailbreak",
    "tap": "prompt_injection",
    "continuation": "jailbreak",
    "lmrc": "jailbreak",
    "realtoxicityprompts": "jailbreak",
    "knownbads": "jailbreak",
    "topic": "prompt_injection",
    "suffix": "prompt_injection",
    "xss": "prompt_injection",
    "visual_jailbreak": "jailbreak",
    "base64": "prompt_injection",
    "ansiescape": "prompt_injection",
    "figstep": "jailbreak",
    "latentinjection": "prompt_injection",
}

_CANONICAL_CATEGORIES = frozenset(
    {"prompt_injection", "jailbreak", "pii_leak", "hallucination"}
)


def _engage_garak_registry_shield() -> None:
    """Re-apply whois payload shield after garak.* eviction / hot reload."""
    try:
        import garak as _garak
        import garak.payloads as _payloads

        if not hasattr(_payloads, "Payload"):
            _payloads.Payload = type("Payload", (), {"payload_list": {}})
        if not hasattr(_payloads.Payload, "payload_list"):
            _payloads.Payload.payload_list = {}
        if "whois_injection_contexts" not in _payloads.Payload.payload_list:
            _payloads.Payload.payload_list["whois_injection_contexts"] = {"path": "dummy"}
            print("[SYSTEM] Garak KeyError Shield: SEALED.")
    except Exception as e:
        print(f"[SYSTEM] Garak Shield bypass logic engaged via fallback: {e}")


def canonical_garak_family(category: str) -> str:
    """Map any Garak category to one of four tier-filterable families."""
    cat = category.replace("-", "_").lower()
    if cat not in _CANONICAL_CATEGORIES:
        cat = _MODULE_TO_CATEGORY.get(cat, cat)
    if cat not in _CANONICAL_CATEGORIES:
        if "leak" in cat or "pii" in cat:
            cat = "pii_leak"
        elif "jail" in cat or "dan" in cat:
            cat = "jailbreak"
        elif "halluc" in cat or "mislead" in cat:
            cat = "hallucination"
        else:
            cat = "prompt_injection"
    return f"garak_{cat}"


@dataclass(frozen=True)
class GarakProbeSpec:
    """One discoverable Garak probe class."""

    registry_name: str
    module_name: str
    class_name: str
    category: str
    family: str
    level: str


def _level_for_module(module_name: str) -> str:
    """Assign catalogue tier from probe family name."""
    hardish = {"dan", "malwaregen", "atkgen", "jailbreak", "leak", "packagehallucination"}
    if module_name in hardish:
        return "medium"
    return "easy"


def _category_for_module(module_name: str) -> str:
    """Map garak submodule to curated fallback category."""
    key = module_name.lower().replace("-", "_")
    return _MODULE_TO_CATEGORY.get(key, key)


def _is_probe_class(obj: Any, modname: str) -> bool:
    """Return True if ``obj`` looks like a Garak Probe class."""
    if not inspect.isclass(obj):
        return False
    name = getattr(obj, "__name__", "")
    if not name or name.startswith("_"):
        return False
    if name in ("Probe", "TreeSearchProbe"):
        return False
    mod = getattr(obj, "__module__", "") or ""
    if not mod.startswith("garak.probes"):
        return False
    try:
        from garak.probes.base import Probe  # type: ignore

        return issubclass(obj, Probe) and obj is not Probe
    except Exception:  # noqa: BLE001
        return bool(re.match(r"^[A-Z][A-Za-z0-9_]+$", name))


def _probe_family_key(modname: str) -> str:
    """Extract probe family from a garak.probes.* module path."""
    parts = modname.split(".")
    if len(parts) >= 3 and parts[0] == "garak" and parts[1] == "probes":
        return parts[2].lower().replace("-", "_")
    return parts[-1].lower().replace("-", "_")


def _registry_name_for(modname: str, class_name: str) -> str:
    """Build forgeguard registry key: garak.<relative>.ClassName."""
    rel = modname.split("garak.probes.", 1)[-1] if modname.startswith("garak.probes.") else modname
    return f"garak.{rel}.{class_name}"


def _iter_garak_probe_modules(probes_root: Any) -> List[str]:
    """
    Force-walk every importable ``garak.probes.*`` module (including nested).

    Uses ``pkgutil.walk_packages`` so dynamic plugin subpackages are not missed.
    """
    prefix = probes_root.__name__ + "."
    names: List[str] = []
    for _finder, modname, ispkg in pkgutil.walk_packages(
        probes_root.__path__, prefix=prefix
    ):
        if ispkg:
            continue
        leaf = modname.rsplit(".", 1)[-1]
        if leaf.startswith("_"):
            continue
        names.append(modname)
    names.sort()
    return names


def _runtime_keys_present() -> bool:
    import os

    return any(os.environ.get(k, "").strip() for k in _RUNTIME_KEY_VARS)


def _sync_runtime_env_for_garak(env: Optional[Dict[str, str]] = None) -> None:
    """
    Push runtime LLM keys into os.environ before Garak probe imports.

    Some garak.probes submodules read API keys at import time; passing an
    explicit env snapshot ensures discovery sees the live bunker credentials.
    """
    import os

    source: Dict[str, str] = dict(env) if env is not None else dict(os.environ)
    for key in _RUNTIME_KEY_VARS:
        val = (source.get(key) or os.environ.get(key) or "").strip()
        if val:
            os.environ[key] = val
    for key, val in source.items():
        if key.startswith("GARAK_") and val:
            os.environ.setdefault(key, val)


def discover_garak_probes(
    env: Optional[Dict[str, str]] = None,
) -> List[GarakProbeSpec]:
    """
    Walk ``garak.probes.*`` and collect concrete Probe subclasses.

    Returns an empty list when garak is not installed; callers fall back to
    the four legacy garak.* catalogue entries.
    """
    import os

    _sync_runtime_env_for_garak(env or dict(os.environ))
    _engage_garak_registry_shield()
    specs: List[GarakProbeSpec] = []
    seen: set[str] = set()
    modules_tried = 0
    modules_failed = 0
    try:
        import garak  # type: ignore  # noqa: F401 — force parent package
        import garak.probes as probes_root  # type: ignore
    except ImportError:
        logger.warning("[garak_catalog] garak not installed — using legacy 4 probes")
        return specs

    modnames = _iter_garak_probe_modules(probes_root)
    logger.info(
        "[garak_catalog] manual garak.probes.* walk: %d module paths queued",
        len(modnames),
    )

    for modname in modnames:
        modules_tried += 1
        try:
            family_key = _probe_family_key(modname)
            try:
                mod = importlib.import_module(modname)
            except Exception:  # noqa: BLE001
                modules_failed += 1
                continue

            category = _category_for_module(family_key)
            family = canonical_garak_family(category)
            level = _level_for_module(family_key)

            for _attr, obj in inspect.getmembers(mod, inspect.isclass):
                try:
                    if not _is_probe_class(obj, modname):
                        continue
                    class_name = obj.__name__
                    registry_name = _registry_name_for(modname, class_name)
                    if registry_name in seen:
                        continue
                    seen.add(registry_name)
                    specs.append(
                        GarakProbeSpec(
                            registry_name=registry_name,
                            module_name=family_key,
                            class_name=class_name,
                            category=category,
                            family=family,
                            level=level,
                        )
                    )
                except Exception:  # noqa: BLE001
                    continue
        except Exception:  # noqa: BLE001
            modules_failed += 1
            continue

    specs.sort(key=lambda s: s.registry_name)
    logger.info(
        "[garak_catalog] discovered %d Garak probe classes "
        "(%d modules tried, %d import failures)",
        len(specs),
        modules_tried,
        modules_failed,
    )
    return specs


def probe_count(*, log: bool = True, env: Optional[Dict[str, str]] = None) -> int:
    """Return number of discoverable Garak probe specs (for health checks)."""
    specs = discover_garak_probes(env=env)
    n = len(specs)
    if log:
        msg = f"[registry] Cold-start probes detected: {n}"
        print(msg, flush=True)
        logger.info(msg)
    return n


def _scan_key_env_for_garak(*, scan_api_key: str, target_url: str) -> Dict[str, str]:
    """
    Build env snapshot for Garak probe discovery using the scan-form API key.

    Key Isolation: this only affects probe module import-time checks — kinetic
    strikes still use ``state.api_key`` via ``build_weapon_client``.
    """
    import os

    from .strike_dispatcher import resolve_target_provider

    env = dict(os.environ)
    key = (scan_api_key or "").strip()
    if not key:
        return env
    provider = resolve_target_provider(target_url, "")
    if provider == "groq":
        env["GROQ_API_KEY"] = key
    elif provider == "anthropic":
        env["ANTHROPIC_API_KEY"] = key
    elif provider == "openai":
        env["OPENAI_API_KEY"] = key
    else:
        env.setdefault("OPENROUTER_API_KEY", key)
    return env


def hot_reload_garak_catalog(
    scan_api_key: str = "",
    target_url: str = "",
) -> int:
    """
    Evict garak imports and re-discover the full arsenal via garak.probes.* walk.
    Triggered on first scan start when the bunker is live.
    """
    import os
    import sys

    runtime_env = (
        _scan_key_env_for_garak(scan_api_key=scan_api_key, target_url=target_url)
        if (scan_api_key or "").strip()
        else dict(os.environ)
    )
    _sync_runtime_env_for_garak(runtime_env)

    evicted = 0
    for mod_name in list(sys.modules):
        if mod_name == "garak" or mod_name.startswith("garak."):
            del sys.modules[mod_name]
            evicted += 1
    if evicted:
        logger.info("[registry] Hot reload evicted %d garak.* modules", evicted)

    importlib.invalidate_caches()
    _engage_garak_registry_shield()

    # Force-import and reload probe tree — clears failed import caches
    try:
        garak_pkg = importlib.import_module("garak")
        importlib.reload(garak_pkg)
        probes_root = importlib.import_module("garak.probes")
        importlib.reload(probes_root)
        logger.info(
            "[registry] garak.probes force-reloaded (%s)",
            getattr(probes_root, "__path__", "?"),
        )
    except ImportError as exc:
        logger.warning("[registry] garak import failed during hot reload: %s", exc)
        return 0
    except Exception as exc:  # noqa: BLE001
        logger.warning("[registry] garak.probes reload failed: %s", exc)
        _engage_garak_registry_shield()
        try:
            importlib.import_module("garak")
            importlib.import_module("garak.probes")
        except ImportError:
            return 0

    from forgeguard_bridge import reload_garak_heavy_registry

    added, registry_size = reload_garak_heavy_registry()
    n = probe_count(log=True, env=runtime_env)
    print(f"[registry] Hot reload probes detected: {n}", flush=True)
    msg = (
        f"[registry] Hot reload probes detected: {n} "
        f"(registry={registry_size}, added={added}, target {RUNTIME_TARGET_PROBES}+)"
    )
    logger.info(msg)
    if n < RUNTIME_TARGET_PROBES:
        logger.warning(
            "[registry] Garak count %d below target %d after hot reload — "
            "check garak install and runtime API keys",
            n,
            RUNTIME_TARGET_PROBES,
        )
    return n


def warm_runtime_garak_registry() -> int:
    """
    Re-discover Garak probes after the bunker env is live and extend REGISTRY.

    Idempotent — existing registry names are skipped by the bridge reload helper.
    """
    import os

    n = probe_count(log=True)
    keys_present = _runtime_keys_present()

    if keys_present:
        present = [k for k in _RUNTIME_KEY_VARS if os.environ.get(k, "").strip()]
        logger.info("[registry] Runtime API keys detected: %s", ", ".join(present))
    else:
        logger.info(
            "[registry] No runtime LLM keys set — using cold-start Garak catalogue (%d)",
            n,
        )

    from forgeguard_bridge import REGISTRY, reload_garak_heavy_registry

    added, registry_size = reload_garak_heavy_registry()
    n = probe_count(log=False)
    msg = (
        f"[registry] Runtime arsenal: {registry_size} entries, "
        f"garak_classes={n} (target {RUNTIME_TARGET_PROBES}+)"
    )
    print(msg, flush=True)
    logger.info(msg)
    if added:
        logger.info("[registry] Garak reload added %d new probe entries", added)

    if keys_present and n < RUNTIME_TARGET_PROBES:
        logger.warning(
            "[registry] Runtime Garak count %d below target %d — "
            "some probe modules may still be unavailable",
            n,
            RUNTIME_TARGET_PROBES,
        )

    return n


def get_kinetic_battery_strikes() -> List[Tuple[str, str]]:
    """
    Return (registry_name, category) pairs for the mandatory pre-Brain battery.

    Picks representatives for jailbreak, prompt_injection, and pii_leak first,
    then fills up to 24 strikes from discovered specs.
    """
    specs = discover_garak_probes()
    battery: List[Tuple[str, str]] = []
    seen_categories: set[str] = set()
    priority = ("prompt_injection", "jailbreak", "pii_leak", "hallucination")

    legacy = [
        ("garak.prompt_injection", "prompt_injection"),
        ("garak.jailbreak", "jailbreak"),
        ("garak.pii_leak", "pii_leak"),
        ("garak.hallucination", "hallucination"),
    ]
    for name, cat in legacy:
        battery.append((name, cat))
        seen_categories.add(cat)

    for cat in priority:
        for spec in specs:
            if spec.category != cat:
                continue
            if (spec.registry_name, cat) not in battery:
                battery.append((spec.registry_name, cat))
                seen_categories.add(cat)
                break

    for spec in specs:
        if len(battery) >= 24:
            break
        mod_key = spec.module_name.lower()
        cat = spec.category
        if mod_key in KINETIC_BATTERY_FAMILIES or cat in priority:
            if (spec.registry_name, cat) not in battery:
                battery.append((spec.registry_name, cat))
                seen_categories.add(cat)

    return battery[:24]


def make_registry_entry(
    spec: GarakProbeSpec,
    runner_fn: Callable[..., Any],
) -> Dict[str, Any]:
    """Build one forgeguard_bridge REGISTRY dict for a Garak probe."""

    def _fn(client: Any, model: str, _spec: GarakProbeSpec = spec) -> Any:
        return runner_fn(
            client,
            model,
            probe_module=_spec.module_name,
            probe_class=_spec.class_name,
            category=_spec.category,
            registry_name=_spec.registry_name,
        )

    return {
        "name": spec.registry_name,
        "family": spec.family,
        "level": spec.level,
        "fn": _fn,
    }


def resolve_category_from_registry_name(registry_name: str) -> str:
    """
    Map ``garak.module.Class`` or ``garak.category`` to execution category.

    Used by kinetic strike and ``run_attack`` when the Brain passes a full
    Garak probe name.
    """
    parts = registry_name.split(".")
    if len(parts) >= 3 and parts[0] == "garak":
        return _category_for_module(parts[1])
    if len(parts) == 2 and parts[0] == "garak":
        return _category_for_module(parts[1])
    return registry_name


def build_garak_registry_entries(
    runner_fn: Callable[..., Any],
) -> List[Dict[str, Any]]:
    """
    Produce bridge REGISTRY entries for all discovered Garak probes.

    Args:
        runner_fn: ``run_garak_probe`` from ``garak_runner`` module.
    """
    return [make_registry_entry(spec, runner_fn) for spec in discover_garak_probes()]

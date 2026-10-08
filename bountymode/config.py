"""Configuration: one place for models, the engine, and run defaults.

Resolution order (first value found wins):

1. explicit arguments passed to the API,
2. environment variables,
3. a config file (``$BOUNTYMODE_CONFIG`` or ``./bountymode.json``),
4. the built-in defaults in this module.

Only the standard library is used, so configuration never adds a dependency.

Models
------
The default provider is OpenRouter's *free* tier, because that is the cheapest
way to run a red-team workload end to end and it needs no credit card.  The
default model is ``openrouter/free`` -- OpenRouter's own auto-router, which
selects among the currently available free models, so the configuration keeps
working as the free roster rotates.  Named free models are used for the roles
where a specific capability matters (long-context reasoning for judging,
audio/image for multimodal injection); the full list is in
:data:`FREE_MODEL_FALLBACKS` and is verified against OpenRouter's live model
list at release time.

Swap models without editing code::

    export BOUNTYMODE_MODEL="nvidia/nemotron-3-super-120b-a12b:free"

or point at a different OpenAI-compatible provider entirely::

    export BOUNTYMODE_LLM_BASE_URL="https://api.groq.com/openai/v1"
    export BOUNTYMODE_LLM_API_KEY="gsk_..."
    export BOUNTYMODE_MODEL="llama-3.3-70b-versatile"
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional

# --------------------------------------------------------------------------- #
# defaults                                                                     #
# --------------------------------------------------------------------------- #

#: OpenRouter's auto-router over its free tier -- stable default that survives
#: free-roster churn.  See https://openrouter.ai/docs/guides/routing/routers/free-router
FREE_MODEL_DEFAULT = "openrouter/free"

#: Explicit free models, in preference order.  Verified against the live
#: OpenRouter model list (`/api/v1/models`, zero prompt+completion price).
FREE_MODEL_FALLBACKS: List[str] = [
    "nvidia/nemotron-3-super-120b-a12b:free",              # 262K, strong reasoner
    "google/gemma-4-31b-it:free",                          # 262K, image/video input
    "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free",  # text/audio/image/video
    "nvidia/nemotron-3.5-lightning:free",                  # 1M context, fast
    "liquid/lfm-2.5-2.6b:free",                            # 65K, tiny fallback
]

#: Per-role free models.  Roles map onto how the engine and the upgrades use an
#: LLM: payload/test-case generation, response classification, and multimodal
#: carriers.
ROLE_MODELS: Dict[str, str] = {
    "generate": "nvidia/nemotron-3-super-120b-a12b:free",
    "judge": "nvidia/nemotron-3-ultra-550b-a55b:free",
    "multimodal": "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free",
}

DEFAULT_BASE_URL = "https://openrouter.ai/api/v1"
CONFIG_ENV = "BOUNTYMODE_CONFIG"
DEFAULT_CONFIG_FILES = ("bountymode.json", ".bountymode.json")

#: API-key environment variable -> the OpenAI-compatible base URL that key
#: belongs to.  A key is only valid with the provider that issued it, so the
#: base URL travels with it; otherwise an ambient OPENAI_API_KEY would be sent
#: to OpenRouter (or the reverse) and every call would fail with an opaque 401.
PROVIDER_BASE_URLS: Dict[str, str] = {
    "OPENROUTER_API_KEY": DEFAULT_BASE_URL,
    "GROQ_API_KEY": "https://api.groq.com/openai/v1",
    "OPENAI_API_KEY": "https://api.openai.com/v1",
}

#: A model to fall back to when a provider key is picked up from the ambient
#: environment and the caller did not name a model.  The OpenRouter default is
#: a ``:free`` route, which only makes sense on OpenRouter.
PROVIDER_DEFAULT_MODELS: Dict[str, str] = {
    "OPENROUTER_API_KEY": FREE_MODEL_DEFAULT,
    "GROQ_API_KEY": "llama-3.3-70b-versatile",
    "OPENAI_API_KEY": "gpt-4o-mini",
}

#: Preference order when several provider keys are present.  An explicit
#: BOUNTYMODE_LLM_API_KEY comes first, then OpenRouter -- this project's
#: default, and the only free option.
PROVIDER_KEY_ORDER = (
    "BOUNTYMODE_LLM_API_KEY",
    "OPENROUTER_API_KEY",
    "GROQ_API_KEY",
    "OPENAI_API_KEY",
)


# --------------------------------------------------------------------------- #
# settings                                                                     #
# --------------------------------------------------------------------------- #

@dataclass
class LLMSettings:
    """Settings for the OpenAI-compatible chat client."""

    model: str = FREE_MODEL_DEFAULT
    api_key: str = ""
    base_url: str = DEFAULT_BASE_URL
    temperature: float = 0.7
    max_tokens: int = 1024
    timeout: float = 90.0
    fallbacks: List[str] = field(default_factory=lambda: list(FREE_MODEL_FALLBACKS))

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    def to_dict(self, redact: bool = True) -> Dict[str, Any]:
        return {
            "model": self.model,
            "base_url": self.base_url,
            "configured": self.configured,
            "api_key": ("***" if self.api_key else "") if redact else self.api_key,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "timeout": self.timeout,
            "fallbacks": list(self.fallbacks),
        }


@dataclass
class EngineSettings:
    """Settings for the vendored in-process engine."""

    intensity: str = "standard"          # recon | standard | aggressive | greasy
    model: str = ""                      # empty -> follow the LLM model
    offline: bool = False                # force the deterministic offline client
    path: str = ""                       # override the engine directory

    def to_dict(self) -> Dict[str, Any]:
        return {
            "intensity": self.intensity,
            "model": self.model,
            "offline": self.offline,
            "path": self.path,
        }


@dataclass
class BountyModeConfig:
    """Top-level configuration object."""

    llm: LLMSettings = field(default_factory=LLMSettings)
    engine: EngineSettings = field(default_factory=EngineSettings)
    default_platform: str = "hackerone"
    run_dir: str = "bounty-run"
    source: str = "defaults"             # where the config came from

    def to_dict(self, redact: bool = True) -> Dict[str, Any]:
        return {
            "source": self.source,
            "llm": self.llm.to_dict(redact=redact),
            "engine": self.engine.to_dict(),
            "default_platform": self.default_platform,
            "run_dir": self.run_dir,
        }

    def role_model(self, role: str) -> str:
        """Model for a named role, falling back to the primary model."""
        return ROLE_MODELS.get(role, self.llm.model)


# --------------------------------------------------------------------------- #
# loading                                                                      #
# --------------------------------------------------------------------------- #

def _from_env(env: Dict[str, str]) -> Dict[str, Any]:
    out: Dict[str, Any] = {"llm": {}, "engine": {}}
    llm, eng = out["llm"], out["engine"]

    if env.get("BOUNTYMODE_MODEL"):
        llm["model"] = env["BOUNTYMODE_MODEL"]
    if env.get("BOUNTYMODE_LLM_MODEL"):
        llm["model"] = env["BOUNTYMODE_LLM_MODEL"]
    if env.get("BOUNTYMODE_LLM_BASE_URL"):
        llm["base_url"] = env["BOUNTYMODE_LLM_BASE_URL"]
    for key in PROVIDER_KEY_ORDER:
        if not env.get(key):
            continue
        llm["api_key"] = env[key]
        # Bind the base URL to the provider that issued the key, unless an
        # explicit base URL was given.
        provider_url = PROVIDER_BASE_URLS.get(key)
        if provider_url and not env.get("BOUNTYMODE_LLM_BASE_URL"):
            llm["base_url"] = provider_url
        # A provider key found in the ambient environment must not drag the
        # OpenRouter-only default model along to that provider.
        if (
            key in PROVIDER_DEFAULT_MODELS
            and not env.get("BOUNTYMODE_MODEL")
            and not env.get("BOUNTYMODE_LLM_MODEL")
        ):
            llm["model"] = PROVIDER_DEFAULT_MODELS[key]
        break
    if env.get("BOUNTYMODE_ENGINE_INTENSITY"):
        eng["intensity"] = env["BOUNTYMODE_ENGINE_INTENSITY"]
    if env.get("BOUNTYMODE_ENGINE_MODEL"):
        eng["model"] = env["BOUNTYMODE_ENGINE_MODEL"]
    if env.get("BOUNTYMODE_ENGINE_PATH"):
        eng["path"] = env["BOUNTYMODE_ENGINE_PATH"]
    if str(env.get("BOUNTYMODE_OFFLINE", "")).lower() in ("1", "true", "yes"):
        eng["offline"] = True

    return {k: v for k, v in out.items() if v}


def _config_file_path(env: Dict[str, str]) -> Optional[Path]:
    explicit = env.get(CONFIG_ENV)
    if explicit:
        p = Path(explicit)
        return p if p.is_file() else None
    for name in DEFAULT_CONFIG_FILES:
        p = Path(name)
        if p.is_file():
            return p
    return None


def _from_file(path: Path) -> Dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _merge(base: Dict[str, Any], overlay: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            merged = dict(out[key])
            merged.update(value)
            out[key] = merged
        else:
            out[key] = value
    return out


def load_config(path: Optional[str] = None, env: Optional[Dict[str, str]] = None) -> BountyModeConfig:
    """Build the effective configuration.

    ``path`` forces a specific config file; otherwise the environment variable
    and the default file names are consulted.  ``env`` lets tests inject an
    environment map without touching the process environment.
    """
    environ = dict(os.environ) if env is None else dict(env)
    if path:
        environ[CONFIG_ENV] = path

    data: Dict[str, Any] = {}
    source = "defaults"
    cfg_path = _config_file_path(environ)
    if cfg_path is not None:
        data = _from_file(cfg_path)
        source = str(cfg_path)

    env_layer = _from_env(environ)
    if env_layer:
        data = _merge(data, env_layer)
        source = f"{source}+env" if source != "defaults" else "env"

    llm_data = data.get("llm", {})
    eng_data = data.get("engine", {})

    llm = LLMSettings()
    for f in ("model", "api_key", "base_url", "temperature", "max_tokens", "timeout", "fallbacks"):
        if f in llm_data and llm_data[f] is not None:
            setattr(llm, f, llm_data[f])

    engine = EngineSettings()
    for f in ("intensity", "model", "offline", "path"):
        if f in eng_data and eng_data[f] is not None:
            setattr(engine, f, eng_data[f])

    return BountyModeConfig(
        llm=llm,
        engine=engine,
        default_platform=str(data.get("default_platform", "hackerone")),
        run_dir=str(data.get("run_dir", "bounty-run")),
        source=source,
    )


@lru_cache(maxsize=1)
def default_config() -> BountyModeConfig:
    """Process-wide default configuration."""
    return load_config()


def reset_config_cache() -> None:
    """Drop the cached configuration (used by tests and long-running servers)."""
    default_config.cache_clear()

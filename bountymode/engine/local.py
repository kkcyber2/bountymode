"""Run the vendored engine in-process.

This is the module that removes the second repository and the network hop.  A
Bounty Mode case can now dispatch a technique straight into the engine's own
``REGISTRY`` callable instead of POSTing to a remote scan API.

How it works
------------
The engine's ``REGISTRY`` maps a technique name to a plain callable::

    fn(client, model)                 # simple families
    fn(client, model, intensity)      # plugins that gate on scan tier

where ``client`` is any object exposing ``generate_response(prompt) -> str``.
:class:`LocalEngine` resolves a
:class:`~bountymode.models.Technique` to the matching registry entry, builds a
target client, invokes the callable, and normalises the engine's
``AttackResult`` into Bounty Mode's :class:`~bountymode.runner.adapter.EngineResult`.

Safety
------
The engine is only ever invoked here.  The authorization gate and
stop-conditions are enforced by the case runner *before* it calls this module,
so a denied technique never reaches these functions.
"""

from __future__ import annotations

import inspect
import logging
from typing import Any, Callable, Dict, List, Optional

from ..models import Technique
from ..runner.adapter import EngineResult
from .catalogue import EngineCatalogue, default_catalogue
from .llm import ChatClient, OfflineClient, client_from_config
from .paths import engine_available, ensure_on_path, quiet_engine_boot

log = logging.getLogger(__name__)

#: Scan intensities understood by the engine's tier logic.
INTENSITIES = ("recon", "standard", "aggressive", "greasy")


def _resolve_intensity(name: str) -> Any:
    """Map a plain string onto the engine's ``Intensity`` enum.

    Falls back to the raw string when the enum cannot be imported, so the
    module stays usable even with a partial engine checkout.
    """
    try:
        ensure_on_path()
        with quiet_engine_boot():
            from agathon.attack_tier_logic import Intensity  # type: ignore

        try:
            return Intensity(str(name).strip().lower())
        except ValueError:
            return Intensity.STANDARD
    except Exception:  # noqa: BLE001
        return name


class LocalEngine:
    """In-process dispatcher over the engine's attack catalogue."""

    def __init__(
        self,
        *,
        model: str = "",
        intensity: str = "standard",
        catalogue: Optional[EngineCatalogue] = None,
        client: Optional[Any] = None,
        client_factory: Optional[Callable[[str], Any]] = None,
    ) -> None:
        self.catalogue = catalogue or default_catalogue()
        self.model = model
        self.intensity_name = intensity if intensity in INTENSITIES else "standard"
        self._client = client
        self._client_factory = client_factory
        self._intensity = None

    # -- readiness ---------------------------------------------------------- #

    @property
    def available(self) -> bool:
        return engine_available() and self.catalogue.available()

    def readiness(self) -> Dict[str, Any]:
        return {
            "engine_present": engine_available(),
            "catalogue": self.catalogue.stats(),
            "mode": "offline" if isinstance(self._effective_client(""), OfflineClient) else "live",
            "intensity": self.intensity_name,
        }

    # -- client ------------------------------------------------------------- #

    def _effective_client(self, target: str) -> Any:
        if self._client is not None:
            return self._client
        if self._client_factory is not None:
            return self._client_factory(target)
        return client_from_config()

    def _effective_model(self) -> str:
        if self.model:
            return self.model
        client = self._effective_client("")
        return getattr(client, "model", "") or "unknown"

    def _intensity_value(self) -> Any:
        if self._intensity is None:
            self._intensity = _resolve_intensity(self.intensity_name)
        return self._intensity

    # -- dispatch ----------------------------------------------------------- #

    def run_technique(
        self,
        technique: Technique,
        target: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> EngineResult:
        """Run one technique in-process and normalise the result.

        Never raises: a dispatch problem is returned as an unsuccessful
        :class:`EngineResult` so the runner can record it as an error.
        """
        if not self.catalogue.available():
            return EngineResult(
                technique_id=technique.id,
                target=target,
                success=False,
                evidence=f"engine unavailable: {self.catalogue.error}",
            )

        entry = self.catalogue.resolve(technique.engine_key or technique.id)
        if entry is None:
            return EngineResult(
                technique_id=technique.id,
                target=target,
                success=False,
                evidence=f"no engine technique matches {technique.engine_key or technique.id!r}",
            )

        fn = entry.get("fn")
        if not callable(fn):
            return EngineResult(
                technique_id=technique.id,
                target=target,
                success=False,
                evidence=f"catalogue entry {entry.get('name')!r} has no callable",
            )

        client = self._effective_client(target)
        model = self._effective_model()

        try:
            raw = self._invoke(fn, client, model)
        except Exception as exc:  # noqa: BLE001 - the runner records errors
            log.warning("[engine] %s raised: %s", entry.get("name"), exc)
            return EngineResult(
                technique_id=technique.id,
                target=target,
                success=False,
                evidence=f"engine raised {type(exc).__name__}: {exc}",
            )

        return _normalise(raw, technique, target, entry)

    def _invoke(self, fn: Callable[..., Any], client: Any, model: str) -> Any:
        """Call a registry function, honouring its real arity."""
        try:
            sig = inspect.signature(fn)
            accepts_intensity = len(sig.parameters) >= 3
        except (TypeError, ValueError):
            accepts_intensity = False
        if accepts_intensity:
            return fn(client, model, self._intensity_value())
        return fn(client, model)

    # -- catalogue passthrough --------------------------------------------- #

    def techniques(self) -> List[Dict[str, Any]]:
        return self.catalogue.describe()

    def families(self) -> List[str]:
        return self.catalogue.families()


def _normalise(
    raw: Any,
    technique: Technique,
    target: str,
    entry: Dict[str, Any],
) -> EngineResult:
    """Convert an engine ``AttackResult`` (or dict) into an ``EngineResult``."""
    data: Dict[str, Any] = {}
    if raw is None:
        data = {}
    elif hasattr(raw, "to_dict"):
        try:
            data = dict(raw.to_dict())
        except Exception:  # noqa: BLE001
            data = {}
    elif isinstance(raw, dict):
        data = dict(raw)

    vuln = data.get("vulnerability_type", "")
    if hasattr(vuln, "value"):
        vuln = vuln.value

    success_score = _as_float(data.get("success_score"), 0.0)
    confidence = _as_float(data.get("reliability"), success_score) or success_score

    return EngineResult(
        technique_id=technique.id,
        target=target,
        success=bool(data.get("success", False)),
        success_score=success_score,
        response=str(data.get("response", "") or ""),
        payload_used=str(data.get("payload_used", "") or ""),
        evidence=str(data.get("evidence", "") or ""),
        vulnerability_type=str(vuln or data.get("attack_type", "") or technique.category),
        confidence=confidence,
        target_model=str(data.get("target_model", "") or ""),
    )


def _as_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def build_local_dispatch(
    *,
    model: str = "",
    intensity: str = "standard",
    offline: bool = False,
    canned: Optional[Dict[str, str]] = None,
    simulate_vulnerable: Optional[bool] = None,
) -> Callable[[Technique, str], EngineResult]:
    """Return a ``dispatch(technique, target) -> EngineResult`` for the runner.

    ``offline`` swaps the live model client for the deterministic one.

    An offline run has to answer *something*, so unless the caller says
    otherwise it models a deliberately vulnerable mock target: every reply then
    looks like a successful compromise, which is what makes a dry run exercise
    the whole pipeline (gate -> engine -> evidence -> triage -> report) end to
    end.  Pass ``simulate_vulnerable=False`` for an offline run that should
    mostly report *no* finding, or supply ``canned`` responses to script exact
    outcomes.
    """
    if simulate_vulnerable is None:
        simulate_vulnerable = offline and not canned

    client: Optional[Any] = None
    if offline:
        client = OfflineClient(canned=canned, simulate_vulnerable=bool(simulate_vulnerable))
    engine = LocalEngine(model=model, intensity=intensity, client=client)
    return engine.run_technique

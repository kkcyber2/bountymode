"""Probe primitives -- the three requests every oracle compares.

A single re-sent request proves nothing: it produces the same output whether the
target is vulnerable or merely chatty.  A *probe set* makes the difference
visible by sending three requests of the same shape and comparing them:

``test``
    the request that is expected to trigger the weakness.
``control``
    a benign request of the same shape.  If the test request and the control
    request behave identically, the oracle is measuring nothing.
``negative``
    a request that must **not** trigger anything.  This is the false-positive
    trap: an oracle that fires on the negative control is firing on the target's
    normal behaviour, not on the weakness.

Everything here is transport-agnostic.  A :class:`ProbeSender` is any callable
that takes a :class:`Probe` and returns a :class:`ProbeResult`, so the same
oracles drive a local OpenAI-compatible endpoint, a mock, or a recorded
transcript.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence

#: The role a probe plays in a differential comparison.
TEST = "test"
CONTROL = "control"
NEGATIVE = "negative"

#: Roles, in the order they are sent.
ROLES = (TEST, CONTROL, NEGATIVE)


@dataclass
class Probe:
    """One request to send, and the role it plays in the comparison."""

    role: str
    prompt: str
    #: Free-form label used in evidence (e.g. the oracle that produced it).
    label: str = ""
    #: Optional per-probe request parameters (method, headers, body ...) for
    #: HTTP-shaped targets.  Prompt targets leave this empty.
    params: Dict[str, Any] = field(default_factory=dict)

    @property
    def prompt_key(self) -> str:
        """Stable cache key so an identical probe is never sent twice."""
        return f"{self.role}|{self.label}|{self.prompt}"

    def to_dict(self) -> Dict[str, Any]:
        return {"role": self.role, "prompt": self.prompt, "label": self.label}


@dataclass
class ProbeResult:
    """The target's answer to one :class:`Probe`."""

    role: str
    response: str = ""
    error: str = ""
    ok: bool = True
    status: Optional[int] = None
    latency_ms: float = 0.0
    #: Token usage when the transport reports it (``{"total_tokens": 42}``).
    usage: Dict[str, int] = field(default_factory=dict)
    #: How many times this exact probe was actually sent (cache misses).
    attempts: int = 1

    @property
    def text(self) -> str:
        return self.response or ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "role": self.role,
            "ok": self.ok,
            "status": self.status,
            "latency_ms": round(self.latency_ms, 1),
            "error": self.error,
            "usage": dict(self.usage),
            "response_preview": self.response[:400],
        }


@dataclass
class ProbeSet:
    """The test / control / negative triple one oracle evaluates."""

    test: Probe
    control: Probe
    negative: Probe
    label: str = ""

    def ordered(self) -> List[Probe]:
        return [self.test, self.control, self.negative]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "label": self.label,
            "test": self.test.to_dict(),
            "control": self.control.to_dict(),
            "negative": self.negative.to_dict(),
        }


@dataclass
class ProbeOutcome:
    """The three answers produced by running one :class:`ProbeSet`."""

    test: ProbeResult
    control: ProbeResult
    negative: ProbeResult
    #: The probe set that produced these answers, when known.  Retained so an
    #: oracle can recover the canary it embedded and so evidence can quote the
    #: exact request that was sent.
    probes: Optional[ProbeSet] = None

    def by_role(self) -> Dict[str, ProbeResult]:
        return {TEST: self.test, CONTROL: self.control, NEGATIVE: self.negative}

    @property
    def errored(self) -> bool:
        """True when no probe produced a usable answer."""
        return all(not r.ok for r in (self.test, self.control, self.negative))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "test": self.test.to_dict(),
            "control": self.control.to_dict(),
            "negative": self.negative.to_dict(),
            "errored": self.errored,
        }


#: A sender performs one probe and returns its result.
ProbeSender = Callable[[Probe], ProbeResult]


class ProbeRunner:
    """Send probes, caching identical ones so a replay costs nothing extra.

    The verifier runs a probe set once per reproduction attempt.  Without a
    cache that means the *same* control and negative requests are sent N times,
    which is pure waste (and, against a rate-limited target, an easy way to get
    throttled).  The cache keys on the exact prompt, so only genuinely new
    probes cost a request.
    """

    def __init__(self, send: ProbeSender, *, cache: bool = True) -> None:
        self._send = send
        self._cache: Optional[Dict[str, ProbeResult]] = {} if cache else None
        #: Requests actually sent (cache misses).
        self.sent = 0
        #: Requests served from the cache.
        self.reused = 0

    def run(self, probe: Probe) -> ProbeResult:
        key = probe.prompt_key
        if self._cache is not None and key in self._cache:
            self.reused += 1
            cached = self._cache[key]
            return ProbeResult(
                role=cached.role,
                response=cached.response,
                error=cached.error,
                ok=cached.ok,
                status=cached.status,
                latency_ms=cached.latency_ms,
                usage=dict(cached.usage),
                attempts=cached.attempts,
            )
        self.sent += 1
        started = time.monotonic()
        try:
            result = self._send(probe)
        except Exception as exc:  # noqa: BLE001 - a failed probe is data, not a crash
            result = ProbeResult(
                role=probe.role,
                ok=False,
                error=f"{type(exc).__name__}: {exc}",
            )
        if not result.latency_ms:
            result.latency_ms = (time.monotonic() - started) * 1000.0
        if result.role != probe.role:
            result.role = probe.role
        if self._cache is not None:
            self._cache[key] = result
        return result

    def run_set(
        self,
        probes: ProbeSet,
        fresh_roles: Sequence[str] = (TEST,),
    ) -> ProbeOutcome:
        """Run a probe set, forcing ``fresh_roles`` to bypass the cache.

        The *test* probe must be genuinely re-sent on every replay attempt,
        otherwise N-of-M would report a cached answer instead of measuring
        reproducibility.  The control and negative baselines are stable, so
        re-sending them is pure cost (and an easy way to get rate-limited) --
        they are cached by default.
        """
        fresh = frozenset(fresh_roles)
        results: Dict[str, ProbeResult] = {}
        for probe in probes.ordered():
            if probe.role in fresh and self._cache is not None:
                self._cache.pop(probe.prompt_key, None)
            results[probe.role] = self.run(probe)
        return ProbeOutcome(
            test=results[TEST],
            control=results[CONTROL],
            negative=results[NEGATIVE],
            probes=probes,
        )

    def stats(self) -> Dict[str, int]:
        return {
            "sent": self.sent,
            "reused": self.reused,
            "total": self.sent + self.reused,
        }


# --------------------------------------------------------------------------- #
# Senders
# --------------------------------------------------------------------------- #

def client_sender(client: Any, *, max_tokens: int = 256, temperature: float = 0.0) -> ProbeSender:
    """Build a :class:`ProbeSender` from an LLM client.

    Accepts anything exposing ``chat(prompt)`` returning an object with
    ``text`` / ``ok`` / ``error`` (the engine's :class:`ChatClient` and
    :class:`OfflineClient` both qualify) or the simpler
    ``generate_response(prompt) -> str`` contract.
    """

    def send(probe: Probe) -> ProbeResult:
        started = time.monotonic()
        chat = getattr(client, "chat", None)
        if callable(chat):
            try:
                res = chat(probe.prompt, max_tokens=max_tokens, temperature=temperature)
            except TypeError:
                res = chat(probe.prompt)
            latency = (time.monotonic() - started) * 1000.0
            return ProbeResult(
                role=probe.role,
                response=str(getattr(res, "text", "") or ""),
                ok=bool(getattr(res, "ok", True)),
                error=str(getattr(res, "error", "") or ""),
                latency_ms=latency,
                usage=dict(getattr(res, "usage", {}) or {}),
            )
        gen = getattr(client, "generate_response", None)
        if not callable(gen):
            raise TypeError("client exposes neither chat() nor generate_response()")
        text = gen(probe.prompt)
        latency = (time.monotonic() - started) * 1000.0
        return ProbeResult(role=probe.role, response=str(text or ""), latency_ms=latency)

    return send


def callable_sender(fn: Callable[[str], str]) -> ProbeSender:
    """Build a sender from a plain ``prompt -> response`` callable."""

    def send(probe: Probe) -> ProbeResult:
        started = time.monotonic()
        try:
            text = fn(probe.prompt)
        except Exception as exc:  # noqa: BLE001
            return ProbeResult(
                role=probe.role,
                ok=False,
                error=f"{type(exc).__name__}: {exc}",
                latency_ms=(time.monotonic() - started) * 1000.0,
            )
        return ProbeResult(
            role=probe.role,
            response=str(text or ""),
            latency_ms=(time.monotonic() - started) * 1000.0,
        )

    return send


_CANARY_RE = re.compile(r"[A-Z0-9]{4}-[A-Z0-9]{4,}")


def canary_token(seed: str) -> str:
    """A short, high-entropy marker that is safe to look for in a response.

    A canary makes reflection and instruction-following measurable without any
    guesswork: if the marker the *test* probe carried comes back but the marker
    the *control* probe carried does not, the target acted on our input.
    """
    digest = re.sub(r"[^A-Za-z0-9]", "", seed.upper())[:6] or "AAAAAA"
    return f"VERIFY-{digest}"

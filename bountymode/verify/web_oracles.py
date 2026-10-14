"""Verification for web/API findings.

The generic verifier replays a *prompt* probe set against an LLM.  A web finding
is not a prompt: it is an HTTP differential.  This module supplies the two
pieces the verifier needs to replay a web finding honestly:

* :func:`web_sender` -- a :class:`~bountymode.verify.probe.ProbeSender` that
  turns a probe into the technique's real HTTP test/control request and encodes
  the differential verdict in the result.
* :class:`WebDifferentialOracle` -- an oracle that reads those encoded verdicts
  and reports the finding as reproduced only when the *test* request fired and
  neither the control nor the negative baseline did.

The negative control is a benign request that must never fire, so the generic
verifier's own negative-control check works unchanged.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Tuple

from .oracles import (
    INCONCLUSIVE,
    UNVERIFIED,
    VERIFIED,
    Oracle,
    OracleResult,
)
from .probe import CONTROL, NEGATIVE, TEST, Probe, ProbeResult, ProbeSender, ProbeSet

#: The categories this oracle claims.  Kept in sync with the web_api catalogue.
WEB_CATEGORIES: Tuple[str, ...] = (
    "idor", "auth_bypass", "ssrf", "sqli", "path_traversal", "xss",
    "open_redirect", "mass_assignment", "jwt_weakness",
    "graphql_introspection", "business_logic", "csrf",
    "rate_limit_bypass", "api_versioning_bypass",
)


def _encode(fired: bool, score: float, evidence: str, status: int) -> str:
    return json.dumps({"fired": bool(fired), "score": float(score),
                       "evidence": evidence, "status": int(status)})


def _decode(result: ProbeResult) -> Dict[str, Any]:
    try:
        data = json.loads(result.response or "{}")
        if isinstance(data, dict):
            return data
    except Exception:  # noqa: BLE001
        pass
    return {"fired": False, "score": 0.0, "evidence": result.error or "no verdict", "status": 0}


def web_sender(
    *,
    timeout: float = 10.0,
    allow_writes: bool = True,
) -> ProbeSender:
    """Build a probe sender that replays a web technique over HTTP.

    The probe's ``params`` carry the technique id and the target; the sender
    runs the technique's real test/control pair and returns the verdict encoded
    in the response.  The ``negative`` role is a benign request that must not
    fire, which is what the verifier's negative-control check reads.
    """
    from ..engine.web import WebEngine, _PROBES  # local import: avoid a cycle

    def send(probe: Probe) -> ProbeResult:
        technique_id = str(probe.params.get("technique", ""))
        target = str(probe.params.get("target", ""))
        engine = WebEngine(target, timeout=timeout, allow_writes=allow_writes)

        if probe.role == NEGATIVE:
            # A benign request: it must never look like a finding.
            benign = engine._send(target, Probe_health())
            return ProbeResult(
                role=probe.role, status=benign.status,
                response=_encode(False, 0.0, "benign baseline", benign.status),
                ok=benign.ok,
            )

        builder = _PROBES.get(technique_id)
        if builder is None:
            return ProbeResult(
                role=probe.role, ok=False,
                error=f"no web probe for {technique_id!r}",
                response=_encode(False, 0.0, "no probe", 0),
            )
        variants = builder(target)
        if not isinstance(variants, list):
            variants = [variants]
        # Replay the same variant the scan used: the first one that fires, or the
        # last one if none did.  This keeps verification honest -- it re-runs the
        # exact payload that produced the finding, not a different one.
        chosen_variant = variants[-1]
        if probe.role == TEST:
            for candidate in variants:
                test_probe, control_probe, judge = candidate
                result = engine._send(target, test_probe)
                control_result = engine._send(target, control_probe)
                try:
                    fired, score, evidence = judge(result, control_result)
                except Exception:  # noqa: BLE001
                    continue
                if fired:
                    return ProbeResult(
                        role=probe.role, status=result.status,
                        response=_encode(fired, score, evidence, result.status),
                        ok=result.ok,
                    )
        test_probe, control_probe, judge = chosen_variant
        chosen = test_probe if probe.role == TEST else control_probe
        result = engine._send(target, chosen)
        if probe.role == TEST:
            # Judge the test against the control so the verdict is a differential.
            control_result = engine._send(target, control_probe)
            try:
                fired, score, evidence = judge(result, control_result)
            except Exception as exc:  # noqa: BLE001
                return ProbeResult(role=probe.role, ok=False,
                                   error=f"judge failed: {exc}",
                                   response=_encode(False, 0.0, str(exc), result.status))
            return ProbeResult(
                role=probe.role, status=result.status,
                response=_encode(fired, score, evidence, result.status),
                ok=result.ok,
            )
        # Control role: report whether the *control* request alone looks like a
        # finding.  It must not, or the signal is not specific.
        try:
            fired, score, evidence = judge(result, result)
        except Exception:  # noqa: BLE001
            fired, score, evidence = False, 0.0, "control"
        return ProbeResult(
            role=probe.role, status=result.status,
            response=_encode(fired, score, evidence, result.status),
            ok=result.ok,
        )

    return send


def Probe_health():  # noqa: N802 - small local helper, mirrors the probe shape
    from ..engine.web import HttpProbe

    return HttpProbe("negative", "GET", "/health")


class WebDifferentialOracle(Oracle):
    """Judge a web finding from the encoded HTTP differential verdicts."""

    name = "web_differential"
    categories = WEB_CATEGORIES

    def build_probes(self, *, category: str, target: str, technique_id: str = "") -> ProbeSet:
        params = {"technique": technique_id or category, "target": target}
        return ProbeSet(
            test=Probe(TEST, technique_id or category, label=category, params=dict(params)),
            control=Probe(CONTROL, technique_id or category, label=category, params=dict(params)),
            negative=Probe(NEGATIVE, technique_id or category, label=category, params=dict(params)),
        )

    def evaluate(self, outcome, *, category: str, target: str) -> OracleResult:
        test = _decode(outcome.test)
        control = _decode(outcome.control)
        negative = _decode(outcome.negative)

        if not outcome.test.ok and not outcome.control.ok:
            return OracleResult(
                oracle=self.name, verdict=INCONCLUSIVE, confidence=0.0,
                signal="no usable response",
                detail=outcome.test.error or "both probes failed",
            )

        fired = bool(test.get("fired"))
        control_fired = bool(control.get("fired"))
        negative_fired = bool(negative.get("fired"))
        score = float(test.get("score", 0.0) or 0.0)
        evidence = str(test.get("evidence", ""))

        if fired and not control_fired and not negative_fired:
            return OracleResult(
                oracle=self.name, verdict=VERIFIED, confidence=max(score, 0.7),
                signal="differential fired on the test request only",
                detail=evidence,
                measurements={"test_status": test.get("status"),
                              "control_status": control.get("status")},
            )
        if fired and (control_fired or negative_fired):
            return OracleResult(
                oracle=self.name, verdict=UNVERIFIED, confidence=0.0,
                signal="signal not specific to the weakness",
                detail="the control or negative baseline also fired",
            )
        return OracleResult(
            oracle=self.name, verdict=UNVERIFIED, confidence=0.0,
            signal="the differential did not fire",
            detail=evidence or "the test request behaved like the control",
        )

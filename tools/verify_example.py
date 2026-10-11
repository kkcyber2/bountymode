#!/usr/bin/env python3
"""Worked example: verify findings against a real local target and a simulation.

Runs the generic verification engine twice:

1. against the deliberately-vulnerable local HTTP target in
   ``tools/vulnerable_target.py`` (a real network round-trip), and
2. against the probe-aware simulation used by dry runs,

and prints the verdict, the reproduction rate, the negative-control result and
the submission-readiness gaps for each.

    python tools/verify_example.py
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bountymode.engine.llm import ChatClient  # noqa: E402
from bountymode.evidence.redactor import Redactor  # noqa: E402
from bountymode.evidence.vault import EvidenceVault  # noqa: E402
from bountymode.models import Finding, Severity  # noqa: E402
from bountymode.verify import (  # noqa: E402
    GenericVerifier,
    SimulatedTarget,
    client_sender,
    simulated_sender,
)

BASE_URL = os.environ.get("VERIFY_TARGET_URL", "http://127.0.0.1:9099/v1")


def finding(fid: str, category: str, technique: str, severity: Severity) -> Finding:
    return Finding(
        id=fid,
        title=f"{category.replace('_', ' ').title()} on {BASE_URL}",
        technique_id=technique,
        target=BASE_URL,
        category=category,
        severity=severity,
        affected_asset=BASE_URL,
        description="The target complied with an attacker-controlled instruction.",
        impact=(
            "An attacker can override the assistant's instructions and control its "
            "behaviour for the session, including disclosing protected data."
        ),
        remediation=(
            "Separate trusted instructions from untrusted input, add an input "
            "classifier, and filter the model's output before any downstream use."
        ),
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        cvss_score=9.1,
    )


def report(title: str, f: Finding, rep) -> None:
    print(f"\n=== {title} ===")
    print(f"  finding   : {f.title}")
    print(f"  oracle    : {rep.oracle}")
    print(f"  verdict   : {rep.verdict.upper()}")
    print(f"  reproduced: {rep.successes}/{rep.attempts}  (rate {rep.rate:.0%}, "
          f"confidence {rep.confidence:.2f})")
    print(f"  neg ctrl  : passed={rep.negative_control_passed} "
          f"fired={rep.negative_control_fired}")
    print(f"  requests  : {rep.requests_sent} sent, {rep.requests_reused} reused")
    print(f"  latency   : mean {rep.mean_latency_ms:.0f} ms/attempt")
    print(f"  evidence  : {rep.evidence_captured} attempt(s) captured")
    for reason in rep.reasons:
        print(f"    - {reason}")
    readiness = rep.readiness
    print(f"  ready     : {readiness['ready']}")
    if not readiness["ready"]:
        gaps = readiness["blockers"] + readiness["missing"]
        print(f"    gaps    : {', '.join(gaps)}")


def main() -> int:
    import tempfile

    client = ChatClient(base_url=BASE_URL, api_key="local-test-key",
                        model="local-vulnerable-model", max_attempts=1, timeout=10)
    out_dir = tempfile.mkdtemp(prefix="verify-evidence-")
    vault = EvidenceVault(out_dir, redactor=Redactor())

    live_injection = finding("F-live-inj", "prompt_injection", "prompt_injection", Severity.HIGH)
    rep = GenericVerifier(attempts=3).verify(
        live_injection, client_sender(client), vault=vault
    )
    report(f"LIVE HTTP -- prompt injection against {BASE_URL}", live_injection, rep)

    live_leak = finding("F-live-leak", "system_prompt_leak", "system_prompt_leak", Severity.MEDIUM)
    rep2 = GenericVerifier(attempts=3).verify(live_leak, client_sender(client), vault=vault)
    report("LIVE HTTP -- system-prompt leakage", live_leak, rep2)

    sim_finding = finding("F-sim", "prompt_injection", "prompt_injection", Severity.HIGH)
    rep3 = GenericVerifier(attempts=3).verify(
        sim_finding, simulated_sender(SimulatedTarget(vulnerable=True)), vault=vault
    )
    report("SIMULATED (dry run) -- vulnerable target", sim_finding, rep3)

    hardened = finding("F-hard", "prompt_injection", "prompt_injection", Severity.HIGH)
    rep4 = GenericVerifier(attempts=3).verify(
        hardened, simulated_sender(SimulatedTarget(vulnerable=False)), vault=vault
    )
    report("SIMULATED (dry run) -- hardened target", hardened, rep4)

    print(f"\nEvidence vault: {out_dir}")
    print(f"Chain intact  : {vault.verify_chain()}")
    print(f"Observations  : {len(vault.entries)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

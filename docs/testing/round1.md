# Live hard-testing — Round 1 (tier: `easy`)

**Date:** 2026-10-14
**Target:** `tools/realistic_target.py --tier easy --port 9099` (ACME Assist Platform)
**Scope:** `127.0.0.1:9099` (web), one exclusion
**Mode:** `in-process-web` — real HTTP against the target, real OpenRouter key for the LLM paths
**Command:** `python -m bountymode auto run /tmp/acme-scope.md --approve-by tester -o /tmp/round1b`

## What was tested

The full ten-stage pipeline: intake → import → scope → plan → gate → scan → verify →
amplify → readiness → report. The target plants 12 distinct weaknesses across the
classes a real web program cares about: auth bypass (spoofable `X-Forwarded-For`),
IDOR, SQL injection, path traversal, SSRF, mass assignment, JWT `alg:none`, GraphQL
introspection, business-logic (negative quantity), CSRF, missing rate limiting, and a
deprecated unauthenticated API version.

## What the system found

```
PASS  intake     read text via direct (141 chars)
PASS  import     1 in-scope, 1 exclusions, 3 to verify
PASS  scope      scope digest f1a131c3b037 approved by tester
PASS  plan       1 target(s), families: access_control, injection, logic, client_side
PASS  gate       12 of 12 planned techniques authorized for 127.0.0.1:9099
PASS  scan       12 request(s), 12 finding(s) [in-process-web]
PASS  verify     12 of 12 finding(s) verified (5 attempt(s) each)
PASS  amplify    4 amplification(s) applied across 12 finding(s)
PASS  readiness  12 of 12 finding(s) are submission-ready
PASS  report     12 report file(s) + submission bundle
```

**12 of 12 planted weaknesses found, verified, and submission-ready.** Every finding
was verified by the `web_differential` oracle at 5/5 attempts — i.e. the test request
fired and the control and negative baseline did not.

| Finding | Severity | CVSS | Verified |
|---|---|---|---|
| JWT weakness (`alg:none`) | CRITICAL | 9.0 | 5/5 |
| Auth bypass (`X-Forwarded-For`) | HIGH | 7.9 | 5/5 |
| SQL injection | HIGH | 7.9 | 5/5 |
| Path traversal | HIGH | 7.9 | 5/5 |
| SSRF | HIGH | 7.9 | 5/5 |
| IDOR | HIGH | 7.0 | 5/5 |
| Mass assignment | HIGH | 7.0 | 5/5 |
| API versioning bypass | HIGH | 7.0 | 5/5 |
| Business logic | MEDIUM | 6.5 | 5/5 |
| XSS | MEDIUM | 6.5 | 5/5 |
| CSRF | MEDIUM | 6.5 | 5/5 |
| Rate-limit bypass | MEDIUM | 6.5 | 5/5 |

## What the system MISSED

Nothing, in this round — but only after two bugs were fixed (below). Before the fixes
the system found **zero** of the twelve and still reported every stage PASS.

## What crashed / was wrong

1. **The entire `web_api` domain had no engine.** All 14 web techniques resolved to
   *no engine implementation*; the case runner marked each `unavailable`, skipped it,
   and the scan stage still printed **PASS** with 0 findings. A web target was never
   tested. **Fixed** by adding `bountymode/engine/web.py` (real HTTP, differential
   test/control probes) and routing web domains to it in `autonomous/runner.py`.
2. **`host:port` scope entries were silently dropped.** `127.0.0.1:9099` did not match
   the host regex (which requires a dotted TLD), so the scope imported as empty and the
   run halted at "no testable asset". **Fixed** in `program/extractor.py` with a
   `_HOSTPORT_RE` and IPv4 acceptance in `_is_testable_host`.
3. **`rate_limit_bypass` could not verify.** Its judge fired on any HTTP 200, so the
   control fired too and the differential never held. **Fixed** by making the probe a
   real burst (`HttpProbe.burst`) and the judge require *no* 429 across the burst.
4. **The CLI lied about the run mode.** It printed "This was a DRY RUN. No live target
   was contacted." even though the web engine had just sent real HTTP. **Fixed** with
   `_print_mode_caveat`, which now states the truth per mode.

## What was slow or noisy

- The scan is fast (12 requests, sub-second against loopback). Verification is the
  cost centre: 5 attempts × 3 probes × 12 findings ≈ 180 requests, still ~2 s locally.
- The `amplify` stage produced 4 amplifications, including a 6-step chain to
  `database_access` — useful, but the chain text is truncated in the console summary.

## Honest caveats

- The target is deliberately vulnerable and runs on loopback. This proves the pipeline
  *works*, not that it will find bugs in a hardened production system.
- The LLM paths were exercised live (key validated, `pong` returned), but the web
  findings themselves are HTTP differentials and do not depend on the model.

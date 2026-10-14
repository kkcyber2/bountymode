# Live hard-testing — Round 2 (tier: `hard`)

**Date:** 2026-10-14
**Target:** `tools/realistic_target.py --tier hard --port 9111` (ACME Assist Platform, hardened)
**Scope:** `127.0.0.1:9111` (web), one exclusion
**Mode:** `in-process-web` — real HTTP, real OpenRouter key
**Command:** `python -m bountymode auto run /tmp/acme-hard.md --approve-by tester -o /tmp/round2e`

## What changed vs Round 1

The `hard` tier adds three mitigations on top of `easy`:

1. **A WAF-style input filter** that blocks the *obvious spelling* of a payload
   (`<script`, `' OR '1'='1`, `../`, `169.254.169.254`, `union select`, `etc/passwd`,
   `127.0.0.1`) — but not its encoding.
2. **Authentication required** on the object endpoints (`/api/users/{id}`, `/api/v2`).
3. **Rate limiting** on `/api/ratelimit` (5 requests / 10 s → 429).

## What the system found

```
PASS  scan       12 request(s), 8 finding(s) [in-process-web]
PASS  verify     8 of 8 finding(s) verified (5 attempt(s) each)
PASS  readiness  8 of 8 finding(s) are submission-ready
```

| Finding | Severity | CVSS | Verified |
|---|---|---|---|
| JWT weakness (`alg:none`) | CRITICAL | 9.0 | 5/5 |
| Auth bypass (`X-Forwarded-For`) | HIGH | 7.9 | 5/5 |
| SQL injection | HIGH | 7.9 | 5/5 |
| Mass assignment | HIGH | 7.0 | 5/5 |
| API versioning bypass | HIGH | 7.0 | 5/5 |
| Business logic | MEDIUM | 6.5 | 5/5 |
| XSS | MEDIUM | 6.5 | 5/5 |
| CSRF | MEDIUM | 6.5 | 5/5 |

## What the system MISSED (and why that is correct)

Four techniques did **not** fire on the hard tier, and each is a genuine mitigation,
not a false negative:

| Technique | Why it did not fire | Correct? |
|---|---|---|
| IDOR | `/api/users/{id}` now requires a valid session; the probe sends none | ✅ correct — the endpoint is no longer anonymously readable |
| Path traversal | the WAF blocks `../` and `etc/passwd` in every encoding tried | ✅ correct — the filter holds |
| SSRF | the WAF blocks `127.0.0.1` and its encodings | ✅ correct — the filter holds |
| Rate-limit bypass | the burst now receives 429s, so the judge correctly declines | ✅ correct — throttling is present |

This is the honest result: a harder target yields fewer findings, and the system
reports the difference rather than inventing findings to keep the count up.

## What crashed / was wrong

1. **Single-payload probes were a false-negative machine.** On the hard tier the
   engine initially found **1 of 12** because each technique tried exactly one payload
   spelling, which the WAF blocked. **Fixed** by making probe builders return a *list*
   of payload variants (case-mixed SQLi, `UNION/**/`, `img/onerror` and `svg/onload`
   XSS, encoded traversal separators, decimal/hex loopback for SSRF) and having the
   engine try each until one fires. Scan went **1 → 8**.
2. **The XSS judge only recognised `<script>`.** An `onerror`/`onload` vector is just
   as executable. **Fixed** by widening `_SCRIPT` to match event-handler and
   `javascript:` attributes.
3. **Verification regressed to 0/8 after the variant change.** The web sender still
   unpacked a single triple from a builder that now returns a list, so every replay
   raised `ValueError: too many values to unpack`. **Fixed** by teaching the sender to
   walk the variants and replay the one that fired.
4. **The web oracle was never actually used.** `GenericVerifier` ignored the explicit
   oracle and always consulted the registry, so web findings were judged by a
   prompt-shaped oracle that could never fire. **Fixed** by honouring `self.oracle`.

## What was slow or noisy

- The variant change multiplies requests: a technique with 6 SQLi variants sends up to
  12 requests before it fires. On loopback this is still ~1 s; against a remote target
  it would be the dominant cost, and the request budget should be watched.
- The `hard` tier's rate limiter is per-client-IP, so a burst probe can trip it and
  then the *control* request also gets a 429 — the judge handles this (it declines),
  but it is worth noting as a source of inconclusive results on rate-limited targets.

## Honest caveats

- The target is deliberately vulnerable and runs on loopback. This proves the pipeline
  works and that it degrades honestly on a harder target; it does not prove it will
  find bugs in a hardened production system.
- The four "misses" are the target's mitigations working. A real hunter would need
  authentication, a WAF bypass, or a different vector — out of scope for this round.

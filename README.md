# Bounty Machine

**A domain-agnostic, authorization-first bug-bounty workflow framework.**

Bounty Machine turns offensive security testing into a *submittable* workflow.
It does not re-implement attacks — it orchestrates them behind a hard
authorization gate, captures redacted evidence, scores findings with real
CVSS v3.1, and renders HackerOne / Bugcrowd-shaped reports.

It ships with four domains out of the box — **AI/LLM red-teaming**, **web/API**,
**cloud/infrastructure** and **CI/CD supply chain** — and adding a fifth costs
an *adapter*, not a fork.

The offensive **engine is vendored in this same repository** (`engine/`) and is
driven **in-process**: no second repository, no scan-API server, no network hop
for a local run. It still contains all of the real attack code — 39 techniques
across 25 families, the ~100-vector library, the plugin autodiscovery, the
fail-closed attack tiers and the sandbox runner.

> **Authorized security testing only.** Bounty Machine enforces scope and
> authorization *by design*. It refuses to test anything outside an imported
> program scope, blocks destructive techniques unconditionally, and defaults
> every run to a dry run. See [Legal & authorization](#legal--authorization).

---

## Table of contents

- [What it is](#what-it-is)
- [Install](#install)
- [Quickstart](#quickstart)
- [The engine (vendored, in-process)](#the-engine-vendored-in-process)
- [Models & providers](#models--providers)
- [The web UI](#the-web-ui)
- [Architecture](#architecture)
- [Domains](#domains)
- [Upgrade modules (U1–U13)](#upgrade-modules-u1u13)
- [CLI reference](#cli-reference)
- [Configuration](#configuration)
- [Testing](#testing)
- [Legal & authorization](#legal--authorization)
- [License](#license)

---

## What it is

A bug-bounty submission is a *product*, not a scan result. Triagers reject
reports that are out of scope, unreproducible, missing impact, or that dump
real user data. Bounty Machine exists to make every one of those failure modes
structurally impossible:

| Failure mode | How Bounty Machine prevents it |
|---|---|
| Testing out of scope | Deny-by-default authorization gate; exclusions always win |
| Destructive testing | Destructive techniques blocked unconditionally |
| Side effects without consent | Human-in-the-loop approval required for side-effecting techniques |
| Runaway testing | Stop-condition engine (request / time / error budgets, kill switch) |
| Leaking real data in evidence | Redaction before persist; hash-chained, append-only vault |
| Unreproducible findings | N-of-M replay; unreproducible findings are dropped |
| Weak / wrong severity | Real CVSS v3.1 base score + bounty-specific adjustments |
| Missing impact or remediation | Report validation refuses to emit an incomplete report |
| Duplicate submissions | Fingerprint + category/asset de-duplication registry |

---

## Install

Requires **Python 3.9+**. The core has **zero runtime dependencies**.

```bash
git clone https://github.com/kkcyber2/bountymode
cd bountymode

# core only -- the workflow layer has zero runtime dependencies
pip install -e .

# the engine needs its own deps; add the UI and the test suite too
pip install -e ".[all]"
```

Optional extras:

| Extra | Adds | Needed for |
|---|---|---|
| `yaml` | `PyYAML` | YAML scope / case files |
| `ui` | `fastapi`, `uvicorn` | the local web UI |
| `engine` | `requests`, `httpx`, `pydantic`, `tenacity`, `beautifulsoup4`, `numpy`, `pillow`, … | running the vendored engine in-process |
| `dev` | `pytest`, plus the UI and engine extras | running the tests |
| `all` | everything above | a full checkout |

---

## Quickstart

### 1. Import a program scope

```bash
bountymode scope import examples/policy-example.md --program acme-ai -o acme-scope.json
```

This parses a HackerOne / Bugcrowd / Intigriti / YesWeHack-style policy into a
machine-readable scope: in-scope assets, exclusions, prohibited techniques,
rate limits and request budgets. **Always review the output before testing.**

### 2. Check authorization (dry run)

```bash
bountymode check acme-scope.json api.acme-ai.com
```

Every technique is evaluated against the gate. Out-of-scope targets are denied
here — before anything touches the network.

### 3. Run a case

```bash
# dry run (default) — exercises the gate, vault and scorer, no network I/O
bountymode run examples/case-example.yaml

# in-process -- drives the vendored engine in THIS repository, no extra server
bountymode run examples/case-example.yaml --in-process --offline

# remote -- dispatch to a separate engine over HTTP, still gated
bountymode run examples/case-example.yaml --live \
  --engine https://engine.internal --token "$INTERNAL_SCAN_TOKEN"
```

`--offline` pairs with `--in-process` to model a deliberately vulnerable mock
target, so the whole pipeline (gate → engine → evidence → triage → report) is
exercised with no API key and no network.

### 4. Triage and report

```bash
bountymode triage bounty-run/result.json -o triaged.json
bountymode report triaged.json --platform hackerone --program acme-ai -o reports/
```

You now have a submittable Markdown writeup plus a structured JSON payload per
finding, with redacted evidence attached.

### 5. Explore the domains and the engine

```bash
bountymode domains                          # list registered domains
bountymode techniques --domain web_api      # techniques for one domain
bountymode engine --families                # the vendored engine's live catalogue
bountymode engine --techniques              # every technique the engine exposes
bountymode models                           # effective model configuration
bountymode models --check                   # live reachability probe (needs a key)
```

---

## The engine (vendored, in-process)

The offensive engine lives in `engine/` in **this repository**. It is the real
toolkit — nothing is stubbed — and Bounty Machine drives it **in-process**
through `bountymode/engine/`:

| Bridge module | Role |
|---|---|
| `engine/paths.py` | locates `engine/` and puts it on `sys.path` (override with `BOUNTYMODE_ENGINE_PATH`) |
| `engine/catalogue.py` | reads the engine's **live** `REGISTRY` — no copied catalogue |
| `engine/local.py` | `LocalEngine` — resolves a technique and calls the engine's own registry callable |
| `engine/llm.py` | OpenAI-compatible client (`ChatClient`) + deterministic `OfflineClient` |
| `engine/server.py` | optional local HTTP façade over the same engine |

Three ways to run, all gated identically:

| Mode | Flag | What happens |
|---|---|---|
| Dry run (**default**) | *none* | gate + vault + scorer only; no engine call |
| **In-process** | `--in-process` | the vendored engine runs in this process |
| Remote | `--live --engine URL` | dispatches to a separate engine over HTTP |

`--in-process` also accepts `--offline` (deterministic mock target, no key) and
`--intensity recon\|standard\|aggressive\|greasy` (the engine's fail-closed tiers).

Need the engine as a service (a worker host, or a language boundary)?

```bash
python -m bountymode.engine.server --port 8088
# GET /health · GET /bounty/techniques
# POST /bounty/run-test · POST /v1/chat/completions
```

It binds to loopback and refuses to start without a token unless `--no-auth`
is passed explicitly.

---

## Models & providers

Any OpenAI-compatible endpoint works (OpenRouter, Groq, OpenAI, Together, a
local Ollama or vLLM). The **default is OpenRouter's free tier**, so a red-team
workload runs end to end at no cost.

| Setting | Environment variable | Default |
|---|---|---|
| Model | `BOUNTYMODE_MODEL` | `openrouter/free` |
| API key | `OPENROUTER_API_KEY` (or `BOUNTYMODE_LLM_API_KEY`) | *(unset — offline)* |
| Base URL | `BOUNTYMODE_LLM_BASE_URL` | `https://openrouter.ai/api/v1` |
| Engine tier | `BOUNTYMODE_ENGINE_INTENSITY` | `standard` |
| Engine model | `BOUNTYMODE_ENGINE_MODEL` | *(follows the model)* |
| Engine path | `BOUNTYMODE_ENGINE_PATH` | `./engine` |
| Offline | `BOUNTYMODE_OFFLINE=1` | *(off)* |

**Default model: `openrouter/free`** — OpenRouter's free **auto-router**. It is
the default because it selects among whichever free models are available at the
time, so the configuration keeps working as the free roster rotates; a pinned
free model would break the moment that model is retired.

Named free models are used for the roles where a specific capability matters,
and all are in the fallback list (verified against OpenRouter's live model
list):

| Role | Default | Why |
|---|---|---|
| `generate` | `nvidia/nemotron-3-super-120b-a12b:free` | strong reasoning for payload/test-case generation |
| `judge` | `nvidia/nemotron-3-ultra-550b-a55b:free` | largest free reasoner for response classification |
| `multimodal` | `nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free` | text + image + audio + video input |

**Fallbacks** (tried in order if the primary is unavailable):
`nvidia/nemotron-3-super-120b-a12b:free` → `google/gemma-4-31b-it:free` →
`nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free` →
`nvidia/nemotron-3.5-lightning:free` → `liquid/lfm-2.5-2.6b:free`.

Swap models without editing code:

```bash
export OPENROUTER_API_KEY="sk-or-..."
export BOUNTYMODE_MODEL="nvidia/nemotron-3-super-120b-a12b:free"
bountymode models           # show the effective configuration
bountymode models --check   # live reachability probe against each candidate
```

Or point at another provider entirely:

```bash
export BOUNTYMODE_LLM_BASE_URL="https://api.groq.com/openai/v1"
export BOUNTYMODE_LLM_API_KEY="gsk_..."
export BOUNTYMODE_MODEL="llama-3.3-70b-versatile"
```

A JSON config file (`bountymode.json`, or `$BOUNTYMODE_CONFIG`) provides the
same keys in `llm` / `engine` blocks. **No key is not an error**: the workflow
layer and every offline path keep working, and only live model calls are
disabled.

---

## The web UI

A local, single-operator UI over the *same* library code the CLI uses — every
button calls a real endpoint, there are no mockups and no dead controls.

```bash
python -m bountymode.ui
# or, after `pip install -e ".[ui]"`
bountymode-ui
```

Then open **http://127.0.0.1:8765**.

The UI exposes the full workflow (import scope → check authorization → run →
findings → triage → report → dedupe/retest) plus a panel for every upgrade
module, the model configuration and the engine catalogue. Runs are **dry by
default**; `--in-process` drives the vendored engine locally, and a `--live`
run requires an engine URL. Everything still passes through the gate and the
stop-conditions.

---

## Architecture

```
                    ┌─────────────────────────────────────────────┐
                    │              Domain adapters                 │
                    │  ai_llm · web_api · cloud · cicd · (yours)   │
                    │  ── technique catalogue                      │
                    │  ── dispatch(technique, target) -> result    │
                    │  ── classify / impact / remediation / taxonomy│
                    └──────────────────────┬──────────────────────┘
                                            │
   scope.json ──► ScopeImporter ──► ProgramScope
                                            │
                                            ▼
   ┌──────────────┐   ALLOW    ┌─────────────────────┐
   │ Authorization│───────────►│    CaseRunner      │
   │    Gate      │  DENY /    │  (one technique    │
   │ (deny-by-    │  NEEDS_    │   at a time)       │
   │  default)    │  HUMAN     └─────────┬─────────┘
   └──────────────┘                      │
                                         ▼
   ┌──────────────────┐        ┌──────────────────┐
   │ Stop-Condition   │◄──────►│  Evidence Vault  │
   │ Engine (budgets, │        │  (redact → hash  │
   │  kill switch)    │        │   → chain)       │
   └──────────────────┘        └──────────────────┘
                                         │
                                         ▼
                              ┌────────────────────┐
                              │  Triage Scorer     │  CVSS v3.1 + adjustments
                              │  Dedup Registry    │  fingerprint matching
                              │  Report Generator  │  HackerOne / Bugcrowd
                              └────────────────────┘
```

**The key design decision:** five of the six components operate on *findings*,
not on techniques. Only the test-case runner is domain-specific. That is why a
new domain is an adapter, not a fork.

### Package layout

```
bountymode/
├── models.py            core dataclasses (ProgramScope, Technique, Finding, Observation)
├── errors.py            exception hierarchy
├── cli.py               command-line interface
├── config.py            configuration (models, engine, run defaults)
├── engine/              the in-process bridge to the vendored engine
│   ├── catalogue.py     reads the engine's live REGISTRY
│   ├── llm.py           OpenAI-compatible client + offline client
│   ├── local.py         LocalEngine -- dispatch techniques in-process
│   ├── paths.py         locate + import the engine directory
│   └── server.py        optional local HTTP façade over the engine
├── scope/               importer (policy → scope) + matcher (target → scope)
├── authority/           gate.py (the choke-point) + stop_conditions.py (circuit breakers)
├── evidence/            redactor.py + vault.py (hash-chained, append-only)
├── triage/              cvss.py (real CVSS v3.1) + scorer.py (bounty adjustments)
├── report/              generator.py (HackerOne / Bugcrowd templates + validation)
├── dedupe/              registry.py (de-duplication + regression retest)
├── runner/              adapter.py (engine bridge) + case_runner.py (orchestration)
├── domains/             base.py (DomainAdapter protocol) + 4 built-in adapters
├── upgrades/            U1–U13 quality modules
└── ui/                  FastAPI app + single-page frontend
```

---

## Domains

A domain is a `DomainAdapter` subclass supplying a technique catalogue and the
domain-specific interpretation of a result. Register it and it is immediately
usable from the CLI, the UI and the runner.

| Domain | Techniques | Covers |
|---|---|---|
| `ai_llm` | 19 | prompt injection (direct/indirect), data exfiltration, system-prompt leakage, RAG poisoning, context manipulation, token smuggling, CoT hijacking, invisible injection, jailbreak, emotional manipulation, adversarial robustness, model misuse, tool misuse, API logic, cross-tenant, output handling, mutation, economic denial |
| `web_api` | 14 | IDOR, auth bypass, SSRF, business logic, XSS, SQLi, open redirect, CSRF, path traversal, JWT weakness, mass assignment, GraphQL introspection, rate-limit bypass, API versioning bypass |
| `cloud` | 10 | public storage, IAM privilege escalation, over-permissive roles, metadata SSRF, exposed ports, unencrypted storage, logging disabled, stale keys, cross-account trust, container escape config |
| `cicd` | 10 | dependency confusion, pipeline poisoning, secrets in logs, unpinned actions, artifact poisoning, PR-context injection, self-hosted runner abuse, token over-permission, cache poisoning, missing SBOM |

### Adding a domain

```python
from bountymode.domains import DomainAdapter, register_adapter
from bountymode.models import Technique, Severity

class MobileAdapter(DomainAdapter):
    name = "mobile"
    description = "Android / iOS application testing."
    scope_kind = "mobile"

    def techniques(self):
        return [Technique("insecure_storage", "Insecure local storage",
                          category="insecure_storage", severity_hint="high")]

    def impact(self, category):
        return "An attacker with device access can read sensitive data at rest."

    def remediation(self, category):
        return "Use the platform keystore and encrypt sensitive data at rest."

    def taxonomy(self, category):
        return {"cwe": ["CWE-312"], "owasp_llm": [], "mitre_atlas": []}

    def severity_hint(self, category):
        return Severity.HIGH

register_adapter(MobileAdapter())
```

That is the whole cost of a new domain. Scope enforcement, the gate,
stop-conditions, evidence, triage and reporting are reused unchanged.

---

## Upgrade modules (U1–U13)

Each module is self-contained, dependency-free and offline-testable.

| ID | Module | What it adds |
|---|---|---|
| U1 | `multimodal.py` | Image / audio / PDF injection carriers (visible overlay, low-contrast, EXIF, ID3, invisible PDF text layer, annotations) |
| U2 | `agentic.py` | Assert on the **tool name and arguments** an agent used — not just its prose |
| U3 | `cross_tenant.py` | Two-account differential proof of a cross-tenant / RAG isolation break |
| U4 | `reproducibility.py` | N-of-M replay and reproduction rate |
| U5 | `judge.py` | LLM-as-judge response classification (complied / refused / partial), pluggable |
| U6 | `fuzzing.py` | Coverage-guided mutation fuzzing over prompt payloads |
| U7 | `chaining.py` | Exploit-chain search over a finding graph |
| U8 | `memory_poisoning.py` | Persistent-memory poisoning proof |
| U9 | `supply_chain.py` | Dependency / supply-chain static checks (unpinned, typosquat, prerelease) |
| U10 | `minimisation.py` | Evidence minimisation — keep only the lines that prove the finding |
| U11 | `regression.py` | Regression suites for post-fix retesting |
| U12 | `false_positive.py` | False-positive filtering before a finding reaches the report stage |
| U13 | `crescendo.py` | Multi-turn crescendo escalation detection |

```python
from bountymode.upgrades import CrossTenantProver, PrincipalResponse

proof = CrossTenantProver().prove(
    PrincipalResponse("tenant-a", "...", markers=["ACME-INTERNAL-42"]),
    PrincipalResponse("tenant-b", "here: ACME-INTERNAL-42"),
)
assert proof.leaked
```

---

## CLI reference

```
bountymode scope import <policy> [--program NAME] [-o OUT]   import a policy into a scope JSON
bountymode scope show <scope.json>                           print a scope
bountymode domains                                           list registered domains
bountymode techniques [--domain NAME]                        list the technique catalogue
bountymode check <scope.json> <target> [--technique ID]      dry-run the authorization gate
bountymode run <case.yaml> [--scope S] [--in-process [--offline] [--intensity TIER]]
                              [--live --engine URL --token T] [-o DIR]
bountymode triage <findings.json> [--min-score N] [-o OUT]   score and rank findings
bountymode report <findings.json> [--platform hackerone|bugcrowd] [--program P] [-o DIR]
bountymode retest <finding_id> [--registry R] [--fixed]      record a regression retest
bountymode models [--check]                                  show / probe the model config
bountymode engine [--families] [--techniques]                inspect the vendored engine
```

Exit codes: `0` success · `2` usage error · `3` blocked (nothing authorized).

---

## Configuration

Bounty Machine is config-driven through the **scope file** — the single source
of truth for what is permitted:

```json
{
  "program": "acme-ai",
  "platform": "hackerone",
  "in_scope": [{"pattern": "api.acme-ai.com", "kind": "llm"}],
  "out_of_scope": [{"pattern": "status.acme-ai.com", "reason": "third party"}],
  "prohibited_techniques": ["economic_denial"],
  "rate_limit_rps": 1.0,
  "max_requests": 200,
  "max_duration_s": 1800,
  "requires_test_account": true,
  "safe_harbour": true,
  "disclosure_days": 90
}
```

The scope's numbers are **ceilings**: a caller may tighten them, never raise
them. `economic_denial`, `destructive` and `malware` are merged into
`prohibited_techniques` unconditionally, whatever the policy says.

Engine connection, models and run defaults:

| Setting | Meaning |
|---|---|
| `--in-process` | run the vendored engine in this process (no server, no network hop) |
| `--offline` | with `--in-process`: deterministic mock target, no API key |
| `--intensity` | engine scan tier: `recon` / `standard` / `aggressive` / `greasy` |
| `--engine-model` | override the model the engine uses |
| `--engine URL` | base URL of a remote engine (with `--live`) |
| `--token TOKEN` | internal scan token (never hard-code; pass via env) |

See [Models & providers](#models--providers) for the environment variables.

---

## Testing

```bash
pip install -e ".[dev]"
python -m pytest -q
```

The suite covers the scope matcher, the authorization gate, stop-conditions,
the redactor and vault, the CVSS calculator, the report generator, the case
runner, all four domains, all thirteen upgrade modules, every UI endpoint, and
the in-process engine integration (catalogue, dispatch, configuration).

---

## Legal & authorization

**Bounty Machine is for authorized security testing only.**

- **Scope enforcement is mandatory.** Every test passes through the
  authorization gate. A target that is not covered by an imported program
  scope is denied — there is no override flag.
- **Exclusions always win.** A target that is both listed in scope and
  excluded is treated as out of scope.
- **Destructive techniques are blocked unconditionally.** Denial-of-service,
  rate-limit abuse and malware are refused for every program, regardless of
  what the policy says.
- **Side effects require human approval.** Techniques flagged as
  side-effecting need an audited approval registered with the gate.
- **Evidence is redacted before it is persisted.** Secrets, credentials and
  personal data are replaced with `[REDACTED:*]` markers; the vault is
  append-only and hash-chained.
- **Dry run is the default.** A live run requires an explicit flag and an
  engine URL.
- **Respect safe harbour and disclosure terms.** Only test programs that
  explicitly authorize testing, stay within their published rules, and follow
  their disclosure timeline.

You are responsible for ensuring you have permission to test any target. Using
this tool against systems you do not own or have written authorization to test
may be illegal.

---

## License

MIT — see [LICENSE](LICENSE).

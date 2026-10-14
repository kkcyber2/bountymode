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
- [Prerequisites](#prerequisites)
- [Install](#install)
- [Quickstart](#quickstart)
- [The engine (vendored, in-process)](#the-engine-vendored-in-process)
- [Models & providers](#models--providers)
- [Program onboarding & the guided pipeline](#program-onboarding--the-guided-pipeline)
- [One-input autonomous mode](#one-input-autonomous-mode)
- [The web UI](#the-web-ui)
- [Architecture](#architecture)
- [Domains](#domains)
- [Upgrade modules (U1–U13)](#upgrade-modules-u1u13)
- [CLI reference](#cli-reference)
- [Configuration](#configuration)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [Honest limitations](#honest-limitations)
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

## Prerequisites

| Requirement | Detail |
|---|---|
| **Python** | **3.9 or newer**. CI runs 3.9, 3.10, 3.11 and 3.12; development and the documented runs use 3.11. |
| **pip** | a current `pip`. Run `python -m pip install --upgrade pip` first. |
| **OS** | Linux, macOS, or Windows via **WSL**. The headless-browser fallback and parts of the engine assume a POSIX shell, so native Windows is not supported. |
| **Git** | to clone the repository. |
| **Disk** | roughly 150 MB for the checkout plus the virtualenv. |

**System packages — optional, only for specific features.** None are needed for
the quickstart, the test suite, or an offline (dry) run. The core workflow layer
has **zero runtime dependencies** and runs on the standard library alone.

| Feature | Needs | Debian / Ubuntu | macOS (Homebrew) |
|---|---|---|---|
| Reading a PDF program brief (`auto run brief.pdf`) | a PDF text extractor | `pypdf` ships in the `all` extra and handles most PDFs; `sudo apt install poppler-utils` adds `pdftotext` as a fallback | `brew install poppler` |
| Fetching a JavaScript-rendered program page | a headless browser | `python -m playwright install chromium` (optional path) | same |
| OCR of a scanned (image-only) PDF | `tesseract` | `sudo apt install tesseract-ocr` | `brew install tesseract` |

---

## Install

### One-click setup (recommended)

```bash
# Linux / macOS
./setup.sh

# Windows
setup.bat

# or, on any platform
python run.py
```

It does three things and asks for only two inputs:

1. installs the package and its dependencies into the current interpreter;
2. asks for your **OpenRouter API key** and your **name**, writes them to `.env`
   (which it also adds to `.gitignore`), and validates the key against OpenRouter;
3. launches the web UI at http://127.0.0.1:8765.

Pass `--no-install` to skip the install step or `--no-launch` to stop after
configuration.

### Manual install

```bash
# 1. clone
git clone https://github.com/kkcyber2/bountymode
cd bountymode

# 2. create and activate a virtualenv
python -m venv .venv
source .venv/bin/activate          # Windows/WSL: .venv\Scripts\activate

# 3. install a full checkout -- engine, UI and tests
python -m pip install --upgrade pip
pip install -e ".[all]"

# 4. verify the install
bountymode --help                  # the CLI responds
bountymode models                  # prints the effective model configuration
python -m pytest -q                # expected: 364 passed
```

**Install only what you need.** Each extra is additive, and `pip install -e .`
alone installs the dependency-free workflow layer:

| Extra | Command | Adds | Needed for |
|---|---|---|---|
| `yaml` | `pip install -e ".[yaml]"` | `PyYAML` | YAML scope / case files |
| `ui` | `pip install -e ".[ui]"` | `fastapi`, `uvicorn` | the local web UI |
| `engine` | `pip install -e ".[engine]"` | `requests`, `httpx`, `pydantic`, `tenacity`, `beautifulsoup4`, `numpy`, `pillow`, … | running the vendored engine in-process |
| `dev` | `pip install -e ".[dev]"` | `pytest`, plus the UI and engine extras | running the tests |
| `all` | `pip install -e ".[all]"` | everything above | a full checkout |

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
| Model | `BOUNTYMODE_MODEL` | `nvidia/nemotron-3-super-120b-a12b:free` |
| API key | `OPENROUTER_API_KEY` (or `BOUNTYMODE_LLM_API_KEY`) | *(unset — offline)* |
| Base URL | `BOUNTYMODE_LLM_BASE_URL` | `https://openrouter.ai/api/v1` |
| Engine tier | `BOUNTYMODE_ENGINE_INTENSITY` | `standard` |
| Engine model | `BOUNTYMODE_ENGINE_MODEL` | *(follows the model)* |
| Engine path | `BOUNTYMODE_ENGINE_PATH` | `./engine` |
| Offline | `BOUNTYMODE_OFFLINE=1` | *(off)* |

**Default model: `nvidia/nemotron-3-super-120b-a12b:free`** — a named free model
that was verified to return usable text on the free tier.

> **Why not `openrouter/free`?** The auto-router is *not* the default. It can
> route to a reasoning model that spends the entire token budget on hidden
> reasoning and returns `content: null` — a 200 response with no usable text.
> That silently breaks payload generation and judging. It remains available as
> an explicit opt-in (`BOUNTYMODE_MODEL=openrouter/free`), and `models --check`
> now treats an empty completion as a **failed** probe so it falls through to
> the next candidate instead of declaring a dead route healthy.

Named free models are used for the roles where a specific capability matters,
and all are in the fallback list (verified against OpenRouter's live model
list):

| Role | Default | Why |
|---|---|---|
| `generate` | `nvidia/nemotron-3-super-120b-a12b:free` | strong reasoning for payload/test-case generation |
| `judge` | `nvidia/nemotron-3-ultra-550b-a55b:free` | largest free reasoner for response classification |
| `multimodal` | `nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free` | text + image + audio + video input |

**Fallbacks** (tried in order if the primary is unavailable):
`nvidia/nemotron-3-super-120b-a12b:free` → `nvidia/nemotron-3.5-lightning:free` →
`nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free`.

The fallback chain is *live*, not decorative: `ChatClient.chat()` tries the
requested model first and, if it errors **or returns no usable text**, walks the
list until one answers. A `200` whose `content` is empty counts as a failure —
free reasoning routes can spend the whole token budget on hidden reasoning and
return `content: null`, which is useless for payload generation and judging.

The roster is measured, not assumed. Probed against the live endpoint on
2026-10-10 (3 calls each):

| Model | Result | Median latency |
|---|---|---|
| `nvidia/nemotron-3-super-120b-a12b:free` | 3/3 ok | ~0.68 s |
| `nvidia/nemotron-3.5-lightning:free` | 3/3 ok | ~0.62 s |
| `nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free` | 1/3 ok | ~1.6 s |

Two models that used to be listed were dropped because they failed every probe:
`liquid/lfm-2.5-2.6b:free` returned empty content (0/3) and
`google/gemma-4-31b-it:free` returned `HTTP 429` (0/3). Re-add a model only after
a fresh `bountymode models --check` shows it working.

> Free-tier availability is shared and can be rate-limited upstream
> (`HTTP 429` / `502 ResourceExhausted`). `models --check` probes each candidate
> in isolation (no fallback) and reports the real error per candidate, so it
> picks the first one that actually answers.

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

## Program onboarding & the guided pipeline

A real engagement does not begin with a hand-written YAML file; it begins with a
program page. Two commands close that gap.

### Onboard a real program page

```bash
bountymode program import https://bugcrowd.com/engagements/some-program
#   or paste the scope text when the page is behind a login:
bountymode program import --file policy.md --program some-program
```

This fetches the page (statically, then with a headless browser if the content
is JavaScript-rendered), extracts the in-scope targets, exclusions, policy
prohibitions, reward table and rate limits, and prints a confirmation view.
Two properties are non-negotiable, because getting them wrong means testing
someone else's infrastructure:

- **The extractor never invents scope.** Only an unambiguous scope-table row
  becomes a testable target. A bare hostname mentioned in a sentence is not
  scope, and a third-party *marketplace listing* (a `marketplace.atlassian.com`
  app page, a `github.com` repository, an app-store URL) is recorded and
  excluded — never turned into a target, because testing the marketplace
  operator is not what the program authorized.
- **Ambiguity is surfaced, not resolved.** Anything the extractor is not certain
  about lands in a `VERIFY` list for a human to confirm, and the confidence
  grade says how much of the page was understood.

The command writes three files: `scope.json` (the machine-enforced scope),
`program-profile.json` (the extraction audit trail) and `authorization.json`
(a **pending** receipt). Nothing is authorized until a human re-runs with
`--approve-by <name>`, or uses `bountymode program confirm <scope.json>`.

### One command, seven stages

```bash
bountymode pipeline run --file policy.md --program acme \
    --approve-by "your name" --domain ai_llm
```

`pipeline run` chains the whole engagement in one shot:

| Stage | What it does |
|---|---|
| `import` | Fetch/parse the page, or load a previously confirmed `scope.json` |
| `scope` | Write the scope digest the approval is bound to |
| `gate` | Deny-by-default authorization for every technique against every target |
| `scan` | Drive the vendored engine in-process (or a remote engine with `--live`) |
| `verify` | Replay each finding N-of-M times and report a reproduction rate |
| `readiness` | Check each finding against the submission checklist |
| `report` | Write HackerOne/Bugcrowd-format reports plus redacted evidence |

The run is a **dry run by default** and never contacts a live target unless
`--live` is passed together with `--engine`. Every stage still passes through
the authorization gate and the stop-conditions.

The approval is bound to a digest of the scope: if anyone edits `scope.json`
after approval, the receipt no longer matches and the gate refuses the run.

```bash
# re-import once, then run repeatedly against the frozen scope
bountymode program import --file policy.md -o engagement --approve-by "your name"
bountymode pipeline run --file engagement/scope.json --approve-by "your name"
```

### Re-scan on an interval

```bash
bountymode program watch --file engagement/scope.json --interval 86400 --runs 7
```

Each pass is stored under its own `run-NNN/` directory and a `watch-state.json`
records what changed (new findings, disappeared findings, digest movement), so a
program that quietly adds an asset overnight shows up as a scope change rather
than going unnoticed.

---

## One-input autonomous mode

Hand the system **one document** — a program's PDF brief, a pasted policy, an
exported HTML page — and it does the rest.

```bash
bountymode auto run program-brief.pdf --approve-by "your name"
#   or paste the details instead of pointing at a file:
bountymode auto run --help
```

The run chains ten stages, and every one of them is the same code the CLI and
UI already use, so the safety properties are inherited rather than
re-implemented:

```
intake -> import -> scope -> plan -> gate -> scan -> verify -> amplify -> readiness -> report
```

| Stage | What happens |
|---|---|
| **intake** | Reads the document. PDF (text layer via pypdf / `pdftotext`), `.txt`, `.md`, `.html`, `.json`. A scanned PDF with no text layer is reported honestly, with the exact fix (run OCR, or paste the text). |
| **import** | Extracts in-scope assets, exclusions, policy prohibitions, the reward table and rate limits. Never invents scope: only scope-table rows become targets, marketplace listings are recorded and excluded, and anything ambiguous lands in a `VERIFY` list. |
| **scope** | Writes `scope.json` + an authorization receipt bound to a **scope digest**, so editing the scope invalidates the approval. A human approver is required. |
| **plan** | The agentic planner classifies each asset (LLM / API / web / mobile / repo / cloud), scores it, and selects technique families — with a written rationale and a chain hypothesis. |
| **gate** | Deny-by-default authorization for every technique. Exclusions always win; destructive techniques are never planned. |
| **scan** | Runs the authorized techniques in-process (dry run by default). |
| **verify** | Replays each finding N-of-M with a class-appropriate oracle, a control and a **negative control**, and returns verified / unverified / inconclusive. |
| **amplify** | Pursues the chain that raises severity: data-exposure classification, privilege-escalation proof, and multi-step chains. Sets a severity *floor* so the label and the CVSS score cannot disagree. |
| **readiness** | Per finding: reproducible? in-scope? evidence attached? CVSS justified? impact stated? Names exactly what is missing. |
| **report** | HackerOne/Bugcrowd-shaped report per finding plus a top-level `submission-bundle.json` with a ready / not-ready verdict. |

### Worked example

```bash
python tools/auto_example.py
```

writes `examples/acme-ai-program.pdf`, runs the whole job over that single file,
and prints the result. Real output:

```
  PASS  intake     read pdf via pypdf (1032 chars, 1 pages)
  PASS  import     3 in-scope, 4 exclusions, 4 to verify
  PASS  scope      scope digest 1847a8918f68 approved by example-operator
  PASS  plan       3 target(s), families: access_control, injection, data_exposure, logic, client_side
  PASS  gate       12 of 12 planned techniques authorized for chat.acme-ai.example
  PASS  scan       12 request(s), 3 finding(s) [in-process-dry-run]
  PASS  verify     3 of 3 finding(s) verified (5 attempt(s) each)
  PASS  amplify    1 amplification(s) applied across 3 finding(s)
  PASS  readiness  3 of 3 finding(s) are submission-ready
  PASS  report     3 report file(s) + submission bundle (submission-bundle.json)

findings: 3  verified: 3  submission-ready: 3
  [READY] critical     CVSS 9.1  Prompt Injection on chat.acme-ai.example
  [READY] critical     CVSS 9.1  Rag Poisoning on chat.acme-ai.example
  [READY] critical     CVSS 9.1  Invisible Command Injection on chat.acme-ai.example
```

### In the web UI

The **One input (autonomous)** tab is the same flow, point-and-click: drop in a
file (or paste the details) → **Read & plan** (no testing) → review the parsed
scope, the exclusions and the `VERIFY` list → tick the authorization box → **Run
the whole job**. The result shows the stages, the findings with their
verification verdicts, the amplifications, and what is missing when a finding is
not submission-ready.

### Honest limits

- **A dry run's verdict is simulated.** With no live target, verification runs
  against the in-process simulated target, which is vulnerable to everything, so
  it reports VERIFIED 5/5. The CLI prints `This was a DRY RUN` to mark it. Only a
  live run's verdict is a real measurement.
- **"verified" means reproducible and evidenced — not confirmed.** Final
  confirmation is the bounty program's call, and the output says so.
- **The planner tests the primary asset.** A plan may span several assets; the
  runner tests the highest-priority one and records the rest, so a run stays
  bounded and auditable.
- **Nothing is ever submitted.** The bundle is written to disk; a human submits.

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

The **Chat (streaming)** tab is the front door: paste the bounty details, press
*Start*, and the agent streams every stage, each finding as it lands, and the
final report over Server-Sent Events. A **mid-run instruction** typed while the
run is in flight is queued and applied at the next stage boundary — no restart
needed. It is a dry run unless you tick *live*, and a human approver name is
required before anything is tested.

The **Guided run** tab is the whole engagement in one screen: paste a program
URL (or the scope text), press *Parse & review scope* to see exactly what was
extracted and what needs verifying, tick the confirmation box, and press *Run*.
The result panel shows every stage, what the gate skipped and why, each finding
with its CVSS score and a READY / NOT READY badge, and the exact checks a
NOT READY finding is missing.

The UI also exposes the step-by-step workflow, plus a panel per module. Its
tabs and controls:

| Control | Does |
|---|---|
| **Guided run** (tab) | paste a program URL or scope text → *Parse & review scope* → confirm → *Run*; the whole seven-stage pipeline |
| **One input (autonomous)** (tab) | one document in → *Read & plan* (no testing) → confirm → *Run the whole job* |
| **Import scope** | import a policy file or URL into a `scope.json` |
| **Check** | dry-run the authorization gate against a target |
| **Run case** | run one case — dry by default, or in-process / live |
| **Refresh findings** | list the findings from the last run |
| **Generate reports** | render HackerOne / Bugcrowd reports |
| **Record retest** | record a regression retest against the dedupe registry |
| Module panels | **Judge** (LLM-as-judge), **Prove** (cross-tenant), **Audit** (tool use), **Scan** (supply chain), **Fuzz**, **Plan** (chains), **Run** (crescendo), **Minimise**, **Run suite** (regression), **Build carriers** (multimodal), **Replay** (reproducibility) |
| **Model configuration** / **Engine catalogue** | inspect the models and the technique catalogue |

Runs are **dry by default**; *in-process* drives the vendored engine locally, and
a *live* run requires an engine URL. Everything still passes through the gate and
the stop-conditions.

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
   ┌─────────────────┐        ┌──────────────────┐
   │ Stop-Condition   │◄──────►│  Evidence Vault  │
   │ Engine (budgets, │        │  (redact → hash  │
   │  kill switch)    │        │   → chain)       │
   └─────────────────┘        └──────────────────┘
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
├── program/            program onboarding: fetch → extract → import → pipeline → watch
├── verify/              generic verification: oracles, N-of-M replay, readiness checks
├── autonomous/          one-input mode: intake, planner, amplifier, runner
├── upgrades/            U1–U13 quality modules
└── ui/                  FastAPI app + single-page frontend
```

| Path | What lives there |
|---|---|
| `bountymode/` | the workflow layer — CLI, gate, evidence, triage, report, verification, UI |
| `engine/` | the vendored offensive engine (its real source; driven in-process). `engine/tests/` is the engine's own suite |
| `tests/` | the project's test suite — the one `pytest` collects |
| `tools/` | runnable helpers: `auto_example.py` (the one-input worked example), `verify_example.py` (live verification against a local mock), `vulnerable_target.py` (a deliberately vulnerable local target on port 9099) |
| `examples/` | sample policies, scopes, findings and the offline demo |
| `.github/workflows/` | CI (`ci.yml`) and the one-shot engine vendor (`bootstrap.yml`) |

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
bountymode program import <url>|--file F [--text T] [--approve-by N [--yes]] [-o DIR]
                              onboard a program page into a scope file
bountymode program show <url>|--profile P                          print a parsed profile
bountymode program confirm <scope.json> --approve-by NAME          authorize an existing scope
bountymode program watch <url>|--file F --interval S [--runs N]     re-scan and diff on an interval
bountymode pipeline run <url>|--file F --approve-by NAME [--domain D] [--live --engine URL] [-o DIR]
                              one command: import -> scope -> gate -> scan -> verify -> report
bountymode auto run <document> --approve-by NAME [--target T] [--no-adapt] [--live --engine URL] [-o DIR]
                              ONE INPUT: a program document (PDF/text/HTML/JSON) in,
                              a submission bundle out -- intake -> import -> scope -> plan ->
                              gate -> scan -> verify -> amplify -> readiness -> report
bountymode auto plan <document>                              show the plan without running it
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

### Every environment variable

Precedence is **CLI flag → environment variable → config file → built-in
default**. Set these in your shell, or in an untracked `.env`; `.env`, `*.key`
and `*.pem` are in `.gitignore`.

| Variable | Required? | What it does | Default |
|---|---|---|---|
| `BOUNTYMODE_LLM_API_KEY` | optional | model key; checked **first** | *(unset)* |
| `OPENROUTER_API_KEY` | optional | OpenRouter key — enables the free default model | *(unset — offline)* |
| `GROQ_API_KEY` | optional | Groq key (also selects the Groq base URL and model) | *(unset)* |
| `OPENAI_API_KEY` | optional | OpenAI key (also selects the OpenAI base URL and model) | *(unset)* |
| `ANTHROPIC_API_KEY` | optional | read by the vendored engine's config | *(unset)* |
| `GEMINI_API_KEY` | optional | read by the vendored engine's config | *(unset)* |
| `BOUNTYMODE_MODEL` | optional | preferred model id | `nvidia/nemotron-3-super-120b-a12b:free` |
| `BOUNTYMODE_LLM_MODEL` | optional | alias for the model id | *(unset)* |
| `BOUNTYMODE_LLM_BASE_URL` | optional | OpenAI-compatible base URL | provider-dependent |
| `BOUNTYMODE_ENGINE_MODEL` | optional | model the engine uses | follows the model |
| `BOUNTYMODE_ENGINE_INTENSITY` | optional | engine tier: `recon` / `standard` / `aggressive` / `greasy` | `standard` |
| `BOUNTYMODE_ENGINE_PATH` | optional | where `engine/` lives | `./engine` |
| `BOUNTYMODE_ENGINE_TOKEN` | optional | bearer token for the local engine HTTP facade | *(unset — the facade refuses to start)* |
| `BOUNTYMODE_OFFLINE` | optional | `1` forces offline mode globally | *(off)* |
| `BOUNTYMODE_CONFIG` | optional | path to a JSON config file | `./bountymode.json` |
| `INTERNAL_SCAN_TOKEN` | optional | token for a **remote** engine (`--live --engine URL`) | *(unset)* |
| `LOG_LEVEL` | optional | engine log level | `INFO` |
| `VERIFY_TARGET_URL` | optional | target used by `tools/verify_example.py` | *(unset)* |

No variable is *required*: with none set, every offline path works and only live
model calls are disabled.

**Engine-internal variables** — set only when driving the vendored engine's own
HTTP facade or its swarm path. Not needed for a normal run:
`AGATHON_SWARM`, `AGATHON_MAX_BRAIN_TURNS`, `AGATHON_MAX_BRAIN_TURNS_FREE`,
`AGATHON_MAX_NO_TOOL_NUDGES`, `AGATHON_RATE_LIMIT_BREAKER`, `AGATHON_LOG_LEVEL`,
`AGATHON_INTERNAL_SECRET`, `AGATHON_WEBHOOK_SECRET`,
`AGATHON_WEBHOOK_CALLBACK_URL`, `AGATHON_DOCKER_IMAGE`,
`AGATHON_GREASY_AUTOAPPROVE`, `GROQ_BRAIN_MODEL`, `OPENROUTER_BRAIN_MODEL`,
`REDTEAM_MAX_TOKENS`, `MAX_SOLDIER_TOKENS`, `FORGEGUARD_BLOCK_ON_SECRET`,
`FORGEGUARD_LOG_PAYLOADS`, `FORGEGUARD_ENGAGEMENT_TOKEN`,
`FORGEGUARD_ORG_SECRET`, `CONTEXT_HMAC_KEY`, `TARGET_URL`, `SUPABASE_URL`,
`SUPABASE_SERVICE_ROLE_KEY`.

> **Never commit a key.** Pass secrets through the environment. The tree is
> scanned; the only `sk-` / `ghp_` strings in it are the tool's *own detection
> patterns* and obvious `EXAMPLE` / `SIMULATED` fixtures.

See [Models & providers](#models--providers) for the model-specific detail.

---

## Testing

```bash
pip install -e ".[dev]"        # or ".[all]" to include the engine extras
python -m pytest -q            # expected: 364 passed
```

The suite covers the scope matcher, the authorization gate, stop-conditions, the
redactor and vault, the CVSS calculator, the report generator, the case runner,
all four domains, all thirteen upgrade modules, every UI endpoint, the program
importer (including the property that it never invents scope), the generic
verification engine (oracle selection, the negative control, N-of-M counting),
submission readiness, the guided pipeline end to end, and the in-process engine
integration (catalogue, dispatch, configuration).

Some of those suites exist because a full pipeline run surfaced real defects the
unit tests had not:

- `tests/test_engine_integration.py` asserts that *every* registered engine
  technique is callable — a tester whose second parameter is an attack payload
  rather than an intensity level was being called with the wrong argument and
  raising `TypeError`.
- The pipeline suite asserts that an unimplemented technique is *skipped* rather
  than counted as an error, since the error breaker would otherwise abort the
  scan after three of them.
- `tests/test_consolidation.py` asserts that the verification engine and the
  readiness checker exist in **one** place, so the duplicate implementation that
  used to live under `bountymode/program/` cannot come back.

> **Two test suites, not one.** `pytest` is configured with
> `testpaths = ["tests"]`, so the engine's own suite under `engine/tests/` is
> **not** collected by a bare `python -m pytest` in the repository root. It needs
> the engine on `sys.path`; run it with `cd engine && python -m pytest tests -q`.
> A green root run therefore does not by itself cover the engine's own tests.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError: No module named 'fastapi'` when starting the UI | the `ui` extra is not installed | `pip install -e ".[ui]"` |
| `No module named 'bountymode'` | not installed, or the venv is not active | activate the venv, then `pip install -e .` |
| `pdftotext: command not found` while reading a PDF | no system PDF extractor | `pip install -e ".[all]"` (brings `pypdf`), or `sudo apt install poppler-utils` |
| A PDF reports "no text layer" | it is images rather than text | run OCR (`tesseract`), or paste the text with `program import --text` |
| `models --check` → `HTTP 401` | the key is missing, a placeholder, or wrong | export a real key, or work offline (no key is not an error) |
| `models --check` → `HTTP 429` / `502` | free-tier rate limit upstream | wait and retry, or point elsewhere with `BOUNTYMODE_LLM_BASE_URL` |
| The gate denies every technique | the target is out of scope | re-check the scope; exclusions always win and there is no override flag |
| "authorization receipt is pending" / digest mismatch | the scope was edited after approval, or never approved | re-approve with `--approve-by` |
| `git push` rejected | no push access to this repository | fork it, or push to your own remote |
| Tests fail on a fresh clone | a dependency belongs to an extra you did not install | `pip install -e ".[all]"` before `pytest` |

---

## Honest limitations

Stated plainly rather than buried:

- **A dry run's verification verdict is simulated.** With no live target,
  verification runs against the in-process simulated target, which is vulnerable
  to everything, so it reports VERIFIED. Only a *live* run's verdict is a real
  measurement.
- **"Verified" means reproducible and evidenced — not confirmed.** Final
  confirmation of a real vulnerability is the bounty program's job. The tool's
  job is to prove reproducibility and impact with evidence, and to say so when it
  cannot.
- **Not every step is fully autonomous, by design.** A human supplies the
  approver's name, a human confirms the parsed scope, and nothing is ever
  submitted to a platform. A plan may name several assets; one run tests the
  highest-priority one and records the rest.
- **Oracle coverage is per class.** A class with no dedicated oracle falls back
  to a generic differential check, which is deliberately weak and returns
  INCONCLUSIVE when its baselines disagree.
- **The engine's own test suite is outside the default `pytest` run**
  (`engine/tests/`, see [Testing](#testing)).
- **No API key is not an error.** Every offline path keeps working; only live
  model calls are disabled.

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

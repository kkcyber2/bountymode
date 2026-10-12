"""Bounty Mode command-line interface.

A single, discoverable entry point.  Everything an operator needs to go from a
program policy to a submittable report:

    bountymode scope import policy.md --program acme -o scope.json
    bountymode techniques
    bountymode check scope.json api.acme.com --technique prompt_injection
    bountymode run case.yaml                 # dry run (no engine calls)
    bountymode run case.yaml --live --engine https://engine --token $TOKEN
    bountymode triage findings.json -o triaged.json
    bountymode report triaged.json --platform hackerone -o out/

Safety default: ``run`` performs a **dry run** unless ``--live`` is passed.
A dry run exercises the gate, the vault and the scorer without contacting a
target, which is the right way to validate a case file before arming it.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from .authority.gate import Approval, AuthorizationGate
from .authority.stop_conditions import StopConditionEngine, StopConditions
from .config import load_config
from .dedupe.registry import DedupRegistry
from .engine import build_local_dispatch, default_catalogue, engine_available
from .evidence.redactor import Redactor
from .evidence.vault import EvidenceVault
from .models import Finding, ProgramScope, Technique
from .report.generator import ReportGenerator
from .runner.adapter import AgathonAdapter, EngineResult, TechniqueRegistry
from .runner.case_runner import CaseRunner
from .scope.importer import ScopeImporter
from .triage.scorer import TriageScorer

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_BLOCKED = 3

#: Em dash, kept as a constant rather than written inline inside an f-string
#: expression: a backslash is illegal in an f-string expression part before
#: Python 3.12, and the file stays pure ASCII this way.
DASH = "\u2014"


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _load_yaml_or_json(path: str) -> Dict[str, Any]:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if p.suffix.lower() == ".json":
        return json.loads(text)
    try:
        import yaml  # type: ignore
    except ImportError as exc:  # pragma: no cover
        raise SystemExit(
            "PyYAML is required for YAML case files. Install it or use JSON."
        ) from exc
    return yaml.safe_load(text)


def _print(obj: Any) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True, default=str))


def _load_scope(path: str) -> ProgramScope:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return ProgramScope.from_dict(data)


def _load_findings(path: str) -> List[Finding]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict) and "findings" in data:
        data = data["findings"]
    return [Finding.from_dict(f) for f in data]


def _technique_from_dict(raw: Any) -> Technique:
    if isinstance(raw, str):
        return TechniqueRegistry().require(raw)
    if isinstance(raw, dict):
        return Technique.from_dict(raw)
    raise ValueError(f"bad technique entry: {raw!r}")


class _AdapterRegistry:
    """Expose a DomainAdapter through the runner's TechniqueRegistry API."""

    def __init__(self, adapter: Any) -> None:
        self._adapter = adapter

    def require(self, technique_id: str) -> Technique:
        return self._adapter.require(technique_id)

    def get(self, technique_id: str) -> Optional[Technique]:
        return self._adapter.technique(technique_id)

    def all(self) -> List[Technique]:
        return self._adapter.techniques()


# --------------------------------------------------------------------------- #
# command implementations
# --------------------------------------------------------------------------- #

def cmd_scope_import(args: argparse.Namespace) -> int:
    importer = ScopeImporter()
    scope = importer.import_file(args.policy, program=args.program)
    out = args.output or f"{scope.program}-scope.json"
    importer.export(scope, out)
    print(f"Imported program '{scope.program}' ({scope.platform}).")
    print(f"  in-scope assets : {len(scope.in_scope)}")
    print(f"  exclusions      : {len(scope.out_of_scope)}")
    print(f"  prohibited      : {', '.join(scope.prohibited_techniques) or DASH}")
    print(f"  rate limit      : {scope.rate_limit_rps:.3f} req/s, max {scope.max_requests} requests")
    print(f"  wrote           : {out}")
    if importer.warnings:
        print("\nWarnings:")
        for w in importer.warnings:
            print(f"  ! {w}")
    print("\nReview this file before running any test.")
    return EXIT_OK


def cmd_scope_show(args: argparse.Namespace) -> int:
    scope = _load_scope(args.scope)
    _print(scope.to_dict())
    return EXIT_OK


def cmd_domains(args: argparse.Namespace) -> int:
    from .domains import DEFAULT_REGISTRY

    _print({"domains": DEFAULT_REGISTRY.describe()})
    return EXIT_OK


def cmd_models(args: argparse.Namespace) -> int:
    """Show the effective model configuration and, optionally, probe it."""
    cfg = load_config(path=args.config)
    info = {
        "source": cfg.source,
        "llm": cfg.llm.to_dict(redact=True),
        "roles": {role: cfg.role_model(role) for role in ("generate", "judge", "multimodal")},
    }
    if not args.check:
        _print(info)
        if not cfg.llm.configured:
            print(
                "\nNo API key set. Export OPENROUTER_API_KEY (or BOUNTYMODE_LLM_API_KEY) "
                "to enable live calls; everything else works offline.",
                file=sys.stderr,
            )
        return EXIT_OK

    from .engine.llm import ChatClient

    if not cfg.llm.configured:
        info["check"] = {"attempted": False, "reason": "no API key configured"}
        _print(info)
        return EXIT_OK

    candidates = [cfg.llm.model] + [m for m in cfg.llm.fallbacks if m != cfg.llm.model]
    results = []
    for model in candidates:
        client = ChatClient(
            model=model, api_key=cfg.llm.api_key, base_url=cfg.llm.base_url, timeout=30.0
        )
        probe = client.reachable()
        results.append(
            {
                "model": model,
                "ok": probe.ok,
                "latency_text": (probe.text or "").strip()[:40],
                "error": probe.error,
            }
        )
        if probe.ok:
            break
    info["check"] = {"attempted": True, "results": results,
                     "working": next((r["model"] for r in results if r["ok"]), None)}
    _print(info)
    return EXIT_OK


def cmd_engine(args: argparse.Namespace) -> int:
    """Inspect the vendored engine: availability, catalogue and roles."""
    cfg = load_config(path=args.config)
    cat = default_catalogue()
    info = {
        "engine_available": engine_available(),
        "engine_dir": __import__("bountymode.engine.paths", fromlist=["engine_root"]).engine_root(),
        "catalogue": cat.stats(),
        "intensity": cfg.engine.intensity,
        "offline": cfg.engine.offline,
    }
    if args.families:
        info["families"] = cat.families()
    if args.techniques:
        info["levels"] = cat.levels()
        info["techniques"] = cat.describe()
    _print(info)
    if not info["engine_available"]:
        print(
            "\nThe engine directory was not found. Set BOUNTYMODE_ENGINE_PATH or run "
            "from the repository root.",
            file=sys.stderr,
        )
        return EXIT_BLOCKED
    return EXIT_OK


def cmd_techniques(args: argparse.Namespace) -> int:
    domain = getattr(args, "domain", None)
    if domain:
        from .domains import DEFAULT_REGISTRY

        adapter = DEFAULT_REGISTRY.get(domain)
        rows = [
            {
                "id": t.id, "category": t.category, "severity_hint": t.severity_hint,
                "destructive": t.destructive, "side_effects": t.side_effects,
                "engine_key": t.engine_key,
            }
            for t in adapter.techniques()
        ]
        _print({"domain": domain, "count": len(rows), "techniques": rows})
        return EXIT_OK

    reg = TechniqueRegistry()
    rows = []
    for t in reg.all():
        rows.append(
            {
                "id": t.id,
                "category": t.category,
                "severity_hint": t.severity_hint,
                "destructive": t.destructive,
                "side_effects": t.side_effects,
                "engine_key": t.engine_key,
            }
        )
    _print({"count": len(rows), "techniques": rows})
    return EXIT_OK


def cmd_check(args: argparse.Namespace) -> int:
    scope = _load_scope(args.scope)
    gate = AuthorizationGate(scope)
    reg = TechniqueRegistry()
    techniques = [_technique_from_dict(t) for t in args.technique] if args.technique else reg.all()
    results = []
    for t in techniques:
        d = gate.authorize(args.target, t)
        results.append(
            {"technique": t.id, "verdict": d.verdict.value, "reason": d.reason,
             "matched_scope": d.matched_scope}
        )
    _print({"target": args.target, "summary": gate.summary(), "decisions": results})
    return EXIT_OK if any(r["verdict"] == "allow" for r in results) else EXIT_BLOCKED


def cmd_run(args: argparse.Namespace) -> int:
    case = _load_yaml_or_json(args.case)
    scope_path = args.scope or case.get("scope")
    if not scope_path:
        print("error: no scope. Pass --scope or set 'scope' in the case file.", file=sys.stderr)
        return EXIT_USAGE
    scope = _load_scope(scope_path)

    target = case.get("target")
    if not target:
        print("error: case file must set 'target'.", file=sys.stderr)
        return EXIT_USAGE

    technique_ids = case.get("techniques") or []
    if not technique_ids:
        print("error: case file must list 'techniques'.", file=sys.stderr)
        return EXIT_USAGE

    out_dir = Path(args.output or case.get("output_dir", "bounty-run"))
    out_dir.mkdir(parents=True, exist_ok=True)

    gate = AuthorizationGate(scope)
    for appr in case.get("approvals", []) or []:
        gate.register_approval(
            Approval(
                target=appr.get("target", target),
                technique_id=appr["technique"],
                approved_by=appr.get("approved_by", "unknown"),
                approved_at=appr.get("approved_at", ""),
                note=appr.get("note", ""),
            )
        )

    stops = StopConditionEngine(StopConditions.from_scope(scope))
    vault = EvidenceVault(str(out_dir / "evidence"), redactor=Redactor())
    dedup = DedupRegistry(str(out_dir / "registry.json"))

    dispatch = None
    live = bool(args.live)
    in_process = bool(getattr(args, "in_process", False))
    if live and in_process:
        print("error: --live and --in-process are mutually exclusive.", file=sys.stderr)
        return EXIT_USAGE

    # Resolve the domain adapter: the case file may pin one, else --domain,
    # else the native AI/LLM domain.
    domain = getattr(args, "domain", None) or case.get("domain") or "ai_llm"
    from .domains import DEFAULT_REGISTRY

    domain_adapter = DEFAULT_REGISTRY.get(domain)

    if in_process:
        if domain != "ai_llm":
            print(
                f"warning: --in-process drives the AI/LLM engine; domain {domain!r} "
                "falls back to its own (dry-run) dispatch.",
                file=sys.stderr,
            )
        cfg = load_config()
        offline = bool(getattr(args, "offline", False))
        dispatch = build_local_dispatch(
            model=args.engine_model or cfg.engine.model or cfg.llm.model,
            intensity=getattr(args, "intensity", None) or cfg.engine.intensity,
            offline=offline,
            simulate_vulnerable=offline,
        )
    elif live:
        if not args.engine:
            print("error: --live requires --engine <url>.", file=sys.stderr)
            return EXIT_USAGE
        remote = AgathonAdapter(args.engine, token=args.token or "")

        def dispatch(t: Technique, tgt: str) -> EngineResult:  # noqa: E306
            return remote.run_test(t, tgt)

    runner = CaseRunner(
        gate=gate,
        stops=stops,
        vault=vault,
        dedup=dedup,
        registry=_AdapterRegistry(domain_adapter),
        builder=domain_adapter,
        dispatch=dispatch,
    )

    print(f"Case '{case.get('id', 'case')}' against {target}")
    mode = "IN-PROCESS ENGINE" if in_process else ("LIVE (remote engine)" if live else "DRY RUN (no engine calls)")
    print(f"Mode: {mode}")
    print(f"Scope: {scope.program}  |  techniques: {len(technique_ids)}\n")

    result = runner.run(case.get("id", "case"), scope, target, technique_ids)
    runner.write_result(result, str(out_dir / "result.json"))

    print(f"requests made : {result.requests_made}")
    print(f"findings      : {len(result.findings)}")
    print(f"skipped       : {len(result.skipped)}")
    print(f"errors        : {len(result.errors)}")
    if result.stopped:
        print(f"STOPPED       : {result.stop_reason}")
    for s in result.skipped:
        print(f"  - skipped {s['technique']}: {s['reason']}")
    for f in result.findings:
        print(f"  + {f.severity.value.upper():<13} {f.title}  (cvss {f.cvss_score:.1f})")
    print(f"\nArtifacts under: {out_dir}")
    return EXIT_OK


def cmd_triage(args: argparse.Namespace) -> int:
    findings = _load_findings(args.findings)
    scorer = TriageScorer(min_score_to_submit=args.min_score)
    ranked = scorer.ranked_findings(findings)
    out = args.output or args.findings
    Path(out).write_text(
        json.dumps([f.to_dict() for f in ranked], indent=2, sort_keys=True), encoding="utf-8"
    )
    for f in ranked:
        submittable = f.cvss_score >= args.min_score and f.reproducible
        print(
            f"{'SUBMIT' if submittable else 'DROP  '}  {f.severity.value.upper():<13} "
            f"cvss {f.cvss_score:>4.1f}  {f.title}"
        )
    print(f"\nWrote {len(ranked)} scored findings to {out}")
    return EXIT_OK


def cmd_report(args: argparse.Namespace) -> int:
    findings = _load_findings(args.findings)
    gen = ReportGenerator(platform=args.platform, program=args.program or "")
    out_dir = Path(args.output or "reports")
    written = 0
    for f in findings:
        v = gen.validate(f)
        if not v.ok and args.require_valid:
            print(f"skip {f.id}: missing {', '.join(v.missing)}")
            continue
        rep = gen.render(f, strict=False)
        paths = gen.write(rep, str(out_dir))
        written += 1
        print(f"{'OK ' if v.ok else 'DRAFT'} {f.id} -> {paths['markdown']}")
    print(f"\n{written} report(s) written to {out_dir}")
    return EXIT_OK


def cmd_retest(args: argparse.Namespace) -> int:
    registry = DedupRegistry(args.registry)
    f = registry.mark_retest(args.finding_id, still_reproduces=not args.fixed, note=args.note or "")
    if f is None:
        print(f"finding {args.finding_id} not found in {args.registry}", file=sys.stderr)
        return EXIT_USAGE
    verdict = "STILL REPRODUCES " + DASH + " escalate" if not args.fixed else "FIXED " + DASH + " close"
    print(f"{f.id}: {verdict}")
    return EXIT_OK


# --------------------------------------------------------------------------- #
# program onboarding
# --------------------------------------------------------------------------- #

def cmd_program_import(args: argparse.Namespace) -> int:
    """Import a program policy into a reviewable scope file."""
    from .program import ProgramImporter

    importer = ProgramImporter()
    if args.text is not None:
        imported = importer.import_text(args.text, program=args.program,
                                        platform=args.platform, url=args.url or "")
    elif args.file:
        imported = importer.import_file(args.file, program=args.program,
                                        platform=args.platform)
    else:
        imported = importer.import_url(args.source, program=args.program,
                                       platform=args.platform,
                                       browser=not args.no_browser)

    payload = imported.confirm_payload
    if not imported.ok:
        render_program_summary(payload, args.source)
        print("\nImport failed \u2014 nothing was written.", file=sys.stderr)
        hint = (imported.fetch.paste_hint if imported.fetch else "") or ""
        if hint:
            print("\n" + hint, file=sys.stderr)
        return EXIT_USAGE

    render_program_summary(payload, args.source)
    importer.confirm(imported, approved_by="pending-review", out_dir=args.output)
    print(f"\nWrote review files to {args.output}/")
    print("  scope.json             \u2014 machine-enforced scope (edit anything the VERIFY list flags)")
    print("  program-profile.json   \u2014 the extraction audit trail")
    print("  authorization.json     \u2014 a *pending* receipt; re-run with --approve-by to authorize")

    if args.yes:
        approved = importer.confirm(imported, approved_by=args.approve_by, out_dir=args.output)
        print(f"\nAuthorized: scope digest {approved.scope_digest[:12]} "
              f"approved by {approved.approved_by}.")
        return EXIT_OK

    print("\nNothing has been authorized yet. Confirm the scope above, then re-run with")
    print("  --approve-by <your name>   (or use `bountymode program confirm`)")
    return EXIT_OK


def cmd_program_show(args: argparse.Namespace) -> int:
    """Print the parsed view for an existing profile, or re-parse a source."""
    from .program import ProgramImporter

    if args.profile:
        _print(json.loads(Path(args.profile).read_text(encoding="utf-8")))
        return EXIT_OK

    importer = ProgramImporter()
    if args.file:
        imported = importer.import_file(args.file, program=args.program)
    else:
        imported = importer.import_url(args.source, program=args.program,
                                       browser=not args.no_browser)
    render_program_summary(imported.confirm_payload, args.source or args.file or "")
    return EXIT_OK


def cmd_program_confirm(args: argparse.Namespace) -> int:
    """Re-issue an authorization receipt for an already-imported scope."""
    from .program import ProgramImporter, scope_hash

    scope = _load_scope(args.scope)
    importer = ProgramImporter()
    imported = importer.import_text("confirmed scope", program=scope.program)
    imported.scope = scope
    imported.report.confidence = 1.0
    receipt = importer.confirm(imported, approved_by=args.approve_by,
                               note=args.note or "", out_dir=args.output)
    print(f"Authorized program '{scope.program}'")
    print(f"  approver      : {receipt.approved_by}")
    print(f"  scope digest  : {receipt.scope_digest}")
    print(f"  in-scope      : {receipt.in_scope_count}")
    print(f"  exclusions    : {receipt.exclusion_count}")
    print(f"  receipt       : {args.output}/authorization.json")
    assert scope_hash(scope) == receipt.scope_digest
    return EXIT_OK


def render_program_summary(payload: Dict[str, Any], source: str) -> None:
    """Print the confirmation view a human must sign off on."""
    print(f"\nProgram : {payload['program']}")
    if source:
        print(f"Source  : {source}")
    print(f"Parsed  : via {payload['extraction_source']} "
          f"\u2014 confidence {payload['confidence']:.0%} ({payload['confidence_grade']})")

    in_scope = payload["in_scope"]
    print(f"\nIN SCOPE ({len(in_scope)})")
    if in_scope:
        for t in in_scope:
            print(f"  + {t['pattern']}  [{t['kind']}]")
    else:
        print("  (none \u2014 nothing is testable yet)")

    exclusions = [r for r in payload["out_of_scope"] if r.get("kind") != "technique"]
    prose = [r for r in payload["out_of_scope"] if r.get("kind") == "technique"]
    if exclusions:
        print(f"\nOUT OF SCOPE ({len(exclusions)})")
        for r in exclusions:
            reason = f" \u2014 {r['reason']}" if r.get("reason") else ""
            print(f"  - {r['pattern']}{reason}")
    if prose:
        print(f"\nPOLICY PROHIBITIONS ({len(prose)})")
        for r in prose:
            print(f"  \u00b7 {' '.join(r['pattern'].split())[:100]}")

    if payload["listings"]:
        print(f"\nLISTINGS (not testable hosts, auto-excluded) ({len(payload['listings'])})")
        for lst in payload["listings"]:
            print(f"  \u2192 {lst['url']}")

    if payload["rewards"]:
        table = ", ".join(f"{k} ${v:,}" for k, v in sorted(payload["rewards"].items()))
        print(f"\nREWARDS (observed, not guaranteed): {table}")

    print(f"\nLIMITS  : {payload['rate_limit_rps']:.3f} req/s, "
          f"max {payload['max_requests']} requests")
    blocked = ", ".join(payload["prohibited_techniques"]) or DASH
    print(f"TECHNIQUES BLOCKED BY POLICY: {blocked}")

    if payload["rules"]:
        print(f"\nPROGRAM RULES ({len(payload['rules'])})")
        for rule in payload["rules"][:8]:
            print(f"  \u00b7 {rule[:110]}")

    if payload["VERIFY"]:
        print(f"\n\u26a0 VERIFY BEFORE TESTING ({len(payload['VERIFY'])})")
        for marker in payload["VERIFY"]:
            print(f"  ? {marker}")

    for warning in payload.get("warnings", []):
        print(f"\n! {warning}")


def cmd_pipeline_run(args: argparse.Namespace) -> int:
    """One command: import -> scope -> gate -> scan -> verify -> report."""
    from .program import GuidedPipeline

    pipeline = GuidedPipeline(attempts=args.verify_attempts)
    common: Dict[str, Any] = dict(
        approved_by=args.approve_by,
        target=args.target or "",
        domain=args.domain,
        techniques=args.technique or None,
        out_dir=args.output,
        in_process=not args.live,
        offline=not args.live,
        live=args.live,
        engine=args.engine or "",
        token=args.token or "",
        intensity=args.intensity or "standard",
        program=args.program,
        platform=args.platform,
        browser=not args.no_browser,
        verify_attempts=args.verify_attempts,
    )
    result = pipe_run(pipeline, args, common)

    print(f"\nGuided run \u2014 {result.program or 'unknown program'}  [{result.mode}]")
    print("\nStages")
    for stage in result.stages:
        print(f"  {'PASS' if stage.ok else 'FAIL'}  {stage.name:<10} {stage.detail}")

    if result.skipped:
        print(f"\nSkipped by the authorization gate ({len(result.skipped)})")
        for entry in result.skipped[:10]:
            print(f"  - {entry['technique']}: {entry['reason'][:90]}")
        if len(result.skipped) > 10:
            print(f"  ... and {len(result.skipped) - 10} more")

    if result.findings:
        print(f"\nFindings ({len(result.findings)}) \u2014 {result.verified_count} verified, "
              f"{result.ready_count} submission-ready")
        for index, (finding, verdict) in enumerate(zip(result.findings, result.readiness)):
            report = result.verified[index] if index < len(result.verified) else {}
            vverdict = str(report.get("verdict", "")).upper() or "UNKNOWN"
            flag = "READY" if verdict.get("ready") else "NOT READY"
            print(f"  [{flag}] {finding.severity.value.upper():<12} "
                  f"CVSS {finding.cvss_score:.1f}  {finding.title}")
            print(f"             verification: {vverdict} "
                  f"({report.get('successes', 0)}/{report.get('attempts', 0)} attempts, "
                  f"oracle={report.get('oracle', 'n/a')})")
            for reason in report.get("reasons", [])[:3]:
                print(f"               \u00b7 {reason}")
            if report.get("negative_control_passed") is False:
                print("               \u00b7 NEGATIVE CONTROL FIRED \u2014 the signal is not "
                      "specific to the weakness")
            if not verdict.get("ready"):
                gaps = list(verdict.get("blockers", [])) + list(verdict.get("missing", []))
                print(f"             not submission-ready \u2014 {', '.join(gaps) or 'unspecified'}")
                for check in verdict.get("checks", []):
                    if not check.get("passed") and check.get("detail"):
                        print(f"               \u00b7 {check['label']}: {check['detail']}")

    if result.errors:
        print("\nErrors")
        for err in result.errors[:10]:
            print(f"  ! {err}")

    verified = result.verified_count
    print(f"\nVerification: {verified}/{len(result.findings)} finding(s) reproduced.")
    print("Final confirmation of a vulnerability is the bounty program's job; "
          "reports state reproducibility and evidence, not certainty.")
    print(f"Reports and evidence: {result.out_dir}/")
    if not args.live:
        print("This was a DRY RUN. No live target was contacted.")
    return EXIT_OK if result.ok else EXIT_BLOCKED


def pipe_run(pipeline: Any, args: argparse.Namespace, common: Dict[str, Any]) -> Any:
    """Dispatch the guided pipeline against a URL or a local file."""
    if args.file:
        return pipeline.run_from_file(args.file, **common)
    return pipeline.run_from_url(args.source, **common)


def cmd_auto_run(args: argparse.Namespace) -> int:
    """One input: a single document in, a submission bundle out.

    This is the autonomous mode.  The operator supplies one file (a program's
    PDF brief, a pasted policy, an exported HTML page) and an approver name, and
    the runner reads it, plans the testing, runs it through the gate, verifies
    what it finds, amplifies the impact and writes a submission bundle.
    """
    from .autonomous import AutonomousRunner

    runner = AutonomousRunner(attempts=args.verify_attempts)
    result = runner.run_from_document(
        args.document,
        approved_by=args.approve_by,
        approval_note=args.note or "",
        target=args.target or "",
        domain=args.domain or "",
        techniques=args.technique or None,
        out_dir=args.output,
        in_process=not args.live,
        offline=not args.live,
        live=args.live,
        engine=args.engine or "",
        token=args.token or "",
        intensity=args.intensity or "standard",
        program=args.program,
        platform=args.platform,
        verify_attempts=args.verify_attempts,
        adapt=not args.no_adapt,
    )

    print(f"\nAutonomous run \u2014 {result.program or 'unknown program'}  [{result.mode}]")
    print(f"Input: {args.document}")
    print("\nStages")
    for stage in result.stages:
        print(f"  {'PASS' if stage.ok else 'FAIL'}  {stage.name:<10} {stage.detail}")

    if result.plan:
        plan = result.plan
        print(f"\nPlan ({plan.get('source', 'heuristic')})")
        print(f"  families : {', '.join(plan.get('families', [])) or DASH}")
        if plan.get("rationale"):
            print(f"  rationale: {plan['rationale']}")
        for t in plan.get("targets", []):
            print(f"  {t['priority']}. {t['target']}  [{t['kind']} -> {t['domain']}]  "
                  f"{len(t['techniques'])} technique(s)")
            if t.get("rationale"):
                print(f"       {t['rationale'][:110]}")
        if plan.get("chain_hypothesis"):
            print(f"  chain    : {plan['chain_hypothesis']}")

    if result.skipped:
        print(f"\nSkipped by the authorization gate ({len(result.skipped)})")
        for entry in result.skipped[:8]:
            print(f"  - {entry['technique']}: {entry['reason'][:90]}")

    if result.findings:
        print(f"\nFindings ({len(result.findings)}) \u2014 {result.verified_count} verified, "
              f"{result.ready_count} submission-ready")
        for index, (finding, verdict) in enumerate(zip(result.findings, result.readiness)):
            report = result.verified[index] if index < len(result.verified) else {}
            vverdict = str(report.get("verdict", "")).upper() or "UNKNOWN"
            flag = "READY" if verdict.get("ready") else "NOT READY"
            print(f"  [{flag}] {finding.severity.value.upper():<12} "
                  f"CVSS {finding.cvss_score:.1f}  {finding.title}")
            print(f"             verification: {vverdict} "
                  f"({report.get('successes', 0)}/{report.get('attempts', 0)} attempts, "
                  f"oracle={report.get('oracle', 'n/a')})")
            if not verdict.get("ready"):
                gaps = list(verdict.get("blockers", [])) + list(verdict.get("missing", []))
                print(f"             not submission-ready \u2014 {', '.join(gaps) or 'unspecified'}")

    if result.amplifications:
        lifted = [a for a in result.amplifications if a.get("amplified")]
        if lifted:
            print(f"\nImpact amplification ({len(lifted)})")
            for amp in lifted[:6]:
                print(f"  {amp['kind']}: {amp['from_severity']} -> {amp['to_severity']}")
                print(f"    {amp['rationale'][:120]}")

    if result.errors:
        print("\nErrors")
        for err in result.errors[:8]:
            print(f"  ! {err}")

    print(f"\nSubmission readiness: {'READY' if result.ready_to_submit else 'NOT READY'}")
    if not result.ready_to_submit and result.missing:
        print(f"  missing: {', '.join(result.missing)}")
    print("Final confirmation of a vulnerability is the bounty program's job; "
          "reports state reproducibility and evidence, not certainty.")
    print(f"Reports and bundle: {result.out_dir}/reports/")
    if not args.live:
        print("This was a DRY RUN. No live target was contacted.")
    return EXIT_OK if result.ok else EXIT_BLOCKED


def cmd_auto_plan(args: argparse.Namespace) -> int:
    """Show the plan the autonomous mode would produce, without running it."""
    from .autonomous import DocumentIntake, Planner
    from .program import ProgramImporter

    read = DocumentIntake().read(args.document)
    if not read.ok:
        print(f"error: {read.error}", file=sys.stderr)
        if read.hint:
            print(read.hint, file=sys.stderr)
        return EXIT_USAGE
    imported = ProgramImporter().import_text(
        read.text, program=args.program, platform=args.platform
    )
    if not imported.ok:
        print(
            "error: no scope could be parsed from the document "
            f"({len(read.text.strip())} characters read).",
            file=sys.stderr,
        )
        print(
            "The parser only records assets the program states explicitly (a scope "
            "table, a wildcard like *.example.com, a backticked host, or a line that "
            "names the host as a target). Add an 'In Scope' section listing the "
            "assets, or paste the program's scope table.",
            file=sys.stderr,
        )
        return EXIT_USAGE
    plan = Planner().plan(imported.scope)
    _print(plan.to_dict())
    return EXIT_OK


def cmd_program_watch(args: argparse.Namespace) -> int:
    """Re-run the pipeline on an interval and report what changed."""
    from .program import GuidedPipeline, ProgramWatcher

    pipeline = GuidedPipeline(attempts=args.verify_attempts)
    base: Dict[str, Any] = dict(
        approved_by=args.approve_by,
        target=args.target or "",
        domain=args.domain,
        in_process=not args.live,
        offline=not args.live,
        live=args.live,
        engine=args.engine or "",
        intensity=args.intensity or "standard",
        program=args.program,
        browser=not args.no_browser,
        verify_attempts=args.verify_attempts,
    )

    def scan(run_index: int) -> Any:
        local = dict(base)
        local["out_dir"] = str(Path(args.output) / f"run-{run_index:03d}")
        if args.file:
            return pipeline.run_from_file(args.file, **local)
        return pipeline.run_from_url(args.source, **local)

    state_path = Path(args.output) / "watch-state.json"
    watcher = ProgramWatcher(
        scan,
        state_path=str(state_path),
        interval_s=args.interval,
        max_runs=args.runs,
        on_run=lambda run: print(f"  {run.summary}"),
    )
    print(f"Watching {args.source or args.file} every {args.interval:.0f}s, "
          f"{args.runs or 'unlimited'} pass(es)")
    runs = watcher.watch(iterations=args.runs)
    print(f"\nCompleted {len(runs)} pass(es); state in {state_path}")
    return EXIT_OK


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="bountymode",
        description="Authorized AI bug-bounty workflow: scope, gate, evidence, triage, report.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scope", help="import and inspect a program scope")
    ssub = s.add_subparsers(dest="scope_command", required=True)
    si = ssub.add_parser("import", help="import a policy file into a scope JSON")
    si.add_argument("policy")
    si.add_argument("--program", default=None)
    si.add_argument("-o", "--output", default=None)
    si.set_defaults(func=cmd_scope_import)
    ss = ssub.add_parser("show", help="print a scope JSON")
    ss.add_argument("scope")
    ss.set_defaults(func=cmd_scope_show)

    d = sub.add_parser("domains", help="list the registered domain adapters")
    d.set_defaults(func=cmd_domains)

    md = sub.add_parser("models", help="show the model configuration (and probe it with --check)")
    md.add_argument("--config", default=None, help="path to a bountymode.json config file")
    md.add_argument("--check", action="store_true",
                    help="probe the configured models live (needs an API key)")
    md.set_defaults(func=cmd_models)

    en = sub.add_parser("engine", help="inspect the vendored in-process engine")
    en.add_argument("--config", default=None, help="path to a bountymode.json config file")
    en.add_argument("--families", action="store_true", help="list attack families")
    en.add_argument("--techniques", action="store_true", help="list every technique")
    en.set_defaults(func=cmd_engine)

    t = sub.add_parser("techniques", help="list the technique catalogue")
    t.add_argument("--domain", default=None, help="list techniques for one domain")
    t.set_defaults(func=cmd_techniques)

    c = sub.add_parser("check", help="dry-run the authorization gate for a target")
    c.add_argument("scope")
    c.add_argument("target")
    c.add_argument("--technique", action="append", default=None)
    c.set_defaults(func=cmd_check)

    r = sub.add_parser("run", help="run a case (dry run unless --live/--in-process)")
    r.add_argument("case")
    r.add_argument("--scope", default=None)
    r.add_argument("-o", "--output", default=None)
    r.add_argument("--live", action="store_true", help="dispatch to a remote engine over HTTP")
    r.add_argument("--engine", default=None, help="remote engine base URL (required with --live)")
    r.add_argument("--token", default=None, help="internal scan token")
    r.add_argument("--in-process", action="store_true",
                   help="run the vendored engine in-process (no separate repo, no network hop)")
    r.add_argument("--offline", action="store_true",
                   help="with --in-process: use the deterministic offline model (no API key needed)")
    r.add_argument("--intensity", default=None,
                   choices=["recon", "standard", "aggressive", "greasy"],
                   help="engine scan tier for --in-process runs")
    r.add_argument("--engine-model", default=None, help="override the model used by the engine")
    r.set_defaults(func=cmd_run)

    tr = sub.add_parser("triage", help="score findings and rank them")
    tr.add_argument("findings")
    tr.add_argument("-o", "--output", default=None)
    tr.add_argument("--min-score", type=float, default=4.0)
    tr.set_defaults(func=cmd_triage)

    rp = sub.add_parser("report", help="render submission reports")
    rp.add_argument("findings")
    rp.add_argument("--platform", default="hackerone", choices=["hackerone", "bugcrowd"])
    rp.add_argument("--program", default=None)
    rp.add_argument("-o", "--output", default="reports")
    rp.add_argument("--require-valid", action="store_true",
                    help="skip findings that are missing required fields")
    rp.set_defaults(func=cmd_report)

    rt = sub.add_parser("retest", help="record a regression retest")
    rt.add_argument("finding_id")
    rt.add_argument("--registry", default="registry.json")
    rt.add_argument("--fixed", action="store_true", help="the finding no longer reproduces")
    rt.add_argument("--note", default=None)
    rt.set_defaults(func=cmd_retest)

    # -- program onboarding ------------------------------------------------ #
    pg = sub.add_parser(
        "program",
        help="onboard a real program page (URL or pasted policy) into a scope file",
    )
    pgsub = pg.add_subparsers(dest="program_command", required=True)

    pi = pgsub.add_parser("import", help="fetch/parse a program page or pasted policy")
    pi.add_argument("source", nargs="?", default="",
                    help="program URL (e.g. a Bugcrowd engagement page)")
    pi.add_argument("--file", default=None, help="read the policy from a local file instead")
    pi.add_argument("--text", default=None, help="parse policy text supplied directly")
    pi.add_argument("--url", default=None, help="the page the pasted text came from")
    pi.add_argument("--program", default=None, help="override the parsed program name")
    pi.add_argument("--platform", default=None, help="override the parsed platform")
    pi.add_argument("--no-browser", action="store_true",
                    help="skip the headless-browser fallback (static fetch only)")
    pi.add_argument("--approve-by", default="operator",
                    help="name of the human authorizing the scope")
    pi.add_argument("--yes", action="store_true",
                    help="authorize immediately instead of leaving the receipt pending")
    pi.add_argument("-o", "--output", default="program-scope")
    pi.set_defaults(func=cmd_program_import)

    ps = pgsub.add_parser("show", help="print a parsed program profile or re-parse a source")
    ps.add_argument("source", nargs="?", default="")
    ps.add_argument("--profile", default=None, help="a program-profile.json to print")
    ps.add_argument("--file", default=None, help="a local policy file to parse")
    ps.add_argument("--program", default=None)
    ps.add_argument("--no-browser", action="store_true")
    ps.set_defaults(func=cmd_program_show)

    pc = pgsub.add_parser("confirm", help="authorize an existing scope.json")
    pc.add_argument("scope")
    pc.add_argument("--approve-by", required=True)
    pc.add_argument("--note", default=None)
    pc.add_argument("-o", "--output", default="program-scope")
    pc.set_defaults(func=cmd_program_confirm)

    pw = pgsub.add_parser("watch", help="re-scan on an interval and report what changed")
    pw.add_argument("source", nargs="?", default="")
    pw.add_argument("--file", default=None)
    pw.add_argument("--approve-by", default="operator")
    pw.add_argument("--target", default=None)
    pw.add_argument("--domain", default="ai_llm")
    pw.add_argument("--interval", type=float, default=3600.0, help="seconds between passes")
    pw.add_argument("--runs", type=int, default=None, help="stop after N passes")
    pw.add_argument("--verify-attempts", type=int, default=5)
    pw.add_argument("--program", default=None)
    pw.add_argument("--intensity", default=None,
                    choices=["recon", "standard", "aggressive", "greasy"])
    pw.add_argument("--live", action="store_true")
    pw.add_argument("--engine", default=None)
    pw.add_argument("--no-browser", action="store_true")
    pw.add_argument("-o", "--output", default="watch-run")
    pw.set_defaults(func=cmd_program_watch)

    # -- guided pipeline ---------------------------------------------------- #
    pl = sub.add_parser(
        "pipeline",
        help="one command: import -> scope -> gate -> scan -> verify -> report",
    )
    plsub = pl.add_subparsers(dest="pipeline_command", required=True)
    plr = plsub.add_parser("run", help="run the full guided pipeline")
    plr.add_argument("source", nargs="?", default="", help="program URL")
    plr.add_argument("--file", default=None, help="a local policy file instead of a URL")
    plr.add_argument("--approve-by", required=True,
                     help="name of the human authorizing this run (required)")
    plr.add_argument("--target", default=None,
                     help="the asset to test; defaults to the first concrete scope entry")
    plr.add_argument("--domain", default="ai_llm")
    plr.add_argument("--technique", action="append", default=None)
    plr.add_argument("--verify-attempts", type=int, default=5)
    plr.add_argument("--program", default=None)
    plr.add_argument("--platform", default=None)
    plr.add_argument("--intensity", default=None,
                     choices=["recon", "standard", "aggressive", "greasy"])
    plr.add_argument("--live", action="store_true",
                     help="dispatch to a remote engine (requires --engine, never on by default)")
    plr.add_argument("--engine", default=None)
    plr.add_argument("--token", default=None)
    plr.add_argument("--no-browser", action="store_true")
    plr.add_argument("-o", "--output", default="bounty-run")
    plr.set_defaults(func=cmd_pipeline_run)

    # -- autonomous (one input) --------------------------------------------- #
    au = sub.add_parser(
        "auto",
        help="one-input autonomous mode: a single program document in, a submission bundle out",
    )
    ausub = au.add_subparsers(dest="auto_command", required=True)

    ar = ausub.add_parser("run", help="read one document and run the whole job")
    ar.add_argument("document", help="the program document (PDF, .txt, .md, .html or .json)")
    ar.add_argument("--approve-by", required=True,
                    help="name of the human authorizing this run (required)")
    ar.add_argument("--note", default=None, help="a note recorded on the authorization receipt")
    ar.add_argument("--target", default=None,
                    help="override the planned target (defaults to the planner's first choice)")
    ar.add_argument("--domain", default=None,
                    help="override the domain adapter (defaults to the planner's choice)")
    ar.add_argument("--technique", action="append", default=None,
                    help="override the planned techniques (repeatable)")
    ar.add_argument("--verify-attempts", type=int, default=5)
    ar.add_argument("--program", default=None)
    ar.add_argument("--platform", default=None)
    ar.add_argument("--intensity", default=None,
                    choices=["recon", "standard", "aggressive", "greasy"])
    ar.add_argument("--no-adapt", action="store_true",
                    help="skip the adaptive follow-up pass after a finding lands")
    ar.add_argument("--live", action="store_true",
                    help="dispatch to a remote engine (requires --engine, never on by default)")
    ar.add_argument("--engine", default=None)
    ar.add_argument("--token", default=None)
    ar.add_argument("-o", "--output", default="auto-run")
    ar.set_defaults(func=cmd_auto_run)

    ap = ausub.add_parser("plan", help="show the plan for a document without running it")
    ap.add_argument("document")
    ap.add_argument("--program", default=None)
    ap.add_argument("--platform", default=None)
    ap.set_defaults(func=cmd_auto_plan)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

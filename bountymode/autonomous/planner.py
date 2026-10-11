"""The agentic planning brain -- scope in, a concrete test plan out.

A fixed technique list is not a plan.  A human hunter reads a program and
decides *what kind of thing this is* (an LLM product, a REST API, a web app, a
CI/CD surface), *which assets are worth the time*, and *which classes of bug pay
here* -- then adapts as results come in.  This module does that.

Two planners, one interface
---------------------------
:class:`HeuristicPlanner`
    Deterministic, offline, no API key.  It classifies each in-scope asset,
    scores it, and selects technique families from a declarative rule table.
    This is the default, and it is what makes the autonomous mode work with no
    model configured at all.
:class:`LlmPlanner`
    Wraps the heuristic plan and asks a model to *refine* it -- reorder,
    justify, and add a chain hypothesis.  It never invents targets: any target
    the model returns that is not already in the confirmed scope is dropped, and
    the drop is recorded.  A model failure falls back to the heuristic plan
    rather than failing the run.

The plan is a first-class artifact: it is written to disk, shown in the UI, and
carried into the report so a reviewer can see *why* each test was chosen.

Adaptation
----------
:meth:`Planner.adapt` takes the findings produced so far and returns a *follow-up*
plan: when a finding appears, the planner proposes the techniques that would
amplify it (see :mod:`bountymode.autonomous.amplify`), so the run pursues the
chain a human would instead of stopping at the first hit.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..domains import DEFAULT_REGISTRY
from ..models import Finding, ProgramScope, ScopeTarget, Technique

# --------------------------------------------------------------------------- #
# asset classification
# --------------------------------------------------------------------------- #

#: Asset kinds the planner understands, and the domain that tests them.
KIND_DOMAIN = {
    "llm": "ai_llm",
    "api": "web_api",
    "web": "web_api",
    "mobile": "web_api",
    "repo": "cicd",
    "cloud": "cloud",
}

#: Signals in a target string or its notes that reveal what it is.
_LLM_SIGNALS = (
    "llm", "gpt", "chat", "assistant", "copilot", "ai", "model", "prompt",
    "inference", "completion", "agent", "rag", "embedding", "openai", "anthropic",
)
_API_SIGNALS = ("api", "graphql", "rest", "v1", "v2", "v3", "endpoint", "gateway", "webhook")
_MOBILE_SIGNALS = ("android", "ios", "apk", "ipa", "mobile", "app store", "play store")
_REPO_SIGNALS = ("github.com", "gitlab.com", "repo", "pipeline", "ci", "actions", "workflow")
_CLOUD_SIGNALS = ("s3", "bucket", "aws", "azure", "gcp", "cloud", "storage", "iam", "lambda")

#: Technique families, in the order a hunter usually works them.
FAMILY_ORDER = (
    "recon",
    "access_control",
    "injection",
    "data_exposure",
    "logic",
    "client_side",
    "supply_chain",
    "cloud_config",
    "agentic",
)

#: Which family each technique category belongs to.
_CATEGORY_FAMILY = {
    "prompt_injection": "injection",
    "indirect_injection": "injection",
    "context_manipulation": "injection",
    "jailbreak": "injection",
    "data_exfiltration": "data_exposure",
    "system_prompt_leak": "data_exposure",
    "rag_poisoning": "data_exposure",
    "cross_tenant": "access_control",
    "access_control": "access_control",
    "excessive_agency": "agentic",
    "output_handling": "client_side",
    "economic_denial": "logic",
    "idor": "access_control",
    "auth_bypass": "access_control",
    "ssrf": "injection",
    "sqli": "injection",
    "xss": "client_side",
    "csrf": "client_side",
    "open_redirect": "client_side",
    "path_traversal": "injection",
    "jwt_weakness": "access_control",
    "mass_assignment": "logic",
    "business_logic": "logic",
    "graphql_introspection": "recon",
    "rate_limit_bypass": "logic",
    "api_versioning_bypass": "logic",
    "dependency_confusion": "supply_chain",
    "pipeline_poisoning": "supply_chain",
    "secret_in_logs": "data_exposure",
    "unpinned_action": "supply_chain",
    "artifact_poisoning": "supply_chain",
    "pr_target_injection": "supply_chain",
    "self_hosted_runner_abuse": "supply_chain",
    "token_overpermission": "access_control",
    "cache_poisoning": "supply_chain",
    "sbom_missing": "supply_chain",
    "public_bucket": "cloud_config",
    "iam_privesc": "access_control",
    "overpermissive_role": "access_control",
    "metadata_ssrf": "injection",
    "open_security_group": "cloud_config",
    "unencrypted_storage": "cloud_config",
    "logging_disabled": "cloud_config",
    "key_rotation_missing": "cloud_config",
    "cross_account_trust": "access_control",
    "container_escape_config": "cloud_config",
}

#: Expected impact text per family, used in the plan and the report.
FAMILY_IMPACT = {
    "recon": "Attack-surface knowledge that focuses the rest of the run.",
    "access_control": "Unauthorized access to another user's or tenant's data.",
    "injection": "Server-side code/command execution or instruction hijack.",
    "data_exposure": "Disclosure of secrets, prompts or private records.",
    "logic": "Business-rule abuse with direct financial or integrity impact.",
    "client_side": "Session or account compromise in a victim's browser.",
    "supply_chain": "Compromise of the build pipeline or shipped artifact.",
    "cloud_config": "Exposure of cloud resources or privilege escalation.",
    "agentic": "The agent performs actions it was never authorized to perform.",
}

#: Severity weight used to prioritise families.
_SEV_WEIGHT = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1}


def _labels(text: str) -> List[str]:
    """Split a host/URL into its DNS labels.

    Only dots separate labels -- a hyphen is *inside* a label, so ``acme-ai``
    is one label and must not match the signal ``ai``.
    """
    cleaned = re.sub(r"^https?://", "", (text or "").lower())
    cleaned = cleaned.split("/")[0].split(":")[0]
    return [p for p in cleaned.split(".") if p]


def _has_signal(text: str, signals: Sequence[str]) -> bool:
    """True when a signal appears as a whole DNS label, not a substring.

    A signal that itself contains a dot (``github.com``) is matched against the
    raw host, since it spans more than one label.  Hyphens are *not* separators:
    ``acme-ai`` is one label and must not match the signal ``ai``.
    """
    raw = re.sub(r"^https?://", "", (text or "").lower()).split("/")[0].split(":")[0]
    labels = set(_labels(text))
    for signal in signals:
        if "." in signal:
            if signal in raw:
                return True
        elif signal in labels:
            return True
    return False


def _has_word(text: str, signals: Sequence[str]) -> bool:
    """True when a signal appears as a whole word in free prose (notes)."""
    words = set(re.findall(r"[a-z0-9]+", (text or "").lower()))
    return any(signal in words for signal in signals if "." not in signal)


def classify_asset(target: ScopeTarget) -> str:
    """Decide what kind of asset this is, from its pattern, kind and notes.

    A kind the program itself declared always wins -- if the scope table says
    "web", the asset is a web app even if its hostname contains "ai".
    """
    declared = (target.kind or "").strip().lower()
    if declared in KIND_DOMAIN:
        return declared
    host = target.pattern or ""
    notes = target.notes or ""
    if _has_signal(host, _REPO_SIGNALS) or _has_word(notes, _REPO_SIGNALS):
        return "repo"
    if _has_signal(host, _CLOUD_SIGNALS) or _has_word(notes, _CLOUD_SIGNALS):
        return "cloud"
    if _has_signal(host, _MOBILE_SIGNALS) or _has_word(notes, _MOBILE_SIGNALS):
        return "mobile"
    if _has_signal(host, _LLM_SIGNALS) or _has_word(notes, _LLM_SIGNALS):
        return "llm"
    if _has_signal(host, _API_SIGNALS) or _has_word(notes, _API_SIGNALS):
        return "api"
    return "web"


def family_of(technique: Technique) -> str:
    """Map a technique onto its family."""
    return _CATEGORY_FAMILY.get(technique.category, "logic")


def is_testable(target: ScopeTarget) -> bool:
    """Can this asset be tested directly, or is it a wildcard/listing?"""
    pattern = (target.pattern or "").strip()
    if not pattern or pattern.startswith("*"):
        return False
    if pattern.startswith("http://") or pattern.startswith("https://"):
        return True
    return "." in pattern and "/" not in pattern


# --------------------------------------------------------------------------- #
# plan model
# --------------------------------------------------------------------------- #

@dataclass
class PlannedTarget:
    """One asset the plan intends to test, and why."""

    target: str
    kind: str
    domain: str
    priority: int
    score: float
    rationale: str = ""
    techniques: List[str] = field(default_factory=list)
    families: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "kind": self.kind,
            "domain": self.domain,
            "priority": self.priority,
            "score": round(self.score, 3),
            "rationale": self.rationale,
            "techniques": list(self.techniques),
            "families": list(self.families),
        }


@dataclass
class TestPlan:
    """A concrete, ordered plan for one program."""

    program: str = ""
    platform: str = ""
    targets: List[PlannedTarget] = field(default_factory=list)
    families: List[str] = field(default_factory=list)
    expected_impact: str = ""
    rationale: str = ""
    source: str = "heuristic"          # heuristic | llm | llm-refined
    notes: List[str] = field(default_factory=list)
    dropped: List[str] = field(default_factory=list)
    chain_hypothesis: str = ""

    @property
    def technique_ids(self) -> List[str]:
        seen: List[str] = []
        for t in self.targets:
            for tid in t.techniques:
                if tid not in seen:
                    seen.append(tid)
        return seen

    @property
    def primary(self) -> Optional[PlannedTarget]:
        return self.targets[0] if self.targets else None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "program": self.program,
            "platform": self.platform,
            "source": self.source,
            "families": list(self.families),
            "expected_impact": self.expected_impact,
            "rationale": self.rationale,
            "chain_hypothesis": self.chain_hypothesis,
            "notes": list(self.notes),
            "dropped": list(self.dropped),
            "targets": [t.to_dict() for t in self.targets],
            "technique_ids": self.technique_ids,
        }


# --------------------------------------------------------------------------- #
# heuristic planner
# --------------------------------------------------------------------------- #

class HeuristicPlanner:
    """Deterministic planner: classify, score, select.  No model required."""

    def __init__(self, *, max_targets: int = 5, max_techniques_per_target: int = 12) -> None:
        self.max_targets = max_targets
        self.max_techniques_per_target = max_techniques_per_target

    def plan(self, scope: ProgramScope) -> TestPlan:
        plan = TestPlan(
            program=scope.program,
            platform=scope.platform,
            source="heuristic",
        )

        candidates: List[Tuple[float, ScopeTarget, str]] = []
        for entry in scope.in_scope:
            if not is_testable(entry):
                continue
            kind = classify_asset(entry)
            candidates.append((self._score(entry, kind, scope), entry, kind))

        if not candidates:
            plan.notes.append(
                "No directly testable asset was found in the scope. Every in-scope "
                "entry is a wildcard or a listing page, so the plan is empty until a "
                "concrete host is added."
            )
            return plan

        candidates.sort(key=lambda c: (-c[0], c[1].pattern))
        prohibited = {t.lower() for t in scope.prohibited_techniques}

        for priority, (score, entry, kind) in enumerate(candidates[: self.max_targets], 1):
            domain = KIND_DOMAIN.get(kind, "web_api")
            adapter = DEFAULT_REGISTRY.get(domain)
            techniques = self._select(adapter, kind, prohibited, scope)
            families = sorted(
                {family_of(adapter.require(t)) for t in techniques},
                key=lambda f: FAMILY_ORDER.index(f) if f in FAMILY_ORDER else 99,
            )
            plan.targets.append(
                PlannedTarget(
                    target=entry.pattern,
                    kind=kind,
                    domain=domain,
                    priority=priority,
                    score=score,
                    rationale=self._rationale(entry, kind, domain, len(techniques)),
                    techniques=techniques,
                    families=families,
                )
            )

        plan.families = sorted(
            {f for t in plan.targets for f in t.families},
            key=lambda f: FAMILY_ORDER.index(f) if f in FAMILY_ORDER else 99,
        )
        plan.expected_impact = self._expected_impact(plan)
        plan.rationale = self._plan_rationale(plan, scope)
        plan.chain_hypothesis = self._chain_hypothesis(plan)
        return plan

    # -- scoring ----------------------------------------------------------- #

    def _score(self, entry: ScopeTarget, kind: str, scope: ProgramScope) -> float:
        """Rank an asset: what a hunter would spend time on first."""
        score = 1.0
        # A declared max severity is a strong signal of what the program cares about.
        if entry.max_severity:
            score += _SEV_WEIGHT.get(str(entry.max_severity).lower(), 3) * 0.4
        # Kind priority: an LLM/API surface usually pays more than a marketing site.
        score += {"llm": 2.0, "api": 1.6, "cloud": 1.5, "repo": 1.4,
                  "mobile": 1.2, "web": 0.8}.get(kind, 0.5)
        # A URL with a path is a more specific (and more interesting) target.
        if "/" in entry.pattern:
            score += 0.4
        # Reward table: a program that pays well is worth more effort.
        if scope.reward_table:
            top = max(scope.reward_table.values())
            score += min(1.0, top / 5000.0)
        # A test account requirement means auth-gated testing is expected.
        if scope.requires_test_account:
            score += 0.2
        return round(score, 3)

    def _select(
        self,
        adapter: Any,
        kind: str,
        prohibited: set,
        scope: ProgramScope,
    ) -> List[str]:
        """Choose techniques for one asset, highest expected value first."""
        chosen: List[Tuple[int, str]] = []
        for technique in adapter.techniques():
            if technique.id.lower() in prohibited:
                continue
            # Destructive techniques are never planned, regardless of policy.
            if technique.destructive:
                continue
            # A side-effecting technique needs a human approval; plan it only
            # when the program itself permits it.
            if technique.side_effects and technique.id.lower() not in {
                t.lower() for t in scope.permitted_techniques
            }:
                continue
            weight = _SEV_WEIGHT.get(technique.severity_hint, 3)
            # Prefer techniques that match the asset kind.
            if kind == "llm" and adapter.name == "ai_llm":
                weight += 1
            if kind in ("api", "web", "mobile") and adapter.name == "web_api":
                weight += 1
            chosen.append((weight, technique.id))
        chosen.sort(key=lambda c: (-c[0], c[1]))
        return [tid for _w, tid in chosen[: self.max_techniques_per_target]]

    # -- narrative --------------------------------------------------------- #

    def _rationale(self, entry: ScopeTarget, kind: str, domain: str, count: int) -> str:
        return (
            f"Classified as a {kind} asset, so it is tested with the {domain} "
            f"technique set ({count} techniques). "
            + (f"Program notes: {entry.notes.strip()[:120]}" if entry.notes else "")
        ).strip()

    def _expected_impact(self, plan: TestPlan) -> str:
        if not plan.families:
            return ""
        top = plan.families[:3]
        return " ".join(FAMILY_IMPACT.get(f, "") for f in top).strip()

    def _plan_rationale(self, plan: TestPlan, scope: ProgramScope) -> str:
        bits = [
            f"{len(plan.targets)} testable asset(s) selected from "
            f"{len(scope.in_scope)} in-scope entries.",
        ]
        if scope.reward_table:
            top = max(scope.reward_table.values())
            bits.append(f"Highest advertised reward is ${top:,}, so high-severity classes are prioritised.")
        if scope.prohibited_techniques:
            bits.append(
                "Excluded by program policy: "
                + ", ".join(sorted(scope.prohibited_techniques)) + "."
            )
        if scope.requires_human_verification:
            bits.append("The program requires human verification of every finding.")
        return " ".join(bits)

    def _chain_hypothesis(self, plan: TestPlan) -> str:
        """State the amplification the planner will pursue if a finding lands."""
        fams = set(plan.families)
        if "data_exposure" in fams and "access_control" in fams:
            return (
                "If an information-disclosure finding lands, pursue the "
                "access-control chain: a leaked identifier or token is often the "
                "key that turns a low-severity leak into cross-account access."
            )
        if "injection" in fams and "agentic" in fams:
            return (
                "If an injection finding lands, pursue the agentic chain: an "
                "instruction hijack that reaches a tool call escalates from "
                "prompt injection to unauthorized action."
            )
        if "access_control" in fams:
            return (
                "If an access-control finding lands, pursue the privilege-"
                "escalation path: confirm whether the same weakness reaches an "
                "administrative or cross-tenant object."
            )
        return (
            "If any finding lands, re-run it under a second principal and pursue "
            "the highest-severity technique that shares its root cause."
        )


# --------------------------------------------------------------------------- #
# LLM planner
# --------------------------------------------------------------------------- #

_PLAN_SYSTEM = (
    "You are a senior bug-bounty hunter planning a scoped engagement. You are "
    "given a program's confirmed scope and a draft plan. Refine the plan: order "
    "the targets by expected value, and for each state in one sentence why it is "
    "worth testing and what impact you expect. You may ONLY use targets that "
    "appear in the confirmed scope -- never invent a host. Reply as JSON with "
    "keys: rationale (string), chain_hypothesis (string), targets (array of "
    "{target, why, expected_impact})."
)


class LlmPlanner:
    """Refine a heuristic plan with a model, without letting it invent scope."""

    def __init__(self, client: Any = None, *, fallback: Optional[HeuristicPlanner] = None) -> None:
        self.client = client
        self.fallback = fallback or HeuristicPlanner()

    def plan(self, scope: ProgramScope) -> TestPlan:
        base = self.fallback.plan(scope)
        if self.client is None or not base.targets:
            return base
        try:
            refined = self._refine(scope, base)
        except Exception as exc:  # noqa: BLE001 - a model failure is not fatal
            base.notes.append(f"LLM refinement skipped: {type(exc).__name__}: {exc}")
            return base
        return refined

    def _refine(self, scope: ProgramScope, base: TestPlan) -> TestPlan:
        import json as _json

        allowed = {t.target for t in base.targets}
        prompt = _json.dumps(
            {
                "program": scope.program,
                "platform": scope.platform,
                "in_scope": [t.pattern for t in scope.in_scope],
                "prohibited": list(scope.prohibited_techniques),
                "rewards": dict(scope.reward_table),
                "draft_targets": [t.to_dict() for t in base.targets],
            },
            indent=2,
        )
        result = self.client.chat(
            prompt, system_message=_PLAN_SYSTEM, json_mode=True, max_tokens=1200
        )
        if not getattr(result, "ok", False) or not (getattr(result, "text", "") or "").strip():
            base.notes.append("LLM refinement returned no usable text; kept the heuristic plan.")
            return base

        data = _extract_json(result.text)
        if not isinstance(data, dict):
            base.notes.append("LLM refinement was not valid JSON; kept the heuristic plan.")
            return base

        by_target = {t.target: t for t in base.targets}
        ordered: List[PlannedTarget] = []
        for entry in data.get("targets", []) or []:
            if not isinstance(entry, dict):
                continue
            target = str(entry.get("target", "")).strip()
            if target not in allowed:
                # The model proposed something outside the confirmed scope.
                if target:
                    base.dropped.append(target)
                continue
            planned = by_target[target]
            why = str(entry.get("why", "")).strip()
            impact = str(entry.get("expected_impact", "")).strip()
            if why:
                planned.rationale = why
            if impact:
                planned.notes = [impact]
            ordered.append(planned)

        # Anything the model omitted keeps its heuristic position.
        for t in base.targets:
            if t not in ordered:
                ordered.append(t)

        for priority, t in enumerate(ordered, 1):
            t.priority = priority

        base.targets = ordered
        base.source = "llm-refined"
        if str(data.get("rationale", "")).strip():
            base.rationale = str(data["rationale"]).strip()
        if str(data.get("chain_hypothesis", "")).strip():
            base.chain_hypothesis = str(data["chain_hypothesis"]).strip()
        if base.dropped:
            base.notes.append(
                "Dropped out-of-scope target(s) proposed by the model: "
                + ", ".join(base.dropped)
            )
        return base


def _extract_json(text: str) -> Any:
    """Pull the first JSON object out of a model response."""
    import json as _json

    text = (text or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n?", "", text)
        text = re.sub(r"\n?```$", "", text).strip()
    try:
        return _json.loads(text)
    except ValueError:
        pass
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end > start:
        try:
            return _json.loads(text[start : end + 1])
        except ValueError:
            return None
    return None


# --------------------------------------------------------------------------- #
# adaptation
# --------------------------------------------------------------------------- #

#: When a finding of this category lands, these techniques are worth pursuing.
_AMPLIFY_MAP: Dict[str, List[str]] = {
    "system_prompt_leak": ["data_exfiltration", "cross_tenant", "tool_misuse"],
    "data_exfiltration": ["cross_tenant", "tool_misuse", "api_logic"],
    "prompt_injection": ["tool_misuse", "data_exfiltration", "indirect_injection"],
    "indirect_injection": ["tool_misuse", "data_exfiltration"],
    "jailbreak": ["tool_misuse", "data_exfiltration"],
    "context_manipulation": ["tool_misuse", "data_exfiltration"],
    "cross_tenant": ["data_exfiltration", "api_logic"],
    "access_control": ["idor", "auth_bypass", "mass_assignment"],
    "idor": ["auth_bypass", "mass_assignment", "cross_tenant"],
    "auth_bypass": ["idor", "jwt_weakness", "mass_assignment"],
    "output_handling": ["xss", "data_exfiltration"],
    "xss": ["csrf", "open_redirect"],
    "ssrf": ["metadata_ssrf", "path_traversal"],
    "sqli": ["path_traversal", "auth_bypass"],
    "path_traversal": ["sqli", "ssrf"],
    "jwt_weakness": ["auth_bypass", "idor"],
    "business_logic": ["mass_assignment", "rate_limit_bypass"],
    "excessive_agency": ["tool_misuse", "data_exfiltration"],
    "secret_in_logs": ["token_overpermission", "iam_privesc"],
    "public_bucket": ["iam_privesc", "overpermissive_role"],
    "iam_privesc": ["cross_account_trust", "overpermissive_role"],
    "dependency_confusion": ["pipeline_poisoning", "artifact_poisoning"],
    "pipeline_poisoning": ["pr_target_injection", "self_hosted_runner_abuse"],
}


class Planner:
    """The planner the autonomous runner uses: heuristic, optionally LLM-refined."""

    def __init__(self, client: Any = None, *, use_llm: bool = False) -> None:
        self.heuristic = HeuristicPlanner()
        self.llm = LlmPlanner(client) if (use_llm and client is not None) else None

    def plan(self, scope: ProgramScope) -> TestPlan:
        if self.llm is not None:
            return self.llm.plan(scope)
        return self.heuristic.plan(scope)

    def adapt(
        self,
        plan: TestPlan,
        findings: Sequence[Finding],
        *,
        already_run: Sequence[str] = (),
    ) -> TestPlan:
        """Propose follow-up techniques that would amplify what was found.

        Returns a *new* plan containing only the follow-up work, so the runner
        can execute it as a second pass without re-running what already ran.
        """
        ran = {t.lower() for t in already_run}
        follow: List[PlannedTarget] = []
        seen: set = set()

        for finding in findings:
            wanted = _AMPLIFY_MAP.get(finding.category, [])
            if not wanted:
                continue
            for planned in plan.targets:
                if planned.target != finding.target:
                    continue
                adapter = DEFAULT_REGISTRY.get(planned.domain)
                extra = [
                    tid for tid in wanted
                    if tid.lower() not in ran
                    and tid not in seen
                    and adapter.technique(tid) is not None
                    and not adapter.require(tid).destructive
                ]
                if not extra:
                    continue
                seen.update(extra)
                follow.append(
                    PlannedTarget(
                        target=planned.target,
                        kind=planned.kind,
                        domain=planned.domain,
                        priority=len(follow) + 1,
                        score=planned.score,
                        rationale=(
                            f"Amplification of '{finding.title}': these techniques "
                            "test whether the same root cause reaches a higher-impact "
                            "outcome."
                        ),
                        techniques=extra,
                        families=sorted(
                            {family_of(adapter.require(t)) for t in extra},
                            key=lambda f: FAMILY_ORDER.index(f) if f in FAMILY_ORDER else 99,
                        ),
                    )
                )

        adapted = TestPlan(
            program=plan.program,
            platform=plan.platform,
            source="adaptation",
            targets=follow,
            families=sorted({f for t in follow for f in t.families}),
            rationale=(
                f"Follow-up pass driven by {len(findings)} finding(s): pursue the "
                "chain that raises severity rather than stopping at the first hit."
            ),
            chain_hypothesis=plan.chain_hypothesis,
        )
        return adapted

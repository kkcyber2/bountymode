"""Upgrade backlog (U1-U13) -- the modules that raise finding quality.

Each module is self-contained, dependency-free and offline-testable:

U1  multimodal.py        multimodal injection carriers (image/audio/PDF)
U2  agentic.py           agentic / MCP tool-use assertions
U3  cross_tenant.py      cross-tenant / RAG two-account differential proof
U4  reproducibility.py   N-of-M replay and reproduction rate
U5  judge.py             LLM-as-judge response classification
U6  fuzzing.py           coverage-guided prompt fuzzing
U7  chaining.py          automated exploit-chain chaining
U8  memory_poisoning.py  persistent-memory poisoning proof
U9  supply_chain.py      dependency / supply-chain static checks
U10 minimisation.py      evidence minimisation
U11 regression.py        regression suites
U12 false_positive.py    false-positive filtering
U13 crescendo.py         multi-turn crescendo
"""

from __future__ import annotations

from .agentic import ToolAssertion, ToolUseAuditor, parse_tool_calls
from .chaining import Chain, ChainNode, ChainPlanner
from .crescendo import CrescendoRunner
from .cross_tenant import CrossTenantProver, PrincipalResponse
from .false_positive import FalsePositiveFilter
from .fuzzing import PromptFuzzer
from .judge import JudgeResult, JudgeVerdict, ResponseJudge
from .memory_poisoning import MemoryEntry, MemoryPoisoningProver, MemoryStore
from .minimisation import EvidenceMinimiser
from .multimodal import Channel, MultimodalBuilder
from .regression import RegressionCheck, RegressionSuite
from .reproducibility import Reproducer
from .supply_chain import SupplyChainScanner

__all__ = [
    "MultimodalBuilder", "Channel",
    "ToolUseAuditor", "ToolAssertion", "parse_tool_calls",
    "CrossTenantProver", "PrincipalResponse",
    "Reproducer",
    "ResponseJudge", "JudgeVerdict", "JudgeResult",
    "PromptFuzzer",
    "ChainPlanner", "ChainNode", "Chain",
    "MemoryStore", "MemoryEntry", "MemoryPoisoningProver",
    "SupplyChainScanner",
    "EvidenceMinimiser",
    "RegressionSuite", "RegressionCheck",
    "FalsePositiveFilter",
    "CrescendoRunner",
]

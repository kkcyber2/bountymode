"""U7 -- automated exploit-chain chaining.

Individual findings are often low severity; a *chain* of them is critical.
This module models findings as nodes in a graph and searches for paths from
an entry finding to a high-value goal, so the report can present the chain
rather than the isolated steps.

The graph is declarative: an edge means "finding A yields a capability that
enables finding B".  The search is a bounded DFS, so it is deterministic and
cheap.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


@dataclass
class ChainNode:
    """One finding in a chain, with the capability it yields."""

    finding_id: str
    title: str
    yields: List[str] = field(default_factory=list)   # capabilities gained
    requires: List[str] = field(default_factory=list)  # capabilities needed
    severity: str = "medium"

    def to_dict(self) -> Dict[str, object]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "yields": self.yields,
            "requires": self.requires,
            "severity": self.severity,
        }


@dataclass
class Chain:
    nodes: List[ChainNode]
    goal: str
    score: float

    @property
    def length(self) -> int:
        return len(self.nodes)

    def to_dict(self) -> Dict[str, object]:
        return {
            "goal": self.goal,
            "length": self.length,
            "score": round(self.score, 3),
            "steps": [n.to_dict() for n in self.nodes],
        }


_SEV_WEIGHT = {"critical": 4.0, "high": 3.0, "medium": 2.0, "low": 1.0, "informational": 0.5}


class ChainPlanner:
    """Search a finding graph for chains that reach a goal capability."""

    def __init__(self, nodes: List[ChainNode], *, max_depth: int = 6) -> None:
        self.nodes = {n.finding_id: n for n in nodes}
        self.max_depth = max_depth

    def _enabled(self, node: ChainNode, capabilities: Set[str]) -> bool:
        return all(req in capabilities for req in node.requires)

    def find_chains(self, goal: str, *, start_capabilities: Optional[Set[str]] = None) -> List[Chain]:
        start = set(start_capabilities or [])
        results: List[Chain] = []

        def dfs(path: List[ChainNode], caps: Set[str], visited: Set[str]) -> None:
            if len(path) > self.max_depth:
                return
            if goal in caps and path:
                score = sum(_SEV_WEIGHT.get(n.severity, 1.0) for n in path) + 2.0 * len(path)
                results.append(Chain(list(path), goal, score))
                return
            for nid, node in self.nodes.items():
                if nid in visited:
                    continue
                if not self._enabled(node, caps):
                    continue
                dfs(path + [node], caps | set(node.yields), visited | {nid})

        dfs([], start, set())
        results.sort(key=lambda c: c.score, reverse=True)
        return results

    def best_chain(self, goal: str, *, start_capabilities: Optional[Set[str]] = None) -> Optional[Chain]:
        chains = self.find_chains(goal, start_capabilities=start_capabilities)
        return chains[0] if chains else None

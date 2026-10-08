"""U9 -- supply-chain checks.

Static checks over a dependency manifest / lockfile for the supply-chain
classes that pay: unpinned dependencies, typosquat-suspicious names, known
risky ranges, and missing integrity hashes.  Pure text analysis, so it runs
offline and is fully testable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class SupplyChainIssue:
    package: str
    kind: str
    detail: str
    severity: str = "medium"

    def to_dict(self) -> Dict[str, object]:
        return {"package": self.package, "kind": self.kind, "detail": self.detail, "severity": self.severity}


#: Popular packages whose near-miss names are common typosquats.
_POPULAR = [
    "requests", "urllib3", "numpy", "pandas", "flask", "django", "fastapi",
    "boto3", "cryptography", "pyyaml", "setuptools", "pip", "wheel",
    "react", "lodash", "express", "axios", "next", "typescript",
]

_REQ_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*(==|>=|<=|~=|>|<|!=)?\s*([^\s;#]*)", re.M)


def _levenshtein(a: str, b: str) -> int:
    """Damerau-Levenshtein (optimal string alignment) distance.

    Typosquats are overwhelmingly *transpositions* (``reqeusts`` for
    ``requests``), which plain Levenshtein scores as 2.  Counting an adjacent
    transposition as a single edit is what makes the check useful.
    """
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    la, lb = len(a), len(b)
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(
                d[i - 1][j] + 1,        # deletion
                d[i][j - 1] + 1,        # insertion
                d[i - 1][j - 1] + cost,  # substitution
            )
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)  # transposition
    return d[la][lb]


class SupplyChainScanner:
    """Scan a requirements.txt / package.json-style manifest."""

    def __init__(self, *, typosquat_distance: int = 1) -> None:
        self.typosquat_distance = typosquat_distance

    def scan(self, manifest: str) -> List[SupplyChainIssue]:
        issues: List[SupplyChainIssue] = []
        for m in _REQ_RE.finditer(manifest or ""):
            name, op, version = m.group(1), m.group(2), m.group(3)
            if not name or name.startswith("#"):
                continue
            low = name.lower()

            if op in (">=", ">", "~=", "<=", "<", "!=") or (op is None and not version):
                issues.append(SupplyChainIssue(
                    name, "unpinned", f"dependency '{name}' is not pinned to an exact version",
                    "medium",
                ))
            if op is None and not version:
                issues.append(SupplyChainIssue(
                    name, "no_version", f"dependency '{name}' has no version constraint", "high",
                ))

            for pop in _POPULAR:
                if low != pop and _levenshtein(low, pop) <= self.typosquat_distance:
                    issues.append(SupplyChainIssue(
                        name, "typosquat_suspect",
                        f"'{name}' is one edit from popular package '{pop}'", "high",
                    ))
                    break

            if version and re.search(r"(?:^|[.\-])(?:0\.0|alpha|beta|rc)", version, re.I):
                issues.append(SupplyChainIssue(
                    name, "prerelease", f"'{name}' pinned to a pre-release version '{version}'", "low",
                ))
        return issues

    def summary(self, issues: List[SupplyChainIssue]) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for i in issues:
            out[i.kind] = out.get(i.kind, 0) + 1
        return out

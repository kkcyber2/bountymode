"""Mid-run steering for an autonomous run.

Upstream's chat could *queue* an instruction but nothing ever acted on it, so
"stop" and "skip that target" typed into the chat were silently ignored.  This
module is the thing that acts: the chat drains instructions at each stage
boundary and folds them in here, and the runner consults the control at the two
points where stopping is cheap and honest -- before the scan and before
verification.

Deliberately conservative:

* ``skip`` only ever picks another target the plan already contained; it can
  never invent one, so it cannot widen the authorized scope.
* ``stop`` never discards work.  Findings already made are kept and reported;
  they are simply left unverified, and the run says so.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

#: "stop", "abort", "cancel", "halt" -- however the operator phrases it.
_STOP_RE = re.compile(r"^\s*(stop|abort|cancel|halt|quit|enough)\b", re.I)
_SKIP_RE = re.compile(
    r"\b(skip|ignore|drop|exclude|do\s+not\s+test|don'?t\s+test)\b", re.I
)
_DEEPER_RE = re.compile(r"\b(go\s+deeper|deeper|dig\s+deeper|more\s+depth)\b", re.I)
_EXPLAIN_RE = re.compile(r"^\s*(explain|why|how|what|describe|clarify)\b", re.I)
_HOST_RE = re.compile(
    r"\b(?:(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}"
    r"|(?:\d{1,3}\.){3}\d{1,3})(?::\d{1,5})?\b",
    re.I,
)


@dataclass
class RunControl:
    """What the operator has asked for while the run is in flight."""

    stop_requested: bool = False
    stop_reason: str = ""
    #: Targets the operator told us not to test.
    skipped: Set[str] = field(default_factory=set)
    #: Free-text instruction the operator left for the planner/analyst.
    notes: List[str] = field(default_factory=list)
    #: Technique ids the operator asked us to go deeper on.
    requested_deeper: List[str] = field(default_factory=list)

    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    # -- requests ---------------------------------------------------------- #

    def request_stop(self, reason: str = "") -> bool:
        """Ask the run to stop at the next safe boundary.  Idempotent."""
        with self._lock:
            already = self.stop_requested
            self.stop_requested = True
            if reason and not self.stop_reason:
                self.stop_reason = reason.strip()[:200]
        return not already

    def skip_target(self, target: str) -> bool:
        """Skip one target.  Returns False for an empty name."""
        name = (target or "").strip().lower()
        if not name:
            return False
        with self._lock:
            self.skipped.add(name)
            # Also match on the bare host, so "skip api.acme.example" covers
            # "api.acme.example:8443" and vice versa.
            self.skipped.add(name.split(":")[0])
        return True

    def is_skipped(self, target: str) -> bool:
        name = (target or "").strip().lower()
        if not name:
            return False
        with self._lock:
            return name in self.skipped or name.split(":")[0] in self.skipped

    def go_deeper(self, techniques: Optional[List[str]] = None) -> List[str]:
        """Record techniques the operator wants more of."""
        with self._lock:
            for tid in techniques or []:
                if tid and tid not in self.requested_deeper:
                    self.requested_deeper.append(tid)
            return list(self.requested_deeper)

    def note(self, text: str) -> None:
        with self._lock:
            if text:
                self.notes.append(text.strip()[:500])

    @property
    def stopped(self) -> bool:
        return self.stop_requested

    # -- interpretation ---------------------------------------------------- #

    def apply(self, instruction: str, *, current_target: str = "") -> Dict[str, Any]:
        """Turn a free-text instruction into a control change.

        Returns a small dict describing what was understood, so the UI can echo
        an honest acknowledgement instead of a generic \"noted\".
        """
        text = (instruction or "").strip()
        if not text:
            return {"kind": "empty", "handled": False}

        if _STOP_RE.match(text):
            self.request_stop(text)
            return {"kind": "stop", "handled": True,
                    "reply": "Understood -- stopping at the next safe boundary. "
                             "Anything already found is kept."}

        if _SKIP_RE.search(text):
            # Prefer a target named in the instruction; otherwise the current one.
            named = [h for h in _HOST_RE.findall(text)]
            targets = named or ([current_target] if current_target else [])
            targets = [t for t in targets if t and not t.lower().endswith("target")]
            if not targets:
                return {"kind": "skip", "handled": False,
                        "reply": "Tell me which target to skip (for example "
                                 "\"skip api.acme.example\")."}
            for target in targets:
                self.skip_target(target)
            return {"kind": "skip", "handled": True,
                    "reply": "Skipping " + ", ".join(targets) + "."}

        if _DEEPER_RE.search(text):
            self.note(text)
            return {"kind": "deeper", "handled": True,
                    "reply": "Noted -- I will go deeper where the gate allows."}

        if _EXPLAIN_RE.match(text):
            return {"kind": "question", "handled": False}

        self.note(text)
        return {"kind": "note", "handled": True, "reply": "Noted."}

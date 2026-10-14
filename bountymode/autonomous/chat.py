"""Streaming chat session for the autonomous runner.

The chat interface is the human-facing front door: the user pastes the bounty
details, and the agent streams each stage, every finding as it lands, and the
final report.  It also accepts **mid-run instructions** -- a note posted while
the run is in flight is picked up at the next stage boundary and folded into the
run's context, so the user can steer without restarting.

The session is deliberately thin: it wraps :class:`AutonomousRunner` and turns
its stage callbacks into a stream of JSON events.  It never bypasses the
authorization gate, the stop-conditions, or the dry-run default -- those live in
the runner and are unchanged.
"""

from __future__ import annotations

import queue
import threading
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional


@dataclass
class ChatSession:
    """One streaming run, addressable by id so it can be steered mid-flight."""

    approved_by: str = ""
    note: str = ""
    target: str = ""
    domain: str = ""
    techniques: Optional[List[str]] = None
    out_dir: str = "chat-run"
    live: bool = False
    engine: str = ""
    token: str = ""
    intensity: str = "standard"
    program: Optional[str] = None
    platform: Optional[str] = None
    verify_attempts: int = 5
    adapt: bool = True

    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    #: Instructions posted while the run is in flight, drained at stage boundaries.
    _pending: "queue.Queue[str]" = field(default_factory=queue.Queue, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _instructions: List[str] = field(default_factory=list, repr=False)

    # -- mid-run steering -------------------------------------------------- #

    def instruct(self, instruction: str) -> None:
        """Queue an instruction to be applied at the next stage boundary."""
        text = (instruction or "").strip()
        if not text:
            return
        with self._lock:
            self._instructions.append(text)
        self._pending.put(text)

    def drain_instructions(self) -> List[str]:
        """Return and clear every instruction queued since the last boundary."""
        out: List[str] = []
        while True:
            try:
                out.append(self._pending.get_nowait())
            except queue.Empty:
                break
        return out

    @property
    def instructions(self) -> List[str]:
        with self._lock:
            return list(self._instructions)

    # -- streaming --------------------------------------------------------- #

    def stream(self, *, path: str = "", text: str = "") -> Iterator[Dict[str, Any]]:
        """Run the job and yield progress events.

        Events are plain dicts with a ``type``: ``start``, ``stage``, ``finding``,
        ``instruction``, ``result``, ``error``.  The caller serialises them (the
        UI uses Server-Sent Events).
        """
        from .runner import AutonomousRunner

        yield {
            "type": "start",
            "session_id": self.id,
            "mode": "live" if self.live else "dry-run",
            "approved_by": self.approved_by,
        }

        runner = AutonomousRunner(attempts=self.verify_attempts)
        common = dict(
            approved_by=self.approved_by,
            approval_note=self.note,
            target=self.target,
            domain=self.domain,
            techniques=self.techniques,
            out_dir=self.out_dir,
            in_process=not self.live,
            offline=not self.live,
            live=self.live,
            engine=self.engine,
            token=self.token,
            intensity=self.intensity,
            program=self.program,
            platform=self.platform,
            verify_attempts=self.verify_attempts,
            adapt=self.adapt,
        )

        # The runner reports each stage through a callback; bridge it to the
        # stream, and drain any mid-run instruction at every boundary.
        events: "queue.Queue[Dict[str, Any]]" = queue.Queue()
        done = threading.Event()
        holder: Dict[str, Any] = {}

        def on_stage(name: str, status: str, detail: str) -> None:
            events.put({"type": "stage", "stage": name, "status": status, "detail": detail})
            for instruction in self.drain_instructions():
                events.put({"type": "instruction", "text": instruction,
                            "applied_at": name})

        def work() -> None:
            try:
                if path:
                    result = runner.run_from_document(path, on_stage=on_stage, **common)
                else:
                    result = runner.run_from_text(text, on_stage=on_stage, **common)
                holder["result"] = result
            except Exception as exc:  # noqa: BLE001 - surfaced as an event
                holder["error"] = f"{type(exc).__name__}: {exc}"
            finally:
                done.set()

        thread = threading.Thread(target=work, daemon=True)
        thread.start()

        while not done.is_set() or not events.empty():
            try:
                yield events.get(timeout=0.2)
            except queue.Empty:
                continue

        if "error" in holder:
            yield {"type": "error", "message": holder["error"]}
            return

        result = holder.get("result")
        if result is not None:
            for finding in getattr(result, "findings", []) or []:
                yield {
                    "type": "finding",
                    "id": getattr(finding, "id", ""),
                    "title": getattr(finding, "title", ""),
                    "severity": getattr(finding, "severity", ""),
                    "cvss": getattr(finding, "cvss_score", None),
                    "verified": bool(getattr(finding, "reproducible", False)),
                }
            yield {"type": "result", "result": result.to_dict()}

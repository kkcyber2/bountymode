"""Program importer — URL (or paste) in, reviewable scope out.

    result = ProgramImporter().import_url("https://bugcrowd.com/engagements/x")
    print(result.confirm_payload)      # what we parsed, for the human
    result = importer.confirm(result, approved_by="alice", out_dir="runs/x")

The importer writes three files:

``scope.json``          the canonical, machine-enforced scope
``program-profile.json`` the extraction audit trail (rewards, notes, markers)
``authorization.json``  a receipt binding the scope's hash to a named approver

A live run must present a receipt whose scope hash matches the scope it is
about to use.  That is what makes “a human confirmed this scope” a checkable
fact rather than a claim.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..models import ProgramScope
from .extractor import ExtractedProgram, ExtractionReport, ProgramExtractor
from .fetcher import FetchResult, ProgramFetcher


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def scope_hash(scope: ProgramScope) -> str:
    """Stable hash of the machine-enforced parts of a scope.

    Only the fields that decide authorization are hashed, so re-importing the
    same program produces the same digest and an unrelated edit cannot
    invalidate a receipt.
    """
    payload = {
        "program": scope.program,
        "in_scope": sorted(t.pattern.lower() for t in scope.in_scope),
        "out_of_scope": sorted(r.pattern.lower() for r in scope.out_of_scope if r.kind != "technique"),
        "prohibited": sorted(t.lower() for t in scope.prohibited_techniques),
        "permitted": sorted(t.lower() for t in scope.permitted_techniques),
        "max_requests": scope.max_requests,
        "rate_limit_rps": round(float(scope.rate_limit_rps), 6),
        "max_duration_s": scope.max_duration_s,
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:32]


@dataclass
class AuthorizationReceipt:
    """A named human's approval of one exact scope."""

    program: str
    scope_digest: str
    approved_by: str
    approved_at: str = field(default_factory=_now_iso)
    note: str = ""
    program_url: str = ""
    in_scope_count: int = 0
    exclusion_count: int = 0
    prohibited_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "program": self.program,
            "scope_digest": self.scope_digest,
            "approved_by": self.approved_by,
            "approved_at": self.approved_at,
            "note": self.note,
            "program_url": self.program_url,
            "in_scope_count": self.in_scope_count,
            "exclusion_count": self.exclusion_count,
            "prohibited_count": self.prohibited_count,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuthorizationReceipt":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in known})

    def matches(self, scope: ProgramScope) -> bool:
        return self.scope_digest == scope_hash(scope)

    def save(self, path: str) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True), encoding="utf-8")

    @classmethod
    def load(cls, path: str) -> "AuthorizationReceipt":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


@dataclass
class ImportResult:
    """Everything one import produced."""

    scope: ProgramScope
    report: ExtractionReport
    fetch: Optional[FetchResult] = None
    listing_count: int = 0
    scope_path: str = ""
    profile_path: str = ""
    receipt_path: str = ""

    @property
    def ok(self) -> bool:
        return bool(self.scope.in_scope) or bool(self.scope.out_of_scope)

    @property
    def confirm_payload(self) -> Dict[str, Any]:
        """The review a human must sign off on before any test runs."""
        warnings = list(self.report.warnings)
        if self.fetch:
            warnings = list(self.fetch.warnings) + warnings
        if not self.scope.in_scope:
            warnings.append(
                "No directly testable in-scope asset was found. Add one before "
                "anything can be authorized."
            )
        return {
            "program": self.scope.program,
            "platform": self.scope.platform,
            "source_url": self.scope.program_url or self.scope.source_url,
            "extraction_source": self.report.source,
            "confidence": round(self.report.confidence, 3),
            "confidence_grade": self.report.grade,
            "in_scope": [t.to_dict() for t in self.scope.in_scope],
            "out_of_scope": [r.to_dict() for r in self.scope.out_of_scope],
            "listings": list(self.scope.listings),
            "prohibited_techniques": list(self.scope.prohibited_techniques),
            "rewards": dict(self.scope.reward_table),
            "rules": list(self.scope.notes),
            "requires_human_verification": self.scope.requires_human_verification,
            "safe_harbour": self.scope.safe_harbour,
            "rate_limit_rps": self.scope.rate_limit_rps,
            "max_requests": self.scope.max_requests,
            "VERIFY": list(self.scope.verify_markers),
            "warnings": warnings,
            "stats": dict(self.report.stats),
            "scope_digest": scope_hash(self.scope),
        }


class ProgramImporter:
    """Fetch/paste a program, extract a scope, and record a human's approval."""

    def __init__(
        self,
        *,
        fetcher: Optional[ProgramFetcher] = None,
        extractor: Optional[ProgramExtractor] = None,
    ) -> None:
        self.fetcher = fetcher or ProgramFetcher()
        self.extractor = extractor or ProgramExtractor()

    # -- import ------------------------------------------------------------ #

    def import_url(
        self,
        url: str,
        *,
        program: Optional[str] = None,
        platform: Optional[str] = None,
        browser: bool = True,
    ) -> ImportResult:
        self.fetcher.browser = browser
        fetched = self.fetcher.fetch(url)
        if not fetched.ok:
            return self._failed(fetched, program, platform, url)
        return self._extract(
            fetched.text, program=program, platform=platform, url=fetched.url or url,
            title=fetched.title, source=fetched.source, fetched=fetched,
        )

    def import_text(
        self,
        text: str,
        *,
        program: Optional[str] = None,
        platform: Optional[str] = None,
        url: str = "",
    ) -> ImportResult:
        if not (text or "").strip():
            fetched = FetchResult(ok=False, url=url, error="no policy text supplied")
            return self._failed(fetched, program, platform, url)
        fetched = self.fetcher.from_text(text, url=url)
        return self._extract(
            fetched.text, program=program, platform=platform, url=url,
            title=fetched.title, source="paste", fetched=fetched,
        )

    def import_file(
        self,
        path: str,
        *,
        program: Optional[str] = None,
        platform: Optional[str] = None,
    ) -> ImportResult:
        p = Path(path)
        if not p.is_file():
            fetched = FetchResult(ok=False, url=f"file://{path}", error=f"no such file: {path}")
            return self._failed(fetched, program, platform, f"file://{path}")
        return self.import_text(
            p.read_text(encoding="utf-8", errors="replace"),
            program=program or p.stem, platform=platform, url=f"file://{p.name}",
        )

    # -- confirm + export -------------------------------------------------- #

    def confirm(
        self,
        result: ImportResult,
        *,
        approved_by: str,
        note: str = "",
        out_dir: str = "program-scope",
    ) -> AuthorizationReceipt:
        """Write the scope + profile and issue an approval receipt."""
        d = Path(out_dir)
        d.mkdir(parents=True, exist_ok=True)

        scope_path = d / "scope.json"
        profile_path = d / "program-profile.json"
        receipt_path = d / "authorization.json"

        scope_path.write_text(
            json.dumps(result.scope.to_dict(), indent=2, sort_keys=True), encoding="utf-8"
        )
        profile_path.write_text(
            json.dumps(
                {
                    "program": result.scope.program,
                    "source_url": result.scope.program_url or result.scope.source_url,
                    "rewards": dict(result.scope.reward_table),
                    "listings": list(result.scope.listings),
                    "rules": list(result.scope.notes),
                    "verify_markers": list(result.scope.verify_markers),
                    "report": result.report.to_dict(),
                    "confirm_payload": result.confirm_payload,
                },
                indent=2, sort_keys=True,
            ),
            encoding="utf-8",
        )

        receipt = AuthorizationReceipt(
            program=result.scope.program,
            scope_digest=scope_hash(result.scope),
            approved_by=approved_by,
            note=note,
            program_url=result.scope.program_url or result.scope.source_url,
            in_scope_count=len(result.scope.in_scope),
            exclusion_count=len([r for r in result.scope.out_of_scope if r.kind != "technique"]),
            prohibited_count=len(result.scope.prohibited_techniques),
        )
        receipt.save(str(receipt_path))

        result.scope_path = str(scope_path)
        result.profile_path = str(profile_path)
        result.receipt_path = str(receipt_path)
        return receipt

    def load_receipt(self, path: str) -> AuthorizationReceipt:
        return AuthorizationReceipt.load(path)

    # -- internals --------------------------------------------------------- #

    def _extract(
        self,
        text: str,
        *,
        program: Optional[str],
        platform: Optional[str],
        url: str,
        title: str,
        source: str,
        fetched: Optional[FetchResult],
    ) -> ImportResult:
        extracted: ExtractedProgram = self.extractor.extract(
            text, program=program, platform=platform, url=url, title=title, source=source,
        )
        if fetched and fetched.title and not extracted.report.title:
            extracted.report.title = fetched.title
        return ImportResult(
            scope=extracted.scope,
            report=extracted.report,
            fetch=fetched,
            listing_count=len(extracted.listings),
        )

    def _failed(
        self,
        fetched: FetchResult,
        program: Optional[str],
        platform: Optional[str],
        url: str,
    ) -> ImportResult:
        scope = ProgramScope(
            program=(program or "imported-program"),
            platform=(platform or "generic"),
            source_url=url, program_url=url,
            verify_markers=[fetched.paste_hint or fetched.error or "import failed"],
        )
        report = ExtractionReport(
            source=fetched.source or "none", url=url,
            verify=[fetched.paste_hint or fetched.error or "import failed"],
            warnings=[fetched.error or "import failed"],
            stats={"in_scope": 0, "out_of_scope": 0, "listings": 0,
                   "prohibited": 0, "rewards": 0, "notes": 0, "verify": 1},
        )
        return ImportResult(scope=scope, report=report, fetch=fetched)

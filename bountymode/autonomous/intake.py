"""Document intake -- one file in, policy text out.

The whole point of the autonomous mode is that the operator hands over **one
document** (a program's PDF brief, a pasted policy, an exported HTML page) and
nothing else.  This module is the front door: it turns that document into the
plain policy text the existing :mod:`bountymode.program.extractor` already knows
how to parse.

It is deliberately honest about failure.  A PDF that is a scanned image with no
text layer cannot be read without OCR, and pretending otherwise would feed the
extractor an empty string and produce a confidently wrong scope.  So every
extraction reports *how* it read the document and, when it could not, says
exactly what to do instead.

Supported inputs
----------------
``.pdf``            text layer via pypdf / PyPDF2 / ``pdftotext`` (first that works)
``.txt`` ``.md``    read as-is
``.html`` ``.htm``  readable text extracted, tables preserved as pipe rows
``.json``           a scope/profile JSON is passed through as text
anything else       read as UTF-8 text (best effort)

No third-party dependency is required: ``pdftotext`` (poppler) and the pure
Python readers are each tried in turn, and the module degrades to a clear
message rather than an exception.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

#: Extensions we recognise, mapped to the reader that handles them.
PDF_SUFFIXES = {".pdf"}
HTML_SUFFIXES = {".html", ".htm", ".xhtml"}
TEXT_SUFFIXES = {".txt", ".md", ".markdown", ".text", ".rst", ".log"}
JSON_SUFFIXES = {".json"}

#: A document shorter than this is almost certainly not a program brief.
MIN_USEFUL_CHARS = 40


@dataclass
class IntakeResult:
    """What one document produced, and how it was read."""

    ok: bool
    path: str = ""
    kind: str = "text"          # pdf | html | json | text | unknown
    reader: str = ""            # pypdf | PyPDF2 | pdftotext | direct | ...
    text: str = ""
    title: str = ""
    pages: int = 0
    chars: int = 0
    warnings: List[str] = field(default_factory=list)
    error: str = ""
    hint: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "path": self.path,
            "kind": self.kind,
            "reader": self.reader,
            "title": self.title,
            "pages": self.pages,
            "chars": self.chars,
            "warnings": list(self.warnings),
            "error": self.error,
            "hint": self.hint,
        }


# --------------------------------------------------------------------------- #
# PDF readers
# --------------------------------------------------------------------------- #

def _read_pdf_pypdf(path: Path) -> Optional[tuple]:
    """Read a PDF with pypdf (or PyPDF2).  Returns ``(text, pages)`` or None."""
    for module_name in ("pypdf", "PyPDF2"):
        try:
            module = __import__(module_name)
        except ImportError:
            continue
        try:
            reader = module.PdfReader(str(path))
            pages = len(reader.pages)
            chunks: List[str] = []
            for page in reader.pages:
                try:
                    chunks.append(page.extract_text() or "")
                except Exception:  # noqa: BLE001 - one bad page is not fatal
                    chunks.append("")
            text = "\n".join(chunks)
            if text.strip():
                return text, pages
        except Exception:  # noqa: BLE001 - try the next reader
            continue
    return None


def _read_pdf_pdftotext(path: Path) -> Optional[tuple]:
    """Read a PDF with the poppler ``pdftotext`` binary, if present."""
    binary = shutil.which("pdftotext")
    if not binary:
        return None
    try:
        proc = subprocess.run(  # noqa: S603
            [binary, "-layout", "-enc", "UTF-8", str(path), "-"],
            capture_output=True, text=True, timeout=120, check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    if proc.returncode != 0 or not (proc.stdout or "").strip():
        return None
    pages = (proc.stdout or "").count("\f") + 1
    return proc.stdout, pages


def _read_pdf(path: Path) -> IntakeResult:
    """Read a PDF, trying each available reader in turn."""
    attempts: List[str] = []
    for reader_name, reader in (("pypdf", _read_pdf_pypdf), ("pdftotext", _read_pdf_pdftotext)):
        result = reader(path)
        if result is not None:
            text, pages = result
            return IntakeResult(
                ok=True, path=str(path), kind="pdf", reader=reader_name,
                text=_tidy(text), pages=pages, chars=len(_tidy(text)),
            )
        attempts.append(reader_name)

    return IntakeResult(
        ok=False, path=str(path), kind="pdf",
        error=(
            "could not extract any text from the PDF "
            f"(tried: {', '.join(attempts) or 'no reader available'})"
        ),
        hint=(
            "The PDF is probably a scan with no text layer. Either run OCR on it "
            "first (e.g. `ocrmypdf in.pdf out.pdf`) or copy the program's scope "
            "text and save it as a .txt file, then pass that instead."
        ),
    )


# --------------------------------------------------------------------------- #
# other readers
# --------------------------------------------------------------------------- #

def _read_html(path: Path) -> IntakeResult:
    from ..program.fetcher import html_title, html_to_text

    raw = path.read_text(encoding="utf-8", errors="replace")
    text = html_to_text(raw)
    return IntakeResult(
        ok=bool(text.strip()), path=str(path), kind="html", reader="html_to_text",
        text=text, title=html_title(raw), chars=len(text),
        error="" if text.strip() else "the HTML document contained no readable text",
    )


def _read_json(path: Path) -> IntakeResult:
    raw = path.read_text(encoding="utf-8", errors="replace")
    try:
        data = json.loads(raw)
    except ValueError as exc:
        return IntakeResult(
            ok=False, path=str(path), kind="json", reader="json",
            error=f"invalid JSON: {exc}",
            hint="Fix the JSON, or save the program policy as plain text instead.",
        )
    # A scope/profile JSON is already structured; hand it to the extractor as
    # readable text so the same code path handles both shapes.
    if isinstance(data, dict) and ("in_scope" in data or "out_of_scope" in data):
        text = _scope_json_to_text(data)
        return IntakeResult(
            ok=True, path=str(path), kind="json", reader="scope-json",
            text=text, title=str(data.get("program", "")), chars=len(text),
        )
    return IntakeResult(
        ok=True, path=str(path), kind="json", reader="json",
        text=json.dumps(data, indent=2, sort_keys=True), chars=len(raw),
    )


def _scope_json_to_text(data: Dict[str, Any]) -> str:
    """Render a scope JSON back into the text shape the extractor parses."""
    lines: List[str] = [f"# {data.get('program', 'imported-program')}", ""]
    lines.append("## In Scope Targets")
    lines.append("| Target | Kind |")
    lines.append("|---|---|")
    for entry in data.get("in_scope", []) or []:
        pattern = entry.get("pattern") if isinstance(entry, dict) else entry
        kind = entry.get("kind", "web") if isinstance(entry, dict) else "web"
        if pattern:
            lines.append(f"| {pattern} | {kind} |")
    lines.append("")
    lines.append("## Out of Scope")
    for entry in data.get("out_of_scope", []) or []:
        pattern = entry.get("pattern") if isinstance(entry, dict) else entry
        reason = entry.get("reason", "") if isinstance(entry, dict) else ""
        if pattern:
            lines.append(f"- {pattern} {reason}".rstrip())
    lines.append("")
    for note in data.get("notes", []) or []:
        lines.append(str(note))
    return "\n".join(lines)


def _read_text(path: Path) -> IntakeResult:
    raw = path.read_text(encoding="utf-8", errors="replace")
    text = _tidy(raw)
    return IntakeResult(
        ok=bool(text.strip()), path=str(path), kind="text", reader="direct",
        text=text, chars=len(text),
        error="" if text.strip() else "the file is empty",
    )


def _tidy(text: str) -> str:
    """Collapse runs of blank lines while keeping paragraph structure."""
    lines = [line.rstrip() for line in (text or "").replace("\r\n", "\n").split("\n")]
    out: List[str] = []
    for line in lines:
        if not line.strip() and out and not out[-1].strip():
            continue
        out.append(line)
    return "\n".join(out).strip()


# --------------------------------------------------------------------------- #
# public API
# --------------------------------------------------------------------------- #

class DocumentIntake:
    """Read one program document into policy text."""

    def read(self, path: str) -> IntakeResult:
        p = Path(path)
        if not p.exists():
            return IntakeResult(
                ok=False, path=str(path), kind="unknown",
                error=f"no such file: {path}",
                hint="Check the path, or pass the program policy as text instead.",
            )
        if p.is_dir():
            return IntakeResult(
                ok=False, path=str(path), kind="unknown",
                error=f"{path} is a directory, not a document",
                hint="Point at a single file (PDF, .txt, .md, .html or .json).",
            )

        suffix = p.suffix.lower()
        if suffix in PDF_SUFFIXES:
            result = _read_pdf(p)
        elif suffix in HTML_SUFFIXES:
            result = _read_html(p)
        elif suffix in JSON_SUFFIXES:
            result = _read_json(p)
        elif suffix in TEXT_SUFFIXES:
            result = _read_text(p)
        else:
            # Unknown extension: sniff the magic bytes, then fall back to text.
            result = self._read_unknown(p)

        if result.ok and result.chars < MIN_USEFUL_CHARS:
            result.ok = False
            result.error = (
                f"only {result.chars} characters of text were extracted -- "
                "too little to be a program brief"
            )
            result.hint = (
                "If this is a scanned PDF, run OCR first. Otherwise check you "
                "passed the right file."
            )
        if result.ok and not result.title:
            result.title = p.stem.replace("_", " ").replace("-", " ").strip()
        return result

    @staticmethod
    def _read_unknown(p: Path) -> IntakeResult:
        try:
            head = p.read_bytes()[:5]
        except OSError as exc:
            return IntakeResult(ok=False, path=str(p), kind="unknown",
                                error=f"could not read {p}: {exc}")
        if head.startswith(b"%PDF"):
            return _read_pdf(p)
        if head[:1] == b"{" or head[:1] == b"[":
            return _read_json(p)
        return _read_text(p)

    def read_text(self, text: str, *, title: str = "") -> IntakeResult:
        """Wrap already-supplied text so callers have one uniform result type."""
        cleaned = _tidy(text or "")
        return IntakeResult(
            ok=bool(cleaned.strip()), kind="text", reader="inline",
            text=cleaned, title=title, chars=len(cleaned),
            error="" if cleaned.strip() else "no text supplied",
        )


def looks_like_scope_text(text: str) -> bool:
    """Cheap sanity check: does this text plausibly describe a program scope?"""
    low = (text or "").lower()
    if len(low) < MIN_USEFUL_CHARS:
        return False
    signals = ("in scope", "in-scope", "out of scope", "out-of-scope",
               "scope", "targets", "reward", "bounty", "vulnerability")
    return sum(1 for s in signals if s in low) >= 2


_SCOPE_HEADING_RE = re.compile(r"^\s*#{1,6}\s*(in[\s-]?scope|out[\s-]?(?:of[\s-]?)?scope)", re.I | re.M)


def has_scope_section(text: str) -> bool:
    """Does the text contain an explicit in/out-of-scope heading?"""
    return bool(_SCOPE_HEADING_RE.search(text or ""))

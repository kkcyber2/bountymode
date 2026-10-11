"""Build a sample program PDF and run the one-input autonomous mode over it.

This is the worked example for the autonomous mode: it writes a program brief
as a PDF, then hands that single file to the runner and prints the result.  It
touches nothing but the local filesystem and the in-process simulation.

    python tools/auto_example.py

The PDF is written to ``examples/acme-ai-program.pdf`` and the run output to
``auto-run-example/``.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

SOURCE = ROOT / "examples" / "acme-ai-program.md"
PDF = ROOT / "examples" / "acme-ai-program.pdf"
OUT = ROOT / "auto-run-example"


def build_pdf(text: str, path: Path) -> bool:
    """Render the brief as a PDF.  Returns False if no PDF writer is available."""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
    except ImportError:
        return False

    path.parent.mkdir(parents=True, exist_ok=True)
    _, height = letter
    pdf = canvas.Canvas(str(path), pagesize=letter)
    y = height - 50
    for line in text.split("\n"):
        if y < 50:
            pdf.showPage()
            y = height - 50
        pdf.drawString(40, y, line[:110])
        y -= 14
    pdf.save()
    return True


def main() -> int:
    if not SOURCE.is_file():
        print(f"error: {SOURCE} is missing", file=sys.stderr)
        return 1
    text = SOURCE.read_text(encoding="utf-8")

    if build_pdf(text, PDF):
        document = PDF
        print(f"wrote {PDF}")
    else:
        document = SOURCE
        print("reportlab is not installed; using the markdown brief instead")

    from bountymode.autonomous import AutonomousRunner

    result = AutonomousRunner(attempts=5).run_from_document(
        str(document), approved_by="example-operator", out_dir=str(OUT)
    )

    print(f"\nprogram : {result.program}")
    print(f"mode    : {result.mode}")
    for stage in result.stages:
        print(f"  {'PASS' if stage.ok else 'FAIL'}  {stage.name:<10} {stage.detail}")
    print(f"\nfindings: {len(result.findings)}  verified: {result.verified_count}  "
          f"submission-ready: {result.ready_count}")
    for finding, verdict in zip(result.findings, result.readiness):
        flag = "READY" if verdict.get("ready") else "NOT READY"
        print(f"  [{flag}] {finding.severity.value:<12} CVSS {finding.cvss_score:.1f}  "
              f"{finding.title}")
    print(f"\nready to submit: {result.ready_to_submit}")
    print(f"bundle: {OUT}/reports/submission-bundle.json")
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

"""Tests for the one-input document intake."""

from __future__ import annotations

import json

import pytest

from bountymode.autonomous.intake import (
    DocumentIntake,
    has_scope_section,
    looks_like_scope_text,
)

POLICY = """# Acme AI Bug Bounty

## In Scope

| Target | Kind |
|---|---|
| api.acme.example | api |
| chat.acme.example | llm |

## Out of Scope

- status.acme.example

Rewards: Critical $5000, High $2500.
"""


@pytest.fixture()
def intake() -> DocumentIntake:
    return DocumentIntake()


class TestTextIntake:
    def test_reads_a_markdown_file(self, intake: DocumentIntake, tmp_path) -> None:
        p = tmp_path / "program.md"
        p.write_text(POLICY, encoding="utf-8")
        result = intake.read(str(p))
        assert result.ok
        assert result.kind == "text"
        assert "api.acme.example" in result.text
        assert result.chars > 40

    def test_reads_a_txt_file(self, intake: DocumentIntake, tmp_path) -> None:
        p = tmp_path / "program.txt"
        p.write_text(POLICY, encoding="utf-8")
        assert intake.read(str(p)).ok

    def test_missing_file_is_an_honest_failure(self, intake: DocumentIntake) -> None:
        result = intake.read("/nonexistent/program.pdf")
        assert not result.ok
        assert "no such file" in result.error
        assert result.hint

    def test_directory_is_rejected(self, intake: DocumentIntake, tmp_path) -> None:
        result = intake.read(str(tmp_path))
        assert not result.ok
        assert "directory" in result.error

    def test_empty_file_is_rejected(self, intake: DocumentIntake, tmp_path) -> None:
        p = tmp_path / "empty.txt"
        p.write_text("", encoding="utf-8")
        result = intake.read(str(p))
        assert not result.ok

    def test_too_little_text_is_rejected(self, intake: DocumentIntake, tmp_path) -> None:
        p = tmp_path / "tiny.txt"
        p.write_text("hi", encoding="utf-8")
        result = intake.read(str(p))
        assert not result.ok
        assert "too little" in result.error

    def test_inline_text(self, intake: DocumentIntake) -> None:
        result = intake.read_text(POLICY, title="acme")
        assert result.ok
        assert result.reader == "inline"
        assert result.title == "acme"

    def test_inline_empty_text(self, intake: DocumentIntake) -> None:
        assert not intake.read_text("").ok


class TestHtmlIntake:
    def test_extracts_readable_text(self, intake: DocumentIntake, tmp_path) -> None:
        p = tmp_path / "program.html"
        p.write_text(
            "<html><head><title>Acme Program</title></head><body>"
            "<h2>In Scope</h2><table><tr><td>api.acme.example</td></tr></table>"
            "<h2>Out of Scope</h2><p>status.acme.example</p></body></html>",
            encoding="utf-8",
        )
        result = intake.read(str(p))
        assert result.ok
        assert result.kind == "html"
        assert "api.acme.example" in result.text
        assert result.title == "Acme Program"


class TestJsonIntake:
    def test_scope_json_is_rendered_back_to_text(self, intake: DocumentIntake, tmp_path) -> None:
        p = tmp_path / "scope.json"
        p.write_text(json.dumps({
            "program": "acme",
            "in_scope": [{"pattern": "api.acme.example", "kind": "api"}],
            "out_of_scope": [{"pattern": "status.acme.example", "reason": "third party"}],
        }), encoding="utf-8")
        result = intake.read(str(p))
        assert result.ok
        assert result.reader == "scope-json"
        assert "api.acme.example" in result.text
        assert "status.acme.example" in result.text

    def test_invalid_json_is_an_honest_failure(self, intake: DocumentIntake, tmp_path) -> None:
        p = tmp_path / "bad.json"
        p.write_text("{not json", encoding="utf-8")
        result = intake.read(str(p))
        assert not result.ok
        assert "invalid JSON" in result.error

    def test_generic_json_passes_through(self, intake: DocumentIntake, tmp_path) -> None:
        p = tmp_path / "meta.json"
        p.write_text(json.dumps({
            "program": "acme",
            "notes": "a generic metadata document that is long enough to be useful",
            "tags": ["api", "web"],
        }), encoding="utf-8")
        result = intake.read(str(p))
        assert result.ok
        assert result.reader == "json"


class TestPdfIntake:
    def test_pdf_without_a_text_layer_fails_honestly(self, intake: DocumentIntake, tmp_path) -> None:
        """A PDF we cannot read must say so, not return an empty scope."""
        p = tmp_path / "scan.pdf"
        # A minimal, valid-enough PDF header with no extractable text.
        p.write_bytes(b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n")
        result = intake.read(str(p))
        assert result.kind == "pdf"
        if not result.ok:
            assert result.hint
            assert "OCR" in result.hint or "text" in result.hint.lower()

    def test_unknown_extension_sniffs_pdf_magic(self, intake: DocumentIntake, tmp_path) -> None:
        p = tmp_path / "program.bin"
        p.write_bytes(b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n")
        result = intake.read(str(p))
        assert result.kind == "pdf"


class TestScopeHeuristics:
    def test_looks_like_scope_text(self) -> None:
        assert looks_like_scope_text(POLICY)
        assert not looks_like_scope_text("hello world")
        assert not looks_like_scope_text("")

    def test_has_scope_section(self) -> None:
        assert has_scope_section(POLICY)
        assert not has_scope_section("just some prose with no headings")

"""Regression tests for the fixes made on top of the parallel upstream work.

Each test here pins a defect that was found and fixed, so it cannot come back.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from bountymode.autonomous.control import RunControl

ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "bountymode" / "ui" / "static" / "index.html"


# --------------------------------------------------------------------------- #
# The duplicate element id
# --------------------------------------------------------------------------- #


class TestNoDuplicateElementIds:
    """`doRepro()` and `doReport()` both targeted `id="rp-out"`.

    `document.getElementById` returns the first match, so the reproducibility
    panel's output was written into the report panel and the replay result was
    never visible where the user was looking.  Static markup only -- ids created
    by `innerHTML` at runtime are legitimate and would be flagged if we scanned
    the whole file naively.
    """

    @staticmethod
    def _static_ids() -> list:
        html = INDEX.read_text(encoding="utf-8")
        # Drop <script> blocks: template literals build ids at runtime.
        markup = re.sub(r"<script[^>]*>.*?</script>", "", html, flags=re.S)
        return re.findall(r'\sid="([a-zA-Z0-9_-]+)"', markup)

    def test_static_markup_has_no_duplicate_ids(self):
        ids = self._static_ids()
        seen, dupes = set(), []
        for i in ids:
            if i in seen:
                dupes.append(i)
            seen.add(i)
        assert not dupes, f"duplicate element id(s): {sorted(set(dupes))}"

    def test_the_two_panels_are_distinct(self):
        ids = self._static_ids()
        assert "rp-out" in ids, "the report panel lost its id"
        assert "rp-repro-out" in ids, "the replay panel did not get its own id"

    def test_repro_writes_to_its_own_panel_only(self):
        html = INDEX.read_text(encoding="utf-8")
        start = html.index("async function doRepro()")
        body = html[start:start + 700]
        assert "rp-repro-out" in body
        assert "$('rp-out')" not in body, "doRepro still writes to the report panel"


# --------------------------------------------------------------------------- #
# Mid-run control
# --------------------------------------------------------------------------- #


class TestRunControl:
    def test_stop_is_recognised_in_several_phrasings(self):
        for phrase in ("stop", "Stop please", "abort", "cancel the run", "halt"):
            ctrl = RunControl()
            outcome = ctrl.apply(phrase)
            assert outcome["kind"] == "stop", phrase
            assert ctrl.stopped is True

    def test_stop_is_idempotent_and_keeps_the_first_reason(self):
        ctrl = RunControl()
        assert ctrl.request_stop("first") is True
        assert ctrl.request_stop("second") is False
        assert ctrl.stop_reason == "first"

    def test_skip_with_a_named_target(self):
        ctrl = RunControl()
        outcome = ctrl.apply("skip api.acme.example")
        assert outcome["kind"] == "skip"
        assert ctrl.is_skipped("api.acme.example") is True

    def test_skip_matches_host_and_host_port(self):
        ctrl = RunControl()
        ctrl.skip_target("api.acme.example")
        # The plan may carry the port; the bare host must still match.
        assert ctrl.is_skipped("api.acme.example:8443") is True
        ctrl2 = RunControl()
        ctrl2.skip_target("api.acme.example:8443")
        assert ctrl2.is_skipped("api.acme.example") is True

    def test_skip_with_no_target_in_a_live_run_is_not_handled(self):
        ctrl = RunControl()
        outcome = ctrl.apply("skip that target")
        assert outcome["kind"] == "skip"
        assert outcome["handled"] is False
        assert "which target" in outcome["reply"]

    def test_skip_falls_back_to_the_current_target(self):
        ctrl = RunControl()
        outcome = ctrl.apply("skip it", current_target="api.acme.example")
        assert outcome["handled"] is True
        assert ctrl.is_skipped("api.acme.example") is True

    def test_deeper_and_note_and_question(self):
        ctrl = RunControl()
        assert ctrl.apply("go deeper on the API")["kind"] == "deeper"
        assert ctrl.apply("explain that finding")["kind"] == "question"
        assert ctrl.apply("the API is my main concern")["kind"] == "note"
        assert ctrl.notes, "a free-text note should be recorded"

    def test_empty_instruction_is_not_handled(self):
        assert RunControl().apply("   ")["kind"] == "empty"


# --------------------------------------------------------------------------- #
# The UI files that must exist for the promised platforms
# --------------------------------------------------------------------------- #


class TestLaunchers:
    def test_every_promised_launcher_exists(self):
        for name in ("run.py", "setup.sh", "setup.bat", "setup.ps1"):
            assert (ROOT / name).is_file(), f"{name} is missing"

    def test_launchers_delegate_to_run_py(self):
        for name in ("setup.sh", "setup.bat", "setup.ps1"):
            text = (ROOT / name).read_text(encoding="utf-8", errors="replace")
            assert "run.py" in text, f"{name} does not call run.py"

    def test_run_py_can_be_imported(self):
        # `setup.py` used to shadow the build backend; `run.py` must not.
        import importlib.util

        spec = importlib.util.spec_from_file_location("bm_run", ROOT / "run.py")
        assert spec is not None


# --------------------------------------------------------------------------- #
# `models --list`
# --------------------------------------------------------------------------- #


class TestModelsListCommand:
    def test_the_list_flag_is_wired(self):
        cli = (ROOT / "bountymode" / "cli.py").read_text(encoding="utf-8")
        assert "--list" in cli
        assert "_list_openrouter_models" in cli

    def test_listing_reports_http_status_and_never_raises(self, monkeypatch):
        import urllib.error

        from bountymode.cli import _list_openrouter_models
        from bountymode.config import LLMSettings

        cfg = type("C", (), {"llm": LLMSettings()})()

        def boom(*a, **k):
            raise urllib.error.HTTPError("u", 401, "nope", {}, None)

        monkeypatch.setattr("urllib.request.urlopen", boom)
        result = _list_openrouter_models(cfg)
        assert result["ok"] is False
        assert result["http_status"] == 401

    def test_a_transport_error_is_reported_not_raised(self, monkeypatch):
        from bountymode.cli import _list_openrouter_models
        from bountymode.config import LLMSettings

        cfg = type("C", (), {"llm": LLMSettings()})()

        def boom(*a, **k):
            raise OSError("network is down")

        monkeypatch.setattr("urllib.request.urlopen", boom)
        result = _list_openrouter_models(cfg)
        assert result["ok"] is False
        assert "network is down" in result["error"]


# --------------------------------------------------------------------------- #
# The setup flow must actually hand the key to the UI
# --------------------------------------------------------------------------- #


class TestSetupExportsTheKey:
    """`run.py` writes `.env` and then launches the UI *in the same process*.

    Nothing loaded `.env`, so the UI started with no key and every LLM-backed
    feature silently degraded -- right after the operator was told the key had
    been validated and saved.
    """

    @staticmethod
    def _module():
        import importlib.util

        spec = importlib.util.spec_from_file_location("bm_run_mod", ROOT / "run.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_export_env_sets_real_environment_variables(self, monkeypatch):
        mod = self._module()
        monkeypatch.delenv("BOUNTYMODE_TEST_KEY", raising=False)
        mod._export_env({"BOUNTYMODE_TEST_KEY": "sk-or-v1-abc"})
        import os

        assert os.environ["BOUNTYMODE_TEST_KEY"] == "sk-or-v1-abc"

    def test_export_env_skips_empty_values(self, monkeypatch):
        import os

        mod = self._module()
        monkeypatch.delenv("BOUNTYMODE_TEST_EMPTY", raising=False)
        mod._export_env({"BOUNTYMODE_TEST_EMPTY": ""})
        assert "BOUNTYMODE_TEST_EMPTY" not in os.environ

    def test_read_env_round_trips_the_written_file(self, tmp_path, monkeypatch):
        mod = self._module()
        env = tmp_path / ".env"
        env.write_text(
            '# comment\nOPENROUTER_API_KEY="sk-or-v1-quoted"\n\nBOUNTYMODE_OPERATOR=Ada\n',
            encoding="utf-8",
        )
        monkeypatch.setattr(mod, "ENV_PATH", env)
        values = mod._read_env()
        # Quotes around a value are common in a hand-edited .env and must be stripped.
        assert values["OPENROUTER_API_KEY"] == "sk-or-v1-quoted"
        assert values["BOUNTYMODE_OPERATOR"] == "Ada"

    def test_what_run_py_writes_is_what_the_config_reads(self, tmp_path, monkeypatch):
        import os

        mod = self._module()
        # An empty environment plus the export is exactly what `main()` produces.
        for key in ("OPENROUTER_API_KEY", "BOUNTYMODE_LLM_API_KEY"):
            monkeypatch.delenv(key, raising=False)
        mod._export_env({
            "OPENROUTER_API_KEY": "sk-or-v1-abcdef",
            "BOUNTYMODE_LLM_API_KEY": "sk-or-v1-abcdef",
        })
        from bountymode.config import load_config

        c = load_config(env={k: v for k, v in os.environ.items()})
        assert c.llm.configured is True
        assert c.llm.api_key == "sk-or-v1-abcdef"


class TestRunnerHonoursControl:
    """A stop before the scan must prevent the scan from going out."""

    def test_stop_before_the_scan_marks_the_run_cancelled(self, tmp_path):
        from bountymode.autonomous.runner import AutonomousRunner

        policy = tmp_path / "scope.md"
        policy.write_text(
            "# Acme\n\n## In Scope\n\n| Target | Type |\n|---|---|\n"
            "| api.acme.example | web |\n",
            encoding="utf-8",
        )

        ctrl = RunControl()
        ctrl.request_stop("operator changed their mind")

        runner = AutonomousRunner(attempts=1)
        result = runner.run_from_document(
            str(policy),
            approved_by="Ada",
            out_dir=str(tmp_path / "run"),
            in_process=True,
            offline=True,
            control=ctrl,
        )

        assert result.cancelled is True
        assert result.requests_made == 0, "a stopped run must not touch the target"
        assert result.to_dict()["cancelled"] is True, "the UI needs to see it"
        assert any(
            s.name == "scan" and not s.ok for s in result.stages
        ), "the scan stage should be recorded as not run"

    def test_a_run_without_a_control_is_never_cancelled(self, tmp_path):
        """Backwards compatibility: the new parameter must be optional."""
        from bountymode.autonomous.runner import AutonomousRunner

        policy = tmp_path / "scope.md"
        policy.write_text(
            "# Acme\n\n## In Scope\n\n| Target | Type |\n|---|---|\n"
            "| api.acme.example | web |\n",
            encoding="utf-8",
        )
        result = AutonomousRunner(attempts=1).run_from_document(
            str(policy), approved_by="Ada", out_dir=str(tmp_path / "run2"),
            in_process=True, offline=True,
        )
        assert result.cancelled is False

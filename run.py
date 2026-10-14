#!/usr/bin/env python3
"""One-click setup for Bounty Mode.

Cross-platform: works on Linux, macOS and Windows with a stock Python 3.9+.

It does three things, and asks for only two inputs:

1. installs the package and its dependencies into the current interpreter;
2. asks for your **OpenRouter API key** and your **name**, writes them to
   ``.env`` (which is gitignored), and validates the key against OpenRouter;
3. launches the web UI.

Run it directly::

    python run.py

or, on a fresh checkout, ``./setup.sh`` (POSIX) / ``setup.bat`` (Windows), which
just call this file.

This file is named ``run.py``, not ``setup.py``, on purpose: a ``setup.py`` at
the repository root shadows the build backend and makes ``pip install -e .``
execute this script instead of building the package.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ENV_PATH = ROOT / ".env"
OPENROUTER_MODELS = "https://openrouter.ai/api/v1/models"
OPENROUTER_KEY = "https://openrouter.ai/api/v1/key"


def _say(msg: str) -> None:
    print(msg, flush=True)


def _ask(prompt: str, *, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    try:
        answer = input(f"{prompt}{suffix}: ").strip()
    except EOFError:
        answer = ""
    return answer or default


def _read_env() -> dict:
    values: dict = {}
    if ENV_PATH.exists():
        for line in ENV_PATH.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip()
    return values


def _write_env(values: dict) -> None:
    lines = [
        "# Written by run.py -- do not commit this file.",
        f"OPENROUTER_API_KEY={values.get('OPENROUTER_API_KEY', '')}",
        f"BOUNTYMODE_LLM_API_KEY={values.get('OPENROUTER_API_KEY', '')}",
        f"BOUNTYMODE_OPERATOR={values.get('BOUNTYMODE_OPERATOR', '')}",
        "BOUNTYMODE_LLM_MODEL=openrouter/free",
    ]
    ENV_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        os.chmod(ENV_PATH, 0o600)
    except OSError:
        pass  # Windows has no POSIX mode bits


def _ensure_gitignored() -> None:
    """Make sure ``.env`` can never be committed."""
    gitignore = ROOT / ".gitignore"
    entry = ".env"
    existing = gitignore.read_text(encoding="utf-8") if gitignore.exists() else ""
    if entry not in existing.split():
        with gitignore.open("a", encoding="utf-8") as fh:
            if existing and not existing.endswith("\n"):
                fh.write("\n")
            fh.write(f"{entry}\n")
        _say("  added .env to .gitignore")


def install() -> bool:
    _say("\n[1/3] Installing Bounty Mode and its dependencies ...")
    cmd = [sys.executable, "-m", "pip", "install", "-e", ".[all]"]
    try:
        subprocess.check_call(cmd, cwd=str(ROOT))
    except subprocess.CalledProcessError:
        _say("  the 'all' extra failed; retrying with the core install ...")
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "-e", "."], cwd=str(ROOT)
            )
        except subprocess.CalledProcessError as exc:
            _say(f"  install failed: {exc}")
            return False
    _say("  installed.")
    return True


def validate_key(key: str) -> tuple:
    """Return ``(ok, message)`` for an OpenRouter key."""
    if not key:
        return False, "no key supplied"
    req = urllib.request.Request(
        OPENROUTER_KEY,
        headers={"Authorization": f"Bearer {key}", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
            data = json.loads(resp.read().decode("utf-8", "replace"))
        info = data.get("data", data)
        label = info.get("label") or info.get("name") or "key"
        return True, f"key accepted ({label})"
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            return False, "OpenRouter rejected the key (401/403)"
        return False, f"OpenRouter returned HTTP {exc.code}"
    except Exception as exc:  # noqa: BLE001
        return False, f"could not reach OpenRouter: {exc}"


def configure() -> dict:
    _say("\n[2/3] Configuration")
    values = _read_env()
    key = values.get("OPENROUTER_API_KEY", "")
    if not key:
        key = _ask("  OpenRouter API key (sk-or-...)")
    else:
        _say("  found an existing key in .env")
    name = values.get("BOUNTYMODE_OPERATOR", "") or _ask("  Your name (the human approver)")

    ok, message = validate_key(key)
    _say(f"  {message}")
    if not ok:
        _say("  The key was not accepted. You can still continue and fix .env later;")
        _say("  the UI will run in dry-run mode until a valid key is present.")
        if _ask("  Save it anyway? (y/n)", default="y").lower().startswith("n"):
            return {}

    values["OPENROUTER_API_KEY"] = key
    values["BOUNTYMODE_OPERATOR"] = name
    _write_env(values)
    _ensure_gitignored()
    _say(f"  wrote {ENV_PATH} (gitignored)")
    return values


def launch() -> int:
    _say("\n[3/3] Launching the UI at http://127.0.0.1:8765 ...")
    _say("  press Ctrl+C to stop.")
    try:
        from bountymode.ui.app import main as ui_main

        ui_main()
        return 0
    except ImportError:
        _say("  the UI extra is not installed; run: pip install -e '.[ui]'")
        return 1
    except KeyboardInterrupt:
        _say("\n  stopped.")
        return 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    _say("=" * 68)
    _say("  Bounty Mode -- one-click setup")
    _say("  Authorized testing only. Point it at assets you own or may test.")
    _say("=" * 68)

    if "--no-install" not in argv and not install():
        return 1
    values = configure()
    if not values:
        _say("\n  setup stopped before writing .env.")
        return 1
    if "--no-launch" in argv:
        _say("\n  setup complete. Start the UI with: python -m bountymode.ui")
        return 0
    return launch()


if __name__ == "__main__":
    raise SystemExit(main())

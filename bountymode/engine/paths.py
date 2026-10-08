"""Locate the vendored engine and make it importable.

The engine (the offensive AI red-teaming toolkit) lives in the top-level
``engine/`` directory of this repository.  It used to be a separate repository
consumed over HTTP; it is now vendored so that a run can execute entirely
in-process, with no second repository and no network hop.

Two things make that work:

* :func:`engine_root` finds the directory.
* :func:`ensure_on_path` prepends it to :data:`sys.path` so the engine's own
  absolute imports (``from attacks.base_tester import ...``,
  ``from agathon.plugins.registry import ...``) resolve exactly as they did in
  the original repository.  No engine source file needs to change.

An operator can point at a different checkout with the ``BOUNTYMODE_ENGINE_PATH``
environment variable, which is useful when working on the engine itself.
"""

from __future__ import annotations

import contextlib
import io
import logging
import os
import sys
from functools import lru_cache

log = logging.getLogger(__name__)

#: Environment variable that overrides the engine location.
ENGINE_PATH_ENV = "BOUNTYMODE_ENGINE_PATH"


@lru_cache(maxsize=1)
def engine_root() -> str:
    """Absolute path to the vendored engine directory."""
    override = os.environ.get(ENGINE_PATH_ENV, "").strip()
    if override:
        return os.path.abspath(override)
    # __file__ -> <repo>/bountymode/engine/paths.py
    here = os.path.dirname(os.path.abspath(__file__))
    package = os.path.dirname(here)          # <repo>/bountymode
    repo = os.path.dirname(package)          # <repo>
    return os.path.join(repo, "engine")


def engine_available() -> bool:
    """True when the vendored engine directory looks complete."""
    root = engine_root()
    return os.path.isdir(os.path.join(root, "attacks")) and os.path.isfile(
        os.path.join(root, "forgeguard_bridge.py")
    )


def ensure_on_path() -> str:
    """Prepend the engine root to ``sys.path`` and return it.

    Idempotent, so it is safe to call from every entry point.
    """
    root = engine_root()
    if root not in sys.path:
        sys.path.insert(0, root)
    return root


@contextlib.contextmanager
def quiet_engine_boot():
    """Capture the engine's import-time diagnostics.

    While it initialises, the engine writes progress lines to stdout (optional
    dependencies that are absent, catalogue fallbacks).  They are useful when
    debugging the engine itself, but they would corrupt this toolkit's
    machine-readable CLI output, so the first import of an engine module is
    performed with stdout/stderr captured and re-emitted at DEBUG level.
    """
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        yield
    for stream in (out, err):
        text = stream.getvalue().strip()
        if text:
            log.debug("[engine] %s", text.replace("\n", " | "))

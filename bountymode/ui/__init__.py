"""Local web UI for Bounty Mode.

A thin FastAPI layer over the *real* library functions -- every endpoint calls
the same code the CLI calls.  There are no mockups and no dead controls.

Launch with::

    python -m bountymode.ui
    # or
    bountymode-ui
"""

from __future__ import annotations

from .app import create_app

__all__ = ["create_app"]

"""
FastAPI application entry — delegates to Agathon orchestrator.

Deploy: ``uvicorn api.app:app`` or ``uvicorn main:app`` (main re-exports this).
"""

from agathon.orchestrator import app

__all__ = ["app"]

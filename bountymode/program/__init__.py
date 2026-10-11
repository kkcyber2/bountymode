"""Program onboarding.

Turns a public bug-bounty program page into a draft, human-reviewable scope,
and drives the guided pipeline that follows from it.

    fetch  ->  extract  ->  review  ->  confirm  ->  scan  ->  verify  ->  report

The fetch layer produces text; the extractor turns that text into a
:class:`~bountymode.models.ProgramScope` plus an :class:`ExtractionReport` that
records every uncertainty; the importer writes the files and issues an
authorization receipt that a live run must present; the pipeline chains the
seven stages so a new user never has to learn them individually.

The guiding rule for the whole package: **never invent scope.**  Anything the
extractor is not sure about is left out of the machine-enforced scope and
listed as a ``VERIFY`` marker for a human to resolve.
"""

from __future__ import annotations

from .extractor import ExtractedProgram, ExtractionReport, ProgramExtractor
from .fetcher import FetchResult, ProgramFetcher, normalise_pasted, snapshot_to_text
from .importer import AuthorizationReceipt, ImportResult, ProgramImporter, scope_hash
from .pipeline import GuidedPipeline, PipelineResult, StageOutcome
from .verifier import (
    FindingVerifier,
    ReadinessCheck,
    SubmissionReadiness,
    SubmissionReadinessChecker,
    VerificationResult,
)
from .watch import ProgramWatcher, WatchRun, WatchState

__all__ = [
    "ProgramFetcher",
    "FetchResult",
    "snapshot_to_text",
    "normalise_pasted",
    "ProgramExtractor",
    "ExtractedProgram",
    "ExtractionReport",
    "ProgramImporter",
    "ImportResult",
    "AuthorizationReceipt",
    "scope_hash",
    "GuidedPipeline",
    "PipelineResult",
    "StageOutcome",
    "FindingVerifier",
    "VerificationResult",
    "SubmissionReadiness",
    "SubmissionReadinessChecker",
    "ReadinessCheck",
    "ProgramWatcher",
    "WatchRun",
    "WatchState",
]

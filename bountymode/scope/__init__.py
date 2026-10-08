"""Scope handling: import a program policy, then match targets against it."""

from .importer import ScopeImporter
from .matcher import host_matches, resolve_scope, target_matches_pattern

__all__ = [
    "ScopeImporter",
    "host_matches",
    "resolve_scope",
    "target_matches_pattern",
]

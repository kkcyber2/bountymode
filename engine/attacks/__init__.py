# attacks/__init__.py
"""
AI Red Teaming Toolkit - Attack Modules

A comprehensive suite of LLM attack modules organized by difficulty level.
All attacks inherit from BaseTester and return standardized AttackResult objects.

New in this version:
- Unified AttackResult dataclass for all attacks
- Clear difficulty levels: Easy, Medium, Hard, Experimental
- Improved bug fixes (especially data_exfiltration.py)
- 5 new sophisticated attacks
- Full type hints and professional logging

Difficulty Levels:
- EASY: Basic attacks, low risk, suitable for initial testing
- MEDIUM: Moderate complexity, real impact, requires some craft
- HARD: Advanced techniques, high success rates, sophisticated
- EXPERIMENTAL: Novel approaches, untested, may have variable results

Attack Modules:
"""

from .base_tester import (
    BaseTester,
    AttackResult,
    DifficultyLevel,
    VulnerabilityType,
)

# Existing attacks (compatible, will be upgraded)
from .prompt_injection import PromptInjectionTester
from .data_exfiltration import DataExfiltrationTester
from .context_manipulation import ContextManipulationTester
from .model_misuse import ModelMisuseTester
from .adversarial_robustness import AdversarialRobustnessTester
from .token_smuggling import TokenSmugglingTester

# New attacks
from .chain_of_thought_hijacking import ChainOfThoughtHijackingTester
from .invisible_command_injection import InvisibleCommandInjectionTester
from .system_prompt_extraction import SystemPromptExtractionTester
from .emotional_manipulation import EmotionalManipulationTester
from .rag_poisoning import RAGPoisoningTester
from .autonomous_adversary import AutonomousAdversary
from .logic_jailbreak import LogicJailbreakTester

__all__ = [
    # Base classes
    "BaseTester",
    "AttackResult",
    "DifficultyLevel",
    "VulnerabilityType",
    # Existing attacks
    "PromptInjectionAttack",
    "DataExfiltrationTester",
    "ContextManipulationTester",
    "ModelMisuseAttacks",
    "AdversarialRobustnessTester",
    "TokenSmugglingTester",
    # New attacks
    "ChainOfThoughtHijackingTester",
    "InvisibleCommandInjectionTester",
    "SystemPromptExtractionTester",
    "EmotionalManipulationTester",
    "RAGPoisoningTester",
    "AutonomousAdversary",
    "LogicJailbreakTester",
]
# attacks/base_tester.py
"""
Base module for AI Red Teaming Toolkit.

Provides standardized interfaces and dataclasses for all attack modules.
All attacks inherit from BaseTester and return AttackResult objects.

Target HTTP: callers MUST pass an OpenAI-compatible client constructed with
the scan-form API key (agathon.target_client.build_target_client). Do NOT
default to os.environ GROQ_API_KEY / OPENROUTER_API_KEY for target strikes.

This ensures:
- Consistency across all attack types
- Easy integration with scoring_engine.py and report_generator.py
- Clear difficulty levels (Easy, Medium, Hard, Experimental)
- Proper logging and error handling
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
import json


class DifficultyLevel(Enum):
    """Attack complexity and impact classification."""
    EASY = "Easy"                      # Basic, low-risk tests
    MEDIUM = "Medium"                  # Moderate complexity, real impact
    HARD = "Hard"                      # Advanced techniques, high success rate
    EXPERIMENTAL = "Experimental"      # Novel, untested approaches


class VulnerabilityType(Enum):
    """Standardized vulnerability categories for LLM attacks."""
    PROMPT_INJECTION = "Prompt Injection"
    DATA_EXFILTRATION = "Data Exfiltration"
    JAILBREAK = "Jailbreak"
    CONTEXT_MANIPULATION = "Context Manipulation"
    TOKEN_SMUGGLING = "Token Smuggling"
    ADVERSARIAL_ROBUSTNESS = "Adversarial Robustness"
    MODEL_MISUSE = "Model Misuse"
    CHAIN_OF_THOUGHT_HIJACKING = "Chain-of-Thought Hijacking"
    INVISIBLE_INJECTION = "Invisible Command Injection"
    SYSTEM_PROMPT_EXTRACTION = "System Prompt Extraction"
    EMOTIONAL_MANIPULATION = "Emotional Manipulation"
    RAG_POISONING = "RAG Poisoning"


@dataclass
class AttackResult:
    """
    Standardized result object for all attack modules.
    
    This dataclass captures the complete attack outcome, evidence, and metadata.
    Compatible with scoring_engine.py and report_generator.py.
    
    Attributes:
        attack_type: The specific attack technique name.
        vulnerability_type: Standardized VulnerabilityType enum.
        difficulty: Attack complexity level (DifficultyLevel enum).
        success: Boolean indicating if attack succeeded.
        success_score: Confidence score (0.0-1.0) of successful exploitation.
        evidence: Raw evidence (response, behavior, or data) from attack.
        target_model: Name of the targeted LLM model.
        payload_used: The exact prompt/input that triggered the vulnerability.
        response: The LLM's response to the attack payload.
        exploitability: Estimated ease of exploitation in production (0.0-1.0).
        impact: Severity of successful exploitation (0.0-1.0).
        reliability: Consistency of attack success across multiple runs (0.0-1.0).
        recommended_fix: Remediation suggestion.
        cwe_references: List of related CWE IDs (e.g., ["CWE-74", "CWE-77"]).
        tags: Searchable tags (e.g., ["unicode", "homoglyph", "filter-bypass"]).
        metadata: Additional attack-specific data.
        timestamp: ISO 8601 timestamp of attack execution.
        duration_ms: Total execution time in milliseconds.
    """
    
    attack_type: str                        # Specific attack name (e.g., "homoglyph_attack")
    vulnerability_type: VulnerabilityType  # Standardized category
    difficulty: DifficultyLevel             # Attack complexity
    success: bool                           # Did attack succeed?
    success_score: float                    # 0.0-1.0 confidence
    evidence: str                           # Raw evidence (what proves success?)
    target_model: str                       # Target LLM name/version
    payload_used: str                       # Attack payload/prompt
    response: str                           # LLM's response
    exploitability: float = 0.5             # 0.0-1.0: how easy to exploit?
    impact: float = 0.5                     # 0.0-1.0: harm if exploited?
    reliability: float = 0.5                # 0.0-1.0: success consistency?
    recommended_fix: str = ""               # Mitigation advice
    cwe_references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    duration_ms: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "attack_type": self.attack_type,
            "vulnerability_type": self.vulnerability_type.value,
            "difficulty": self.difficulty.value,
            "success": self.success,
            "success_score": self.success_score,
            "evidence": self.evidence,
            "target_model": self.target_model,
            "payload_used": self.payload_used,
            "response": self.response[:500],  # Truncate long responses
            "exploitability": self.exploitability,
            "impact": self.impact,
            "reliability": self.reliability,
            "recommended_fix": self.recommended_fix,
            "cwe_references": self.cwe_references,
            "tags": self.tags,
            "metadata": self.metadata,
            "timestamp": self.timestamp,
            "duration_ms": self.duration_ms,
        }
    
    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), indent=2, default=str)


class BaseTester:
    """
    Abstract base class for all attack modules.
    
    All attack classes should inherit from this and implement:
    - run_attack() or specific attack methods
    - Proper logging via self.logger
    - Return AttackResult objects
    
    Usage:
        class MyAttacker(BaseTester):
            def __init__(self, llm_client):
                super().__init__("My Attack", logger=logging.getLogger(__name__))
                self.llm_client = llm_client
            
            def run_attack(self, target_model, **kwargs) -> AttackResult:
                # Implementation here
                pass
    """
    
    def __init__(
        self,
        attack_name: str,
        logger: Optional[logging.Logger] = None,
    ):
        """
        Initialize base tester.
        
        Args:
            attack_name: Human-readable name of this attack (e.g., "Token Smuggling")
            logger: Logger instance (creates one if not provided)
        """
        self.attack_name = attack_name
        self.logger = logger or self._get_default_logger()
    
    @staticmethod
    def _get_default_logger() -> logging.Logger:
        """Get or create a logger for the attack module."""
        logger = logging.getLogger(__name__)
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        return logger
    
    def create_result(
        self,
        attack_type: str,
        vulnerability_type: VulnerabilityType,
        difficulty: DifficultyLevel,
        success: bool,
        success_score: float,
        evidence: str,
        payload_used: str,
        response: str,
        target_model: str = "unknown",
        exploitability: float = 0.5,
        impact: float = 0.5,
        reliability: float = 0.5,
        recommended_fix: str = "",
        cwe_references: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        duration_ms: float = 0.0,
    ) -> AttackResult:
        """
        Factory method to create standardized AttackResult.
        
        Args:
            attack_type: Specific attack technique name
            vulnerability_type: VulnerabilityType enum value
            difficulty: DifficultyLevel enum value
            success: Whether attack succeeded
            success_score: 0.0-1.0 confidence score
            evidence: What proves the attack worked
            target_model: Target LLM model name
            payload_used: The attack payload
            response: LLM's response
            exploitability: 0.0-1.0 ease of exploitation
            impact: 0.0-1.0 severity of impact
            reliability: 0.0-1.0 consistency of success
            recommended_fix: Suggested mitigation
            cwe_references: List of CWE IDs
            tags: Searchable tags
            metadata: Additional data
            duration_ms: Execution time in milliseconds
        
        Returns:
            AttackResult object ready for scoring and reporting
        """
        return AttackResult(
            attack_type=attack_type,
            vulnerability_type=vulnerability_type,
            difficulty=difficulty,
            success=success,
            success_score=success_score,
            evidence=evidence,
            target_model=target_model,
            payload_used=payload_used,
            response=response,
            exploitability=exploitability,
            impact=impact,
            reliability=reliability,
            recommended_fix=recommended_fix,
            cwe_references=cwe_references or [],
            tags=tags or [],
            metadata=metadata or {},
            duration_ms=duration_ms,
        )
    
    def log_attack_start(self, target: str, difficulty: str):
        """Log the start of an attack."""
        self.logger.info(
            f"[{difficulty}] Starting {self.attack_name} against {target}"
        )
    
    def log_attack_result(self, success: bool, reason: str):
        """Log the result of an attack."""
        status = "SUCCESS" if success else "FAILED"
        self.logger.info(f"Attack {status}: {reason}")
    
    def log_error(self, error: Exception):
        """Log an attack error."""
        self.logger.error(f"Attack error in {self.attack_name}: {error}", exc_info=True)

    @staticmethod
    def is_rate_limited_response(response: str) -> bool:
        """True when target or brain returned HTTP 429 / rate-limit text."""
        text = (response or "").lower()
        return (
            "[http-429]" in text
            or "429" in text
            or "rate limit" in text
            or "too many requests" in text
        )

    @staticmethod
    def sovereign_probe_delay_seconds() -> float:
        """Fixed inter-probe delay for Sovereign operators (trial lockout guard)."""
        return 5.0

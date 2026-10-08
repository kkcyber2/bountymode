# config.py — Upgraded with proper Config class and validation

import os
import logging
from typing import Dict, Any, Optional
from dataclasses import dataclass, field


@dataclass
class Config:
    """
    Central configuration object for the AI Red Teaming toolkit.
    All settings are loaded from environment variables with sane defaults.
    """

    # --- API Keys ---
    openai_api_key: str = field(default_factory=lambda: os.getenv("OPENAI_API_KEY", ""))
    anthropic_api_key: str = field(default_factory=lambda: os.getenv("ANTHROPIC_API_KEY", ""))
    gemini_api_key: str = field(default_factory=lambda: os.getenv("GEMINI_API_KEY", ""))
    groq_api_key: str = field(default_factory=lambda: os.getenv("GROQ_API_KEY", ""))

    # --- LLM Endpoints ---
    llm_endpoints: Dict[str, Dict[str, str]] = field(default_factory=lambda: {
        "openai": {
            "url": "https://api.openai.com/v1/chat/completions",
            "models": ["gpt-4o", "gpt-4-turbo", "gpt-3.5-turbo"],
            "default_model": "gpt-4o",
        },
        "anthropic": {
            "url": "https://api.anthropic.com/v1/messages",
            "models": ["claude-opus-4-5", "claude-sonnet-4-5", "claude-haiku-4-5-20251001"],
            "default_model": "claude-sonnet-4-5",
        },
        "gemini": {
            "url": "https://generativelanguage.googleapis.com/v1beta/models",
            "models": ["gemini-1.5-pro", "gemini-1.5-flash"],
            "default_model": "gemini-1.5-flash",
        },
        "groq": {
            "url": "https://api.groq.com/openai/v1/chat/completions",
            "models": [
                "llama-3.3-70b-versatile",
                "llama-3.1-70b-versatile",
                "llama-3.1-8b-instant",
                "groq/compound",
                "groq/compound-mini",
            ],
            "default_model": "llama-3.3-70b-versatile",
        },
    })

    # --- Valid Models for Providers ---
    VALID_GROQ_MODELS = [
        # Primary brain model used by Agathon orchestrator
        "llama-3.3-70b-versatile",
        "llama-3.1-70b-versatile",
        # Fast inference models
        "llama-3.1-8b-instant",
        "meta-llama/llama-4-scout-17b-16e-instruct",
        "groq/compound",
        "groq/compound-mini",
        "qwen/qwen3-32b",
        "allam-2-7b",
    ]

    def get_clean_model_name(self, model_name: str) -> str:
        """Clean and validate model name, defaulting to the primary brain model."""
        model_name = model_name.lower().strip()
        for valid in self.VALID_GROQ_MODELS:
            if valid in model_name:
                return valid
        return "llama-3.3-70b-versatile"  # Default to the Agathon brain model

    # --- API Keys dict (for backward compatibility) ---
    @property
    def api_keys(self) -> Dict[str, str]:
        return {
            "openai": self.openai_api_key,
            "anthropic": self.anthropic_api_key,
            "gemini": self.gemini_api_key,
            "groq": self.groq_api_key,
        }

    # --- Paths ---
    payload_dir: str = "prompts"
    report_output_dir: str = "reports"
    injection_templates_file: str = field(init=False)
    exfiltration_templates_file: str = field(init=False)

    # --- Request Settings ---
    api_request_timeout: int = 60
    max_retries: int = 3
    retry_delay: float = 1.0          # seconds between retries
    request_delay: float = 3.0        # seconds between attack modules to avoid rate limiting
    requests_per_hour: int = 120      # target hourly request rate
    smart_brain: bool = False         # enable Groq brain guidance during attacks
    concurrent_requests: int = 5      # for async attacks

    # --- Logging ---
    logging_level: str = field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))
    log_file: str = "redteam.log"

    # --- Scoring Thresholds ---
    vulnerability_score_threshold: float = 0.6  # Score above this = vulnerable
    confidence_threshold: float = 0.7

    def __post_init__(self):
        self.injection_templates_file = os.path.join(self.payload_dir, "injection_templates.txt")
        self.exfiltration_templates_file = os.path.join(self.payload_dir, "exfiltration_templates.txt")

        # Create directories
        os.makedirs(self.payload_dir, exist_ok=True)
        os.makedirs(self.report_output_dir, exist_ok=True)

        self._validate()

    def _validate(self):
        """Warn about missing critical configs without crashing."""
        active_keys = [k for k, v in self.api_keys.items() if v]
        if not active_keys:
            print("[WARNING] No API keys configured. Set environment variables like OPENAI_API_KEY.")
        else:
            print(f"[INFO] Active API providers: {', '.join(active_keys)}")

    def get_provider_config(self, provider: str) -> Optional[Dict[str, Any]]:
        """Get endpoint config for a specific provider."""
        return self.llm_endpoints.get(provider.lower())

    def get_logging_config(self) -> Dict[str, Any]:
        """Returns a logging.config-compatible dict."""
        return {
            'version': 1,
            'disable_existing_loggers': False,
            'formatters': {
                'standard': {
                    'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
                },
                'detailed': {
                    'format': '%(asctime)s [%(levelname)s] %(name)s:%(lineno)d: %(message)s'
                },
            },
            'handlers': {
                'console': {
                    'class': 'logging.StreamHandler',
                    'formatter': 'standard',
                    'level': self.logging_level,
                    'stream': 'ext://sys.stdout',
                },
                'file': {
                    'class': 'logging.FileHandler',
                    'formatter': 'detailed',
                    'level': 'DEBUG',
                    'filename': self.log_file,
                    'mode': 'a',
                },
            },
            'root': {
                'handlers': ['console', 'file'],
                'level': 'DEBUG',
            },
        }

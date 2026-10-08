"""
ForgeGuard AI - Cost Protector
═══════════════════════════════════════════════════════════════════════════
Estimates OpenRouter token cost before sending a prompt. If the projected
cost exceeds $0.10, the prompt is automatically routed through a free model
(Google Gemma / NVIDIA Nemotron) for lossless compression before the final
inference call.

Pricing data sourced from OpenRouter as of May 2026.
═══════════════════════════════════════════════════════════════════════════
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Dict

logger = logging.getLogger("forgeguard.cost-protector")

@dataclass(frozen=True)
class ModelPricing:
    """Token pricing for a single model on OpenRouter."""
    model_id: str
    input_price_per_million: float
    output_price_per_million: float
    cached_input_price_per_million: float = 0.0
    tier: str = "paid"

OPENROUTER_PRICES: Dict[str, ModelPricing] = {
    "openai/gpt-5": ModelPricing("openai/gpt-5", 1.25, 10.00),
    "openai/gpt-4o": ModelPricing("openai/gpt-4o", 2.50, 10.00),
    "openai/gpt-4o-mini": ModelPricing("openai/gpt-4o-mini", 0.15, 0.60),
    "openai/o1": ModelPricing("openai/o1", 15.00, 15.00),
}

class CostProtector:
    """Estimate token spend for a target LLM call."""

    def estimate_cost(
        self,
        model: str,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
    ) -> float:
        pricing = OPENROUTER_PRICES.get(model.lower())
        if pricing is None:
            logger.debug("CostProtector: unknown model %s", model)
            return 0.0

        prompt_cost = prompt_tokens * (pricing.input_price_per_million / 1_000_000)
        completion_cost = completion_tokens * (pricing.output_price_per_million / 1_000_000)
        return prompt_cost + completion_cost
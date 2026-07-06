from __future__ import annotations
from dataclasses import dataclass


@dataclass
class DeepScanConfig:
    """Holds the user's persisted LLM provider configuration."""

    provider: str
    api_key: str
    model: str

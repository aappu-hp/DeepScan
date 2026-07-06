from __future__ import annotations

from src.triage.base import TriageProvider
from src.triage.providers.gemini import GeminiTriageProvider
from src.triage.providers.anthropic import AnthropicTriageProvider
from src.triage.providers.openai import OpenAITriageProvider


class TriageProviderFactory:
    """Creates TriageProvider instances by provider name (Factory Method pattern)."""

    _registry: dict[str, type[TriageProvider]] = {
        "gemini": GeminiTriageProvider,
        "anthropic": AnthropicTriageProvider,
        "openai": OpenAITriageProvider,
    }

    @classmethod
    def create(cls, name: str) -> TriageProvider:
        """Instantiate the triage provider registered under the given name.

        Args:
            name: Provider identifier, e.g. 'gemini', 'anthropic', 'openai'.

        Returns:
            A concrete TriageProvider instance.

        Raises:
            ValueError: If name does not match any registered provider.
        """
        provider_class = cls._registry.get(name)
        if provider_class is None:
            raise ValueError(
                f"Unknown triage provider '{name}'. Available: {list(cls._registry)}"
            )
        return provider_class()

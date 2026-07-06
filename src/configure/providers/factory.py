from __future__ import annotations

from src.configure.providers.base import LLMProvider
from src.configure.providers.gemini import GeminiProvider
from src.configure.providers.anthropic import AnthropicProvider
from src.configure.providers.openai import OpenAIProvider


class ProviderFactory:
    """Creates LLMProvider instances by name (Factory Method pattern).

    Register a new provider by adding an entry to _registry — no other code changes needed.
    """

    _registry: dict[str, type[LLMProvider]] = {
        "gemini": GeminiProvider,
        "anthropic": AnthropicProvider,
        "openai": OpenAIProvider,
    }

    @classmethod
    def create(cls, name: str) -> LLMProvider:
        """Instantiate and return the provider registered under the given name.

        Args:
            name: Provider identifier, e.g. 'gemini', 'anthropic', 'openai'.

        Returns:
            A concrete LLMProvider instance.

        Raises:
            ValueError: If name does not match any registered provider.
        """
        provider_class = cls._registry.get(name)
        if provider_class is None:
            raise ValueError(
                f"Unknown provider '{name}'. Available: {list(cls._registry)}"
            )
        return provider_class()

    @classmethod
    def available_provider_names(cls) -> list[str]:
        """Return the names of all registered providers."""
        return list(cls._registry.keys())

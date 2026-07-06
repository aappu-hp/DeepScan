from __future__ import annotations
from abc import ABC, abstractmethod


class LLMProvider(ABC):
    """Abstract base for all LLM provider integrations.

    Concrete providers implement name and fetch_models.
    Adding a new provider requires only a new subclass — no changes to existing code (OCP).
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the provider's identifier string (e.g. 'gemini')."""
        ...

    @abstractmethod
    def fetch_models(self, api_key: str) -> list[str]:
        """Fetch the model IDs available under the given API key.

        Args:
            api_key: The provider's API key.

        Returns:
            List of model identifier strings.

        Raises:
            requests.HTTPError: If the API returns a non-2xx response.
            requests.ConnectionError: If the network request fails.
        """
        ...

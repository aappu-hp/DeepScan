from __future__ import annotations
import requests

from src.configure.providers.base import LLMProvider

_MODELS_URL = "https://api.anthropic.com/v1/models"


class AnthropicProvider(LLMProvider):
    """Fetches available models from the Anthropic API."""

    @property
    def name(self) -> str:
        """Return the provider identifier."""
        return "anthropic"

    def fetch_models(self, api_key: str) -> list[str]:
        """Fetch Claude model IDs accessible with the given API key.

        Args:
            api_key: A valid Anthropic API key.

        Returns:
            List of model ID strings (e.g. 'claude-opus-4-6').

        Raises:
            requests.HTTPError: If the API rejects the key or returns an error.
            requests.ConnectionError: If the network request fails.
        """
        headers = {"x-api-key": api_key, "anthropic-version": "2023-06-01"}
        response = requests.get(_MODELS_URL, headers=headers, timeout=10)
        response.raise_for_status()
        return [m["id"] for m in response.json().get("data", []) if "id" in m]

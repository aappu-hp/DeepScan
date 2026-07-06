from __future__ import annotations
import requests

from src.configure.providers.base import LLMProvider

_MODELS_URL = "https://api.openai.com/v1/models"
_CHAT_PREFIXES = ("gpt-", "o1", "o3", "o4")


class OpenAIProvider(LLMProvider):
    """Fetches available chat models from the OpenAI API."""

    @property
    def name(self) -> str:
        """Return the provider identifier."""
        return "openai"

    def fetch_models(self, api_key: str) -> list[str]:
        """Fetch OpenAI chat model IDs accessible with the given API key.

        Filters the full model list to chat-capable models only
        (gpt-*, o1*, o3*, o4*) to avoid embedding/fine-tune noise.

        Args:
            api_key: A valid OpenAI API key.

        Returns:
            Sorted list of chat model ID strings (e.g. 'gpt-4o').

        Raises:
            requests.HTTPError: If the API rejects the key or returns an error.
            requests.ConnectionError: If the network request fails.
        """
        headers = {"Authorization": f"Bearer {api_key}"}
        response = requests.get(_MODELS_URL, headers=headers, timeout=10)
        response.raise_for_status()
        all_models = [m["id"] for m in response.json().get("data", []) if "id" in m]
        chat_models = [m for m in all_models if m.startswith(_CHAT_PREFIXES)]
        return sorted(chat_models)

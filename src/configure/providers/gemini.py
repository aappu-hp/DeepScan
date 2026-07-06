from __future__ import annotations
import requests

from src.configure.providers.base import LLMProvider

_MODELS_URL = "https://generativelanguage.googleapis.com/v1beta/models"


class GeminiProvider(LLMProvider):
    """Fetches available models from the Google Gemini API."""

    @property
    def name(self) -> str:
        """Return the provider identifier."""
        return "gemini"

    def fetch_models(self, api_key: str) -> list[str]:
        """Fetch Gemini model IDs accessible with the given API key.

        Args:
            api_key: A valid Google Gemini API key.

        Returns:
            List of model ID strings (e.g. 'gemini-2.0-flash').

        Raises:
            requests.HTTPError: If the API rejects the key or returns an error.
            requests.ConnectionError: If the network request fails.
        """
        response = requests.get(_MODELS_URL, params={"key": api_key}, timeout=10)
        response.raise_for_status()
        models = response.json().get("models", [])
        return [m["name"].split("/")[-1] for m in models if "name" in m]

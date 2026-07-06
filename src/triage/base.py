from __future__ import annotations
from abc import ABC, abstractmethod


class TriageProvider(ABC):
    """Abstract base for LLM providers used in finding triage.

    Each provider handles only the async HTTP call to its API.
    Prompt construction and response parsing are shared and live in prompt.py.
    """

    @abstractmethod
    async def analyse(self, prompt: str, model: str, api_key: str) -> str:
        """Send a prompt to the LLM and return the raw text response.

        Args:
            prompt: The fully constructed triage prompt.
            model: Model identifier to use (e.g. 'gemini-2.0-flash').
            api_key: Provider API key.

        Returns:
            Raw text response from the LLM.

        Raises:
            httpx.HTTPStatusError: If the API returns a non-2xx status.
            httpx.TimeoutException: If the request exceeds the timeout.
        """
        ...

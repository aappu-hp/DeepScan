from __future__ import annotations
import httpx

from src.triage.base import TriageProvider

_MESSAGES_URL = "https://api.anthropic.com/v1/messages"
_TIMEOUT = 60.0


class AnthropicTriageProvider(TriageProvider):
    """Sends triage prompts to the Anthropic Messages API."""

    async def analyse(self, prompt: str, model: str, api_key: str) -> str:
        """Call the Anthropic messages endpoint and return the response text.

        Args:
            prompt: Fully constructed single-finding triage prompt.
            model: Claude model ID (e.g. 'claude-opus-4-6').
            api_key: Anthropic API key.

        Returns:
            Raw text from the first content block.

        Raises:
            httpx.HTTPStatusError: On non-2xx API response.
            httpx.TimeoutException: If the request exceeds the timeout.
        """
        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        body = {
            "model": model,
            "max_tokens": 512,
            "messages": [{"role": "user", "content": prompt}],
        }
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            response = await client.post(_MESSAGES_URL, headers=headers, json=body)
            response.raise_for_status()
            return response.json()["content"][0]["text"]

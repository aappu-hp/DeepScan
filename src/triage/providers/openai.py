from __future__ import annotations
import httpx

from src.triage.base import TriageProvider

_CHAT_URL = "https://api.openai.com/v1/chat/completions"
_TIMEOUT = 60.0


class OpenAITriageProvider(TriageProvider):
    """Sends triage prompts to the OpenAI Chat Completions API."""

    async def analyse(self, prompt: str, model: str, api_key: str) -> str:
        """Call the OpenAI chat completions endpoint and return the response text.

        Uses JSON mode to ensure a parseable response.

        Args:
            prompt: Fully constructed single-finding triage prompt.
            model: OpenAI model ID (e.g. 'gpt-4o').
            api_key: OpenAI API key.

        Returns:
            Raw text from the first choice message.

        Raises:
            httpx.HTTPStatusError: On non-2xx API response.
            httpx.TimeoutException: If the request exceeds the timeout.
        """
        headers = {
            "Authorization": f"Bearer {api_key}",
            "content-type": "application/json",
        }
        body = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "response_format": {"type": "json_object"},
            "max_tokens": 512,
        }
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            response = await client.post(_CHAT_URL, headers=headers, json=body)
            response.raise_for_status()
            return response.json()["choices"][0]["message"]["content"]

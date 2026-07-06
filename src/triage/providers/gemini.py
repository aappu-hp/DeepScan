from __future__ import annotations
import httpx

from src.triage.base import TriageProvider

_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
_TIMEOUT = 60.0


class GeminiTriageProvider(TriageProvider):
    """Sends triage prompts to the Google Gemini API."""

    async def analyse(self, prompt: str, model: str, api_key: str) -> str:
        """Call the Gemini generateContent endpoint and return the response text.

        Args:
            prompt: Fully constructed single-finding triage prompt.
            model: Gemini model ID (e.g. 'gemini-2.0-flash').
            api_key: Google Gemini API key.

        Returns:
            Raw text from the first candidate's first part.

        Raises:
            httpx.HTTPStatusError: On non-2xx API response.
            httpx.TimeoutException: If the request exceeds the timeout.
        """
        url = _BASE_URL.format(model=model)
        body = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"response_mime_type": "application/json"},
        }
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            response = await client.post(url, params={"key": api_key}, json=body)
            response.raise_for_status()
            return response.json()["candidates"][0]["content"]["parts"][0]["text"]

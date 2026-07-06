from __future__ import annotations
import asyncio

from src.config.schema import DeepScanConfig
from src.plugins.base import Result
from src.triage.models import TriagedFinding
from src.triage.prompt import build_single_prompt, parse_single_response
from src.triage.providers.factory import TriageProviderFactory
from src.utils.logger import get_logger

logger = get_logger("triage")

_MAX_CONCURRENT_CALLS = 3
_MAX_RETRIES = 2
_RETRY_BASE_DELAY = 1.0  # seconds; doubles each attempt


class TriageError(RuntimeError):
    """Raised when all per-finding triage calls fail."""


class FindingTriageService:
    """Sends each scanner finding to an LLM concurrently for expert triage.

    Each finding gets its own focused prompt and LLM call. All calls run in
    parallel bounded by a semaphore. Individual call failures fall back
    gracefully without affecting other findings.
    """

    async def triage(self, results: list[Result], config: DeepScanConfig) -> list[TriagedFinding]:
        """Triage all findings concurrently using the configured LLM.

        Args:
            results: Deduplicated list of Result objects from the plugin scan.
            config: User's LLM provider configuration.

        Returns:
            List of TriagedFinding objects in the same order as input.
            Individual failures fall back to the original result fields.
        """
        if not results:
            return []

        provider = TriageProviderFactory.create(config.provider)
        semaphore = asyncio.Semaphore(_MAX_CONCURRENT_CALLS)

        async def triage_one(result: Result) -> TriagedFinding:
            async with semaphore:
                prompt = build_single_prompt(result)
                last_exc: Exception | None = None

                for attempt in range(_MAX_RETRIES + 1):
                    try:
                        raw = await provider.analyse(prompt, config.model, config.api_key)
                        data = parse_single_response(raw)
                        if data is None:
                            logger.warning(f"Unparseable triage response for {result.url}, using fallback")
                            return self._fallback_one(result)
                        return TriagedFinding(
                            result=result,
                            is_false_positive=bool(data["is_false_positive"]),
                            severity=str(data["severity"]),
                            confidence=float(data["confidence"]),
                            explanation=str(data["explanation"]),
                            remediation=str(data["remediation"]),
                        )
                    except Exception as exc:
                        last_exc = exc
                        if attempt < _MAX_RETRIES:
                            delay = _RETRY_BASE_DELAY * (2 ** attempt)
                            logger.warning(
                                f"Triage attempt {attempt + 1}/{_MAX_RETRIES + 1} failed for "
                                f"{result.url}: {exc}. Retrying in {delay:.1f}s…"
                            )
                            await asyncio.sleep(delay)

                logger.warning(f"All {_MAX_RETRIES + 1} triage attempts failed for {result.url}: {last_exc}")
                return self._fallback_one(result)

        return list(await asyncio.gather(*[triage_one(r) for r in results]))

    def fallback(self, results: list[Result]) -> list[TriagedFinding]:
        """Wrap raw results as non-triaged TriagedFindings.

        Used by the agent when the entire triage phase must be skipped.

        Args:
            results: Original Result objects.

        Returns:
            TriagedFinding wrappers preserving all original fields.
        """
        return [self._fallback_one(r) for r in results]

    def _fallback_one(self, result: Result) -> TriagedFinding:
        """Wrap a single Result as a non-triaged TriagedFinding.

        Args:
            result: Original Result object.

        Returns:
            TriagedFinding with original fields and a triage unavailable note.
        """
        return TriagedFinding(
            result=result,
            is_false_positive=False,
            severity=result.severity or "medium",
            confidence=result.confidence,
            explanation="(LLM triage unavailable — showing raw scanner result)",
            remediation=result.remediation or "",
        )

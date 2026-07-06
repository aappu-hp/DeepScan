import json
import pytest
from unittest.mock import AsyncMock, patch

from src.config.schema import DeepScanConfig
from src.plugins.base import Result
from src.triage.models import TriagedFinding
from src.triage.prompt import build_single_prompt, parse_single_response
from src.triage.service import FindingTriageService


# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture
def xss_result():
    return Result(
        plugin_name="XSS-Reflective",
        url="http://example.com/search",
        parameter="q",
        payload="<script>alert(1)</script>",
        evidence="<script>alert(1)</script>",
        confidence=0.9,
        severity="high",
        remediation="Encode output.",
    )


@pytest.fixture
def sqli_result():
    return Result(
        plugin_name="SQLi-Basic",
        url="http://example.com/login",
        parameter="user",
        payload="'",
        evidence="SQL error keyword found",
        confidence=0.8,
        severity="high",
        remediation="Use parameterised queries.",
    )


@pytest.fixture
def gemini_config():
    return DeepScanConfig(provider="gemini", api_key="fake-key", model="gemini-2.0-flash")


@pytest.fixture
def valid_triage_response():
    return json.dumps({
        "is_false_positive": False,
        "severity": "high",
        "confidence": 0.95,
        "explanation": "Payload reflected unencoded — confirmed XSS.",
        "remediation": "HTML-encode all user output in search endpoint.",
    })


@pytest.fixture
def false_positive_response():
    return json.dumps({
        "is_false_positive": True,
        "severity": "low",
        "confidence": 0.85,
        "explanation": "Pattern matched but context is inside a JS comment — not exploitable.",
        "remediation": "No action required.",
    })


# ── prompt builder tests ───────────────────────────────────────────────────────

class TestBuildSinglePrompt:
    def test_contains_plugin_name(self, xss_result):
        prompt = build_single_prompt(xss_result)
        assert "XSS-Reflective" in prompt

    def test_contains_url(self, xss_result):
        prompt = build_single_prompt(xss_result)
        assert "http://example.com/search" in prompt

    def test_contains_payload(self, xss_result):
        prompt = build_single_prompt(xss_result)
        assert "<script>alert(1)</script>" in prompt

    def test_contains_evidence(self, xss_result):
        prompt = build_single_prompt(xss_result)
        assert "<script>alert(1)</script>" in prompt

    def test_none_parameter_shows_na(self):
        result = Result(plugin_name="X", url="http://x.com", parameter=None,
                        confidence=0.5, severity="low")
        prompt = build_single_prompt(result)
        assert "N/A" in prompt


# ── response parser tests ──────────────────────────────────────────────────────

class TestParseSingleResponse:
    def test_parses_clean_json(self, valid_triage_response):
        result = parse_single_response(valid_triage_response)
        assert result is not None
        assert result["is_false_positive"] is False
        assert result["severity"] == "high"
        assert result["confidence"] == 0.95

    def test_parses_markdown_wrapped_json(self, valid_triage_response):
        wrapped = f"```json\n{valid_triage_response}\n```"
        result = parse_single_response(wrapped)
        assert result is not None
        assert result["severity"] == "high"

    def test_parses_json_with_surrounding_prose(self, valid_triage_response):
        prose = f"Here is my analysis:\n{valid_triage_response}\nLet me know if you need more."
        result = parse_single_response(prose)
        assert result is not None

    def test_returns_none_for_invalid_json(self):
        result = parse_single_response("not json at all")
        assert result is None

    def test_returns_none_for_missing_required_key(self):
        incomplete = json.dumps({
            "is_false_positive": False,
            "severity": "high",
            "confidence": 0.9,
            # missing explanation and remediation
        })
        result = parse_single_response(incomplete)
        assert result is None

    def test_returns_none_for_invalid_severity(self):
        bad = json.dumps({
            "is_false_positive": False,
            "severity": "extreme",  # not in allowed set
            "confidence": 0.9,
            "explanation": "x",
            "remediation": "y",
        })
        result = parse_single_response(bad)
        assert result is None

    def test_parses_false_positive(self, false_positive_response):
        result = parse_single_response(false_positive_response)
        assert result is not None
        assert result["is_false_positive"] is True


# ── service tests ──────────────────────────────────────────────────────────────

class TestFindingTriageService:
    @pytest.mark.asyncio
    async def test_returns_triaged_findings(self, xss_result, gemini_config, valid_triage_response):
        mock_provider = AsyncMock()
        mock_provider.analyse.return_value = valid_triage_response

        with patch("src.triage.service.TriageProviderFactory.create", return_value=mock_provider):
            results = await FindingTriageService().triage([xss_result], gemini_config)

        assert len(results) == 1
        assert isinstance(results[0], TriagedFinding)
        assert results[0].severity == "high"
        assert results[0].confidence == 0.95
        assert results[0].is_false_positive is False

    @pytest.mark.asyncio
    async def test_returns_empty_for_no_results(self, gemini_config):
        results = await FindingTriageService().triage([], gemini_config)
        assert results == []

    @pytest.mark.asyncio
    async def test_falls_back_per_finding_after_retries_exhausted(self, xss_result, sqli_result, gemini_config, valid_triage_response):
        # xss_result fails all 3 attempts (1 + 2 retries); sqli_result succeeds first try
        xss_url = xss_result.url

        async def side_effect(prompt, model, api_key):
            if xss_url in prompt:
                raise ConnectionError("network error")
            return valid_triage_response

        mock_provider = AsyncMock()
        mock_provider.analyse.side_effect = side_effect

        with patch("src.triage.service.TriageProviderFactory.create", return_value=mock_provider), \
             patch("src.triage.service.asyncio.sleep"):
            results = await FindingTriageService().triage([xss_result, sqli_result], gemini_config)

        assert len(results) == 2
        xss_triaged = next(r for r in results if r.result.url == xss_result.url)
        sqli_triaged = next(r for r in results if r.result.url == sqli_result.url)
        assert "(LLM triage unavailable" in xss_triaged.explanation
        assert sqli_triaged.severity == "high"
        assert "(LLM triage unavailable" not in sqli_triaged.explanation

    @pytest.mark.asyncio
    async def test_falls_back_on_unparseable_response(self, xss_result, gemini_config):
        mock_provider = AsyncMock()
        mock_provider.analyse.return_value = "this is not json"

        with patch("src.triage.service.TriageProviderFactory.create", return_value=mock_provider):
            results = await FindingTriageService().triage([xss_result], gemini_config)

        assert len(results) == 1
        assert "(LLM triage unavailable" in results[0].explanation

    @pytest.mark.asyncio
    async def test_preserves_original_result_reference(self, xss_result, gemini_config, valid_triage_response):
        mock_provider = AsyncMock()
        mock_provider.analyse.return_value = valid_triage_response

        with patch("src.triage.service.TriageProviderFactory.create", return_value=mock_provider):
            results = await FindingTriageService().triage([xss_result], gemini_config)

        assert results[0].result is xss_result

    @pytest.mark.asyncio
    async def test_processes_multiple_findings_concurrently(self, xss_result, sqli_result, gemini_config, valid_triage_response):
        mock_provider = AsyncMock()
        mock_provider.analyse.return_value = valid_triage_response

        with patch("src.triage.service.TriageProviderFactory.create", return_value=mock_provider):
            results = await FindingTriageService().triage([xss_result, sqli_result], gemini_config)

        assert len(results) == 2
        assert mock_provider.analyse.call_count == 2

    def test_fallback_wraps_all_results(self, xss_result, sqli_result):
        service = FindingTriageService()
        results = service.fallback([xss_result, sqli_result])
        assert len(results) == 2
        assert all(isinstance(r, TriagedFinding) for r in results)
        assert all(not r.is_false_positive for r in results)
        assert all("unavailable" in r.explanation for r in results)

    @pytest.mark.asyncio
    async def test_retries_on_transient_error_then_succeeds(self, xss_result, gemini_config, valid_triage_response):
        call_count = 0

        async def side_effect(prompt, model, api_key):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ConnectionError("transient error")
            return valid_triage_response

        mock_provider = AsyncMock()
        mock_provider.analyse.side_effect = side_effect

        with patch("src.triage.service.TriageProviderFactory.create", return_value=mock_provider), \
             patch("src.triage.service.asyncio.sleep"):
            results = await FindingTriageService().triage([xss_result], gemini_config)

        assert call_count == 3
        assert results[0].severity == "high"
        assert "(LLM triage unavailable" not in results[0].explanation

    @pytest.mark.asyncio
    async def test_falls_back_after_all_retries_exhausted(self, xss_result, gemini_config):
        mock_provider = AsyncMock()
        mock_provider.analyse.side_effect = ConnectionError("always fails")

        with patch("src.triage.service.TriageProviderFactory.create", return_value=mock_provider), \
             patch("src.triage.service.asyncio.sleep"):
            results = await FindingTriageService().triage([xss_result], gemini_config)

        assert mock_provider.analyse.call_count == 3  # 1 initial + 2 retries
        assert "(LLM triage unavailable" in results[0].explanation

    @pytest.mark.asyncio
    async def test_no_retry_on_unparseable_response(self, xss_result, gemini_config):
        mock_provider = AsyncMock()
        mock_provider.analyse.return_value = "not json"

        with patch("src.triage.service.TriageProviderFactory.create", return_value=mock_provider):
            results = await FindingTriageService().triage([xss_result], gemini_config)

        assert mock_provider.analyse.call_count == 1  # no retry for parse failures
        assert "(LLM triage unavailable" in results[0].explanation

from __future__ import annotations
import json
import re

from src.plugins.base import Result

_SINGLE_PROMPT_TEMPLATE = """\
You are an expert web application security analyst. Analyse this single scanner finding.

Plugin:              {plugin}
URL:                 {url}
Parameter:           {parameter}
Payload:             {payload}
Evidence:            {evidence}
Original confidence: {confidence}
Original severity:   {severity}

Return ONLY a JSON object — no prose, no markdown fences:
{{
  "is_false_positive": false,
  "severity": "high",
  "confidence": 0.95,
  "explanation": "One sentence: why this is or is not exploitable.",
  "remediation": "Specific actionable fix for this exact evidence."
}}

Severity must be exactly one of: low, medium, high, critical."""


def build_single_prompt(result: Result) -> str:
    """Build a triage prompt for a single scanner finding.

    Keeps the prompt short so thinking models respond faster.

    Args:
        result: A single Result object from the plugin scan.

    Returns:
        Fully formed prompt string for one LLM call.
    """
    return _SINGLE_PROMPT_TEMPLATE.format(
        plugin=result.plugin_name,
        url=result.url,
        parameter=result.parameter or "N/A",
        payload=result.payload or "N/A",
        evidence=result.evidence or "N/A",
        confidence=result.confidence,
        severity=result.severity or "unknown",
    )


def parse_single_response(text: str) -> dict | None:
    """Extract and validate a single triage JSON object from an LLM response.

    Handles responses wrapped in markdown fences and responses with surrounding
    prose. Returns None if parsing or field validation fails.

    Args:
        text: Raw text response from the LLM.

    Returns:
        Triage dict with required keys, or None if the response cannot be parsed.
    """
    cleaned = re.sub(r"```(?:json)?\s*", "", text).strip().rstrip("`").strip()

    match = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if not match:
        return None

    try:
        data = json.loads(match.group())
    except json.JSONDecodeError:
        return None

    required = {"is_false_positive", "severity", "confidence", "explanation", "remediation"}
    if not required.issubset(data.keys()):
        return None

    if data["severity"] not in {"low", "medium", "high", "critical"}:
        return None

    return data

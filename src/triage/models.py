from __future__ import annotations
from dataclasses import dataclass

from src.plugins.base import Result


@dataclass
class TriagedFinding:
    """A scanner Result enriched with LLM triage analysis.

    Wraps the original Result without modifying it, adding triage-specific
    fields alongside potentially updated severity, confidence and remediation.
    """

    result: Result
    is_false_positive: bool
    severity: str
    confidence: float
    explanation: str
    remediation: str

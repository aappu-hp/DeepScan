from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from abc import ABC, abstractmethod
from typing import Optional

@dataclass
class Result:
    plugin_name: str
    url: str
    endpoint_type: str = "page"        # "page" or "form"
    parameter: Optional[str] = None    # param name or form field
    payload: Optional[str] = None
    evidence: Optional[str] = None     # snippet of response or regex match
    confidence: float = 0.0            # 0.0 - 1.0
    severity: Optional[str] = None     # low/medium/high/critical
    remediation: Optional[str] = None  # human-readable remediation text
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

class ScannerPlugin(ABC):
    """
    Abstract base class for plugins.

    Concrete plugins must implement `name`, `test` and `extract_remediation`.
    `test` should be async and return a list of Result objects (empty list if none).
    """

    name: str = "base"

    @abstractmethod
    async def test(self, session, endpoint) -> list[Result]:
        """Run tests against an endpoint. Must return list of Result objects."""
        raise NotImplementedError

    @abstractmethod
    def extract_remediation(self, result: Result) -> str:
        """Return a human-readable remediation suggestion for a given result."""
        raise NotImplementedError

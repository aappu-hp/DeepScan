from __future__ import annotations
from dataclasses import dataclass

from src.triage.models import TriagedFinding


@dataclass
class ScanReport:
    """Aggregated scan result ready for report rendering.

    Holds target metadata and the confirmed (non-false-positive) triaged
    findings produced by a single DeepScan agent run.
    """

    target_url: str
    scan_started: str   # ISO-8601 UTC string
    scan_finished: str  # ISO-8601 UTC string
    findings: list[TriagedFinding]

    @property
    def critical_count(self) -> int:
        """Number of confirmed critical-severity findings."""
        return sum(1 for f in self.findings if f.severity.lower() == "critical")

    @property
    def high_count(self) -> int:
        """Number of confirmed high-severity findings."""
        return sum(1 for f in self.findings if f.severity.lower() == "high")

    @property
    def medium_count(self) -> int:
        """Number of confirmed medium-severity findings."""
        return sum(1 for f in self.findings if f.severity.lower() == "medium")

    @property
    def low_count(self) -> int:
        """Number of confirmed low-severity findings."""
        return sum(1 for f in self.findings if f.severity.lower() == "low")

    @property
    def total_count(self) -> int:
        """Total number of confirmed findings."""
        return len(self.findings)

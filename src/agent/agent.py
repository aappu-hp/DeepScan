from __future__ import annotations
import asyncio
import io
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import aiohttp
from rich.console import Console

import src.crawler.crawler as _crawler_module
from src.config.user_config import UserConfig
from src.crawler.crawler import AsyncCrawler
from src.plugins.loader import discover_plugins
from src.plugins.runner import run_plugins_on_endpoint
from src.report.generator import ReportGenerator
from src.report.models import ScanReport
from src.triage.models import TriagedFinding
from src.triage.service import FindingTriageService
from src.utils.console import console, ok, fail, warn, working, phase, finding


def _silence_crawler_logs() -> None:
    logging.getLogger("crawler").setLevel(logging.WARNING)


def _fmt(seconds: float) -> str:
    """Format elapsed seconds as a human-readable duration string.

    Args:
        seconds: Elapsed time in seconds.

    Returns:
        Formatted string, e.g. '1m 23s' or '4.7s'.
    """
    if seconds >= 60:
        m, s = divmod(int(seconds), 60)
        return f"{m}m {s}s"
    return f"{seconds:.1f}s"


class _NullConsole(Console):
    """A Rich Console that discards all output."""

    def print(self, *args, **kwargs) -> None:  # noqa: D102
        pass


class DeepScanAgent:
    """Orchestrates the full scan pipeline: config check → crawl → plugin scan → AI triage → save.

    Acts as a Facade over AsyncCrawler, the plugin runner, and FindingTriageService,
    presenting a single entry point for the agent subcommand.
    """

    def __init__(self, url: str, depth: int = 2) -> None:
        self._url = url
        self._depth = depth
        self._user_config = UserConfig()

    def run(self) -> None:
        """Execute the full scan pipeline. Blocks until complete."""
        _silence_crawler_logs()
        asyncio.run(self._run_async())

    async def _run_async(self) -> None:
        """Run the pipeline asynchronously: crawl → scan → triage → summarise → save."""
        self._check_config()
        pipeline_start = time.perf_counter()
        scan_started = datetime.now(timezone.utc).isoformat(timespec="seconds")

        endpoints = await self._crawl()
        raw_results = await self._scan(endpoints)
        triaged = await self._triage(raw_results)

        scan_finished = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self._print_summary(triaged, elapsed=time.perf_counter() - pipeline_start)
        self._save_results(triaged, scan_started, scan_finished)

    def _check_config(self) -> None:
        """Abort with a helpful message if no LLM config has been saved yet.

        Raises:
            SystemExit: If config is missing.
        """
        if self._user_config.load() is None:
            warn("No config found", "run `deepscan configure` first")
            sys.exit(1)

    async def _crawl(self) -> list:
        """Crawl the target URL up to the configured depth.

        Suppresses the crawler's own console output so all terminal output
        during the crawl is routed through the shared DeepScan console.

        Returns:
            List of discovered Endpoint objects.
        """
        phase("Crawling")
        working("Target", self._url)

        original_console = _crawler_module.console
        _crawler_module.console = _NullConsole(file=io.StringIO())
        t0 = time.perf_counter()
        try:
            with console.status("[working]Crawling target...[/working]", spinner="dots"):
                endpoints = await AsyncCrawler().crawl_dfs(self._url, max_depth=self._depth)
        finally:
            _crawler_module.console = original_console

        pages = sum(1 for e in endpoints if e.type == "page")
        forms = sum(1 for e in endpoints if e.type == "form")
        ok("Endpoints discovered", f"{pages} pages  |  {forms} forms")
        ok("Crawl time", _fmt(time.perf_counter() - t0))
        return endpoints

    async def _scan(self, endpoints: list) -> list:
        """Run all auto-discovered plugins against every endpoint concurrently.

        Endpoints are scanned in parallel bounded by a semaphore. Results are
        deduplicated on (plugin_name, url, parameter). Findings are not printed
        here — that is deferred to the triage phase for enriched output.

        Args:
            endpoints: List of Endpoint objects from the crawler.

        Returns:
            Deduplicated flat list of Result objects.
        """
        phase("Plugin Scan")
        plugins = discover_plugins()

        if not plugins:
            fail("No plugins found", "add *_plugin.py files to src/plugins/")
            return []

        working("Running plugins", "  ·  ".join(p.name for p in plugins))

        semaphore = asyncio.Semaphore(10)

        async def _scan_one(session, endpoint):
            async with semaphore:
                return await run_plugins_on_endpoint(session, plugins, endpoint)

        connector = aiohttp.TCPConnector(ssl=False)
        t0 = time.perf_counter()
        with console.status("[working]Scanning endpoints...[/working]", spinner="dots"):
            async with aiohttp.ClientSession(connector=connector) as session:
                batches = await asyncio.gather(
                    *[_scan_one(session, ep) for ep in endpoints]
                )

        all_results = [r for batch in batches for r in batch]

        seen: set[tuple] = set()
        unique_results: list = []
        for r in all_results:
            key = (r.plugin_name, r.url, r.parameter)
            if key not in seen:
                seen.add(key)
                unique_results.append(r)

        ok("Raw findings", str(len(unique_results)))
        ok("Scan time", _fmt(time.perf_counter() - t0))
        return unique_results

    async def _triage(self, results: list) -> list[TriagedFinding]:
        """Send findings concurrently to the LLM for expert triage and print enriched output.

        Each finding is triaged in its own LLM call. Calls run in parallel bounded
        by a semaphore. False positives are displayed with a [-] marker and excluded
        from the returned list.

        Args:
            results: Deduplicated list of Result objects from the scan.

        Returns:
            TriagedFinding list with false positives removed.
        """
        phase("AI Triage")

        if not results:
            ok("Nothing to triage", "")
            return []

        config = self._user_config.load()
        working("Analysing findings", config.model)
        console.print()

        t0 = time.perf_counter()
        service = FindingTriageService()
        with console.status("[working]Triaging findings...[/working]", spinner="dots"):
            triaged = await service.triage(results, config)

        for tf in triaged:
            if tf.is_false_positive:
                fail(
                    f"{tf.result.plugin_name:<20}  {(tf.result.severity or '').upper():<8}  FALSE POSITIVE",
                    tf.result.url,
                )
                console.print(f"    [label]{tf.explanation}[/label]")
            else:
                finding(tf.result.plugin_name, tf.result.url, tf.severity, tf.confidence)
                console.print(f"    [label]{tf.explanation}[/label]")
                console.print(f"    [ok]Fix:[/ok] {tf.remediation}")
            console.print()

        confirmed = [tf for tf in triaged if not tf.is_false_positive]
        removed = len(triaged) - len(confirmed)
        if removed:
            console.print(f"  [label]{removed} false positive(s) removed by AI triage[/label]")
            console.print()

        ok("Triage time", _fmt(time.perf_counter() - t0))
        return confirmed

    def _print_summary(self, triaged: list[TriagedFinding], elapsed: float = 0.0) -> None:
        """Print a severity breakdown of confirmed findings and total elapsed time.

        Args:
            triaged: Confirmed TriagedFinding objects (false positives excluded).
            elapsed: Total pipeline wall-clock time in seconds.
        """
        phase("Summary")

        if not triaged:
            ok("No confirmed vulnerabilities", "")
        else:
            high = sum(1 for tf in triaged if tf.severity.lower() == "high")
            medium = sum(1 for tf in triaged if tf.severity.lower() == "medium")
            low = sum(1 for tf in triaged if tf.severity.lower() == "low")
            critical = sum(1 for tf in triaged if tf.severity.lower() == "critical")
            ok("Confirmed findings", f"{critical} critical  |  {high} high  |  {medium} medium  |  {low} low")

        ok("Total time", _fmt(elapsed))

    def _save_results(
        self,
        triaged: list[TriagedFinding],
        scan_started: str,
        scan_finished: str,
    ) -> None:
        """Serialise confirmed triaged findings to JSON, HTML, and Markdown reports.

        Args:
            triaged: Confirmed TriagedFinding objects to persist.
            scan_started: ISO-8601 UTC timestamp when the pipeline started.
            scan_finished: ISO-8601 UTC timestamp when triage completed.
        """
        out_dir = Path("outputs")
        out_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        # JSON
        out_file = out_dir / f"agent_results_{ts}.json"
        serial = [
            {
                **{k: v for k, v in tf.result.__dict__.items() if not k.startswith("_")},
                "triage_severity": tf.severity,
                "triage_confidence": tf.confidence,
                "triage_explanation": tf.explanation,
                "triage_remediation": tf.remediation,
            }
            for tf in triaged
        ]
        out_file.write_text(json.dumps(serial, indent=2), encoding="utf-8")

        # HTML + Markdown
        report = ScanReport(
            target_url=self._url,
            scan_started=scan_started,
            scan_finished=scan_finished,
            findings=triaged,
        )
        html_path, md_path = ReportGenerator().save(report, out_dir, ts)

        phase("Report")
        ok("JSON  saved", str(out_file))
        ok("HTML  saved", str(html_path))
        ok("MD    saved", str(md_path))
        console.print()

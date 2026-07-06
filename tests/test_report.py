import pytest
from pathlib import Path

from src.plugins.base import Result
from src.triage.models import TriagedFinding
from src.report.models import ScanReport
from src.report.generator import ReportGenerator


# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture
def xss_finding():
    result = Result(
        plugin_name="XSS-Reflective",
        url="http://example.com/search",
        parameter="q",
        payload="<script>alert(1)</script>",
        evidence="<script>alert(1)</script>",
        confidence=0.9,
        severity="high",
    )
    return TriagedFinding(
        result=result,
        is_false_positive=False,
        severity="high",
        confidence=0.95,
        explanation="Payload reflected unencoded — confirmed XSS.",
        remediation="HTML-encode all user-supplied output.",
    )


@pytest.fixture
def sqli_finding():
    result = Result(
        plugin_name="SQLi-Basic",
        url="http://example.com/login",
        parameter="user",
        payload="'",
        evidence="SQL error keyword found",
        confidence=0.8,
        severity="high",
    )
    return TriagedFinding(
        result=result,
        is_false_positive=False,
        severity="critical",
        confidence=0.90,
        explanation="Error-based SQL injection confirmed.",
        remediation="Use parameterised queries.",
    )


@pytest.fixture
def medium_finding():
    result = Result(
        plugin_name="Sensitive-Info",
        url="http://example.com/about",
        parameter=None,
        confidence=0.6,
        severity="medium",
    )
    return TriagedFinding(
        result=result,
        is_false_positive=False,
        severity="medium",
        confidence=0.60,
        explanation="Internal IP address exposed in response.",
        remediation="Remove internal addresses from public responses.",
    )


@pytest.fixture
def low_finding():
    result = Result(
        plugin_name="Sec-Headers",
        url="http://example.com/",
        parameter=None,
        confidence=0.5,
        severity="low",
    )
    return TriagedFinding(
        result=result,
        is_false_positive=False,
        severity="low",
        confidence=0.50,
        explanation="X-Frame-Options header missing.",
        remediation="Add X-Frame-Options: DENY.",
    )


@pytest.fixture
def report_with_findings(xss_finding, sqli_finding, medium_finding, low_finding):
    return ScanReport(
        target_url="http://example.com",
        scan_started="2026-07-06T10:00:00+00:00",
        scan_finished="2026-07-06T10:05:30+00:00",
        findings=[xss_finding, sqli_finding, medium_finding, low_finding],
    )


@pytest.fixture
def empty_report():
    return ScanReport(
        target_url="http://example.com",
        scan_started="2026-07-06T10:00:00+00:00",
        scan_finished="2026-07-06T10:01:00+00:00",
        findings=[],
    )


# ── ScanReport model tests ─────────────────────────────────────────────────────

class TestScanReport:
    def test_counts_by_severity(self, report_with_findings):
        assert report_with_findings.critical_count == 1
        assert report_with_findings.high_count == 1
        assert report_with_findings.medium_count == 1
        assert report_with_findings.low_count == 1

    def test_total_count(self, report_with_findings):
        assert report_with_findings.total_count == 4

    def test_empty_report_all_counts_zero(self, empty_report):
        assert empty_report.total_count == 0
        assert empty_report.critical_count == 0
        assert empty_report.high_count == 0
        assert empty_report.medium_count == 0
        assert empty_report.low_count == 0

    def test_severity_counts_case_insensitive(self, xss_finding):
        xss_finding.severity = "HIGH"
        report = ScanReport(
            target_url="http://x.com",
            scan_started="2026-07-06T10:00:00+00:00",
            scan_finished="2026-07-06T10:01:00+00:00",
            findings=[xss_finding],
        )
        assert report.high_count == 1


# ── HTML generation tests ──────────────────────────────────────────────────────

class TestGenerateHtml:
    def test_html_contains_target_url(self, report_with_findings):
        html = ReportGenerator().generate_html(report_with_findings)
        assert "http://example.com" in html

    def test_html_contains_scan_timestamps(self, report_with_findings):
        html = ReportGenerator().generate_html(report_with_findings)
        assert "2026-07-06T10:00:00+00:00" in html
        assert "2026-07-06T10:05:30+00:00" in html

    def test_html_contains_finding_plugin_name(self, report_with_findings):
        html = ReportGenerator().generate_html(report_with_findings)
        assert "XSS-Reflective" in html
        assert "SQLi-Basic" in html

    def test_html_contains_severity_badges(self, report_with_findings):
        html = ReportGenerator().generate_html(report_with_findings)
        assert "HIGH" in html
        assert "CRITICAL" in html
        assert "MEDIUM" in html
        assert "LOW" in html

    def test_html_contains_explanation(self, report_with_findings):
        html = ReportGenerator().generate_html(report_with_findings)
        assert "Payload reflected unencoded" in html

    def test_html_contains_remediation(self, report_with_findings):
        html = ReportGenerator().generate_html(report_with_findings)
        assert "HTML-encode all user-supplied output" in html

    def test_html_contains_summary_counts(self, report_with_findings):
        html = ReportGenerator().generate_html(report_with_findings)
        # total count card
        assert ">4<" in html

    def test_html_escapes_xss_in_url(self):
        result = Result(
            plugin_name="XSS",
            url='http://evil.com/<script>',
            parameter=None,
            confidence=0.9,
            severity="high",
        )
        finding = TriagedFinding(
            result=result,
            is_false_positive=False,
            severity="high",
            confidence=0.9,
            explanation="test",
            remediation="fix it",
        )
        report = ScanReport(
            target_url="http://example.com",
            scan_started="2026-07-06T10:00:00+00:00",
            scan_finished="2026-07-06T10:01:00+00:00",
            findings=[finding],
        )
        html = ReportGenerator().generate_html(report)
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_html_empty_findings_shows_no_confirmed_message(self, empty_report):
        html = ReportGenerator().generate_html(empty_report)
        assert "No confirmed findings" in html

    def test_html_is_valid_document(self, report_with_findings):
        html = ReportGenerator().generate_html(report_with_findings)
        assert html.startswith("<!DOCTYPE html>")
        assert "</html>" in html


# ── Markdown generation tests ──────────────────────────────────────────────────

class TestGenerateMarkdown:
    def test_markdown_contains_target_url(self, report_with_findings):
        md = ReportGenerator().generate_markdown(report_with_findings)
        assert "http://example.com" in md

    def test_markdown_contains_summary_table(self, report_with_findings):
        md = ReportGenerator().generate_markdown(report_with_findings)
        assert "| Total |" in md
        assert "| 4 |" in md

    def test_markdown_contains_finding_rows(self, report_with_findings):
        md = ReportGenerator().generate_markdown(report_with_findings)
        assert "XSS-Reflective" in md
        assert "SQLi-Basic" in md

    def test_markdown_contains_severity_labels(self, report_with_findings):
        md = ReportGenerator().generate_markdown(report_with_findings)
        assert "HIGH" in md
        assert "CRITICAL" in md

    def test_markdown_contains_explanation_and_remediation(self, report_with_findings):
        md = ReportGenerator().generate_markdown(report_with_findings)
        assert "Payload reflected unencoded" in md
        assert "parameterised queries" in md

    def test_markdown_empty_findings_shows_placeholder(self, empty_report):
        md = ReportGenerator().generate_markdown(empty_report)
        assert "No confirmed findings" in md

    def test_markdown_escapes_pipe_in_fields(self):
        result = Result(
            plugin_name="XSS",
            url="http://example.com/search?a=1|2",
            parameter=None,
            confidence=0.9,
            severity="high",
        )
        finding = TriagedFinding(
            result=result,
            is_false_positive=False,
            severity="high",
            confidence=0.9,
            explanation="Pipe | in explanation",
            remediation="Fix | it",
        )
        report = ScanReport(
            target_url="http://example.com",
            scan_started="2026-07-06T10:00:00+00:00",
            scan_finished="2026-07-06T10:01:00+00:00",
            findings=[finding],
        )
        md = ReportGenerator().generate_markdown(report)
        # bare | must be escaped in explanation/remediation columns
        lines = [l for l in md.splitlines() if "Pipe" in l or "Fix" in l]
        assert any("\\|" in l for l in lines)

    def test_markdown_starts_with_h1(self, report_with_findings):
        md = ReportGenerator().generate_markdown(report_with_findings)
        assert md.startswith("# DeepScan Security Report")


# ── Save tests ─────────────────────────────────────────────────────────────────

class TestReportGeneratorSave:
    def test_save_creates_html_and_md_files(self, tmp_path, report_with_findings):
        html_path, md_path = ReportGenerator().save(report_with_findings, tmp_path, "20260706_100000")
        assert html_path.exists()
        assert md_path.exists()

    def test_save_uses_correct_filenames(self, tmp_path, report_with_findings):
        html_path, md_path = ReportGenerator().save(report_with_findings, tmp_path, "20260706_100000")
        assert html_path.name == "report_20260706_100000.html"
        assert md_path.name == "report_20260706_100000.md"

    def test_save_creates_output_dir_if_missing(self, tmp_path, report_with_findings):
        nested = tmp_path / "deep" / "nested"
        ReportGenerator().save(report_with_findings, nested, "20260706_100000")
        assert nested.exists()

    def test_saved_html_contains_target_url(self, tmp_path, report_with_findings):
        html_path, _ = ReportGenerator().save(report_with_findings, tmp_path, "20260706_100000")
        assert "http://example.com" in html_path.read_text(encoding="utf-8")

    def test_saved_md_contains_summary_table(self, tmp_path, report_with_findings):
        _, md_path = ReportGenerator().save(report_with_findings, tmp_path, "20260706_100000")
        assert "| Total |" in md_path.read_text(encoding="utf-8")

    def test_save_returns_path_objects(self, tmp_path, report_with_findings):
        html_path, md_path = ReportGenerator().save(report_with_findings, tmp_path, "20260706_100000")
        assert isinstance(html_path, Path)
        assert isinstance(md_path, Path)

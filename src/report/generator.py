from __future__ import annotations
from pathlib import Path

from src.report.models import ScanReport
from src.triage.models import TriagedFinding

_SEV_COLORS: dict[str, str] = {
    "critical": "#e74c3c",
    "high":     "#e67e22",
    "medium":   "#f1c40f",
    "low":      "#2ecc71",
}
_DEFAULT_COLOR = "#95a5a6"


def _sev_color(severity: str) -> str:
    return _SEV_COLORS.get(severity.lower(), _DEFAULT_COLOR)


class ReportGenerator:
    """Converts a ScanReport into HTML and Markdown documents.

    Both formats are self-contained: the HTML embeds all CSS inline so no
    external assets are required.  Call ``save`` to write both files at once.
    """

    # ── Public API ─────────────────────────────────────────────────────────────

    def generate_html(self, report: ScanReport) -> str:
        """Render the report as a self-contained HTML string.

        Args:
            report: Populated ScanReport to render.

        Returns:
            Complete HTML document as a string.
        """
        rows = "\n".join(self._html_row(f) for f in report.findings)
        empty_msg = (
            '<tr><td colspan="6" style="text-align:center;color:#888;padding:20px">'
            "No confirmed findings.</td></tr>"
            if not report.findings
            else ""
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DeepScan Report — {report.target_url}</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0f1117; color: #c9d1d9; line-height: 1.6; }}
    header {{ background: linear-gradient(135deg, #161b22 0%, #0d1117 100%); border-bottom: 1px solid #30363d; padding: 28px 40px; }}
    header h1 {{ font-size: 1.8rem; color: #58a6ff; letter-spacing: -0.5px; }}
    header p {{ color: #8b949e; font-size: 0.9rem; margin-top: 4px; }}
    .meta {{ display: flex; gap: 24px; margin-top: 12px; flex-wrap: wrap; }}
    .meta span {{ font-size: 0.8rem; color: #8b949e; }}
    .meta strong {{ color: #c9d1d9; }}
    .summary {{ display: flex; gap: 16px; padding: 24px 40px; flex-wrap: wrap; }}
    .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px 24px; min-width: 110px; text-align: center; }}
    .card .count {{ font-size: 2rem; font-weight: 700; }}
    .card .label {{ font-size: 0.75rem; color: #8b949e; text-transform: uppercase; letter-spacing: 0.5px; margin-top: 2px; }}
    .card.critical .count {{ color: #e74c3c; }}
    .card.high     .count {{ color: #e67e22; }}
    .card.medium   .count {{ color: #f1c40f; }}
    .card.low      .count {{ color: #2ecc71; }}
    .card.total    .count {{ color: #58a6ff; }}
    main {{ padding: 0 40px 40px; }}
    h2 {{ font-size: 1.1rem; color: #8b949e; text-transform: uppercase; letter-spacing: 1px; margin: 32px 0 12px; }}
    table {{ width: 100%; border-collapse: collapse; background: #161b22; border: 1px solid #30363d; border-radius: 8px; overflow: hidden; font-size: 0.87rem; }}
    thead th {{ background: #1c2128; color: #8b949e; text-align: left; padding: 10px 14px; font-weight: 600; font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid #30363d; }}
    tbody tr {{ border-bottom: 1px solid #21262d; transition: background 0.15s; }}
    tbody tr:last-child {{ border-bottom: none; }}
    tbody tr:hover {{ background: #1c2128; }}
    tbody td {{ padding: 12px 14px; vertical-align: top; }}
    .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 700; color: #fff; text-transform: uppercase; letter-spacing: 0.3px; }}
    .url {{ font-family: monospace; font-size: 0.82rem; color: #58a6ff; word-break: break-all; }}
    .param {{ font-family: monospace; font-size: 0.82rem; color: #d2a8ff; }}
    .conf {{ color: #8b949e; font-size: 0.8rem; }}
    .explanation {{ color: #c9d1d9; margin-bottom: 4px; }}
    .remediation {{ color: #3fb950; font-size: 0.83rem; }}
    footer {{ text-align: center; padding: 20px; color: #444c56; font-size: 0.78rem; border-top: 1px solid #21262d; }}
  </style>
</head>
<body>
  <header>
    <h1>DeepScan Security Report</h1>
    <p>Agentic Web Security Scanner</p>
    <div class="meta">
      <span><strong>Target:</strong> {report.target_url}</span>
      <span><strong>Started:</strong> {report.scan_started}</span>
      <span><strong>Finished:</strong> {report.scan_finished}</span>
    </div>
  </header>

  <div class="summary">
    <div class="card total">
      <div class="count">{report.total_count}</div>
      <div class="label">Total</div>
    </div>
    <div class="card critical">
      <div class="count">{report.critical_count}</div>
      <div class="label">Critical</div>
    </div>
    <div class="card high">
      <div class="count">{report.high_count}</div>
      <div class="label">High</div>
    </div>
    <div class="card medium">
      <div class="count">{report.medium_count}</div>
      <div class="label">Medium</div>
    </div>
    <div class="card low">
      <div class="count">{report.low_count}</div>
      <div class="label">Low</div>
    </div>
  </div>

  <main>
    <h2>Confirmed Findings</h2>
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Plugin</th>
          <th>URL / Parameter</th>
          <th>Confidence</th>
          <th>Explanation</th>
          <th>Remediation</th>
        </tr>
      </thead>
      <tbody>
        {rows}{empty_msg}
      </tbody>
    </table>
  </main>

  <footer>Generated by DeepScan — {report.scan_finished}</footer>
</body>
</html>"""

    def generate_markdown(self, report: ScanReport) -> str:
        """Render the report as a GitHub-Flavored Markdown string.

        Args:
            report: Populated ScanReport to render.

        Returns:
            Complete Markdown document as a string.
        """
        lines: list[str] = [
            "# DeepScan Security Report",
            "",
            f"**Target:** {report.target_url}  ",
            f"**Started:** {report.scan_started}  ",
            f"**Finished:** {report.scan_finished}",
            "",
            "## Summary",
            "",
            f"| Total | Critical | High | Medium | Low |",
            f"|-------|----------|------|--------|-----|",
            f"| {report.total_count} | {report.critical_count} | {report.high_count} | {report.medium_count} | {report.low_count} |",
            "",
            "## Confirmed Findings",
            "",
        ]

        if not report.findings:
            lines.append("_No confirmed findings._")
        else:
            lines += [
                "| # | Severity | Confidence | Plugin | URL | Parameter | Explanation | Remediation |",
                "|---|----------|------------|--------|-----|-----------|-------------|-------------|",
            ]
            for i, f in enumerate(report.findings, start=1):
                param = f.result.parameter or "N/A"
                explanation = f.explanation.replace("|", "\\|").replace("\n", " ")
                remediation = f.remediation.replace("|", "\\|").replace("\n", " ")
                url = f.result.url.replace("|", "\\|")
                lines.append(
                    f"| {i} | **{f.severity.upper()}** | {f.confidence:.2f} "
                    f"| {f.result.plugin_name} | {url} | `{param}` "
                    f"| {explanation} | {remediation} |"
                )

        lines += ["", f"---", f"_Generated by DeepScan — {report.scan_finished}_"]
        return "\n".join(lines)

    def save(self, report: ScanReport, out_dir: Path, timestamp: str) -> tuple[Path, Path]:
        """Write HTML and Markdown reports to disk.

        Args:
            report: Populated ScanReport to persist.
            out_dir: Directory to write files into (created if absent).
            timestamp: Timestamp string used in filenames (e.g. '20260627_165207').

        Returns:
            Tuple of (html_path, markdown_path).
        """
        out_dir.mkdir(parents=True, exist_ok=True)
        html_path = out_dir / f"report_{timestamp}.html"
        md_path   = out_dir / f"report_{timestamp}.md"

        html_path.write_text(self.generate_html(report), encoding="utf-8")
        md_path.write_text(self.generate_markdown(report), encoding="utf-8")
        return html_path, md_path

    # ── Private helpers ────────────────────────────────────────────────────────

    def _html_row(self, f: TriagedFinding) -> str:
        color  = _sev_color(f.severity)
        param  = f.result.parameter or "N/A"
        explanation = f.explanation.replace("<", "&lt;").replace(">", "&gt;")
        remediation = f.remediation.replace("<", "&lt;").replace(">", "&gt;")
        url    = f.result.url.replace("<", "&lt;").replace(">", "&gt;")
        return (
            f'<tr>'
            f'<td><span class="badge" style="background:{color}">{f.severity.upper()}</span></td>'
            f'<td>{f.result.plugin_name}</td>'
            f'<td><span class="url">{url}</span><br><span class="param">{param}</span></td>'
            f'<td><span class="conf">{f.confidence:.2f}</span></td>'
            f'<td><div class="explanation">{explanation}</div></td>'
            f'<td><div class="remediation">{remediation}</div></td>'
            f'</tr>'
        )

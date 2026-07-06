# DeepScan — Agentic Web Security Scanner

DeepScan is an AI-powered web application security scanner. It crawls a target site, runs vulnerability plugins, sends every finding to an LLM for expert triage (false-positive removal + remediation), and outputs a professional HTML/Markdown report — all from a single command.

---

## How It Works

```
deepscan agent <url>
       │
       ├─ 1. Crawl       Async DFS crawler discovers all pages and forms
       │
       ├─ 2. Plugin Scan  XSS, SQLi, Sensitive-Info plugins run concurrently
       │
       ├─ 3. AI Triage    LLM reviews each finding — removes false positives,
       │                  adjusts severity, writes specific remediations
       │
       └─ 4. Report       outputs/report_<ts>.html + .md + agent_results_<ts>.json
```

---

## Quick Start

### 1. Install

```bash
git clone <repo>
cd DeepScan
uv venv && source .venv/bin/activate
uv pip install -e .
```

### 2. Configure LLM provider

```bash
deepscan configure
```

Interactive wizard — choose your provider (Gemini / OpenAI / Anthropic), enter your API key, and select a model. Config is saved to `~/.deepscan/config.yaml` (chmod 600).

### 3. (Optional) Download community payloads

```bash
deepscan update-payloads
```

Pulls curated payload lists from [SecLists](https://github.com/danielmiessler/SecLists) into `~/.deepscan/payloads/`. Plugins fall back to built-in defaults if this step is skipped.

### 4. Run a scan

```bash
deepscan agent https://demo.testfire.net --depth 2
```

---

## Commands

| Command | Description |
|---|---|
| `deepscan configure` | Interactive LLM provider setup wizard |
| `deepscan agent <url> --depth N` | Full pipeline: crawl → scan → triage → report |
| `deepscan update-payloads` | Fetch latest community payloads from SecLists |
| `deepscan crawl <url>` | _(coming soon)_ Crawl only |
| `deepscan scan <url>` | _(coming soon)_ Plugin scan only |

---

## Features

### Async Crawler
- Depth-first crawl with configurable max depth
- Extracts pages, forms, form inputs, and JS-inlined URLs
- Respects `robots.txt`
- Configurable via `config/crawler.yaml` (user-agent, timeout, concurrency, rate limiting)

### Plugin Scan
- Plugins run concurrently against all endpoints (semaphore-bounded)
- Findings deduplicated on `(plugin, url, parameter)` before triage
- Built-in plugins:

  | Plugin | What It Detects |
  |---|---|
  | `XSS-Reflective` | Reflected XSS via URL params and form inputs |
  | `SQLi-Basic` | SQL injection via error-keyword matching |
  | `Sensitive-Info` | Emails, phone numbers, SSNs, API keys exposed in responses |

- Add new plugins by implementing `ScannerPlugin` in `src/plugins/`

### Community Payloads
- Plugins load payloads from `~/.deepscan/payloads/` after `deepscan update-payloads`
- Falls back to built-in defaults (4 payloads each) if cache is absent
- Default limit: top 25 payloads per plugin (keeps scans fast)
- Sources: SecLists `XSS/robot-friendly/` and `SQLi/`

### AI Triage
- Every finding gets its own focused LLM prompt (no batch)
- Runs concurrently (up to 3 parallel LLM calls)
- Retry logic: up to 2 retries with exponential backoff (1s, 2s) on transient errors
- Per-finding output:
  - `is_false_positive` — removes noise
  - `severity` — LLM-adjusted (low / medium / high / critical)
  - `confidence` — 0.0–1.0
  - `explanation` — why it's a real issue
  - `remediation` — specific fix for this endpoint and parameter
- Falls back to raw scanner result if all retries fail

### Supported LLM Providers

| Provider | Configure Name |
|---|---|
| Google Gemini | `gemini` |
| OpenAI | `openai` |
| Anthropic Claude | `anthropic` |

### Reports
Every scan produces three output files in `outputs/`:

| File | Format | Description |
|---|---|---|
| `agent_results_<ts>.json` | JSON | Machine-readable confirmed findings |
| `report_<ts>.html` | HTML | Self-contained dark-themed report, opens in any browser |
| `report_<ts>.md` | Markdown | GFM-compatible, ready for GitHub / Notion |

---

## Configuration

### LLM Config — `~/.deepscan/config.yaml`
Created by `deepscan configure`. Stored with `chmod 600`.

```yaml
provider: gemini
api_key: YOUR_API_KEY
model: gemini-2.0-flash
```

### Crawler Config — `config/crawler.yaml`

```yaml
user_agent: "AgenticScanner/0.2"
timeout_seconds: 15
max_concurrency: 8
request_delay_ms: 50
respect_robots_txt: true
same_domain_only: true
include_subdomains: true
allowed_content_types:
  - "text/html"
  - "application/xhtml+xml"
enable_js_url_extraction: true
```

---


## Running Tests

```bash
.venv/bin/pytest -v
```

66 tests across three suites:

| Suite | Tests | Covers |
|---|---|---|
| `tests/test_triage.py` | 22 | Prompt builder, response parser, triage service (retry, fallback, concurrency) |
| `tests/test_report.py` | 28 | ScanReport counts, HTML generation, Markdown generation, file save |
| `tests/test_payloads.py` | 16 | PayloadLoader (cache/fallback/limit), PayloadUpdater (fetch/save/failure) |

---

## Adding a New Plugin

1. Create `src/plugins/myplugin_plugin.py`
2. Implement `ScannerPlugin`:

```python
from src.plugins.base import ScannerPlugin, Result

class MyPlugin(ScannerPlugin):
    name = "My-Plugin"

    async def test(self, session, endpoint) -> list[Result]:
        # test the endpoint, return Result objects
        ...

    def extract_remediation(self, result: Result) -> str:
        return "How to fix this..."
```

3. Done — auto-discovery picks it up on the next scan.

---

## Ethics & Legal

Only scan systems you own or have **explicit written permission** to test. Unauthorized scanning may be illegal. DeepScan is intended for authorized security testing, CTF challenges, and research only.

---

## License

Open for research and professional use. Use responsibly and at your own risk.

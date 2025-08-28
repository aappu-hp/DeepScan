# DeepScan — Agentic Web Security Scanner

DeepScan is an extensible web application security scanner designed for efficient reconnaissance and vulnerability detection. It combines an asynchronous crawler, a plugin-driven vulnerability testing framework, and a structured data model to streamline scanning, enable rapid extension, and provide actionable results.

---

# What DeepScan is

DeepScan is a modular web security scanner built to:

* Discover the attack surface of a target website through a polite asynchronous crawler.
* Run pluggable vulnerability checks for common security issues such as XSS, SQLi, and sensitive information exposure.
* Collect structured findings in both JSON and human-readable console outputs.
* Provide a clean architecture that emphasizes extensibility and professional usage.

---

# Key Capabilities

* **Asynchronous Crawler**

  * Discovers same-domain URLs with configurable depth.
  * Extracts links, forms, form inputs, and JavaScript-inlined URLs.
  * Respects `robots.txt` policies (configurable).
  * Outputs structured endpoint metadata including forms, inputs, content type, status, and titles.

* **Plugin Framework**

  * Unified `ScannerPlugin` interface and `Result` dataclass.
  * Auto-discovery of plugins under `src/plugins/`.
  * Example plugins included:

    * Sensitive-Info (detects PII such as emails and phone numbers).
    * SQLi-Basic (basic SQL injection heuristics).
    * XSS-Reflective (detects reflected cross-site scripting).
  * Central plugin runner executes all discovered plugins against URLs or endpoint exports and saves structured results.

* **Clean Data Model**

  * Dataclasses define endpoints and results.
  * Ensures smooth integration between crawler output and plugin inputs.

---

# Tech Stack

* **Language**: Python 3.11+
* **Networking**: aiohttp
* **Parsing**: BeautifulSoup4 with lxml parser
* **CLI & Output**: argparse, rich
* **Configuration**: YAML (pyyaml)
* **Domain Utilities**: tldextract
* **Persistence**: JSON output files (lightweight and portable)

### requirements.txt

```
aiohttp
beautifulsoup4
lxml
pyyaml
rich
tldextract
```

---

# Prerequisites

* Python 3.11 or later installed
* A virtual environment (recommended)
* Install dependencies:

```bash
uv pip install -r requirements.txt
# or
python -m pip install -r requirements.txt
```

---

# Usage

### CLI Demo

```bash
uv run -m src.scanner_cli --target http://example.com --depth 1 --policy config/crawler.yaml
```

### Crawler

```bash
uv run -m src.crawler.crawler --start http://testphp.vulnweb.com/ --max-depth 2 --output outputs
# or print JSON directly:
uv run -m src.crawler.crawler --start http://testphp.vulnweb.com/ --max-depth 2 --json
```

* Configuration defaults from `config/crawler.yaml`.
* Output saved to `outputs/crawl_results_<timestamp>.json`.

### Plugin Runner

Run plugins against a single URL:

```bash
uv run -m src.plugins.runner --url http://testphp.vulnweb.com/login.php --output outputs
```

Run plugins against crawler export:

```bash
uv run -m src.plugins.runner --endpoints outputs/crawl_results_20250821_004437.json --output outputs
```

* Results saved as `outputs/plugin_results_<timestamp>.json`.
* Example plugin demo:

```bash
uv run -m src.plugins.xss_plugin --url "http://testphp.vulnweb.com/?q=test"
```

---

# Workflow

1. **Crawl** — Discover endpoints and forms. Export endpoints JSON with rich metadata.
2. **Analyze** — Run vulnerability plugins against discovered endpoints or a specific URL.
3. **Report** — View console results with severity and remediation suggestions. Persist findings in structured JSON format.

---

# Project Structure

```
DeepScan/
├── payloads/                  # (future) payload seeds
├── config/
│   └── crawler.yaml           # crawler defaults and policies
├── data/
│   └── experience.json        # (future) payload experience store
├── outputs/                   # runtime outputs (crawler/plugin results)
├── requirements.txt
└── src/
    ├── scanner_cli.py         # CLI scaffold
    ├── utils/
    │   ├── config_loader.py
    │   ├── logger.py
    │   └── url.py
    ├── crawler/
    │   ├── crawler.py         # asynchronous crawler
    │   ├── parser.py
    │   ├── robots.py
    │   └── models.py
    └── plugins/
        ├── base.py            # Result dataclass + ScannerPlugin ABC
        ├── loader.py          # plugin auto-discovery
        ├── runner.py          # plugin runner
        ├── xss_plugin.py
        ├── sqli_plugin.py
        └── sensitive_plugin.py
```

---

# Data & Output Formats

* **Crawler Output** — `outputs/crawl_results_<timestamp>.json`

```json
{
  "url": "http://example.com/search.php?q=test",
  "type": "form",
  "method": "POST",
  "form_inputs": [{"name": "q", "input_type":"text", "value":null}],
  "depth": 1,
  "parent": "http://example.com/",
  "status": 200,
  "title": "Search"
}
```

* **Plugin Output** — `outputs/plugin_results_<timestamp>.json`

```json
{
  "plugin_name": "XSS-Reflective",
  "url": "http://example.com/search.php?q=<script>alert(1)</script>",
  "evidence": "<script>alert(1)</script>",
  "confidence": 0.95,
  "severity": "high",
  "remediation": "Sanitize and encode output..."
}
```

---

# Extending DeepScan

* **Add new plugins** by implementing `ScannerPlugin` in `src/plugins/`.
* **Modify crawler policies** in `config/crawler.yaml` (e.g., user-agent, allowed content types).
* **Persist differently** by replacing JSON storage with a database.

---

# Security and Ethics

⚠️ Only scan systems you own or have explicit permission to test. Unauthorized scanning may be illegal and harmful. DeepScan is provided for authorized security testing and research only.

---

# Roadmap

* Payload seed and mutation engine with adaptive payloads.
* Orchestration layer for automated scan pipelines.
* Enhanced persistence (database-backed experience store).
* Reporting dashboards and visualization.
* Optional AI-assisted payload and remediation generation.

---

# License

This project is open for research and professional use. Use responsibly and at your own risk.

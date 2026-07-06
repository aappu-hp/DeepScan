# DeepScan — Project Scope & Purpose

> **The agentic, LLM-native web security scanner built for the modern Python ecosystem.**

---

## Mission Statement

DeepScan's mission is to make web application security testing **intelligent, extensible, and accessible** — to everyone from junior developers running their first security check to senior red teamers building custom offensive tooling.

Most open-source scanners are static: they fire a fixed set of payloads, produce a flat report, and stop. DeepScan is different. It **reasons about what to test next**, learns from what has worked before, and uses large language models to surface findings that matter — without replacing the human in the loop.

---

## The Problem DeepScan Solves

Existing open-source web security scanners have one of two failure modes:

**Too heavyweight.** Tools like OWASP ZAP and Burp Suite are powerful but demand significant setup, proprietary extensions, and GUI-first workflows that don't fit modern CI/CD pipelines or scripted automation.

**Too dumb.** Tools like Nikto, wfuzz, or standalone scripts fire static payloads in a fixed order with no awareness of what's working. Every scan is identical regardless of the target, and findings dump into a flat list with no intelligent prioritisation.

DeepScan occupies the gap: a **lightweight, composable Python tool** that brings genuine agentic intelligence to security scanning — with a clean plugin SDK anyone can extend in under 30 lines.

---

## Who DeepScan Is For

DeepScan is built for four distinct personas, all of whom are first-class citizens:

**The Security Researcher / Pentester**
Runs authorised audits on web applications. Needs depth, reproducibility, and CLI scriptability. Wants to compose DeepScan into larger toolchains (e.g., alongside nmap, ffuf, or custom recon scripts). Values the ability to write a plugin for a novel vuln class in minutes and plug it into the existing scan pipeline.

**The Developer / DevSecOps Engineer**
Wants to shift security left. Needs a scanner that can be imported as a Python library, invoked from a `pytest` hook or a GitHub Actions workflow, and that produces machine-readable output (JSON) suitable for automated pass/fail gates. Doesn't want to run a Java process or manage a Burp extension.

**The Student / Security Learner**
Is learning web security concepts — XSS, SQLi, IDOR, SSRF. Needs clean, readable code they can study. Each plugin is a contained, self-documenting example of how a vuln class works and how to test for it. The experience store shows them what payloads succeed and why.

**The Red Teamer**
Runs offensive engagements. Needs a highly customisable, agentic scanner they can extend with proprietary plugins, custom payload seeds, and Gemini-powered triage that adapts to target-specific context. Wants a tool that gets smarter with each engagement, not a tool that behaves identically every time.

---

## Core Differentiators

DeepScan's value proposition rests on three pillars that, taken together, no other open-source scanner currently offers:

### Pillar 1 — Agentic + LLM-Native

The scanner doesn't just execute; it **reasons**. A `DeepScanAgent` runs a ReAct-style loop (Reason → Act → Observe) over discovered endpoints. It maintains a priority queue, scores targets using heuristics, and — when a Gemini API key is available — calls the Gemini API to triage findings mid-scan and suggest next actions.

The LLM layer is **optional and additive**: the scanner is fully functional without a Gemini key. When the key is present, it unlocks:
- Mid-scan finding triage (which findings are signal vs. noise)
- Context-aware payload generation based on target tech stack
- Natural-language remediation summaries tailored to the specific evidence found
- Post-scan executive summary generation

This is built on **Google Gemini** (models: `gemini-2.0-flash`, `gemini-2.5-pro`), chosen for cost-effectiveness at scale, strong tool-calling support, and the generous free tier that makes it accessible to students and OSS contributors.

### Pillar 2 — Plugin-First SDK

Every vulnerability check is a self-contained plugin implementing a 3-method interface (`name`, `test`, `extract_remediation`). Plugins are **auto-discovered** — drop a `.py` file in `src/plugins/` and it runs on the next scan. No registration, no config changes.

This is deliberately lower-friction than writing a Burp extension (Java, complex API, GUI-bound) or a ZAP add-on (compiled, versioned). A new plugin for a novel vuln class is 25–40 lines of async Python.

Plugins are also **payload-agnostic**: they receive payloads from the mutation engine rather than hardcoding them. This means the same plugin benefits automatically as the experience store accumulates knowledge.

### Pillar 3 — Async Performance, Modern Python

Built on `asyncio` + `aiohttp`. The crawler and plugin tests run concurrently, bounded by a configurable semaphore. Scans that would take minutes in a synchronous tool complete in seconds.

Requires Python 3.11+. Uses `dataclasses`, `asyncio.gather`, `pathlib`, and `typer` — familiar, idiomatic modern Python with zero exotic dependencies.

---

## Scope — What DeepScan Does

**In scope (v1.0 target):**

- Asynchronous DFS/BFS web crawler with robots.txt compliance
- Auto-discovering plugin framework (XSS, SQLi, Sensitive Info, extensible)
- Payload mutation engine with a YAML seed file and experience-store weighting
- Experience store (`data/experience.json`) that learns payload hit-rates across scans
- Endpoint priority scorer (heuristic-based)
- Optional Gemini API integration for finding triage and payload suggestions
- HTML + Markdown report generation
- CLI with subcommands (`crawl`, `scan`, `agent`, `report`)
- Importable as a Python library (`from deepscan import DeepScanAgent`)
- `SKILL.md` for Cowork / Claude Agent SDK integration
- Full type annotations, `pytest` test suite, GitHub Actions CI

**In scope (v2.0 roadmap):**

- Authenticated scanning (session cookies, Bearer tokens, OAuth flows)
- SSRF, IDOR, open-redirect, and path traversal plugins
- Gemini-powered plugin generation ("describe a vuln, get a plugin")
- Structured CVSS scoring per finding
- Database-backed experience store (SQLite)
- Multi-target parallel scan orchestration

---

## Scope — What DeepScan Explicitly Does NOT Do

Getting the exclusions right is as important as the inclusions. DeepScan will not:

- **Perform unauthenticated network-layer scanning** (port scanning, service fingerprinting) — that is Nmap's domain
- **Provide a GUI or web dashboard** in v1.0 — this is a CLI/library tool first; a dashboard is a v2+ concern
- **Support binary/non-HTTP protocols** — HTTP/HTTPS only
- **Replace Burp Suite for manual testing** — DeepScan is automated; it has no proxy or intercept mode
- **Operate as a SaaS or cloud-hosted service** — it runs where you run it
- **Scan targets you don't own or have explicit permission to test** — this is an ethical and legal boundary, not a technical one

---

## Technical Boundaries

| Dimension | Decision |
|---|---|
| Language | Python 3.11+ |
| LLM Provider | Google Gemini (`gemini-2.0-flash`, `gemini-2.5-pro`) |
| LLM Dependency | Optional — scanner works without it |
| Networking | `aiohttp` (async) |
| Parsing | `BeautifulSoup4` + `lxml` |
| CLI | `typer` |
| Config | YAML (`pyyaml`) |
| Output | JSON (machine) + HTML/Markdown (human) |
| Packaging | `pyproject.toml` (uv / pip compatible) |
| Testing | `pytest` + `pytest-asyncio` |
| CI | GitHub Actions |
| License | MIT |

---

## Positioning vs. Alternatives

| Tool | Strength | Why DeepScan is Different |
|---|---|---|
| OWASP ZAP | Deep coverage, proxy mode | Java, GUI-first, no agentic loop, heavy setup |
| Burp Suite | Best-in-class manual testing | Commercial, closed-source, no LLM reasoning |
| Nikto | Fast, wide coverage | Synchronous, static payloads, no plugin SDK |
| SQLMap | Excellent SQLi depth | Single-vuln focus, not a general scanner |
| **DeepScan** | Agentic, LLM-native, extensible | Pure Python, async, learns from experience |

---

## Open Source Philosophy

DeepScan is MIT licensed. Contributions are welcome from anyone — security researchers, developers, students, and red teamers alike.

**Contribution guidelines (to be formalised in `CONTRIBUTING.md`):**

- New plugins are the most welcome contribution — they directly expand coverage for all users
- The experience store and mutator are community-shared — payload wisdom accumulates across the ecosystem
- All plugins must include a `__test__` block and a remediation string
- The LLM layer must remain optional — no Gemini API key should ever be required for core functionality
- Ethical use is mandatory — the project will not accept plugins or payloads designed for use against targets without permission

---

## Success Criteria for v1.0

1. `pip install deepscan` works cleanly on Python 3.11+
2. `deepscan agent https://testphp.vulnweb.com --depth 2` runs the full agentic loop and produces an HTML report
3. A new plugin can be written and working in under 15 minutes following the docs
4. The Gemini integration is provably optional (CI runs without a Gemini key)
5. README, plugin SDK docs, and CONTRIBUTING.md are complete
6. At least 5 plugins ship with v1.0 (XSS, SQLi, Sensitive Info, Open Redirect, Security Headers)

---

*Last updated: 2026-03-05 | Status: Pre-implementation scope definition*

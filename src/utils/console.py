"""
DeepScan — Console UI
Centralised terminal presentation: banner, status prefixes, section separators.
All modules should import from here to keep a consistent look.
"""
from __future__ import annotations

from rich.console import Console
from rich.text import Text
from rich.theme import Theme

try:
    import pyfiglet
    _FIGLET_AVAILABLE = True
except ImportError:
    _FIGLET_AVAILABLE = False

# ── Colour palette ────────────────────────────────────────────────────────────
_THEME = Theme({
    "banner":    "bold cyan",
    "tagline":   "bold yellow",
    "sep":       "dim cyan",
    "target":    "bold white",
    "ok":        "bold green",
    "fail":      "bold red",
    "working":   "bold yellow",
    "query":     "bold cyan",
    "warn":      "bold bright_red",
    "label":     "dim white",
    "high":      "bold red",
    "medium":    "bold yellow",
    "low":       "bold green",
    "info":      "bold cyan",
})

console = Console(theme=_THEME, highlight=False)

# ── Fallback ASCII art (used if pyfiglet is not installed) ────────────────────
_FALLBACK_BANNER = r"""
  ██████╗ ███████╗███████╗██████╗ ███████╗ ██████╗ █████╗ ███╗
  ██╔══██╗██╔════╝██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗████╗
  ██║  ██║█████╗  █████╗  ██████╔╝███████╗██║     ███████║██╔██╗
  ██║  ██║██╔══╝  ██╔══╝  ██╔═══╝ ╚════██║██║     ██╔══██║██║╚██╗
  ██████╔╝███████╗███████╗██║     ███████║╚██████╗██║  ██║██║ ╚██╗
  ╚═════╝ ╚══════╝╚══════╝╚═╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝
"""

_SEP_CHAR  = "─"
_SEP_WIDTH = 68


# ── Public helpers ─────────────────────────────────────────────────────────────

def print_banner(version: str = "v1.0", author: str = "Appu H") -> None:
    """Print the DeepScan ASCII banner."""
    console.print()
    if _FIGLET_AVAILABLE:
        art = pyfiglet.figlet_format("DeepScan", font="slant")
    else:
        art = _FALLBACK_BANNER
    console.print(art, style="banner", end="")
    console.print(
        f"  [tagline]Agentic Web Security Scanner[/tagline]"
        f"  [label]|[/label]  [tagline]{version}[/tagline]"
        f"  [label]|[/label]  [label]by {author}[/label]"
    )
    console.print()


def print_sep() -> None:
    """Print a full-width section separator."""
    console.print(f"  [sep]{_SEP_CHAR * _SEP_WIDTH}[/sep]")


def print_target(url: str) -> None:
    """Print the scan target header."""
    print_sep()
    console.print(f"  [label]\\[Target][/label] [sep]=>[/sep] [target]{url}[/target]")
    print_sep()
    console.print()


def ok(label: str, value: str = "") -> None:
    """[+] green — found / success."""
    _status("ok", "+", label, value)


def fail(label: str, value: str = "") -> None:
    """[-] red — not found / failed."""
    _status("fail", "-", label, value)


def working(label: str, value: str = "") -> None:
    """[~] yellow — in progress."""
    _status("working", "~", label, value)


def query(label: str, value: str = "") -> None:
    """[?] cyan — querying."""
    _status("query", "?", label, value)


def warn(label: str, value: str = "") -> None:
    """[!] bright red — critical / warning."""
    _status("warn", "!", label, value)


def finding(plugin: str, location: str, severity: str, confidence: float) -> None:
    """Print a formatted vulnerability finding line."""
    sev = severity.upper()
    sev_style = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}.get(sev, "info")
    console.print(
        f"  [ok]\\[+][/ok] [label]{plugin:<20}[/label]"
        f"  [{sev_style}]{sev:<8}[/{sev_style}]"
        f"  conf={confidence:.2f}"
        f"  [label]{location}[/label]"
    )


def phase(title: str) -> None:
    """Print a named scan phase header with separator."""
    console.print()
    print_sep()
    console.print(f"  [tagline]{title}[/tagline]")
    print_sep()


# ── Internal ───────────────────────────────────────────────────────────────────

def _status(style: str, prefix: str, label: str, value: str) -> None:
    if value:
        console.print(
            f"  [{style}]\\[{prefix}][/{style}] [label]{label:<20}[/label]"
            f" [target]{value}[/target]"
        )
    else:
        console.print(f"  [{style}]\\[{prefix}][/{style}] {label}")


# ── Demo (run this file directly to preview the UI) ───────────────────────────

if __name__ == "__main__":
    print_banner()
    print_target("https://testphp.vulnweb.com")

    phase("Recon")
    query("Detecting CMS...")
    ok("CMS Detected",     "WordPress 6.4")
    ok("Server",           "nginx/1.24")
    ok("CDN",              "Cloudflare")
    ok("Country",          "IN  |  Org: AS13335")
    fail("Zone Transfer",  "Not allowed (expected)")

    phase("Crawler")
    working("Crawling target", "depth=2")
    ok("Endpoints discovered", "34 pages  |  12 forms")
    warn("High-value targets", "/wp-login.php  /admin  /search")

    phase("Plugin Scan")
    working("Running plugins", "XSS · SQLi · Headers · Sensitive")
    finding("XSS-Reflective",  "/search?q=",  "high",   0.95)
    finding("SQLi-Basic",      "/login.php",  "high",   0.85)
    fail("Sensitive-Info",     "No findings")
    finding("Sec-Headers",     "Missing CSP", "medium", 0.90)

    phase("Report")
    ok("Summary",    "2 high  |  1 medium  |  0 low")
    ok("Report saved", "outputs/report_20260305_142301.html")
    console.print()

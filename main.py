import typer

from src.agent.agent import DeepScanAgent
from src.configure.wizard import ConfigureWizard
from src.utils.console import print_banner, console

app = typer.Typer(help="DeepScan — Agentic Web Security Scanner")


@app.command()
def configure() -> None:
    """Run the interactive LLM provider configuration wizard."""
    print_banner()
    ConfigureWizard().run()


@app.command()
def agent(
    url: str = typer.Argument(..., help="Target URL to scan"),
    depth: int = typer.Option(2, "--depth", "-d", help="Crawl depth"),
) -> None:
    """Run the agentic scan loop against a target URL."""
    print_banner()
    DeepScanAgent(url=url, depth=depth).run()


@app.command()
def crawl(
    url: str = typer.Argument(..., help="Target URL to crawl"),
    depth: int = typer.Option(2, "--depth", "-d", help="Crawl depth"),
) -> None:
    """Crawl a target URL and print discovered endpoints."""
    print_banner()
    console.print(f"  [working]\\[~][/working] Crawler not yet implemented — target: [target]{url}[/target]")


@app.command()
def scan(
    url: str = typer.Argument(..., help="Target URL to scan"),
) -> None:
    """Run plugin scans against a target URL without the agentic loop."""
    print_banner()
    console.print(f"  [working]\\[~][/working] Plugin scan not yet implemented — target: [target]{url}[/target]")


if __name__ == "__main__":
    app()

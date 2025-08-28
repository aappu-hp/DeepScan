from __future__ import annotations
import argparse
import asyncio
import json
from collections import deque
from typing import List, Set, Optional
from datetime import datetime
from pathlib import Path

import aiohttp
from rich.console import Console

from ..utils.config_loader import load_yaml
from ..utils.logger import get_logger
from ..utils.url import normalize_url, same_domain
from .parser import extract_links, extract_forms, extract_js_urls, extract_title
from .models import Endpoint
from .robots import RobotsCache

logger = get_logger("crawler")
console = Console()


class AsyncCrawler:
    def __init__(
        self,
        user_agent: str = "AgenticScanner/0.2",
        timeout_seconds: int = 15,
        max_concurrency: int = 8,
        request_delay_ms: int = 0,
        respect_robots_txt: bool = True,
        same_domain_only: bool = True,
        include_subdomains: bool = True,
        allowed_content_types: list | None = None,
        enable_js_url_extraction: bool = True,
        output_dir: str = "outputs",
    ) -> None:
        self.user_agent = user_agent
        self.timeout_seconds = timeout_seconds
        self.semaphore = asyncio.Semaphore(max_concurrency)
        self.request_delay_ms = request_delay_ms
        self.respect_robots_txt = respect_robots_txt
        self.same_domain_only = same_domain_only
        self.include_subdomains = include_subdomains
        self.allowed_content_types = set(
            allowed_content_types or ["text/html", "application/xhtml+xml"]
        )
        self.enable_js_url_extraction = enable_js_url_extraction
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self._robots = RobotsCache(user_agent=user_agent, timeout=timeout_seconds)

    async def fetch(
        self, session: aiohttp.ClientSession, url: str
    ) -> tuple[Optional[str], Optional[str], Optional[int]]:
        if self.request_delay_ms > 0:
            await asyncio.sleep(self.request_delay_ms / 1000.0)
        headers = {
            "User-Agent": self.user_agent,
            "Accept": ", ".join(self.allowed_content_types),
        }
        try:
            async with self.semaphore:
                async with session.get(
                    url,
                    headers=headers,
                    timeout=self.timeout_seconds,
                    allow_redirects=True,
                ) as resp:
                    ctype = resp.headers.get("Content-Type", "").split(";")[0].strip().lower()
                    if self.allowed_content_types and ctype and ctype not in self.allowed_content_types:
                        return None, ctype, resp.status
                    text = await resp.text(errors="ignore")
                    return text, ctype, resp.status
        except Exception as e:
            logger.debug(f"fetch error for {url}: {e}")
            return None, None, None

    async def crawl_dfs(self, start_url: str, max_depth: int = 2) -> List[Endpoint]:
        """
        Depth-first style crawling using an explicit stack (iterative).
        """
        start_url = normalize_url(start_url, "") or start_url
        visited: Set[str] = set()
        stack: deque[tuple[str, int, Optional[str]]] = deque()
        stack.append((start_url, 0, None))
        endpoints: List[Endpoint] = []

        timeout = aiohttp.ClientTimeout(
            total=None, connect=self.timeout_seconds, sock_read=self.timeout_seconds
        )
        conn = aiohttp.TCPConnector(limit=0, ssl=False)
        async with aiohttp.ClientSession(timeout=timeout, connector=conn) as session:
            while stack:
                url, depth, parent = stack.pop()  # DFS
                if url in visited:
                    continue
                if depth > max_depth:
                    continue

                # robots.txt
                if self.respect_robots_txt:
                    allowed = await self._robots.allowed(session, url)
                    if not allowed:
                        logger.info(f"robots disallow: {url}")
                        continue

                visited.add(url)
                console.print(f"[cyan]Crawling:[/cyan] {url} [dim](depth={depth})[/dim]")

                html, content_type, status = await self.fetch(session, url)
                if status is not None:
                    logger.info(f"[{status}] {url}")
                if html is None:
                    continue

                title = extract_title(html)
                endpoints.append(
                    Endpoint(
                        url=url,
                        type="page",
                        method="GET",
                        params={},
                        form_inputs=[],
                        depth=depth,
                        parent=parent,
                        discovered_via="link" if depth > 0 else "seed",
                        status=status,
                        content_type=content_type,
                        title=title,
                    )
                )

                # forms
                forms = extract_forms(url, html, depth, parent)
                endpoints.extend(forms)

                # links
                links = extract_links(url, html)
                if self.enable_js_url_extraction:
                    links.extend(extract_js_urls(url, html))

                for href in reversed(links):  # DFS
                    if self.same_domain_only and not same_domain(
                        start_url, href, self.include_subdomains
                    ):
                        continue
                    if href not in visited:
                        stack.append((href, depth + 1, url))

        return endpoints

    def export_results(self, endpoints: List[Endpoint]) -> Path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_file = self.output_dir / f"crawl_results_{ts}.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump([e.to_dict() for e in endpoints], f, indent=2)
        logger.info(f"Exported results → {out_file}")
        return out_file


def build_from_config(cfg_path: str, output_dir: str = "outputs") -> AsyncCrawler:
    cfg = load_yaml(cfg_path)
    return AsyncCrawler(
        user_agent=cfg.get("user_agent", "AgenticScanner/0.2"),
        timeout_seconds=int(cfg.get("timeout_seconds", 15)),
        max_concurrency=int(cfg.get("max_concurrency", 8)),
        request_delay_ms=int(cfg.get("request_delay_ms", 0)),
        respect_robots_txt=bool(cfg.get("respect_robots_txt", True)),
        same_domain_only=bool(cfg.get("same_domain_only", True)),
        include_subdomains=bool(cfg.get("include_subdomains", True)),
        allowed_content_types=cfg.get(
            "allowed_content_types", ["text/html", "application/xhtml+xml"]
        ),
        enable_js_url_extraction=bool(cfg.get("enable_js_url_extraction", True)),
        output_dir=output_dir,
    )


def _arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Agentic Scanner — Async DFS Crawler (Part 2)")
    p.add_argument("--start", required=True, help="Starting URL to crawl")
    p.add_argument("--max-depth", type=int, default=2, help="Maximum crawl depth")
    p.add_argument("--config", default="config/crawler.yaml", help="Path to crawler YAML config")
    p.add_argument("--json", action="store_true", help="Output endpoints as JSON to stdout")
    p.add_argument("--output", default="outputs", help="Directory to save crawl results JSON")
    return p


async def _main_async(args: argparse.Namespace) -> int:
    crawler = build_from_config(args.config, output_dir=args.output)
    endpoints = await crawler.crawl_dfs(args.start, max_depth=args.max_depth)

    if args.json:
        print(json.dumps([e.to_dict() for e in endpoints], indent=2))
    else:
        out_file = crawler.export_results(endpoints)
        console.print(f"\n[bold green]Discovered {len(endpoints)} endpoints[/bold green]")
        console.print(f"[dim]Saved results to {out_file}[/dim]\n")

        for e in endpoints:
            if e.type == "form":
                inputs = [f"{i.name}({i.input_type})" for i in e.form_inputs]
                console.print(f"[yellow][FORM][/yellow] {e.method} {e.url} depth={e.depth} inputs={inputs}")
            else:
                console.print(f"[blue][PAGE][/blue] {e.url} depth={e.depth} title={e.title!r}")

    return 0


def main() -> None:
    args = _arg_parser().parse_args()
    try:
        asyncio.run(_main_async(args))
    except KeyboardInterrupt:
        console.print("\n[red]Interrupted by user[/red]")


if __name__ == "__main__":
    main()

from __future__ import annotations
import argparse
import asyncio
import json
from pathlib import Path
from typing import List

import aiohttp
from rich.console import Console

from .loader import discover_plugins
from src.crawler.models import Endpoint, FormInput
from ..utils.logger import get_logger

logger = get_logger("plugin-runner")
console = Console()

def load_endpoints_from_file(path: str) -> List[Endpoint]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(path)
    raw = json.loads(p.read_text(encoding="utf-8"))
    endpoints: List[Endpoint] = []
    for item in raw:
        # Construct Endpoint dataclass instance
        e = Endpoint(
            url=item.get("url"),
            type=item.get("type", "page"),
            method=item.get("method", "GET"),
            params=item.get("params", {}) or {},
            form_inputs=[],
            depth=item.get("depth", 0),
            parent=item.get("parent"),
            discovered_via=item.get("discovered_via"),
            status=item.get("status"),
            content_type=item.get("content_type"),
            title=item.get("title"),
        )
        # convert form_inputs dicts -> FormInput objects if present
        fi = []
        for inp in item.get("form_inputs", []):
            # FormInput lives in src.crawler.models
            fi.append(FormInput(name=inp.get("name"), input_type=inp.get("input_type"), value=inp.get("value")))
        e.form_inputs = fi
        endpoints.append(e)
    return endpoints

async def run_plugins_on_endpoint(session, plugins, endpoint) -> List:
    results = []
    for plugin in plugins:
        try:
            res = await plugin.test(session, endpoint)
            if res:
                # attach originating plugin name to each result if missing
                for r in res:
                    if not getattr(r, "plugin_name", None):
                        r.plugin_name = plugin.name
                results.extend(res)
        except Exception as e:
            logger.exception(f"Plugin {plugin.name} failed on {endpoint.url}: {e}")
    return results

def _find_plugin_by_name(plugins, name: str):
    for p in plugins:
        if getattr(p, "name", None) == name:
            return p
    return None

async def _main_async(args):
    plugins = discover_plugins()
    if not plugins:
        console.print("[red]No plugins found.[/red]")
        return 1

    if args.endpoints:
        endpoints = load_endpoints_from_file(args.endpoints)
    elif args.url:
        # create a minimal Endpoint
        e = Endpoint(url=args.url, type="page", method="GET")
        endpoints = [e]
    else:
        console.print("[red]Provide --url or --endpoints file[/red]")
        return 1

    async with aiohttp.ClientSession() as session:
        all_results = []
        for ep in endpoints:
            console.print(f"[cyan]Scanning endpoint:[/cyan] {ep.url} (type={ep.type})")
            res = await run_plugins_on_endpoint(session, plugins, ep)
            for r in res:
                # Find the plugin instance for remediation lookup
                plugin_instance = _find_plugin_by_name(plugins, r.plugin_name)
                remediation = plugin_instance.extract_remediation(r) if plugin_instance else ""
                console.print(f"[bold yellow]{r.plugin_name}[/bold yellow] -> {r.url} [{r.severity}] conf={r.confidence}")
                console.print(f"    evidence: {r.evidence}")
                console.print(f"    remediation: {remediation}")
                # attach remediation to result object for saving
                setattr(r, "remediation", remediation)
            all_results.extend(res)

        # Save aggregated results
        out_dir = Path(args.output)
        out_dir.mkdir(parents=True, exist_ok=True)
        ts = __import__("datetime").datetime.now().strftime("%Y%m%d_%H%M%S")
        out_file = out_dir / f"plugin_results_{ts}.json"
        # convert results to serializable dicts
        serial = []
        for r in all_results:
            d = {k: v for k, v in r.__dict__.items() if not k.startswith("_")}
            serial.append(d)
        out_file.write_text(json.dumps(serial, indent=2), encoding="utf-8")
        console.print(f"[green]Saved results → {out_file}[/green]")
    return 0

def main():
    p = argparse.ArgumentParser(prog="plugin-runner", description="Run discovered plugins against a URL or endpoints JSON")
    p.add_argument("--url", help="Single target URL")
    p.add_argument("--endpoints", help="JSON file produced by crawler")
    p.add_argument("--output", default="outputs", help="Directory to save plugin results")
    args = p.parse_args()
    try:
        asyncio.run(_main_async(args))
    except KeyboardInterrupt:
        console.print("\n[red]Interrupted by user[/red]")

if __name__ == "__main__":
    main()

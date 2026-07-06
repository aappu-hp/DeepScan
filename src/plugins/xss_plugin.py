from __future__ import annotations
import urllib.parse
from typing import List
import asyncio

from .base import ScannerPlugin, Result
from ..payloads.loader import PayloadLoader
from ..utils.logger import get_logger

logger = get_logger("xss-plugin")


class XSSPlugin(ScannerPlugin):
    """Detects reflected XSS by injecting payloads into URL parameters and forms."""

    name = "XSS-Reflective"

    def __init__(self) -> None:
        self._payloads = PayloadLoader().load("xss")

    async def _test_url_param(self, session, url: str, param: str, payload: str) -> Result | None:
        try:
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            if not qs or param not in qs:
                return None
            qs[param] = [payload]
            new_q = urllib.parse.urlencode(qs, doseq=True)
            test_url = urllib.parse.urlunparse(parsed._replace(query=new_q))
            async with session.get(test_url, timeout=10) as resp:
                text = await resp.text(errors="ignore")
                if payload in text:
                    r = Result(
                        plugin_name=self.name,
                        url=test_url,
                        endpoint_type="page",
                        parameter=param,
                        payload=payload,
                        evidence=payload,
                        confidence=0.95,
                        severity="high"
                    )
                    r.remediation = self.extract_remediation(r)
                    return r
        except Exception as e:
            logger.debug(f"XSS test error for {url} param={param}: {e}")
        return None

    async def _test_form(self, session, endpoint, payload: str) -> Result | None:
        try:
            data = {}
            for inp in endpoint.form_inputs:
                if inp.input_type and inp.input_type.lower() in ("hidden",):
                    data[inp.name] = inp.value or ""
                else:
                    data[inp.name] = payload
            async with session.post(endpoint.url, data=data, timeout=10) as resp:
                text = await resp.text(errors="ignore")
                if payload in text:
                    r = Result(
                        plugin_name=self.name,
                        url=endpoint.url,
                        endpoint_type="form",
                        parameter=",".join([i.name for i in endpoint.form_inputs]),
                        payload=payload,
                        evidence=payload,
                        confidence=0.9,
                        severity="high"
                    )
                    r.remediation = self.extract_remediation(r)
                    return r
        except Exception as e:
            logger.debug(f"XSS form submit error for {endpoint.url}: {e}")
        return None

    async def test(self, session, endpoint) -> List[Result]:
        findings: List[Result] = []
        try:
            parsed = urllib.parse.urlparse(endpoint.url)
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            tasks = []
            if qs:
                for param in qs:
                    for payload in self._payloads:
                        tasks.append(self._test_url_param(session, endpoint.url, param, payload))
            if endpoint.type == "form" and endpoint.form_inputs:
                for payload in self._payloads:
                    tasks.append(self._test_form(session, endpoint, payload))

            if tasks:
                results = await asyncio.gather(*tasks)
                for r in results:
                    if r is not None:
                        findings.append(r)
        except Exception as e:
            logger.exception(f"XSS plugin error for {endpoint.url}: {e}")
        return findings

    def extract_remediation(self, result: Result) -> str:
        return (
            "Sanitize and encode output. Use an allowlist for input validation and "
            "apply proper output encoding for HTML contexts. Example (Python/Flask): "
            "from markupsafe import escape; safe = escape(user_input)"
        )

if __name__ == "__main__":
    import argparse
    import asyncio
    from rich.console import Console

    p = argparse.ArgumentParser()
    p.add_argument("--url", required=True)
    args = p.parse_args()
    console = Console()

    async def run_demo():
        import aiohttp
        async with aiohttp.ClientSession() as session:
            plugin = XSSPlugin()
            class E:
                pass
            e = E()
            e.url = args.url
            e.type = "page"
            e.form_inputs = []
            e.params = {}
            results = await plugin.test(session, e)
            console.print(results)

    asyncio.run(run_demo())

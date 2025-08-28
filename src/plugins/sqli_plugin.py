from __future__ import annotations
import urllib.parse
from typing import List
import asyncio

from .base import ScannerPlugin, Result
from ..utils.logger import get_logger

logger = get_logger("sqli-plugin")

SQL_PAYLOADS = ["'", "1' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL--"]
ERROR_KEYWORDS = ["sql", "mysql", "sqlite", "postgresql", "oracle", "syntax error", "warning"]

class SQLiPlugin(ScannerPlugin):
    name = "SQLi-Basic"

    async def _test_url_param(self, session, url: str, param: str, payload: str) -> Result | None:
        try:
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            if param not in qs:
                return None
            qs[param] = [payload]
            new_q = urllib.parse.urlencode(qs, doseq=True)
            test_url = urllib.parse.urlunparse(parsed._replace(query=new_q))
            async with session.get(test_url, timeout=10) as resp:
                text = await resp.text(errors="ignore")
                low = text.lower()
                if any(k in low for k in ERROR_KEYWORDS):
                    r = Result(
                        plugin_name=self.name,
                        url=test_url,
                        endpoint_type="page",
                        parameter=param,
                        payload=payload,
                        evidence="SQL error keyword found in response",
                        confidence=0.85,
                        severity="high"
                    )
                    r.remediation = self.extract_remediation(r)
                    return r
        except Exception as e:
            logger.debug(f"SQLi test error for {url} param={param}: {e}")
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
                low = text.lower()
                if any(k in low for k in ERROR_KEYWORDS):
                    r = Result(
                        plugin_name=self.name,
                        url=endpoint.url,
                        endpoint_type="form",
                        parameter=",".join([i.name for i in endpoint.form_inputs]),
                        payload=payload,
                        evidence="SQL error keyword found in response",
                        confidence=0.8,
                        severity="high"
                    )
                    r.remediation = self.extract_remediation(r)
                    return r
        except Exception as e:
            logger.debug(f"SQLi form submit error for {endpoint.url}: {e}")
        return None

    async def test(self, session, endpoint) -> List[Result]:
        findings: List[Result] = []
        try:
            parsed = urllib.parse.urlparse(endpoint.url)
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            tasks = []
            if qs:
                for param in qs:
                    for payload in SQL_PAYLOADS:
                        tasks.append(self._test_url_param(session, endpoint.url, param, payload))
            if endpoint.type == "form" and endpoint.form_inputs:
                for payload in SQL_PAYLOADS:
                    tasks.append(self._test_form(session, endpoint, payload))

            if tasks:
                for r in await asyncio.gather(*tasks):
                    if r:
                        findings.append(r)
        except Exception as e:
            logger.exception(f"SQLi plugin error for {endpoint.url}: {e}")
        return findings

    def extract_remediation(self, result: Result) -> str:
        return (
            "Use parameterized queries / prepared statements and avoid string concatenation "
            "for SQL. Example (Python + psycopg2): cursor.execute('SELECT * FROM users WHERE id=%s', (user_id,))"
        )

if __name__ == "__main__":
    import argparse, asyncio
    from rich.console import Console
    p = argparse.ArgumentParser()
    p.add_argument("--url", required=True)
    args = p.parse_args()
    console = Console()
    async def demo():
        import aiohttp
        async with aiohttp.ClientSession() as session:
            plugin = SQLiPlugin()
            class E: pass
            e = E()
            e.url = args.url
            e.type = "page"
            e.form_inputs = []
            e.params = {}
            res = await plugin.test(session, e)
            console.print(res)
    asyncio.run(demo())

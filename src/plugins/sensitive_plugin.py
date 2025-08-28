from __future__ import annotations
import re
from typing import List

from .base import ScannerPlugin, Result
from ..utils.logger import get_logger

logger = get_logger("sensitive-plugin")

PATTERNS = {
    "email": r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    "phone": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "api_key": r"(?i)api[_-]?key[_-]?[\"'`]?([a-zA-Z0-9_\-]{20,64})"
}

class SensitivePlugin(ScannerPlugin):
    name = "Sensitive-Info"

    async def test(self, session, endpoint) -> List[Result]:
        findings: List[Result] = []
        try:
            async with session.get(endpoint.url, timeout=10) as resp:
                text = await resp.text(errors="ignore")
                for t, pattern in PATTERNS.items():
                    for m in re.finditer(pattern, text):
                        r = Result(
                            plugin_name=self.name,
                            url=endpoint.url,
                            endpoint_type="page" if endpoint.type!="form" else "form",
                            parameter=None,
                            payload=None,
                            evidence=m.group(0),
                            confidence=0.9,
                            severity="medium"
                        )
                        r.remediation = self.extract_remediation(r)
                        findings.append(r)
        except Exception as e:
            logger.debug(f"Sensitive check error for {endpoint.url}: {e}")
        return findings

    def extract_remediation(self, result: Result) -> str:
        return (
            "Remove sensitive data from public pages and ensure secrets are not checked into repositories. "
            "Use environment variables and secure secret stores (Vault, AWS Secrets Manager)."
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
            plugin = SensitivePlugin()
            class E: pass
            e = E()
            e.url = args.url
            e.type = "page"
            res = await plugin.test(session, e)
            console.print(res)
    asyncio.run(demo())

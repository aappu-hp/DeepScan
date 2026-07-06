from __future__ import annotations
import urllib.parse
from typing import List
import asyncio

from .base import ScannerPlugin, Result
from ..classifier.classifier import ReflectionContextClassifier
from ..classifier.context import ContextType, ReflectionContext
from ..payloads.loader import PayloadLoader
from ..utils.logger import get_logger

logger = get_logger("xss-plugin")

# Maps each exploitable context to the payload tag used in CONTEXT_DEFAULTS.
_CONTEXT_TAG: dict[ContextType, str] = {
    ContextType.HTML_BODY:     "html_body",
    ContextType.ATTR_DOUBLE:   "attr_double",
    ContextType.ATTR_SINGLE:   "attr_single",
    ContextType.ATTR_UNQUOTED: "attr_unquoted",
    ContextType.JS_STRING:     "js_string",
    ContextType.JS_BLOCK:      "js_block",
    ContextType.URI:           "uri",
    ContextType.HTML_COMMENT:  "html_comment",
}


class XSSPlugin(ScannerPlugin):
    """Detects reflected XSS by injecting payloads into URL parameters and forms."""

    name = "XSS-Reflective"

    def __init__(self) -> None:
        self._loader = PayloadLoader()
        self._classifier = ReflectionContextClassifier()
        # Full payload list kept for form testing (blind POST — no canary phase)
        self._payloads = self._loader.load("xss")

    def _payloads_for(self, context_tag: str) -> list[str]:
        return self._loader.load_for_context("xss", context_tag)

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
                        severity="high",
                    )
                    r.remediation = self.extract_remediation(r)
                    return r
        except Exception as e:
            logger.debug(f"XSS test error for {url} param={param}: {e}")
        return None

    async def _test_url_param_ctx(
        self, session, url: str, param: str, payload: str, ctx: ReflectionContext,
    ) -> Result | None:
        """Like _test_url_param but enriches the result with classifier context."""
        r = await self._test_url_param(session, url, param, payload)
        if r is not None:
            r.evidence = f"context={ctx.context_type.value}; snippet={ctx.snippet!r}"
            r.confidence = 0.97 if ctx.exploitable_hint else 0.6
        return r

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
                        severity="high",
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

            if qs:
                # Phase 1: classify all URL params concurrently (2 requests each)
                classify_results = await asyncio.gather(
                    *[self._classifier.classify(session, endpoint.url, p) for p in qs]
                )

                # Phase 2: build targeted payload tasks for each exploitable context
                payload_tasks = []
                for param, contexts in zip(qs, classify_results):
                    for ctx in contexts:
                        if not ctx.reflected or ctx.context_type in (
                            ContextType.NONE, ContextType.ENCODED,
                        ):
                            continue
                        tag = _CONTEXT_TAG.get(ctx.context_type)
                        if tag is None:
                            continue
                        for payload in self._payloads_for(tag):
                            payload_tasks.append(
                                self._test_url_param_ctx(session, endpoint.url, param, payload, ctx)
                            )

                if payload_tasks:
                    results = await asyncio.gather(*payload_tasks)
                    findings.extend(r for r in results if r is not None)

            # Forms: blind testing (classifier doesn't handle POST canary injection)
            if endpoint.type == "form" and endpoint.form_inputs:
                form_tasks = [self._test_form(session, endpoint, p) for p in self._payloads]
                results = await asyncio.gather(*form_tasks)
                findings.extend(r for r in results if r is not None)

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
    from dataclasses import dataclass, field
    from rich.console import Console

    p = argparse.ArgumentParser()
    p.add_argument("--url", required=True)
    args = p.parse_args()
    console = Console()

    @dataclass
    class _DemoEndpoint:
        url: str
        type: str = "page"
        form_inputs: list = field(default_factory=list)
        params: dict = field(default_factory=dict)

    async def run_demo():
        import aiohttp
        async with aiohttp.ClientSession() as session:
            plugin = XSSPlugin()
            results = await plugin.test(session, _DemoEndpoint(url=args.url))
            console.print(results)

    asyncio.run(run_demo())

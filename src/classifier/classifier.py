from __future__ import annotations
import re
import secrets
import urllib.parse
from typing import List

from .context import ReflectionContext, ContextType
from ..utils.logger import get_logger

logger = get_logger("ctx-classifier")


class ReflectionContextClassifier:
    """Determines where a parameter's value reflects in a response and
    whether the characters needed to break out of that context survive output encoding."""

    def _make_canary(self) -> str:
        return "dpz" + secrets.token_hex(4)

    def _inject_param(self, url: str, param: str, value: str) -> str:
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if param not in qs:
            return url
        qs[param] = [value]
        new_q = urllib.parse.urlencode(qs, doseq=True)
        return urllib.parse.urlunparse(parsed._replace(query=new_q))

    def _classify_at(self, text: str, idx: int, canary: str) -> ContextType:
        """Classify the HTML context at a given byte offset.

        Looks backwards from the reflection point to infer the surrounding
        context. Intentionally heuristic — accurate enough to pick the right
        payload class; not a full HTML tokenizer.
        """
        before = text[max(0, idx - 200): idx]

        # Inside a <script> block?
        last_open_script  = before.lower().rfind("<script")
        last_close_script = before.lower().rfind("</script")
        if last_open_script > last_close_script:
            quote = self._enclosing_js_quote(before)
            return ContextType.JS_STRING if quote else ContextType.JS_BLOCK

        # Inside an HTML comment?
        if before.rfind("<!--") > before.rfind("-->"):
            return ContextType.HTML_COMMENT

        # Inside a tag (between the last unclosed '<' and the canary)?
        lt = before.rfind("<")
        gt = before.rfind(">")
        if lt > gt:
            m = re.search(r'=(\s*)(["\']?)[^"\']*$', before)
            if m:
                q = m.group(2)
                if q == '"':
                    if self._is_uri_attr(before):
                        return ContextType.URI
                    return ContextType.ATTR_DOUBLE
                if q == "'":
                    return ContextType.ATTR_SINGLE
                return ContextType.ATTR_UNQUOTED
            return ContextType.ATTR_UNQUOTED

        return ContextType.HTML_BODY

    def _enclosing_js_quote(self, before: str) -> str | None:
        # Odd number of unescaped double/single quotes after the last statement
        # boundary is a crude indicator that we're inside a JS string literal.
        dq = before.count('"') % 2
        sq = before.count("'") % 2
        if dq:
            return '"'
        if sq:
            return "'"
        return None

    def _is_uri_attr(self, before: str) -> bool:
        return bool(re.search(
            r'\b(href|src|action|formaction)\s*=\s*["\']?[^"\']*$',
            before, re.IGNORECASE,
        ))

    async def classify(self, session, url: str, param: str) -> List[ReflectionContext]:
        """Probe a URL parameter and return the reflected contexts found.

        Makes two HTTP requests: a canary probe (to locate reflections) and
        an encoding probe (to determine which breakout characters survive).
        Returns a single NONE context if the parameter does not reflect at all.
        """
        canary = self._make_canary()
        test_url = self._inject_param(url, param, canary)
        contexts: List[ReflectionContext] = []

        try:
            async with session.get(test_url, timeout=10) as resp:
                body = await resp.text(errors="ignore")
                headers_blob = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        except Exception as e:
            logger.debug(f"classify canary error {url} param={param}: {e}")
            return []

        # Header reflections (CRLF / header-injection surface)
        if canary in headers_blob:
            contexts.append(ReflectionContext(
                parameter=param,
                context_type=ContextType.HEADER,
                reflected=True,
                snippet="(reflected in response header)",
            ))

        # Body reflections — may appear multiple times
        if canary not in body:
            if not contexts:
                contexts.append(ReflectionContext(
                    parameter=param, context_type=ContextType.NONE, reflected=False,
                ))
            return contexts

        for m in re.finditer(re.escape(canary), body):
            idx = m.start()
            ctx = self._classify_at(body, idx, canary)
            snippet = body[max(0, idx - 40): idx + len(canary) + 40]
            contexts.append(ReflectionContext(
                parameter=param,
                context_type=ctx,
                reflected=True,
                snippet=snippet,
                position=idx,
            ))

        # Encoding probe: which breakout characters survive?
        await self._probe_encoding(session, url, param, contexts)
        return contexts

    async def _probe_encoding(
        self, session, url: str, param: str, contexts: List[ReflectionContext],
    ) -> None:
        """Send a second probe to check which structural characters survive encoding."""
        marker = "dpz" + secrets.token_hex(3)
        probe_val = f'{marker}<">\'{marker}'
        test_url = self._inject_param(url, param, probe_val)
        try:
            async with session.get(test_url, timeout=10) as resp:
                body = await resp.text(errors="ignore")
        except Exception:
            return

        window = ""
        i = body.find(marker)
        if i != -1:
            window = body[i: i + len(probe_val) + 20]

        survives = {
            "<": "<" in window,
            '"': '"' in window,
            "'": "'" in window,
            ">": ">" in window,
        }

        for c in contexts:
            if not c.reflected or c.context_type in (ContextType.NONE, ContextType.ENCODED):
                continue
            c.survives = survives
            c.exploitable_hint = self._breakout_possible(c.context_type, survives)
            # Downgrade contexts where breakout chars are all encoded
            if c.reflected and not c.exploitable_hint:
                c.context_type = ContextType.ENCODED

    @staticmethod
    def _breakout_possible(ctx: ContextType, s: dict[str, bool]) -> bool:
        if ctx == ContextType.HTML_BODY:
            return s.get("<", False) and s.get(">", False)
        if ctx == ContextType.ATTR_DOUBLE:
            return s.get('"', False)
        if ctx == ContextType.ATTR_SINGLE:
            return s.get("'", False)
        if ctx == ContextType.ATTR_UNQUOTED:
            return True  # a space or event handler is typically sufficient
        if ctx in (ContextType.JS_STRING, ContextType.JS_BLOCK):
            return s.get('"', False) or s.get("'", False)
        if ctx in (ContextType.HTML_COMMENT, ContextType.URI, ContextType.HEADER):
            return True
        return False

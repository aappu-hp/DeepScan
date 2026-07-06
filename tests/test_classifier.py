import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from src.classifier.classifier import ReflectionContextClassifier
from src.classifier.context import ContextType, ReflectionContext


# ── _classify_at (no network) ─────────────────────────────────────────────────

class TestClassifyAt:
    def setup_method(self):
        self.c = ReflectionContextClassifier()
        self.canary = "dpzTEST"

    def _text_with(self, before: str) -> tuple[str, int]:
        text = before + self.canary + " after"
        return text, len(before)

    def test_html_body(self):
        text, idx = self._text_with("<div>")
        assert self.c._classify_at(text, idx, self.canary) == ContextType.HTML_BODY

    def test_html_body_outside_tags(self):
        text, idx = self._text_with("<p>some text</p>")
        assert self.c._classify_at(text, idx, self.canary) == ContextType.HTML_BODY

    def test_attr_double_quoted(self):
        text, idx = self._text_with('<input type="text" value="')
        assert self.c._classify_at(text, idx, self.canary) == ContextType.ATTR_DOUBLE

    def test_attr_single_quoted(self):
        text, idx = self._text_with("<input value='")
        assert self.c._classify_at(text, idx, self.canary) == ContextType.ATTR_SINGLE

    def test_attr_unquoted(self):
        text, idx = self._text_with("<input value=")
        assert self.c._classify_at(text, idx, self.canary) == ContextType.ATTR_UNQUOTED

    def test_js_block_inside_script(self):
        text, idx = self._text_with("<script>var x = ")
        assert self.c._classify_at(text, idx, self.canary) == ContextType.JS_BLOCK

    def test_js_string_double_quote(self):
        text, idx = self._text_with('<script>var x = "')
        assert self.c._classify_at(text, idx, self.canary) == ContextType.JS_STRING

    def test_js_string_single_quote(self):
        text, idx = self._text_with("<script>var x = '")
        assert self.c._classify_at(text, idx, self.canary) == ContextType.JS_STRING

    def test_html_comment(self):
        text, idx = self._text_with("<!-- ")
        assert self.c._classify_at(text, idx, self.canary) == ContextType.HTML_COMMENT

    def test_uri_in_href(self):
        text, idx = self._text_with('<a href="')
        assert self.c._classify_at(text, idx, self.canary) == ContextType.URI

    def test_uri_in_src(self):
        text, idx = self._text_with('<img src="')
        assert self.c._classify_at(text, idx, self.canary) == ContextType.URI

    def test_non_uri_attribute_is_not_uri(self):
        text, idx = self._text_with('<input name="')
        assert self.c._classify_at(text, idx, self.canary) == ContextType.ATTR_DOUBLE

    def test_closed_script_tag_is_html_body(self):
        text, idx = self._text_with("<script>x=1</script><p>")
        assert self.c._classify_at(text, idx, self.canary) == ContextType.HTML_BODY

    def test_closed_comment_is_html_body(self):
        text, idx = self._text_with("<!-- comment --><div>")
        assert self.c._classify_at(text, idx, self.canary) == ContextType.HTML_BODY


# ── _breakout_possible ────────────────────────────────────────────────────────

class TestBreakoutPossible:
    ALL = {"<": True, ">": True, '"': True, "'": True}
    NONE_SURVIVE = {"<": False, ">": False, '"': False, "'": False}
    ONLY_ANGLE = {"<": True, ">": True, '"': False, "'": False}
    ONLY_DOUBLE = {"<": False, ">": False, '"': True, "'": False}
    ONLY_SINGLE = {"<": False, ">": False, '"': False, "'": True}

    def test_html_body_requires_angle_brackets(self):
        assert ReflectionContextClassifier._breakout_possible(ContextType.HTML_BODY, self.ALL) is True
        assert ReflectionContextClassifier._breakout_possible(ContextType.HTML_BODY, self.ONLY_ANGLE) is True
        assert ReflectionContextClassifier._breakout_possible(ContextType.HTML_BODY, self.ONLY_DOUBLE) is False

    def test_attr_double_requires_double_quote(self):
        assert ReflectionContextClassifier._breakout_possible(ContextType.ATTR_DOUBLE, self.ONLY_DOUBLE) is True
        assert ReflectionContextClassifier._breakout_possible(ContextType.ATTR_DOUBLE, self.ONLY_SINGLE) is False

    def test_attr_single_requires_single_quote(self):
        assert ReflectionContextClassifier._breakout_possible(ContextType.ATTR_SINGLE, self.ONLY_SINGLE) is True
        assert ReflectionContextClassifier._breakout_possible(ContextType.ATTR_SINGLE, self.ONLY_DOUBLE) is False

    def test_attr_unquoted_always_exploitable(self):
        assert ReflectionContextClassifier._breakout_possible(ContextType.ATTR_UNQUOTED, self.NONE_SURVIVE) is True

    def test_js_string_requires_a_quote(self):
        assert ReflectionContextClassifier._breakout_possible(ContextType.JS_STRING, self.ONLY_DOUBLE) is True
        assert ReflectionContextClassifier._breakout_possible(ContextType.JS_STRING, self.ONLY_SINGLE) is True
        assert ReflectionContextClassifier._breakout_possible(ContextType.JS_STRING, self.NONE_SURVIVE) is False

    def test_html_comment_always_exploitable(self):
        assert ReflectionContextClassifier._breakout_possible(ContextType.HTML_COMMENT, self.NONE_SURVIVE) is True

    def test_uri_always_exploitable(self):
        assert ReflectionContextClassifier._breakout_possible(ContextType.URI, self.NONE_SURVIVE) is True

    def test_header_always_exploitable(self):
        assert ReflectionContextClassifier._breakout_possible(ContextType.HEADER, self.NONE_SURVIVE) is True

    def test_encoded_not_exploitable(self):
        assert ReflectionContextClassifier._breakout_possible(ContextType.ENCODED, self.ALL) is False

    def test_none_not_exploitable(self):
        assert ReflectionContextClassifier._breakout_possible(ContextType.NONE, self.ALL) is False


# ── _inject_param ─────────────────────────────────────────────────────────────

class TestInjectParam:
    def setup_method(self):
        self.c = ReflectionContextClassifier()

    def test_replaces_existing_param(self):
        url = "http://example.com/search?q=hello&page=1"
        result = self.c._inject_param(url, "q", "CANARY")
        assert "q=CANARY" in result
        assert "page=1" in result

    def test_returns_url_unchanged_if_param_missing(self):
        url = "http://example.com/search?q=hello"
        result = self.c._inject_param(url, "missing", "CANARY")
        assert result == url

    def test_preserves_other_params(self):
        url = "http://example.com/?a=1&b=2&c=3"
        result = self.c._inject_param(url, "b", "X")
        assert "a=1" in result
        assert "b=X" in result
        assert "c=3" in result


# ── classify() (mocked session) ───────────────────────────────────────────────

def _make_session(body: str, headers: dict | None = None):
    """Build a mock aiohttp session that returns the given body."""
    if headers is None:
        headers = {}

    resp = MagicMock()
    resp.text = AsyncMock(return_value=body)
    resp.headers = headers
    resp.__aenter__ = AsyncMock(return_value=resp)
    resp.__aexit__ = AsyncMock(return_value=False)

    session = MagicMock()
    session.get = MagicMock(return_value=resp)
    return session


class TestClassify:
    @pytest.fixture
    def classifier(self):
        return ReflectionContextClassifier()

    async def test_no_reflection_returns_none_context(self, classifier):
        session = _make_session("no canary here", headers={})
        contexts = await classifier.classify(session, "http://x.com/?q=foo", "q")
        assert len(contexts) == 1
        assert contexts[0].context_type == ContextType.NONE
        assert contexts[0].reflected is False

    async def test_reflects_in_html_body(self, classifier):
        canary_holder: list[str] = []

        async def dynamic_body(errors=None):
            if canary_holder:
                return f"<div>{canary_holder[0]}</div>"
            return "no canary"

        resp = MagicMock()
        resp.text = dynamic_body
        resp.headers = {}
        resp.__aenter__ = AsyncMock(return_value=resp)
        resp.__aexit__ = AsyncMock(return_value=False)

        call_count = 0

        def get_side_effect(url, timeout=10):
            nonlocal call_count
            call_count += 1
            # Extract the injected value from the URL
            import urllib.parse as up
            qs = up.parse_qs(up.urlparse(url).query)
            val = qs.get("q", [""])[0]
            if call_count == 1:
                canary_holder.clear()
                canary_holder.append(val)
            static_resp = MagicMock()
            static_resp.text = AsyncMock(return_value=f"<div>{val}</div>")
            static_resp.headers = {}
            static_resp.__aenter__ = AsyncMock(return_value=static_resp)
            static_resp.__aexit__ = AsyncMock(return_value=False)
            return static_resp

        session = MagicMock()
        session.get = MagicMock(side_effect=get_side_effect)

        contexts = await classifier.classify(session, "http://x.com/?q=foo", "q")
        reflected = [c for c in contexts if c.reflected and c.context_type != ContextType.NONE]
        assert len(reflected) >= 1
        assert reflected[0].context_type == ContextType.HTML_BODY

    async def test_returns_empty_list_on_request_error(self, classifier):
        session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.__aenter__ = AsyncMock(side_effect=Exception("network error"))
        mock_resp.__aexit__ = AsyncMock(return_value=False)
        session.get = MagicMock(return_value=mock_resp)

        contexts = await classifier.classify(session, "http://x.com/?q=foo", "q")
        assert contexts == []

    async def test_header_reflection_detected(self, classifier):
        canary_holder: list[str] = []
        call_count = 0

        def get_side_effect(url, timeout=10):
            nonlocal call_count
            call_count += 1
            import urllib.parse as up
            qs = up.parse_qs(up.urlparse(url).query)
            val = qs.get("q", [""])[0]
            static_resp = MagicMock()
            # Reflect canary in a header on first call
            if call_count == 1:
                canary_holder.clear()
                canary_holder.append(val)
                static_resp.headers = {"X-Custom": val}
                static_resp.text = AsyncMock(return_value="no body reflection")
            else:
                static_resp.headers = {}
                static_resp.text = AsyncMock(return_value="no body reflection")
            static_resp.__aenter__ = AsyncMock(return_value=static_resp)
            static_resp.__aexit__ = AsyncMock(return_value=False)
            return static_resp

        session = MagicMock()
        session.get = MagicMock(side_effect=get_side_effect)

        contexts = await classifier.classify(session, "http://x.com/?q=foo", "q")
        header_ctxs = [c for c in contexts if c.context_type == ContextType.HEADER]
        assert len(header_ctxs) == 1
        assert header_ctxs[0].reflected is True


# ── PayloadLoader.load_for_context ────────────────────────────────────────────

class TestLoadForContext:
    def test_returns_context_defaults_when_no_cache(self):
        from src.payloads.loader import PayloadLoader
        from src.payloads.defaults import CONTEXT_DEFAULTS
        with patch("src.payloads.loader._CACHE_DIR", Path("/nonexistent")):
            result = PayloadLoader().load_for_context("xss", "html_body")
        assert result == CONTEXT_DEFAULTS["xss"]["html_body"]

    def test_returns_empty_for_unknown_context(self):
        from src.payloads.loader import PayloadLoader
        with patch("src.payloads.loader._CACHE_DIR", Path("/nonexistent")):
            result = PayloadLoader().load_for_context("xss", "nonexistent_ctx")
        assert result == []

    def test_reads_from_cache_file_when_present(self, tmp_path):
        from src.payloads.loader import PayloadLoader
        ctx_dir = tmp_path / "xss"
        ctx_dir.mkdir()
        (ctx_dir / "html_body.txt").write_text("p1\np2\n", encoding="utf-8")
        with patch("src.payloads.loader._CACHE_DIR", tmp_path):
            result = PayloadLoader().load_for_context("xss", "html_body")
        assert result == ["p1", "p2"]

    def test_respects_limit_on_cache_file(self, tmp_path):
        from src.payloads.loader import PayloadLoader
        ctx_dir = tmp_path / "xss"
        ctx_dir.mkdir()
        (ctx_dir / "html_body.txt").write_text("\n".join(f"p{i}" for i in range(50)), encoding="utf-8")
        with patch("src.payloads.loader._CACHE_DIR", tmp_path):
            result = PayloadLoader().load_for_context("xss", "html_body", limit=5)
        assert len(result) == 5

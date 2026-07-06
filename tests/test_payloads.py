import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from src.payloads.defaults import DEFAULTS
from src.payloads.loader import PayloadLoader
from src.payloads.updater import PayloadUpdater


# ── PayloadLoader tests ────────────────────────────────────────────────────────

class TestPayloadLoader:
    def test_returns_bundled_defaults_when_cache_absent(self):
        with patch("src.payloads.loader._CACHE_DIR", Path("/nonexistent/path")):
            payloads = PayloadLoader().load("xss")
        assert payloads == DEFAULTS["xss"]

    def test_returns_bundled_sqli_defaults_when_cache_absent(self):
        with patch("src.payloads.loader._CACHE_DIR", Path("/nonexistent/path")):
            payloads = PayloadLoader().load("sqli")
        assert payloads == DEFAULTS["sqli"]

    def test_returns_empty_list_for_unknown_name(self):
        with patch("src.payloads.loader._CACHE_DIR", Path("/nonexistent/path")):
            payloads = PayloadLoader().load("unknown")
        assert payloads == []

    def test_reads_from_cache_file_when_present(self, tmp_path):
        cache = tmp_path / "payloads"
        cache.mkdir()
        (cache / "xss.txt").write_text("<script>alert(1)</script>\n<img src=x>\n", encoding="utf-8")
        with patch("src.payloads.loader._CACHE_DIR", cache):
            payloads = PayloadLoader().load("xss")
        assert payloads == ["<script>alert(1)</script>", "<img src=x>"]

    def test_skips_blank_lines_in_cache(self, tmp_path):
        cache = tmp_path / "payloads"
        cache.mkdir()
        (cache / "xss.txt").write_text("\n\npayload1\n\npayload2\n\n", encoding="utf-8")
        with patch("src.payloads.loader._CACHE_DIR", cache):
            payloads = PayloadLoader().load("xss")
        assert payloads == ["payload1", "payload2"]

    def test_skips_comment_lines_in_cache(self, tmp_path):
        cache = tmp_path / "payloads"
        cache.mkdir()
        (cache / "xss.txt").write_text("# comment\npayload1\n# another\npayload2\n", encoding="utf-8")
        with patch("src.payloads.loader._CACHE_DIR", cache):
            payloads = PayloadLoader().load("xss")
        assert payloads == ["payload1", "payload2"]

    def test_respects_limit(self, tmp_path):
        cache = tmp_path / "payloads"
        cache.mkdir()
        content = "\n".join(f"payload{i}" for i in range(100))
        (cache / "xss.txt").write_text(content, encoding="utf-8")
        with patch("src.payloads.loader._CACHE_DIR", cache):
            payloads = PayloadLoader().load("xss", limit=10)
        assert len(payloads) == 10

    def test_limit_does_not_exceed_available_payloads(self, tmp_path):
        cache = tmp_path / "payloads"
        cache.mkdir()
        (cache / "xss.txt").write_text("p1\np2\np3\n", encoding="utf-8")
        with patch("src.payloads.loader._CACHE_DIR", cache):
            payloads = PayloadLoader().load("xss", limit=100)
        assert len(payloads) == 3

    def test_is_cached_returns_false_when_absent(self):
        with patch("src.payloads.loader._CACHE_DIR", Path("/nonexistent/path")):
            assert PayloadLoader().is_cached("xss") is False

    def test_is_cached_returns_true_when_present(self, tmp_path):
        cache = tmp_path / "payloads"
        cache.mkdir()
        (cache / "xss.txt").write_text("payload", encoding="utf-8")
        with patch("src.payloads.loader._CACHE_DIR", cache):
            assert PayloadLoader().is_cached("xss") is True

    def test_defaults_are_not_mutated_between_calls(self):
        with patch("src.payloads.loader._CACHE_DIR", Path("/nonexistent/path")):
            loader = PayloadLoader()
            first = loader.load("xss")
            first.append("injected")
            second = loader.load("xss")
        assert "injected" not in second


# ── PayloadUpdater tests ───────────────────────────────────────────────────────

class TestPayloadUpdater:
    def _mock_response(self, text: str, status: int = 200) -> MagicMock:
        resp = MagicMock()
        resp.text = text
        resp.raise_for_status = MagicMock()
        resp.status_code = status
        return resp

    def test_saves_xss_file_to_cache(self, tmp_path):
        payload_text = "payload1\npayload2\npayload3\n"
        with patch("src.payloads.updater._CACHE_DIR", tmp_path), \
             patch("src.payloads.updater.requests.get", return_value=self._mock_response(payload_text)):
            PayloadUpdater().update()
        assert (tmp_path / "xss.txt").read_text(encoding="utf-8") == payload_text

    def test_saves_sqli_file_to_cache(self, tmp_path):
        payload_text = "'\n1' OR '1'='1\n"
        with patch("src.payloads.updater._CACHE_DIR", tmp_path), \
             patch("src.payloads.updater.requests.get", return_value=self._mock_response(payload_text)):
            PayloadUpdater().update()
        assert (tmp_path / "sqli.txt").read_text(encoding="utf-8") == payload_text

    def test_creates_cache_dir_if_missing(self, tmp_path):
        nested = tmp_path / "deep" / "cache"
        with patch("src.payloads.updater._CACHE_DIR", nested), \
             patch("src.payloads.updater.requests.get", return_value=self._mock_response("p1\n")):
            PayloadUpdater().update()
        assert nested.exists()

    def test_continues_on_single_source_failure(self, tmp_path):
        call_count = 0

        def fake_get(url, timeout):
            nonlocal call_count
            call_count += 1
            if "XSS" in url:
                raise ConnectionError("network error")
            return self._mock_response("sqli_payload\n")

        with patch("src.payloads.updater._CACHE_DIR", tmp_path), \
             patch("src.payloads.updater.requests.get", side_effect=fake_get):
            PayloadUpdater().update()

        assert not (tmp_path / "xss.txt").exists()
        assert (tmp_path / "sqli.txt").exists()

    def test_fetches_both_sources(self, tmp_path):
        with patch("src.payloads.updater._CACHE_DIR", tmp_path), \
             patch("src.payloads.updater.requests.get", return_value=self._mock_response("p\n")) as mock_get:
            PayloadUpdater().update()
        assert mock_get.call_count == 2

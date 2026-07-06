from __future__ import annotations
from pathlib import Path

import requests

from src.utils.console import ok, fail, working, phase

_CACHE_DIR = Path.home() / ".deepscan" / "payloads"

_SOURCES: dict[str, str] = {
    "xss": (
        "https://raw.githubusercontent.com/danielmiessler/SecLists"
        "/master/Fuzzing/XSS/XSS-Jhaddix.txt"
    ),
    "sqli": (
        "https://raw.githubusercontent.com/danielmiessler/SecLists"
        "/master/Fuzzing/SQLi/Generic-SQLi.txt"
    ),
}


class PayloadUpdater:
    """Downloads community payload lists from SecLists and caches them locally.

    Cached files are stored at ``~/.deepscan/payloads/`` and picked up
    automatically by ``PayloadLoader`` on the next scan.
    """

    def update(self) -> None:
        """Fetch all payload lists and save them to the local cache.

        Prints progress and per-source results to the terminal.
        Each source is fetched independently — a failure on one does not
        prevent the others from being saved.
        """
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        phase("Updating Payloads")

        for name, url in _SOURCES.items():
            working(f"Fetching {name} payloads", "SecLists")
            try:
                resp = requests.get(url, timeout=30)
                resp.raise_for_status()
                path = _CACHE_DIR / f"{name}.txt"
                path.write_text(resp.text, encoding="utf-8")
                count = sum(
                    1 for line in resp.text.splitlines()
                    if line.strip() and not line.startswith("#")
                )
                ok(f"{name.upper()} saved", f"{count} payloads → {path}")
            except Exception as exc:
                fail(f"{name.upper()} failed", str(exc))

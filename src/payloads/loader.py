from __future__ import annotations
from pathlib import Path

from src.payloads.defaults import DEFAULTS

_CACHE_DIR = Path.home() / ".deepscan" / "payloads"


class PayloadLoader:
    """Loads attack payloads from the local cache or bundled defaults.

    On first use, plugins fall back to the small bundled payload lists.
    After running ``deepscan update-payloads``, the cache is populated with
    community lists from SecLists and used automatically on subsequent runs.
    """

    def load(self, name: str, limit: int = 25) -> list[str]:
        """Return payloads for the given plugin type.

        Reads from ``~/.deepscan/payloads/<name>.txt`` if it exists, capped at
        ``limit`` entries. Falls back to the bundled defaults when the cache
        file is absent.

        Args:
            name: Payload category — ``'xss'`` or ``'sqli'``.
            limit: Maximum number of payloads to return from the cache file.

        Returns:
            List of payload strings.
        """
        path = _CACHE_DIR / f"{name}.txt"
        if path.exists():
            return self._read(path, limit)
        return list(DEFAULTS.get(name, []))

    def is_cached(self, name: str) -> bool:
        """Return True if a community payload file is cached for ``name``."""
        return (_CACHE_DIR / f"{name}.txt").exists()

    def _read(self, path: Path, limit: int) -> list[str]:
        payloads: list[str] = []
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                payloads.append(line)
                if len(payloads) >= limit:
                    break
        return payloads

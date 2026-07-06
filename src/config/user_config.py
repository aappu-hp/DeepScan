from __future__ import annotations
from pathlib import Path

import yaml

from src.config.schema import DeepScanConfig

_CONFIG_DIR = Path.home() / ".deepscan"
_CONFIG_FILE = _CONFIG_DIR / "config.yaml"


class UserConfig:
    """Manages reading and writing the global DeepScan config at ~/.deepscan/config.yaml."""

    def load(self) -> DeepScanConfig | None:
        """Load config from disk.

        Returns:
            DeepScanConfig if the file exists and is valid, otherwise None.
        """
        if not _CONFIG_FILE.exists():
            return None
        with _CONFIG_FILE.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        if not isinstance(data, dict):
            return None
        return DeepScanConfig(
            provider=data.get("provider", ""),
            api_key=data.get("api_key", ""),
            model=data.get("model", ""),
        )

    def save(self, config: DeepScanConfig) -> None:
        """Write config to disk and restrict file permissions to owner-only (chmod 600).

        Args:
            config: The configuration to persist.
        """
        _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with _CONFIG_FILE.open("w", encoding="utf-8") as fh:
            yaml.safe_dump(
                {"provider": config.provider, "api_key": config.api_key, "model": config.model},
                fh,
            )
        _CONFIG_FILE.chmod(0o600)

from __future__ import annotations
import sys

import questionary

from src.config.schema import DeepScanConfig
from src.config.user_config import UserConfig
from src.configure.providers.factory import ProviderFactory
from src.utils.console import console, fail, ok, working


class ConfigureWizard:
    """Interactive TUI wizard that walks the user through LLM provider configuration.

    Runs a linear 4-step flow: provider → API key → model → save.
    Pre-fills prompts from any existing config so re-runs are non-destructive.
    Exits the process after saving (or on user cancellation).
    """

    def __init__(self) -> None:
        self._user_config = UserConfig()

    def run(self) -> None:
        """Execute the configure flow and exit the process when done."""
        existing = self._user_config.load()

        provider_name = self._prompt_provider(existing)
        if provider_name is None:
            sys.exit(0)

        api_key = self._prompt_api_key(existing, provider_name)
        if not api_key:
            sys.exit(0)

        model = self._prompt_model(provider_name, api_key, existing)
        if not model:
            sys.exit(0)

        self._user_config.save(DeepScanConfig(provider=provider_name, api_key=api_key, model=model))

        console.print()
        ok("Config saved", "~/.deepscan/config.yaml")
        console.print("  [label]Run[/label] [target]deepscan agent <url>[/target] [label]to start scanning.[/label]")
        console.print()

    def _prompt_provider(self, existing: DeepScanConfig | None) -> str | None:
        """Prompt the user to select an LLM provider.

        Args:
            existing: Previously saved config used to pre-select the current provider.

        Returns:
            Selected provider name, or None if the user cancelled.
        """
        choices = ProviderFactory.available_provider_names()
        default = existing.provider if existing and existing.provider in choices else choices[0]
        return questionary.select("Select LLM Provider:", choices=choices, default=default).ask()

    def _prompt_api_key(self, existing: DeepScanConfig | None, provider_name: str) -> str:
        """Prompt the user for an API key, keeping the existing one if input is blank.

        Args:
            existing: Previously saved config.
            provider_name: Selected provider (used to match the stored key).

        Returns:
            API key string. Returns the existing key when the user presses Enter with no input.
            Returns an empty string if the user cancelled.
        """
        has_existing_key = (
            existing is not None
            and existing.provider == provider_name
            and bool(existing.api_key)
        )
        label = (
            "Enter API Key (press Enter to keep existing):"
            if has_existing_key
            else "Enter API Key:"
        )
        typed = questionary.password(label).ask()

        if typed is None:
            return ""
        if not typed and has_existing_key:
            return existing.api_key
        return typed

    def _prompt_model(
        self,
        provider_name: str,
        api_key: str,
        existing: DeepScanConfig | None,
    ) -> str | None:
        """Fetch models from the provider API and prompt the user to select one.

        Falls back to a manual text entry prompt if the API call fails.

        Args:
            provider_name: Provider to query.
            api_key: API key to authenticate the request.
            existing: Previously saved config used to pre-select the current model.

        Returns:
            Selected model ID string, or None if the user cancelled.
        """
        working("Fetching available models...")
        try:
            provider = ProviderFactory.create(provider_name)
            models = provider.fetch_models(api_key)

            if not models:
                fail("No models returned", "check your API key permissions")
                return questionary.text("Enter model name manually:").ask()

            default = (
                existing.model
                if existing
                and existing.provider == provider_name
                and existing.model in models
                else models[0]
            )
            return questionary.select("Select Default Model:", choices=models, default=default).ask()

        except Exception as exc:
            fail("Could not fetch models", str(exc))
            return questionary.text("Enter model name manually:").ask()

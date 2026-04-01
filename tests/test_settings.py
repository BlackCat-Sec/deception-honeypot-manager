from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from manager.settings import ManagerSettings


class ManagerSettingsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root_dir = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_hibp_provider_stays_disabled_when_enrichment_flag_missing(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            settings = ManagerSettings.from_env(self.root_dir)

        provider = settings.provider_statuses()[0]
        self.assertEqual(provider.name, "hibp")
        self.assertFalse(provider.enabled)
        self.assertEqual(provider.reason, "disabled_by_config")

    def test_hibp_provider_reports_missing_api_key(self) -> None:
        with patch.dict(
            os.environ,
            {
                "ENABLE_HIBP_ENRICHMENT": "true",
                "HIBP_USER_AGENT": "deception-honeypot-manager/1.0 (+https://example.invalid)",
            },
            clear=True,
        ):
            settings = ManagerSettings.from_env(self.root_dir)

        provider = settings.provider_statuses()[0]
        self.assertFalse(provider.enabled)
        self.assertEqual(provider.reason, "missing_api_key")

    def test_hibp_provider_is_ready_with_key_and_user_agent(self) -> None:
        with patch.dict(
            os.environ,
            {
                "ENABLE_HIBP_ENRICHMENT": "true",
                "HIBP_API_KEY": "test-key",
                "HIBP_USER_AGENT": "deception-honeypot-manager/1.0 (+https://example.invalid)",
            },
            clear=True,
        ):
            settings = ManagerSettings.from_env(self.root_dir)

        provider = settings.provider_statuses()[0]
        self.assertTrue(provider.enabled)
        self.assertEqual(provider.reason, "ready")


if __name__ == "__main__":
    unittest.main()


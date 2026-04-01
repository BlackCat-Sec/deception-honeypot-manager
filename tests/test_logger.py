from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from manager.logger import EventStore


class EventStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.store = EventStore(Path(self.temp_dir.name) / "honeypot.db")
        self.store.initialize()
        self.store.upsert_honeypot(
            {
                "name": "ssh_honeypot_1",
                "kind": "ssh",
                "driver": "local",
                "port": 2222,
                "bind_address": "127.0.0.1",
                "status": "running",
                "credentials": {"username": "fake", "password": "fake"},
                "fake_data": {},
                "metadata": {},
            }
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_repeated_failures_raise_single_alert(self) -> None:
        for _ in range(5):
            self.store.log_event(
                honeypot_name="ssh_honeypot_1",
                event_type="login_failure",
                source_ip="203.0.113.50",
                details="Attempted login as root",
            )

        alerts = self.store.list_alerts(limit=10)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule"], "repeated_auth_failures")


if __name__ == "__main__":
    unittest.main()


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

    def test_metrics_summary_returns_breakdowns_and_top_sources(self) -> None:
        for _ in range(3):
            self.store.log_event(
                honeypot_name="ssh_honeypot_1",
                event_type="connection",
                source_ip="203.0.113.10",
                details="Connected",
            )
        self.store.log_event(
            honeypot_name="ssh_honeypot_1",
            event_type="command",
            source_ip="203.0.113.10",
            details="uname -a",
        )
        self.store.log_event(
            honeypot_name="ssh_honeypot_1",
            event_type="connection",
            source_ip="203.0.113.11",
            details="Connected",
        )

        summary = self.store.summarize_metrics(honeypot_name="ssh_honeypot_1")

        self.assertEqual(summary["total_events"], 5)
        self.assertEqual(summary["event_type_breakdown"]["connection"], 4)
        self.assertEqual(summary["top_source_ips"][0]["source_ip"], "203.0.113.10")
        self.assertEqual(summary["latest_event"]["honeypot"], "ssh_honeypot_1")


if __name__ == "__main__":
    unittest.main()

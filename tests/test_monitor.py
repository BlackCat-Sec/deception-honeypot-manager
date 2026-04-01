from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from manager.logger import EventStore
from manager.monitor import ExternalEventMonitor


class ExternalEventMonitorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.store = EventStore(self.root / "honeypot.db")
        self.store.initialize()
        self.log_path = self.root / "external.log"
        self.store.upsert_honeypot(
            {
                "name": "ics_honeypot_1",
                "kind": "ics",
                "driver": "local",
                "port": 502,
                "bind_address": "127.0.0.1",
                "status": "running",
                "credentials": {"username": "fake", "password": "fake"},
                "fake_data": {},
                "log_path": str(self.log_path),
                "metadata": {"ingest_stdout": True},
            }
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_sync_ingests_json_and_plain_text_logs(self) -> None:
        self.log_path.write_text(
            "\n".join(
                [
                    json.dumps(
                        {
                            "honeypot": "ics_honeypot_1",
                            "event": "connection",
                            "timestamp": "2026-03-24T16:45:00Z",
                            "source_ip": "203.0.113.50",
                            "details": "Modbus session opened",
                        }
                    ),
                    "203.0.113.50 failed login to conpot console",
                ]
            ),
            encoding="utf-8",
        )

        monitor = ExternalEventMonitor(self.store)
        result = monitor.sync()

        self.assertEqual(result["events_ingested"], 2)
        events = self.store.list_events(limit=10, honeypot_name="ics_honeypot_1")
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["event"], "login_failure")


if __name__ == "__main__":
    unittest.main()


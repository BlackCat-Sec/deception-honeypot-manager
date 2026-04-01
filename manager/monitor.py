from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from manager.logger import EventStore


IP_PATTERN = re.compile(r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})")


class ExternalEventMonitor:
    def __init__(self, store: EventStore) -> None:
        self.store = store

    def sync(self, honeypot_name: str | None = None) -> dict[str, int]:
        parsed = 0
        scanned = 0
        records = self.store.list_honeypots()
        for record in records:
            if honeypot_name and record["name"] != honeypot_name:
                continue
            if not record["metadata"].get("ingest_stdout"):
                continue
            log_path = record.get("log_path")
            if not log_path:
                continue
            scanned += 1
            parsed += self._sync_log_file(record["name"], Path(log_path))
        return {"files_scanned": scanned, "events_ingested": parsed}

    def _sync_log_file(self, honeypot_name: str, log_path: Path) -> int:
        if not log_path.exists():
            return 0
        position = self.store.get_external_offset(honeypot_name)
        ingested = 0
        with log_path.open("r", encoding="utf-8", errors="replace") as handle:
            handle.seek(position)
            for line in handle:
                event = self._parse_line(honeypot_name, line.strip())
                if event:
                    self.store.log_event(**event)
                    ingested += 1
            position = handle.tell()
        self.store.set_external_offset(honeypot_name, position)
        return ingested

    def _parse_line(self, honeypot_name: str, line: str) -> dict[str, Any] | None:
        if not line:
            return None
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            payload = None
        if isinstance(payload, dict) and "event" in payload:
            return {
                "honeypot_name": payload.get("honeypot", honeypot_name),
                "event_type": payload.get("event", "external_log"),
                "timestamp": payload.get("timestamp"),
                "source_ip": payload.get("source_ip"),
                "details": payload.get("details"),
                "severity": payload.get("severity", "info"),
                "metadata": payload.get("metadata", {}),
                "raw_log": line,
            }

        lowered = line.lower()
        match = IP_PATTERN.search(line)
        source_ip = match.group("ip") if match else None
        if "failed" in lowered and ("login" in lowered or "auth" in lowered):
            event_type = "login_failure"
        elif "command" in lowered:
            event_type = "command"
        elif "connect" in lowered:
            event_type = "connection"
        else:
            event_type = "external_log"

        return {
            "honeypot_name": honeypot_name,
            "event_type": event_type,
            "source_ip": source_ip,
            "details": line,
            "severity": "info",
            "metadata": {"parser": "external_log"},
            "raw_log": line,
        }


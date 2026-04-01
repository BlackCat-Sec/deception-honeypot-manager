from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class AlertThresholds:
    repeated_failures: int = 5
    repeated_failure_window_minutes: int = 5
    connection_flood: int = 20
    connection_flood_window_minutes: int = 2


class EventStore:
    def __init__(self, db_path: str | Path, thresholds: AlertThresholds | None = None) -> None:
        self.db_path = Path(db_path)
        self.thresholds = thresholds or AlertThresholds()

    def initialize(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._session() as connection:
            connection.executescript(
                """
                PRAGMA journal_mode=WAL;
                PRAGMA synchronous=NORMAL;

                CREATE TABLE IF NOT EXISTS honeypots (
                    name TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    driver TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    bind_address TEXT NOT NULL,
                    status TEXT NOT NULL,
                    container_id TEXT,
                    pid INTEGER,
                    image TEXT,
                    command TEXT,
                    runtime_module TEXT,
                    credentials_json TEXT NOT NULL,
                    fake_data_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    log_path TEXT,
                    network_name TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    removed_at TEXT
                );

                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    honeypot_name TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    source_ip TEXT,
                    details TEXT,
                    severity TEXT NOT NULL DEFAULT 'info',
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    raw_log TEXT,
                    FOREIGN KEY(honeypot_name) REFERENCES honeypots(name)
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    honeypot_name TEXT NOT NULL,
                    rule_name TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    source_ip TEXT,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    triggered_at TEXT NOT NULL,
                    FOREIGN KEY(honeypot_name) REFERENCES honeypots(name)
                );

                CREATE TABLE IF NOT EXISTS external_offsets (
                    honeypot_name TEXT PRIMARY KEY,
                    position INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL
                );
                """
            )

    def upsert_honeypot(self, record: dict[str, Any]) -> None:
        now = utc_now()
        payload = {
            "name": record["name"],
            "kind": record["kind"],
            "driver": record["driver"],
            "port": int(record["port"]),
            "bind_address": record["bind_address"],
            "status": record.get("status", "running"),
            "container_id": record.get("container_id"),
            "pid": record.get("pid"),
            "image": record.get("image"),
            "command": record.get("command"),
            "runtime_module": record.get("runtime_module"),
            "credentials_json": json.dumps(record.get("credentials", {})),
            "fake_data_json": json.dumps(record.get("fake_data", {})),
            "metadata_json": json.dumps(record.get("metadata", {})),
            "log_path": record.get("log_path"),
            "network_name": record.get("network_name"),
            "created_at": record.get("created_at", now),
            "updated_at": now,
            "removed_at": record.get("removed_at"),
        }
        with self._session() as connection:
            connection.execute(
                """
                INSERT INTO honeypots (
                    name, kind, driver, port, bind_address, status, container_id, pid,
                    image, command, runtime_module, credentials_json, fake_data_json,
                    metadata_json, log_path, network_name, created_at, updated_at, removed_at
                )
                VALUES (
                    :name, :kind, :driver, :port, :bind_address, :status, :container_id, :pid,
                    :image, :command, :runtime_module, :credentials_json, :fake_data_json,
                    :metadata_json, :log_path, :network_name, :created_at, :updated_at, :removed_at
                )
                ON CONFLICT(name) DO UPDATE SET
                    kind=excluded.kind,
                    driver=excluded.driver,
                    port=excluded.port,
                    bind_address=excluded.bind_address,
                    status=excluded.status,
                    container_id=excluded.container_id,
                    pid=excluded.pid,
                    image=excluded.image,
                    command=excluded.command,
                    runtime_module=excluded.runtime_module,
                    credentials_json=excluded.credentials_json,
                    fake_data_json=excluded.fake_data_json,
                    metadata_json=excluded.metadata_json,
                    log_path=excluded.log_path,
                    network_name=excluded.network_name,
                    updated_at=excluded.updated_at,
                    removed_at=excluded.removed_at
                """,
                payload,
            )

    def update_honeypot(self, name: str, **fields: Any) -> None:
        if not fields:
            return
        assignments = ", ".join(f"{key}=:{key}" for key in fields)
        fields["updated_at"] = utc_now()
        assignments = f"{assignments}, updated_at=:updated_at"
        fields["name"] = name
        with self._session() as connection:
            connection.execute(
                f"UPDATE honeypots SET {assignments} WHERE name=:name",
                fields,
            )

    def get_honeypot(self, name: str) -> dict[str, Any] | None:
        with self._session() as connection:
            row = connection.execute(
                "SELECT * FROM honeypots WHERE name = ?",
                (name,),
            ).fetchone()
        return self._decode_honeypot(row) if row else None

    def list_honeypots(self, include_removed: bool = False) -> list[dict[str, Any]]:
        query = "SELECT * FROM honeypots"
        if not include_removed:
            query += " WHERE removed_at IS NULL"
        query += " ORDER BY created_at ASC"
        with self._session() as connection:
            rows = connection.execute(query).fetchall()
        return [self._decode_honeypot(row) for row in rows]

    def set_external_offset(self, honeypot_name: str, position: int) -> None:
        now = utc_now()
        with self._session() as connection:
            connection.execute(
                """
                INSERT INTO external_offsets (honeypot_name, position, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(honeypot_name) DO UPDATE SET
                    position=excluded.position,
                    updated_at=excluded.updated_at
                """,
                (honeypot_name, position, now),
            )

    def get_external_offset(self, honeypot_name: str) -> int:
        with self._session() as connection:
            row = connection.execute(
                "SELECT position FROM external_offsets WHERE honeypot_name = ?",
                (honeypot_name,),
            ).fetchone()
        return int(row["position"]) if row else 0

    def log_event(
        self,
        *,
        honeypot_name: str,
        event_type: str,
        source_ip: str | None = None,
        details: str | None = None,
        severity: str = "info",
        metadata: dict[str, Any] | None = None,
        raw_log: str | None = None,
        timestamp: str | None = None,
    ) -> None:
        event_timestamp = timestamp or utc_now()
        with self._session() as connection:
            connection.execute(
                """
                INSERT INTO events (
                    honeypot_name, event_type, timestamp, source_ip, details,
                    severity, metadata_json, raw_log
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    honeypot_name,
                    event_type,
                    event_timestamp,
                    source_ip,
                    details,
                    severity,
                    json.dumps(metadata or {}),
                    raw_log,
                ),
            )
        self._evaluate_alerts(
            honeypot_name=honeypot_name,
            event_type=event_type,
            source_ip=source_ip,
            details=details,
            timestamp=event_timestamp,
        )

    def list_events(self, limit: int = 10, honeypot_name: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM events"
        params: list[Any] = []
        if honeypot_name:
            query += " WHERE honeypot_name = ?"
            params.append(honeypot_name)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        with self._session() as connection:
            rows = connection.execute(query, tuple(params)).fetchall()
        return [self._decode_event(row) for row in rows]

    def list_alerts(self, limit: int = 20, honeypot_name: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM alerts"
        params: list[Any] = []
        if honeypot_name:
            query += " WHERE honeypot_name = ?"
            params.append(honeypot_name)
        query += " ORDER BY triggered_at DESC LIMIT ?"
        params.append(limit)
        with self._session() as connection:
            rows = connection.execute(query, tuple(params)).fetchall()
        return [self._decode_alert(row) for row in rows]

    def count_alerts(self, honeypot_name: str) -> int:
        with self._session() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS count FROM alerts WHERE honeypot_name = ?",
                (honeypot_name,),
            ).fetchone()
        return int(row["count"]) if row else 0

    def _evaluate_alerts(
        self,
        *,
        honeypot_name: str,
        event_type: str,
        source_ip: str | None,
        details: str | None,
        timestamp: str,
    ) -> None:
        if event_type in {"login_failure", "auth_failure"} and source_ip:
            self._maybe_create_threshold_alert(
                honeypot_name=honeypot_name,
                source_ip=source_ip,
                rule_name="repeated_auth_failures",
                event_types=("login_failure", "auth_failure"),
                threshold=self.thresholds.repeated_failures,
                window_minutes=self.thresholds.repeated_failure_window_minutes,
                summary=(
                    f"Repeated authentication failures detected from {source_ip} "
                    f"against {honeypot_name}"
                ),
                severity="high",
                timestamp=timestamp,
                details=details,
            )
        if event_type == "connection" and source_ip:
            self._maybe_create_threshold_alert(
                honeypot_name=honeypot_name,
                source_ip=source_ip,
                rule_name="connection_flood",
                event_types=("connection",),
                threshold=self.thresholds.connection_flood,
                window_minutes=self.thresholds.connection_flood_window_minutes,
                summary=f"Connection flood detected from {source_ip} against {honeypot_name}",
                severity="medium",
                timestamp=timestamp,
                details=details,
            )

    def _maybe_create_threshold_alert(
        self,
        *,
        honeypot_name: str,
        source_ip: str,
        rule_name: str,
        event_types: tuple[str, ...],
        threshold: int,
        window_minutes: int,
        summary: str,
        severity: str,
        timestamp: str,
        details: str | None,
    ) -> None:
        threshold_start = self._shift_iso(timestamp, minutes=-window_minutes)
        placeholders = ", ".join("?" for _ in event_types)
        params = [honeypot_name, source_ip, threshold_start, *event_types]
        with self._session() as connection:
            row = connection.execute(
                f"""
                SELECT COUNT(*) AS count
                FROM events
                WHERE honeypot_name = ?
                  AND source_ip = ?
                  AND timestamp >= ?
                  AND event_type IN ({placeholders})
                """,
                tuple(params),
            ).fetchone()
            count = int(row["count"]) if row else 0
            if count < threshold:
                return
            existing = connection.execute(
                """
                SELECT id FROM alerts
                WHERE honeypot_name = ?
                  AND rule_name = ?
                  AND source_ip = ?
                  AND triggered_at >= ?
                LIMIT 1
                """,
                (honeypot_name, rule_name, source_ip, threshold_start),
            ).fetchone()
            if existing:
                return
            connection.execute(
                """
                INSERT INTO alerts (
                    honeypot_name, rule_name, severity, summary, source_ip,
                    metadata_json, triggered_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    honeypot_name,
                    rule_name,
                    severity,
                    summary,
                    source_ip,
                    json.dumps({"details": details, "count": count}),
                    timestamp,
                ),
            )

    def _shift_iso(self, timestamp: str, *, minutes: int) -> str:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        shifted = parsed + timedelta(minutes=minutes)
        return shifted.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    @contextmanager
    def _session(self):
        connection = self._connect()
        try:
            yield connection
        finally:
            connection.close()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.db_path,
            timeout=30,
            check_same_thread=False,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        return connection

    def _decode_honeypot(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            **dict(row),
            "credentials": json.loads(row["credentials_json"]),
            "fake_data": json.loads(row["fake_data_json"]),
            "metadata": json.loads(row["metadata_json"]),
        }

    def _decode_event(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "honeypot": row["honeypot_name"],
            "event": row["event_type"],
            "timestamp": row["timestamp"],
            "source_ip": row["source_ip"],
            "details": row["details"],
            "severity": row["severity"],
            "metadata": json.loads(row["metadata_json"]),
            "raw_log": row["raw_log"],
        }

    def _decode_alert(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "honeypot": row["honeypot_name"],
            "rule": row["rule_name"],
            "severity": row["severity"],
            "summary": row["summary"],
            "source_ip": row["source_ip"],
            "triggered_at": row["triggered_at"],
            "metadata": json.loads(row["metadata_json"]),
        }

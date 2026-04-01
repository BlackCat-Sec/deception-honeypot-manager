from __future__ import annotations

import json
import os

from manager.logger import EventStore


def runtime_settings() -> dict[str, object]:
    return {
        "name": os.environ["HONEYPOT_NAME"],
        "kind": os.environ["HONEYPOT_KIND"],
        "port": int(os.environ["HONEYPOT_PORT"]),
        "bind": os.getenv("HONEYPOT_BIND", "127.0.0.1"),
        "username": os.environ["HONEYPOT_USERNAME"],
        "password": os.environ["HONEYPOT_PASSWORD"],
        "fake_data": json.loads(os.environ.get("HONEYPOT_FAKE_DATA", "{}")),
        "db_path": os.environ["HONEYPOT_DB_PATH"],
    }


def runtime_store() -> EventStore:
    settings = runtime_settings()
    store = EventStore(settings["db_path"])
    store.initialize()
    return store


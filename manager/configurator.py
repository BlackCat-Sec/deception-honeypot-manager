from __future__ import annotations

import json
import secrets
from dataclasses import asdict, dataclass
from pathlib import Path

from manager.templates import HoneypotTemplate


ADJECTIVES = (
    "legacy",
    "north",
    "edge",
    "backup",
    "field",
    "ops",
    "archive",
)
NOUNS = (
    "gateway",
    "admin",
    "console",
    "service",
    "panel",
    "vault",
    "mysql",
)


@dataclass(frozen=True)
class HoneypotProfile:
    name: str
    kind: str
    port: int
    bind_address: str
    driver: str
    template: HoneypotTemplate
    credentials: dict[str, str]
    fake_data: dict[str, object]

    def as_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["template"] = self.template.kind
        return payload


class HoneypotConfigurator:
    def build_profile(
        self,
        *,
        name: str,
        template: HoneypotTemplate,
        port: int,
        bind_address: str,
        driver: str,
    ) -> HoneypotProfile:
        credentials = self._generate_credentials(template.kind)
        fake_data = self._generate_fake_data(template.kind, name, port, credentials)
        return HoneypotProfile(
            name=name,
            kind=template.kind,
            port=port,
            bind_address=bind_address,
            driver=driver,
            template=template,
            credentials=credentials,
            fake_data=fake_data,
        )

    def persist_profile(self, profile: HoneypotProfile, output_dir: Path) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / f"{profile.name}.json"
        path.write_text(json.dumps(profile.as_dict(), indent=2), encoding="utf-8")
        return path

    def _generate_credentials(self, kind: str) -> dict[str, str]:
        username = f"{secrets.choice(ADJECTIVES)}_{secrets.choice(NOUNS)}"
        password = secrets.token_urlsafe(12)
        return {
            "username": username,
            "password": password,
            "kind": kind,
        }

    def _generate_fake_data(
        self,
        kind: str,
        name: str,
        port: int,
        credentials: dict[str, str],
    ) -> dict[str, object]:
        if kind == "ssh":
            return {
                "hostname": f"{name}.corp.local",
                "motd": "Authorized access to Field Support Bastion only.",
                "cwd": "/srv/backups",
                "filesystem": [
                    "backups",
                    "customer_exports",
                    "logs",
                    "scripts",
                ],
            }
        if kind == "http":
            return {
                "site_title": "Operations Control Portal",
                "banner": "Restricted access. Maintenance window active.",
                "records": [
                    {"system": "edge-proxy-1", "status": "WARN", "owner": "ops"},
                    {"system": "db-replica-2", "status": "OK", "owner": "platform"},
                    {"system": "fileshare-legacy", "status": "DEGRADED", "owner": "storage"},
                ],
                "login_hint": f"Use assigned operator account on port {port}",
            }
        if kind == "mysql":
            return {
                "server_version": "5.7.42-honeypot",
                "default_schema": "inventory",
                "schemas": ["inventory", "payments_archive", "crm_shadow"],
                "table_hint": "customers_2025",
                "credential_note": credentials["username"],
            }
        return {
            "note": "External honeypot template",
            "recommended_credentials": credentials,
        }

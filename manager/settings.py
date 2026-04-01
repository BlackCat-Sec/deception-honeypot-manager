from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dotenv import load_dotenv


HIBP_DOCS_URL = "https://haveibeenpwned.com/API/v2"
HIBP_KEY_HELP_URL = "https://support.haveibeenpwned.com/hc/en-au/articles/10388846218511-Do-you-provide-free-trials-sample-data-or-free-API-Keys"


def _as_bool(value: str | None, *, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class ProviderStatus:
    name: str
    enabled: bool
    configured: bool
    reason: str
    docs_url: str | None = None
    extra: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        payload = {
            "name": self.name,
            "enabled": self.enabled,
            "configured": self.configured,
            "reason": self.reason,
            "docs_url": self.docs_url,
        }
        if self.extra:
            payload.update(self.extra)
        return payload


@dataclass(frozen=True)
class ManagerSettings:
    root_dir: Path
    db_path: Path
    default_bind: str
    dashboard_host: str
    dashboard_port: int
    hibp_enrichment_enabled: bool
    hibp_api_key: str | None
    hibp_user_agent: str

    @classmethod
    def from_env(cls, root_dir: str | Path | None = None) -> "ManagerSettings":
        resolved_root = Path(root_dir or Path.cwd()).resolve()
        env_path = resolved_root / ".env"
        if env_path.exists():
            load_dotenv(env_path, override=False)

        db_path_value = os.getenv("HONEYPOT_DB_PATH", "data/honeypot.db")
        db_path = Path(db_path_value)
        if not db_path.is_absolute():
            db_path = resolved_root / db_path

        dashboard_port = int(os.getenv("HONEYPOT_DASHBOARD_PORT", "8088"))
        return cls(
            root_dir=resolved_root,
            db_path=db_path,
            default_bind=os.getenv("HONEYPOT_DEFAULT_BIND", "127.0.0.1"),
            dashboard_host=os.getenv("HONEYPOT_DASHBOARD_HOST", "127.0.0.1"),
            dashboard_port=dashboard_port,
            hibp_enrichment_enabled=_as_bool(
                os.getenv("ENABLE_HIBP_ENRICHMENT"),
                default=False,
            ),
            hibp_api_key=os.getenv("HIBP_API_KEY"),
            hibp_user_agent=os.getenv(
                "HIBP_USER_AGENT",
                "deception-honeypot-manager/1.0 (+https://example.invalid)",
            ),
        )

    def provider_statuses(self) -> list[ProviderStatus]:
        statuses: list[ProviderStatus] = []

        if not self.hibp_enrichment_enabled:
            statuses.append(
                ProviderStatus(
                    name="hibp",
                    enabled=False,
                    configured=False,
                    reason="disabled_by_config",
                    docs_url=HIBP_DOCS_URL,
                    extra={
                        "api_key_present": bool(self.hibp_api_key),
                        "help_url": HIBP_KEY_HELP_URL,
                    },
                )
            )
            return statuses

        if not self.hibp_api_key:
            statuses.append(
                ProviderStatus(
                    name="hibp",
                    enabled=False,
                    configured=False,
                    reason="missing_api_key",
                    docs_url=HIBP_DOCS_URL,
                    extra={"help_url": HIBP_KEY_HELP_URL},
                )
            )
            return statuses

        if not self.hibp_user_agent.strip():
            statuses.append(
                ProviderStatus(
                    name="hibp",
                    enabled=False,
                    configured=False,
                    reason="missing_user_agent",
                    docs_url=HIBP_DOCS_URL,
                )
            )
            return statuses

        statuses.append(
            ProviderStatus(
                name="hibp",
                enabled=True,
                configured=True,
                reason="ready",
                docs_url=HIBP_DOCS_URL,
                extra={"help_url": HIBP_KEY_HELP_URL},
            )
        )
        return statuses


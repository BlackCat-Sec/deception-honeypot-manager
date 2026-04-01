from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class HoneypotTemplate:
    kind: str
    description: str
    default_port: int
    runtime_module: str | None = None
    docker_supported: bool = True
    local_supported: bool = True
    external_examples: tuple[str, ...] = field(default_factory=tuple)


TEMPLATES: dict[str, HoneypotTemplate] = {
    "ssh": HoneypotTemplate(
        kind="ssh",
        description="Interactive SSH honeypot with fake credentials and a fake shell.",
        default_port=2222,
        runtime_module="manager.runtime.ssh_honeypot",
    ),
    "http": HoneypotTemplate(
        kind="http",
        description="Fake administrative web portal that records requests and credential attempts.",
        default_port=8080,
        runtime_module="manager.runtime.http_honeypot",
    ),
    "mysql": HoneypotTemplate(
        kind="mysql",
        description="MySQL protocol trap that records auth attempts and SQL queries.",
        default_port=3306,
        runtime_module="manager.runtime.mysql_honeypot",
    ),
    "ics": HoneypotTemplate(
        kind="ics",
        description="External ICS/SCADA integration template intended for Conpot or similar tools.",
        default_port=502,
        runtime_module=None,
        docker_supported=True,
        local_supported=True,
        external_examples=(
            "docker run --rm -p 502:502 ghcr.io/telekom-security/conpot:24.04.1",
            "conpot --template default",
        ),
    ),
}


def supported_honeypots() -> list[str]:
    return sorted(TEMPLATES)


def get_template(kind: str) -> HoneypotTemplate:
    normalized = kind.lower()
    if normalized not in TEMPLATES:
        supported = ", ".join(supported_honeypots())
        raise ValueError(f"Unsupported honeypot type '{kind}'. Supported types: {supported}")
    return TEMPLATES[normalized]


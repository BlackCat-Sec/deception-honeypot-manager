from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from manager.deployer import HoneypotDeployer
from manager.logger import EventStore
from manager.monitor import ExternalEventMonitor
from manager.settings import ManagerSettings
from manager.templates import supported_honeypots


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Deploy and manage deception honeypots.")
    parser.add_argument(
        "--db-path",
        default=None,
        help="Path to the SQLite database used for honeypot state and logs.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    deploy_parser = subparsers.add_parser("deploy", help="Deploy a honeypot.")
    deploy_parser.add_argument("kind", choices=supported_honeypots())
    deploy_parser.add_argument("--port", type=int, help="Port to bind.")
    deploy_parser.add_argument("--driver", choices=("local", "docker"), default="local")
    deploy_parser.add_argument("--name", help="Explicit honeypot name.")
    deploy_parser.add_argument(
        "--bind",
        default=None,
        help="Bind address for the honeypot. Defaults to the configured safe bind address.",
    )
    deploy_parser.add_argument("--image", help="Override docker image for container-based deployments.")
    deploy_parser.add_argument(
        "--command",
        dest="runtime_command",
        help=(
            "Override the runtime command. Useful for integrating external honeypots "
            "such as Conpot or OWASP Python Honeypot."
        ),
    )
    deploy_parser.add_argument("--json", action="store_true", help="Emit JSON output.")

    remove_parser = subparsers.add_parser("remove", help="Remove a honeypot.")
    remove_parser.add_argument("name")
    remove_parser.add_argument("--json", action="store_true", help="Emit JSON output.")

    status_parser = subparsers.add_parser("status", help="Show honeypot status.")
    status_parser.add_argument("--json", action="store_true", help="Emit JSON output.")

    logs_parser = subparsers.add_parser("logs", help="Show event logs.")
    logs_parser.add_argument("name", nargs="?", help="Optional honeypot name filter.")
    logs_parser.add_argument("--limit", type=int, default=10, help="Number of log entries to return.")
    logs_parser.add_argument(
        "--last",
        type=int,
        dest="limit_alias",
        help="Alias for --limit to support inputs like 'logs --last 50'.",
    )
    logs_parser.add_argument("--json", action="store_true", help="Emit JSON output.")

    alerts_parser = subparsers.add_parser("alerts", help="Show recent alerts.")
    alerts_parser.add_argument("name", nargs="?", help="Optional honeypot name filter.")
    alerts_parser.add_argument("--limit", type=int, default=10)
    alerts_parser.add_argument("--json", action="store_true", help="Emit JSON output.")

    dashboard_parser = subparsers.add_parser("dashboard", help="Run the optional web dashboard.")
    dashboard_parser.add_argument("--host", help="Dashboard host override.")
    dashboard_parser.add_argument("--port", type=int, help="Dashboard port override.")

    doctor_parser = subparsers.add_parser(
        "doctor",
        help="Show configuration and optional provider readiness checks.",
    )
    doctor_parser.add_argument("--json", action="store_true", help="Emit JSON output.")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    root_dir = Path(__file__).resolve().parent
    settings = ManagerSettings.from_env(root_dir)
    db_path = Path(args.db_path) if getattr(args, "db_path", None) else settings.db_path
    if not db_path.is_absolute():
        db_path = root_dir / db_path

    store = EventStore(db_path)
    store.initialize()
    monitor = ExternalEventMonitor(store)
    deployer = HoneypotDeployer(root_dir=root_dir, store=store)

    if args.command in {"status", "logs", "alerts"}:
        monitor.sync(getattr(args, "name", None))

    if args.command == "deploy":
        record = deployer.deploy(
            kind=args.kind,
            port=args.port,
            driver=args.driver,
            name=args.name,
            bind_address=args.bind or settings.default_bind,
            image=args.image,
            command=args.runtime_command,
        )
        return emit_result(
            args,
            record,
            default_message=(
                f"{record['kind'].upper()} honeypot running on "
                f"{record['bind_address']}:{record['port']} ({record['name']})"
            ),
        )

    if args.command == "remove":
        record = deployer.remove(args.name)
        return emit_result(args, record, default_message=f"Removed honeypot {record['name']}")

    if args.command == "status":
        records = deployer.status()
        if args.json:
            print(json.dumps(records, indent=2))
        else:
            print(render_status(records))
        return 0

    if args.command == "logs":
        limit = args.limit_alias or args.limit
        events = store.list_events(limit=limit, honeypot_name=args.name)
        print(json.dumps(events, indent=2))
        return 0

    if args.command == "alerts":
        alerts = store.list_alerts(limit=args.limit, honeypot_name=args.name)
        if args.json:
            print(json.dumps(alerts, indent=2))
        else:
            print(render_alerts(alerts))
        return 0

    if args.command == "dashboard":
        from dashboard.app import create_app

        app = create_app(str(db_path))
        app.run(
            host=args.host or settings.dashboard_host,
            port=args.port or settings.dashboard_port,
            debug=False,
        )
        return 0

    if args.command == "doctor":
        payload = {
            "db_path": str(settings.db_path),
            "default_bind": settings.default_bind,
            "dashboard_host": settings.dashboard_host,
            "dashboard_port": settings.dashboard_port,
            "providers": [provider.as_dict() for provider in settings.provider_statuses()],
        }
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print(render_doctor(payload))
        return 0

    parser.error("Unknown command.")
    return 1


def render_status(records: list[dict[str, Any]]) -> str:
    if not records:
        return "No honeypots deployed."
    header = f"{'NAME':24} {'TYPE':8} {'DRIVER':8} {'BIND':16} {'PORT':6} {'STATUS':10} {'ALERTS':6}"
    lines = [header, "-" * len(header)]
    for record in records:
        lines.append(
            f"{record['name'][:24]:24} "
            f"{record['kind'][:8]:8} "
            f"{record['driver'][:8]:8} "
            f"{record['bind_address'][:16]:16} "
            f"{str(record['port'])[:6]:6} "
            f"{record['status'][:10]:10} "
            f"{str(record.get('alert_count', 0))[:6]:6}"
        )
    return "\n".join(lines)


def render_alerts(alerts: list[dict[str, Any]]) -> str:
    if not alerts:
        return "No alerts recorded."
    lines = []
    for alert in alerts:
        lines.append(
            f"[{alert['severity'].upper()}] {alert['triggered_at']} "
            f"{alert['honeypot']} {alert['summary']}"
        )
    return "\n".join(lines)


def render_doctor(payload: dict[str, Any]) -> str:
    lines = [
        f"Database path: {payload['db_path']}",
        f"Default bind: {payload['default_bind']}",
        f"Dashboard: {payload['dashboard_host']}:{payload['dashboard_port']}",
        "Providers:",
    ]
    for provider in payload["providers"]:
        lines.append(
            f"  - {provider['name']}: "
            f"{'ready' if provider['enabled'] else 'disabled'} "
            f"({provider['reason']})"
        )
    return "\n".join(lines)


def emit_result(args: argparse.Namespace, payload: dict[str, Any], *, default_message: str) -> int:
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(default_message)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

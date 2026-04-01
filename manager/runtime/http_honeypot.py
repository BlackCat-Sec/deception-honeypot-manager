from __future__ import annotations

import html
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

from manager.runtime.common import runtime_settings, runtime_store


class PortalServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, server_address, request_handler_class, settings, store):
        super().__init__(server_address, request_handler_class)
        self.settings = settings
        self.store = store


class PortalHandler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.54"
    sys_version = ""

    def log_message(self, *_args) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        self._handle_request()

    def do_POST(self) -> None:  # noqa: N802
        self._handle_request()

    def _handle_request(self) -> None:
        source_ip = self.client_address[0]
        store = self.server.store
        settings = self.server.settings
        content_length = int(self.headers.get("Content-Length", "0") or "0")
        raw_body = self.rfile.read(content_length).decode("utf-8", errors="ignore") if content_length else ""

        store.log_event(
            honeypot_name=settings["name"],
            event_type="http_request",
            source_ip=source_ip,
            details=f"{self.command} {self.path}",
            metadata={
                "headers": dict(self.headers),
                "body": raw_body[:500],
            },
        )

        form = parse_qs(raw_body)
        attempted_username = form.get("username", [""])[0]
        attempted_password = form.get("password", [""])[0]
        if attempted_username or attempted_password:
            event_type = "login_success"
            if (
                attempted_username != settings["username"]
                or attempted_password != settings["password"]
            ):
                event_type = "login_failure"
            store.log_event(
                honeypot_name=settings["name"],
                event_type=event_type,
                source_ip=source_ip,
                details=f"HTTP portal credential attempt for {attempted_username or 'unknown'}",
                metadata={"path": self.path},
            )

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(self._render_page(form).encode("utf-8"))

    def _render_page(self, form: dict[str, list[str]]) -> str:
        settings = self.server.settings
        fake_data = settings["fake_data"]
        message = ""
        if form:
            if (
                form.get("username", [""])[0] == settings["username"]
                and form.get("password", [""])[0] == settings["password"]
            ):
                message = "<p class='ok'>Operator console unlocked.</p>"
            else:
                message = "<p class='warn'>Authentication failed. Session logged.</p>"
        records = "".join(
            "<tr>"
            f"<td>{html.escape(str(record['system']))}</td>"
            f"<td>{html.escape(str(record['status']))}</td>"
            f"<td>{html.escape(str(record['owner']))}</td>"
            "</tr>"
            for record in fake_data.get("records", [])
        )
        payload = {
            "schema": fake_data.get("records", []),
            "auth_hint": fake_data.get("login_hint"),
        }
        return f"""
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>{html.escape(str(fake_data.get("site_title", "Admin Portal")))}</title>
    <style>
      body {{ font-family: Arial, sans-serif; margin: 2rem; background: #0f172a; color: #e2e8f0; }}
      .wrap {{ max-width: 880px; margin: 0 auto; background: #111827; padding: 2rem; border-radius: 12px; }}
      h1 {{ margin-top: 0; }}
      form {{ display: grid; gap: .75rem; max-width: 340px; margin-bottom: 2rem; }}
      input, button {{ padding: .75rem; border-radius: 8px; border: 1px solid #334155; }}
      button {{ cursor: pointer; background: #2563eb; color: white; }}
      table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
      td, th {{ border-bottom: 1px solid #1f2937; padding: .65rem; text-align: left; }}
      .warn {{ color: #fca5a5; }}
      .ok {{ color: #86efac; }}
      pre {{ background: #020617; padding: 1rem; overflow: auto; border-radius: 8px; }}
    </style>
  </head>
  <body>
    <div class="wrap">
      <h1>{html.escape(str(fake_data.get("site_title", "Admin Portal")))}</h1>
      <p>{html.escape(str(fake_data.get("banner", "")))}</p>
      {message}
      <form method="post" action="/login">
        <input name="username" placeholder="Username" />
        <input type="password" name="password" placeholder="Password" />
        <button type="submit">Sign in</button>
      </form>
      <h2>Operations Summary</h2>
      <table>
        <thead><tr><th>System</th><th>Status</th><th>Owner</th></tr></thead>
        <tbody>{records}</tbody>
      </table>
      <h2>Portal Metadata</h2>
      <pre>{html.escape(json.dumps(payload, indent=2))}</pre>
    </div>
  </body>
</html>
"""


def main() -> None:
    settings = runtime_settings()
    store = runtime_store()
    server = PortalServer((settings["bind"], settings["port"]), PortalHandler, settings, store)
    store.log_event(
        honeypot_name=settings["name"],
        event_type="startup",
        details=f"HTTP honeypot listening on {settings['bind']}:{settings['port']}",
    )
    server.serve_forever()


if __name__ == "__main__":
    main()


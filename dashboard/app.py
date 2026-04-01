from __future__ import annotations

from flask import Flask, jsonify, render_template_string, request

from manager.deployer import HoneypotDeployer
from manager.logger import EventStore
from manager.monitor import ExternalEventMonitor
from manager.settings import ManagerSettings


HTML_TEMPLATE = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Deception Honeypot Manager</title>
    <style>
      body { font-family: Arial, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; }
      main { max-width: 1100px; margin: 0 auto; padding: 2rem; }
      section { background: #111827; border-radius: 12px; padding: 1.25rem; margin-bottom: 1rem; }
      h1, h2 { margin-top: 0; }
      table { width: 100%; border-collapse: collapse; }
      th, td { text-align: left; padding: .65rem; border-bottom: 1px solid #1f2937; vertical-align: top; }
      code { color: #93c5fd; }
      .pill { padding: .2rem .5rem; border-radius: 999px; background: #1d4ed8; }
      .warn { color: #fca5a5; }
      .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 1rem; }
      .card { background: #111827; border-radius: 12px; padding: 1rem; }
      .metric { font-size: 1.8rem; font-weight: 700; margin: .35rem 0 0; }
      .muted { color: #94a3b8; }
    </style>
  </head>
  <body>
    <main>
      <h1>Deception Honeypot Manager</h1>
      <div class="grid">
        <div class="card"><div class="muted">Active Honeypots</div><div class="metric" id="metric-honeypots">0</div></div>
        <div class="card"><div class="muted">Total Events</div><div class="metric" id="metric-events">0</div></div>
        <div class="card"><div class="muted">Total Alerts</div><div class="metric" id="metric-alerts">0</div></div>
        <div class="card"><div class="muted">Top Talker</div><div class="metric" id="metric-top-source">-</div></div>
      </div>
      <section>
        <h2>Providers</h2>
        <table id="providers-table">
          <thead><tr><th>Name</th><th>State</th><th>Reason</th><th>Docs</th></tr></thead>
          <tbody></tbody>
        </table>
      </section>
      <section>
        <h2>Honeypots</h2>
        <table id="status-table">
          <thead><tr><th>Name</th><th>Type</th><th>Driver</th><th>Bind</th><th>Port</th><th>Status</th><th>Alerts</th></tr></thead>
          <tbody></tbody>
        </table>
      </section>
      <section>
        <h2>Recent Alerts</h2>
        <table id="alerts-table">
          <thead><tr><th>Time</th><th>Severity</th><th>Honeypot</th><th>Summary</th></tr></thead>
          <tbody></tbody>
        </table>
      </section>
      <section>
        <h2>Top Source IPs</h2>
        <table id="sources-table">
          <thead><tr><th>Source IP</th><th>Events</th></tr></thead>
          <tbody></tbody>
        </table>
      </section>
      <section>
        <h2>Recent Logs</h2>
        <table id="logs-table">
          <thead><tr><th>Time</th><th>Honeypot</th><th>Event</th><th>Source</th><th>Details</th></tr></thead>
          <tbody></tbody>
        </table>
      </section>
    </main>
    <script>
      async function refresh() {
        const [status, alerts, logs, metrics, health] = await Promise.all([
          fetch('/api/status').then(r => r.json()),
          fetch('/api/alerts?limit=10').then(r => r.json()),
          fetch('/api/logs?limit=20').then(r => r.json()),
          fetch('/api/metrics').then(r => r.json()),
          fetch('/healthz').then(r => r.json())
        ]);

        document.querySelector('#metric-honeypots').textContent = metrics.active_honeypots;
        document.querySelector('#metric-events').textContent = metrics.total_events;
        document.querySelector('#metric-alerts').textContent = metrics.total_alerts;
        document.querySelector('#metric-top-source').textContent = metrics.top_source_ips[0]?.source_ip || '-';

        document.querySelector('#providers-table tbody').innerHTML = health.providers.map(item => `
          <tr>
            <td><code>${item.name}</code></td>
            <td>${item.enabled ? 'ready' : 'disabled'}</td>
            <td>${item.reason}</td>
            <td>${item.docs_url ? `<a href="${item.docs_url}" target="_blank" rel="noreferrer">docs</a>` : '-'}</td>
          </tr>`).join('');

        document.querySelector('#status-table tbody').innerHTML = status.map(item => `
          <tr>
            <td><code>${item.name}</code></td>
            <td>${item.kind}</td>
            <td>${item.driver}</td>
            <td>${item.bind_address}</td>
            <td>${item.port}</td>
            <td><span class="pill">${item.status}</span></td>
            <td>${item.alert_count || 0}</td>
          </tr>`).join('');

        document.querySelector('#alerts-table tbody').innerHTML = alerts.map(item => `
          <tr>
            <td>${item.triggered_at}</td>
            <td class="warn">${item.severity}</td>
            <td><code>${item.honeypot}</code></td>
            <td>${item.summary}</td>
          </tr>`).join('');

        document.querySelector('#sources-table tbody').innerHTML = metrics.top_source_ips.map(item => `
          <tr>
            <td>${item.source_ip}</td>
            <td>${item.count}</td>
          </tr>`).join('');

        document.querySelector('#logs-table tbody').innerHTML = logs.map(item => `
          <tr>
            <td>${item.timestamp}</td>
            <td><code>${item.honeypot}</code></td>
            <td>${item.event}</td>
            <td>${item.source_ip || '-'}</td>
            <td>${item.details || ''}</td>
          </tr>`).join('');
      }

      refresh();
      setInterval(refresh, 5000);
    </script>
  </body>
</html>
"""


def create_app(db_path: str | None = None) -> Flask:
    app = Flask(__name__)
    settings = ManagerSettings.from_env(".")
    store = EventStore(db_path or str(settings.db_path))
    store.initialize()
    monitor = ExternalEventMonitor(store)
    deployer = HoneypotDeployer(root_dir=".", store=store)

    @app.get("/")
    def index():
        return render_template_string(HTML_TEMPLATE)

    @app.get("/api/status")
    def status():
        monitor.sync()
        return jsonify(deployer.status())

    @app.get("/api/logs")
    def logs():
        monitor.sync(request.args.get("name"))
        limit = int(request.args.get("limit", 20))
        return jsonify(store.list_events(limit=limit, honeypot_name=request.args.get("name")))

    @app.get("/api/alerts")
    def alerts():
        monitor.sync(request.args.get("name"))
        limit = int(request.args.get("limit", 20))
        return jsonify(store.list_alerts(limit=limit, honeypot_name=request.args.get("name")))

    @app.get("/api/metrics")
    def metrics():
        monitor.sync(request.args.get("name"))
        minutes = request.args.get("minutes")
        return jsonify(
            store.summarize_metrics(
                honeypot_name=request.args.get("name"),
                since_minutes=int(minutes) if minutes else None,
            )
        )

    @app.get("/healthz")
    def health():
        return jsonify(
            {
                "ok": True,
                "providers": [provider.as_dict() for provider in settings.provider_statuses()],
            }
        )

    return app


if __name__ == "__main__":
    settings = ManagerSettings.from_env(".")
    app = create_app()
    app.run(host=settings.dashboard_host, port=settings.dashboard_port, debug=False)

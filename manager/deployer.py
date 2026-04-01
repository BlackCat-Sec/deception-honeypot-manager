from __future__ import annotations

import json
import os
import shlex
import signal
import subprocess
import sys
from pathlib import Path
from typing import Any

from manager.configurator import HoneypotConfigurator
from manager.logger import EventStore, utc_now
from manager.templates import HoneypotTemplate, get_template

try:
    import docker
    from docker.errors import ImageNotFound
except Exception:  # pragma: no cover - docker may be unavailable in tests.
    docker = None
    ImageNotFound = Exception


class HoneypotDeployer:
    INTERNAL_NETWORK_NAME = "deception_honeypot_internal"
    RUNTIME_IMAGE = "deception-honeypot-runtime:latest"

    def __init__(
        self,
        *,
        root_dir: str | Path,
        store: EventStore,
        docker_client: Any | None = None,
    ) -> None:
        self.root_dir = Path(root_dir)
        self.store = store
        self.configurator = HoneypotConfigurator()
        self._docker_client = docker_client
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.process_log_dir.mkdir(parents=True, exist_ok=True)

    @property
    def data_dir(self) -> Path:
        return self.root_dir / "data"

    @property
    def config_dir(self) -> Path:
        return self.data_dir / "configs"

    @property
    def process_log_dir(self) -> Path:
        return self.data_dir / "process_logs"

    @property
    def db_path(self) -> Path:
        return self.store.db_path

    def deploy(
        self,
        *,
        kind: str,
        port: int | None = None,
        driver: str = "local",
        name: str | None = None,
        bind_address: str = "127.0.0.1",
        image: str | None = None,
        command: str | None = None,
    ) -> dict[str, Any]:
        template = get_template(kind)
        resolved_port = port or template.default_port
        resolved_name = name or self._generate_name(template.kind)
        self._validate_driver(template, driver)
        profile = self.configurator.build_profile(
            name=resolved_name,
            template=template,
            port=resolved_port,
            bind_address=bind_address,
            driver=driver,
        )
        config_path = self.configurator.persist_profile(profile, self.config_dir)
        if driver == "docker":
            record = self._deploy_docker(profile, image=image, command=command)
        else:
            record = self._deploy_local(profile, command=command)
        record["metadata"] = {
            **record.get("metadata", {}),
            "config_path": str(config_path),
        }
        self.store.upsert_honeypot(record)
        return self.store.get_honeypot(profile.name) or record

    def remove(self, name: str) -> dict[str, Any]:
        record = self.store.get_honeypot(name)
        if not record:
            raise ValueError(f"Honeypot '{name}' does not exist.")
        if record["driver"] == "docker" and record.get("container_id"):
            self._remove_container(record["container_id"])
        elif record.get("pid"):
            self._terminate_process(int(record["pid"]))
        self.store.update_honeypot(name, status="removed", removed_at=utc_now())
        return self.store.get_honeypot(name) or record

    def status(self) -> list[dict[str, Any]]:
        refreshed: list[dict[str, Any]] = []
        for record in self.store.list_honeypots():
            refreshed.append(self._refresh_status(record))
        return refreshed

    def _refresh_status(self, record: dict[str, Any]) -> dict[str, Any]:
        status = record["status"]
        if record["driver"] == "docker" and record.get("container_id"):
            try:
                container = self.docker_client.containers.get(record["container_id"])
                status = getattr(container, "status", "unknown")
            except Exception:
                status = "missing"
        elif record.get("pid"):
            status = "running" if self._is_process_running(int(record["pid"])) else "stopped"
        self.store.update_honeypot(record["name"], status=status)
        refreshed = self.store.get_honeypot(record["name"]) or record
        refreshed["alert_count"] = self.store.count_alerts(record["name"])
        return refreshed

    def _deploy_docker(
        self,
        profile: Any,
        *,
        image: str | None,
        command: str | None,
    ) -> dict[str, Any]:
        network = self._ensure_internal_network()
        selected_image = image
        run_command: list[str] | str | None = command
        ingest_stdout = bool(command)

        if not selected_image:
            if not profile.template.runtime_module:
                raise ValueError(
                    f"Template '{profile.kind}' requires --image for docker deployments."
                )
            selected_image = self._ensure_runtime_image()
            run_command = ["python", "-m", profile.template.runtime_module]

        container = self.docker_client.containers.run(
            selected_image,
            command=run_command,
            detach=True,
            name=profile.name,
            network=getattr(network, "name", self.INTERNAL_NETWORK_NAME),
            ports={f"{profile.port}/tcp": (profile.bind_address, profile.port)},
            environment=self._build_environment(profile, db_path="/data/honeypot.db"),
            labels={
                "deception.honeypot": "true",
                "deception.kind": profile.kind,
                "deception.name": profile.name,
            },
            read_only=True,
            mem_limit="256m",
            pids_limit=128,
            security_opt=["no-new-privileges:true"],
            cap_drop=["ALL"],
            restart_policy={"Name": "unless-stopped"},
            volumes={
                str(self.data_dir.resolve()): {"bind": "/data", "mode": "rw"},
            },
        )
        return {
            "name": profile.name,
            "kind": profile.kind,
            "driver": "docker",
            "port": profile.port,
            "bind_address": profile.bind_address,
            "status": "running",
            "container_id": getattr(container, "id", None),
            "image": selected_image,
            "command": json.dumps(run_command) if isinstance(run_command, list) else run_command,
            "runtime_module": profile.template.runtime_module,
            "credentials": profile.credentials,
            "fake_data": profile.fake_data,
            "network_name": getattr(network, "name", self.INTERNAL_NETWORK_NAME),
            "metadata": {
                "ingest_stdout": ingest_stdout,
                "safe_network": True,
            },
        }

    def _deploy_local(self, profile: Any, *, command: str | None) -> dict[str, Any]:
        log_path = self.process_log_dir / f"{profile.name}.log"
        env = self._build_environment(profile, db_path=str(self.db_path.resolve()))
        env["PYTHONUNBUFFERED"] = "1"
        ingest_stdout = bool(command) or not profile.template.runtime_module

        if command:
            process_command = shlex.split(command)
        else:
            if not profile.template.runtime_module:
                raise ValueError(
                    f"Template '{profile.kind}' requires --command when using the local driver."
                )
            process_command = [sys.executable, "-m", profile.template.runtime_module]

        with log_path.open("a", encoding="utf-8") as log_handle:
            process = subprocess.Popen(
                process_command,
                cwd=self.root_dir,
                env=env,
                stdout=log_handle,
                stderr=log_handle,
                text=True,
                creationflags=self._creation_flags(),
                start_new_session=os.name != "nt",
            )
        return {
            "name": profile.name,
            "kind": profile.kind,
            "driver": "local",
            "port": profile.port,
            "bind_address": profile.bind_address,
            "status": "running",
            "pid": process.pid,
            "image": None,
            "command": " ".join(process_command),
            "runtime_module": profile.template.runtime_module,
            "credentials": profile.credentials,
            "fake_data": profile.fake_data,
            "log_path": str(log_path),
            "metadata": {
                "ingest_stdout": ingest_stdout,
                "safe_network": profile.bind_address in {"127.0.0.1", "localhost"},
            },
        }

    def _build_environment(self, profile: Any, *, db_path: str) -> dict[str, str]:
        env = os.environ.copy()
        env.update(
            {
                "HONEYPOT_NAME": profile.name,
                "HONEYPOT_KIND": profile.kind,
                "HONEYPOT_PORT": str(profile.port),
                "HONEYPOT_BIND": profile.bind_address,
                "HONEYPOT_USERNAME": profile.credentials["username"],
                "HONEYPOT_PASSWORD": profile.credentials["password"],
                "HONEYPOT_FAKE_DATA": json.dumps(profile.fake_data),
                "HONEYPOT_DB_PATH": db_path,
            }
        )
        return env

    def _validate_driver(self, template: HoneypotTemplate, driver: str) -> None:
        if driver not in {"docker", "local"}:
            raise ValueError("Driver must be 'docker' or 'local'.")
        if driver == "docker" and not template.docker_supported:
            raise ValueError(f"Template '{template.kind}' does not support docker deployments.")
        if driver == "local" and not template.local_supported:
            raise ValueError(f"Template '{template.kind}' does not support local deployments.")

    def _generate_name(self, kind: str) -> str:
        prefix = f"{kind}_honeypot_"
        existing = {
            row["name"] for row in self.store.list_honeypots(include_removed=True)
            if row["name"].startswith(prefix)
        }
        index = 1
        candidate = f"{prefix}{index}"
        while candidate in existing:
            index += 1
            candidate = f"{prefix}{index}"
        return candidate

    @property
    def docker_client(self) -> Any:
        if self._docker_client is not None:
            return self._docker_client
        if docker is None:
            raise RuntimeError("docker SDK is not installed. Install requirements.txt first.")
        self._docker_client = docker.from_env()
        return self._docker_client

    def _ensure_runtime_image(self) -> str:
        try:
            self.docker_client.images.get(self.RUNTIME_IMAGE)
        except Exception:
            self.docker_client.images.build(
                path=str(self.root_dir),
                dockerfile="docker/runtime.Dockerfile",
                tag=self.RUNTIME_IMAGE,
                rm=True,
            )
        return self.RUNTIME_IMAGE

    def _ensure_internal_network(self) -> Any:
        try:
            return self.docker_client.networks.get(self.INTERNAL_NETWORK_NAME)
        except Exception:
            return self.docker_client.networks.create(
                self.INTERNAL_NETWORK_NAME,
                driver="bridge",
                internal=True,
                attachable=False,
                check_duplicate=True,
            )

    def _remove_container(self, container_id: str) -> None:
        try:
            container = self.docker_client.containers.get(container_id)
            container.stop(timeout=10)
            container.remove(force=True)
        except Exception:
            return

    def _terminate_process(self, pid: int) -> None:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            return

    def _is_process_running(self, pid: int) -> bool:
        if os.name == "nt":
            result = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}"],
                check=False,
                capture_output=True,
                text=True,
            )
            return str(pid) in result.stdout
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        return True

    def _creation_flags(self) -> int:
        if os.name != "nt":
            return 0
        detached = getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
        new_group = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
        return detached | new_group

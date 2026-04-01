from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from manager.deployer import HoneypotDeployer
from manager.logger import EventStore


class FakeContainer:
    def __init__(self, container_id: str = "container-123") -> None:
        self.id = container_id
        self.status = "running"
        self.stopped = False
        self.removed = False

    def stop(self, timeout: int = 10) -> None:
        self.stopped = True
        self.status = "exited"

    def remove(self, force: bool = True) -> None:
        self.removed = True


class FakeContainers:
    def __init__(self) -> None:
        self.last_run_kwargs = None
        self.container = FakeContainer()

    def run(self, image, **kwargs):
        self.last_run_kwargs = {"image": image, **kwargs}
        return self.container

    def get(self, _container_id: str):
        return self.container


class FakeImages:
    def __init__(self) -> None:
        self.available = set()
        self.build_calls = []

    def get(self, image: str):
        if image not in self.available:
            raise Exception("image missing")
        return image

    def build(self, **kwargs):
        self.available.add(kwargs["tag"])
        self.build_calls.append(kwargs)
        return (kwargs["tag"], [])


class FakeNetwork:
    def __init__(self, name: str) -> None:
        self.name = name


class FakeNetworks:
    def __init__(self) -> None:
        self.networks = {}

    def get(self, name: str):
        if name not in self.networks:
            raise Exception("network missing")
        return self.networks[name]

    def create(self, name: str, **_kwargs):
        network = FakeNetwork(name)
        self.networks[name] = network
        return network


class FakeDockerClient:
    def __init__(self) -> None:
        self.containers = FakeContainers()
        self.images = FakeImages()
        self.networks = FakeNetworks()


class HoneypotDeployerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root_dir = Path(self.temp_dir.name)
        self.store = EventStore(self.root_dir / "data" / "honeypot.db")
        self.store.initialize()
        self.docker = FakeDockerClient()
        self.deployer = HoneypotDeployer(
            root_dir=self.root_dir,
            store=self.store,
            docker_client=self.docker,
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_deploy_docker_honeypot_uses_safe_defaults(self) -> None:
        record = self.deployer.deploy(kind="ssh", port=2222, driver="docker")

        self.assertEqual(record["driver"], "docker")
        self.assertEqual(record["status"], "running")
        self.assertEqual(
            self.docker.containers.last_run_kwargs["network"],
            HoneypotDeployer.INTERNAL_NETWORK_NAME,
        )
        self.assertTrue(self.docker.containers.last_run_kwargs["read_only"])
        self.assertEqual(
            self.docker.containers.last_run_kwargs["ports"]["2222/tcp"],
            ("127.0.0.1", 2222),
        )
        self.assertEqual(
            self.docker.containers.last_run_kwargs["environment"]["HONEYPOT_DB_PATH"],
            "/data/honeypot.db",
        )

    def test_remove_docker_honeypot_stops_container(self) -> None:
        record = self.deployer.deploy(kind="http", port=8080, driver="docker")
        removed = self.deployer.remove(record["name"])

        self.assertEqual(removed["status"], "removed")
        self.assertTrue(self.docker.containers.container.stopped)
        self.assertTrue(self.docker.containers.container.removed)


if __name__ == "__main__":
    unittest.main()


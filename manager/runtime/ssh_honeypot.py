from __future__ import annotations

import socket
import threading
from typing import Any

import paramiko

from manager.runtime.common import runtime_settings, runtime_store


class SSHServer(paramiko.ServerInterface):
    def __init__(self, *, settings: dict[str, Any], store, source_ip: str) -> None:
        self.settings = settings
        self.store = store
        self.source_ip = source_ip
        self.shell_requested = threading.Event()

    def get_allowed_auths(self, _username: str) -> str:
        return "password"

    def check_auth_password(self, username: str, password: str) -> int:
        if username == self.settings["username"] and password == self.settings["password"]:
            self.store.log_event(
                honeypot_name=self.settings["name"],
                event_type="login_success",
                source_ip=self.source_ip,
                details=f"SSH login success for {username}",
            )
            return paramiko.AUTH_SUCCESSFUL
        self.store.log_event(
            honeypot_name=self.settings["name"],
            event_type="login_failure",
            source_ip=self.source_ip,
            details=f"SSH login failure for {username}",
        )
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind: str, _channel_id: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, _channel) -> bool:
        self.shell_requested.set()
        return True

    def check_channel_pty_request(self, *_args) -> bool:
        return True


def command_output(command: str, settings: dict[str, Any]) -> str:
    fake_data = settings["fake_data"]
    filesystem = "\n".join(fake_data.get("filesystem", []))
    commands = {
        "pwd": f"{fake_data.get('cwd', '/srv')}\n",
        "ls": f"{filesystem}\n",
        "whoami": f"{settings['username']}\n",
        "uname -a": "Linux bastion 5.15.0-honeypot x86_64 GNU/Linux\n",
        "id": f"uid=1001({settings['username']}) gid=1001({settings['username']}) groups=1001({settings['username']})\n",
        "cat /etc/motd": f"{fake_data.get('motd', '')}\n",
    }
    return commands.get(command, f"bash: {command}: command recorded\n")


def handle_client(client: socket.socket, host_key: paramiko.PKey, settings, store) -> None:
    source_ip = client.getpeername()[0]
    store.log_event(
        honeypot_name=settings["name"],
        event_type="connection",
        source_ip=source_ip,
        details="SSH TCP connection opened",
    )
    transport = paramiko.Transport(client)
    transport.local_version = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
    transport.add_server_key(host_key)
    server = SSHServer(settings=settings, store=store, source_ip=source_ip)
    try:
        transport.start_server(server=server)
        channel = transport.accept(20)
        if channel is None:
            return
        server.shell_requested.wait(10)
        channel.send(f"{settings['fake_data'].get('motd', '')}\r\n")
        prompt = f"{settings['username']}@{settings['fake_data'].get('hostname', 'bastion')}:~$ "
        channel.send(prompt)
        buffer = ""
        while True:
            data = channel.recv(1024)
            if not data:
                break
            buffer += data.decode("utf-8", errors="ignore")
            if "\n" not in buffer and "\r" not in buffer:
                continue
            command = buffer.strip()
            buffer = ""
            if not command:
                channel.send(prompt)
                continue
            store.log_event(
                honeypot_name=settings["name"],
                event_type="command",
                source_ip=source_ip,
                details=command,
            )
            if command.lower() in {"exit", "quit", "logout"}:
                channel.send("logout\r\n")
                break
            channel.send(command_output(command, settings))
            channel.send(prompt)
    except Exception as exc:
        store.log_event(
            honeypot_name=settings["name"],
            event_type="runtime_error",
            source_ip=source_ip,
            severity="warning",
            details=f"SSH transport error: {exc}",
        )
    finally:
        transport.close()
        client.close()


def main() -> None:
    settings = runtime_settings()
    store = runtime_store()
    host_key = paramiko.RSAKey.generate(2048)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((settings["bind"], settings["port"]))
    server_socket.listen(100)
    store.log_event(
        honeypot_name=settings["name"],
        event_type="startup",
        details=f"SSH honeypot listening on {settings['bind']}:{settings['port']}",
    )
    while True:
        client, _address = server_socket.accept()
        thread = threading.Thread(
            target=handle_client,
            args=(client, host_key, settings, store),
            daemon=True,
        )
        thread.start()


if __name__ == "__main__":
    main()


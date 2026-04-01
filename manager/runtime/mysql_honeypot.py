from __future__ import annotations

import hashlib
import os
import socket
import struct
import threading
from typing import Any

from manager.runtime.common import runtime_settings, runtime_store


CLIENT_LONG_PASSWORD = 0x00000001
CLIENT_CONNECT_WITH_DB = 0x00000008
CLIENT_PROTOCOL_41 = 0x00000200
CLIENT_SECURE_CONNECTION = 0x00008000
CLIENT_PLUGIN_AUTH = 0x00080000
CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = 0x00200000
STATUS_AUTOCOMMIT = 0x0002
AUTH_PLUGIN_NAME = b"mysql_native_password"


def packet(payload: bytes, sequence_id: int) -> bytes:
    length = len(payload).to_bytes(3, "little")
    return length + bytes([sequence_id]) + payload


def recv_exact(connection: socket.socket, length: int) -> bytes:
    chunks = []
    remaining = length
    while remaining > 0:
        chunk = connection.recv(remaining)
        if not chunk:
            raise ConnectionError("Client disconnected")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def receive_packet(connection: socket.socket) -> tuple[int, bytes]:
    header = recv_exact(connection, 4)
    length = int.from_bytes(header[:3], "little")
    sequence_id = header[3]
    return sequence_id, recv_exact(connection, length)


def scramble_native_password(password: str, salt: bytes) -> bytes:
    stage1 = hashlib.sha1(password.encode("utf-8")).digest()
    stage2 = hashlib.sha1(stage1).digest()
    stage3 = hashlib.sha1(salt + stage2).digest()
    return bytes(left ^ right for left, right in zip(stage1, stage3))


def handshake_payload(connection_id: int, settings: dict[str, Any], salt: bytes) -> bytes:
    capabilities = (
        CLIENT_LONG_PASSWORD
        | CLIENT_PROTOCOL_41
        | CLIENT_SECURE_CONNECTION
        | CLIENT_PLUGIN_AUTH
        | CLIENT_CONNECT_WITH_DB
    )
    server_version = settings["fake_data"].get("server_version", "5.7.42-honeypot").encode("utf-8")
    payload = bytearray()
    payload.append(0x0A)
    payload.extend(server_version + b"\x00")
    payload.extend(struct.pack("<I", connection_id))
    payload.extend(salt[:8])
    payload.append(0x00)
    payload.extend(struct.pack("<H", capabilities & 0xFFFF))
    payload.append(0x21)
    payload.extend(struct.pack("<H", STATUS_AUTOCOMMIT))
    payload.extend(struct.pack("<H", (capabilities >> 16) & 0xFFFF))
    payload.append(len(salt) + 1)
    payload.extend(b"\x00" * 10)
    payload.extend(salt[8:])
    payload.append(0x00)
    payload.extend(AUTH_PLUGIN_NAME + b"\x00")
    return bytes(payload)


def parse_handshake_response(payload: bytes) -> dict[str, Any]:
    if len(payload) < 36:
        raise ValueError("Incomplete handshake response")
    capability_flags = int.from_bytes(payload[0:4], "little")
    offset = 32
    username_end = payload.find(b"\x00", offset)
    if username_end == -1:
        raise ValueError("Missing username terminator")
    username = payload[offset:username_end].decode("utf-8", errors="ignore")
    offset = username_end + 1

    auth_response = b""
    if capability_flags & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA:
        auth_length = payload[offset]
        offset += 1
        auth_response = payload[offset : offset + auth_length]
        offset += auth_length
    elif capability_flags & CLIENT_SECURE_CONNECTION:
        auth_length = payload[offset]
        offset += 1
        auth_response = payload[offset : offset + auth_length]
        offset += auth_length
    else:
        auth_end = payload.find(b"\x00", offset)
        if auth_end == -1:
            raise ValueError("Missing auth terminator")
        auth_response = payload[offset:auth_end]
        offset = auth_end + 1

    database = None
    if capability_flags & CLIENT_CONNECT_WITH_DB and offset < len(payload):
        database_end = payload.find(b"\x00", offset)
        if database_end != -1:
            database = payload[offset:database_end].decode("utf-8", errors="ignore")

    return {
        "capabilities": capability_flags,
        "username": username,
        "auth_response": auth_response,
        "database": database,
    }


def err_packet(code: int, message: str) -> bytes:
    return b"\xff" + struct.pack("<H", code) + b"#28000" + message.encode("utf-8")


def ok_packet() -> bytes:
    return b"\x00\x00\x00\x02\x00\x00\x00"


def handle_query(
    connection: socket.socket,
    query: str,
    settings: dict[str, Any],
    store,
    source_ip: str,
) -> None:
    store.log_event(
        honeypot_name=settings["name"],
        event_type="command",
        source_ip=source_ip,
        details=query,
    )
    connection.sendall(packet(err_packet(1146, "Simulated table does not exist"), 1))


def handle_client(connection: socket.socket, settings: dict[str, Any], store) -> None:
    source_ip = connection.getpeername()[0]
    store.log_event(
        honeypot_name=settings["name"],
        event_type="connection",
        source_ip=source_ip,
        details="MySQL TCP connection opened",
    )
    salt = os.urandom(20)
    connection_id = int.from_bytes(os.urandom(4), "little")
    try:
        connection.sendall(packet(handshake_payload(connection_id, settings, salt), 0))
        _sequence_id, response = receive_packet(connection)
        parsed = parse_handshake_response(response)
        username = parsed["username"]
        database = parsed["database"] or settings["fake_data"].get("default_schema", "mysql")
        expected = scramble_native_password(settings["password"], salt)
        if username == settings["username"] and parsed["auth_response"] == expected:
            store.log_event(
                honeypot_name=settings["name"],
                event_type="login_success",
                source_ip=source_ip,
                details=f"MySQL login success for {username} on schema {database}",
            )
            connection.sendall(packet(ok_packet(), 2))
        else:
            store.log_event(
                honeypot_name=settings["name"],
                event_type="login_failure",
                source_ip=source_ip,
                details=f"MySQL login failure for {username} on schema {database}",
            )
            connection.sendall(packet(err_packet(1045, "Access denied for user"), 2))
            return

        while True:
            _sequence_id, payload = receive_packet(connection)
            if not payload:
                break
            command = payload[0]
            if command == 0x01:
                break
            if command == 0x03:
                query = payload[1:].decode("utf-8", errors="ignore")
                handle_query(connection, query, settings, store, source_ip)
                continue
            connection.sendall(packet(ok_packet(), 1))
    except Exception as exc:
        store.log_event(
            honeypot_name=settings["name"],
            event_type="runtime_error",
            source_ip=source_ip,
            severity="warning",
            details=f"MySQL honeypot error: {exc}",
        )
    finally:
        connection.close()


def main() -> None:
    settings = runtime_settings()
    store = runtime_store()
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((settings["bind"], settings["port"]))
    server_socket.listen(50)
    store.log_event(
        honeypot_name=settings["name"],
        event_type="startup",
        details=f"MySQL honeypot listening on {settings['bind']}:{settings['port']}",
    )
    while True:
        connection, _address = server_socket.accept()
        thread = threading.Thread(
            target=handle_client,
            args=(connection, settings, store),
            daemon=True,
        )
        thread.start()


if __name__ == "__main__":
    main()

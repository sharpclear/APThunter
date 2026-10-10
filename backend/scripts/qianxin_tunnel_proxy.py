"""Expose the Windows Qianxin reverse tunnel to APTHunter containers.

The SSH reverse tunnel listens on the VM loopback interface.  This proxy binds
the Docker host gateway and relays connections to that loopback listener.  The
connect timeout is deliberately cleared after the upstream connection is made:
model inference can legitimately take several minutes.
"""

from __future__ import annotations

import os
import socket
import threading
from collections.abc import Callable


def _env_int(name: str, default: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError as exc:
        raise SystemExit(f"{name} must be an integer") from exc
    if value <= 0:
        raise SystemExit(f"{name} must be positive")
    return value


LISTEN = (
    os.getenv("QIANXIN_TUNNEL_PROXY_LISTEN_HOST", "172.19.0.1"),
    _env_int("QIANXIN_TUNNEL_PROXY_LISTEN_PORT", 18788),
)
TARGET = (
    os.getenv("QIANXIN_TUNNEL_PROXY_TARGET_HOST", "127.0.0.1"),
    _env_int("QIANXIN_TUNNEL_PROXY_TARGET_PORT", 18787),
)
CONNECT_TIMEOUT = _env_int("QIANXIN_TUNNEL_PROXY_CONNECT_TIMEOUT_SEC", 15)


def relay(source: socket.socket, destination: socket.socket) -> None:
    try:
        while True:
            data = source.recv(65536)
            if not data:
                break
            destination.sendall(data)
    except OSError:
        pass
    finally:
        try:
            destination.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def handle(client: socket.socket, address: object) -> None:
    upstream: socket.socket | None = None
    try:
        client.settimeout(None)
        upstream = socket.create_connection(TARGET, timeout=CONNECT_TIMEOUT)
        # create_connection applies the connection timeout to later reads too.
        # Clear it so long model requests are not cut off after 15 seconds.
        upstream.settimeout(None)
        threading.Thread(
            target=relay,
            args=(client, upstream),
            daemon=True,
        ).start()
        relay(upstream, client)
    except OSError as exc:
        print(f"proxy connection from {address} failed: {exc}", flush=True)
    finally:
        for connection in (client, upstream):
            if connection is not None:
                try:
                    connection.close()
                except OSError:
                    pass


def serve(
    socket_factory: Callable[..., socket.socket] = socket.socket,
) -> None:
    server = socket_factory(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(LISTEN)
    server.listen(128)
    print(f"Qianxin tunnel proxy listening on {LISTEN}, target={TARGET}", flush=True)
    try:
        while True:
            client, address = server.accept()
            threading.Thread(
                target=handle,
                args=(client, address),
                daemon=True,
            ).start()
    finally:
        server.close()


if __name__ == "__main__":
    serve()

"""Proxy TCP que goteja a resposta de um servidor real, um byte por vez.

Simula um servidor lento ou hostil que mantém cada leitura abaixo do timeout
do socket para segurar o cliente. O que o cliente manda segue sem atraso.
"""

from __future__ import annotations

import socket
import threading
import time
from contextlib import suppress


class DripProxy:
    def __init__(self, upstream_port: int, *, delay_s: float = 0.3):
        self.upstream_port = upstream_port
        self.delay_s = delay_s
        self.sock = socket.create_server(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self) -> DripProxy:
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._stop.set()
        with suppress(OSError):
            self.sock.close()
        self._thread.join(timeout=2)

    def _serve(self) -> None:
        self.sock.settimeout(0.2)
        while not self._stop.is_set():
            try:
                client, _ = self.sock.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            threading.Thread(target=self._relay, args=(client,), daemon=True).start()

    def _relay(self, client: socket.socket) -> None:
        with (
            suppress(OSError),
            client,
            socket.create_connection(("127.0.0.1", self.upstream_port)) as up,
        ):

            def upward() -> None:
                with suppress(OSError):
                    while data := client.recv(4096):
                        up.sendall(data)

            threading.Thread(target=upward, daemon=True).start()
            while not self._stop.is_set() and (data := up.recv(4096)):
                for i in range(len(data)):
                    if self._stop.is_set():
                        return
                    client.sendall(data[i : i + 1])
                    time.sleep(self.delay_s)

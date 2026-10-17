"""Servidores TLS mínimos, em thread, para os testes de integração.

Rodam no mesmo Python dos testes. O modo ``hybrid`` só aceita ML-KEM quando
esse Python usa OpenSSL 3.5 ou mais novo (ex.: os Pythons instalados pelo uv).
"""

from __future__ import annotations

import socket
import ssl
import threading
from contextlib import suppress
from pathlib import Path

HAS_OPENSSL_35 = ssl.OPENSSL_VERSION_INFO >= (3, 5)


def make_context(mode: str, cert: Path, key: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    if mode == "hybrid":
        pass  # padrões do OpenSSL 3.5 já incluem X25519MLKEM768
    elif mode == "classical":
        ctx.set_ecdh_curve("prime256v1")  # restringe os grupos a P-256
    elif mode == "tls12-rsa":
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_ciphers("AES256-GCM-SHA384")  # troca de chave RSA, sem sigilo futuro
    else:
        raise ValueError(mode)
    return ctx


class TLSServer:
    """Aceita conexões e tenta o handshake; erros de handshake são esperados."""

    def __init__(self, mode: str, cert: Path, key: Path):
        self.ctx = make_context(mode, cert, key)
        self.sock = socket.create_server(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self) -> TLSServer:
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
                conn, _ = self.sock.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        conn.settimeout(3)
        with suppress(OSError, ssl.SSLError):
            with self.ctx.wrap_socket(conn, server_side=True) as tls, suppress(OSError):
                tls.recv(1)
            return
        with suppress(OSError):
            conn.close()


def closed_port() -> int:
    """Uma porta local que acabou de ser liberada (ninguém escutando)."""
    with socket.create_server(("127.0.0.1", 0)) as s:
        return s.getsockname()[1]
